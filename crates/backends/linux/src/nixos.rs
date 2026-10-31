//! `GenerationBackend` over Nix and NixOS's `switch-to-configuration`.
//!
//! Generation ids are Planarian's own, kept in `generations.json`. They map to
//! system store paths, because a candidate needs an id before it is in the
//! system profile (docs/deviations.md).
//!
//! Staging (§9 step 1) copies the owner's Nix-visible files (git-tracked files
//! with their working-tree contents, or the whole directory if it isn't a git
//! repository) into `stage/`. `base_source` is the NAR hash of that copy with
//! the live override; `staged_source`, with the candidate override.
//! Evaluation and build read the staged copy as a `path:` flake in pure-eval
//! mode, never the owner's live tree.
//!
//! Live activation runs `switch-to-configuration test` in a transient unit
//! named after the OpId (`planarian-op-<txn>-<epoch>-<seq>.service`), so
//! `jobs_tagged` can find the work an op started even if the reply was lost.

use crate::Paths;
use crate::admitted;
use crate::cmd::{MAX_OUTPUT, Output, run};
use planarian_changes::{parse as parse_overrides, render};
use planarian_schema::*;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const NIX: Duration = Duration::from_secs(30 * 60);
const QUICK: Duration = Duration::from_secs(30);
pub const ACTIVATION: Duration = Duration::from_secs(16 * 60);

/// systemd-boot entry identities in EFI are UTF-16LE after four attribute
/// bytes. Missing means absent; malformed or unreadable never means absent.
fn efi_entry_at(path: &Path) -> Result<Option<String>, Outcome> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(Outcome::Unknown(format!("cannot read EFI entry: {e}"))),
    };
    if bytes.len() < 6 || bytes.len() % 2 != 0 || bytes.len() > 4096 {
        return Err(Outcome::Unknown("malformed EFI entry".into()));
    }
    let units: Vec<u16> = bytes[4..].chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
    if units.last() != Some(&0) {
        return Err(Outcome::Unknown("unterminated EFI entry".into()));
    }
    let name = String::from_utf16(&units).map_err(|_| Outcome::Unknown("invalid UTF-16 EFI entry".into()))?;
    let name = name.trim_end_matches('\0');
    if name.contains('\0') {
        return Err(Outcome::Unknown("embedded terminator in EFI entry".into()));
    }
    Ok((!name.is_empty()).then(|| name.to_owned()))
}

fn profile_number_for_entry(name: &str) -> Result<u64, Outcome> {
    let number = name
        .strip_prefix("nixos-generation-")
        .and_then(|s| s.strip_suffix(".conf"))
        .and_then(|s| s.parse::<u64>().ok())
        .filter(|n| *n > 0);
    number
        .filter(|n| format!("nixos-generation-{n}.conf") == name)
        .ok_or_else(|| Outcome::Unknown("unrecognized boot entry identity".into()))
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Registry {
    pub next: u64,
    pub paths: BTreeMap<u64, String>,
    pub overrides: BTreeMap<u64, Hash>,
}

impl Registry {
    pub fn id_for(&mut self, path: &str) -> GenerationId {
        if let Some((id, _)) = self.paths.iter().find(|(_, p)| *p == path) {
            return GenerationId(*id);
        }
        self.next = self.next.max(self.paths.keys().max().copied().unwrap_or(0)) + 1;
        self.paths.insert(self.next, path.to_string());
        GenerationId(self.next)
    }
}

/// The JSON a generation exports at `/etc/planarian/export.json` and through
/// `config.services.planarian.export` (see nix/module.nix).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Export {
    pub units: Vec<UnitDef>,
    pub user_units: Vec<UnitDef>,
    pub core_units: BTreeMap<String, String>,
    pub devices: BTreeMap<String, String>,
    /// pname → version of the system packages (§12e).
    pub packages: BTreeMap<String, String>,
    /// pnames whose `meta.knownVulnerabilities` is not empty.
    pub insecure: Vec<String>,
    /// Every system service → the files defining it (§15 provenance).
    #[serde(default)]
    pub declarations: BTreeMap<String, Vec<String>>,
    /// Flake inputs: name → { rev, path }.
    #[serde(default)]
    pub inputs: BTreeMap<String, ExportInput>,
    /// Every undeclared system service → its shipped-table sensitivity (§11).
    #[serde(default)]
    pub services: BTreeMap<String, Sensitivities>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportInput {
    #[serde(default)]
    pub rev: String,
    #[serde(default)]
    pub path: String,
}

impl Export {
    pub fn into_eval(self, source: Hash) -> EvaluatedGeneration {
        EvaluatedGeneration {
            source,
            options: BTreeMap::new(),
            units: self.units.into_iter().map(|d| (d.id.clone(), d)).collect(),
            user_units: self.user_units,
            activation: ActivationPlan::default(),
            locked: BTreeSet::new(),
            core_units: self
                .core_units
                .into_iter()
                .map(|(k, v)| (k, Hash::from_hex(&v).unwrap_or(Hash::of(v.as_bytes()))))
                .collect(),
            packages: self.packages,
            insecure: self.insecure.into_iter().collect(),
            declarations: self.declarations,
            inputs: self.inputs.into_iter().map(|(k, v)| (k, (v.rev, v.path))).collect(),
            services: self.services,
        }
    }
}

/// Why a dry activation gives no usable plan, if it does not (R10).
pub fn dry_activate_failure(o: &Output) -> Option<String> {
    if o.timed_out {
        Some("dry activation timed out: its plan is unknown".into())
    } else if o.truncated {
        Some("dry activation output was cut short: its plan is incomplete".into())
    } else if !o.ok() {
        Some(format!("dry activation failed ({:?}): {}", o.status, o.tail()))
    } else {
        None
    }
}

/// Parse `switch-to-configuration dry-activate` output.
pub fn parse_dry_activate(text: &str) -> ActivationPlan {
    let mut plan = ActivationPlan::default();
    for line in text.lines() {
        let line = line.trim();
        let (set, list) = if let Some(l) = line.strip_prefix("would stop the following units: ") {
            (&mut plan.stop, l)
        } else if let Some(l) = line.strip_prefix("would restart the following units: ") {
            (&mut plan.restart, l)
        } else if let Some(l) = line.strip_prefix("would start the following units: ") {
            (&mut plan.start, l)
        } else if let Some(l) = line.strip_prefix("would reload the following units: ") {
            (&mut plan.reload, l)
        } else {
            continue;
        };
        for u in list.split(',').map(str::trim).filter(|u| !u.is_empty()) {
            if let Some(n) = u.strip_suffix(".service") {
                set.insert(UnitId::service(n));
            } else if let Some(n) = u.strip_suffix(".target") {
                set.insert(UnitId::target(n));
            }
        }
    }
    plan
}

/// Accept only the pinned NixOS dry-activation protocol. Empty, malformed or
/// truncated discovery is not evidence of an activation with no effects.
fn checked_dry_activate(out: &Output) -> Result<ActivationPlan, Outcome> {
    if let Some(why) = dry_activate_failure(out) {
        return Err(Outcome::Unknown(why));
    }
    if out.stdout.len() >= MAX_OUTPUT
        || out.stderr.len() >= MAX_OUTPUT
        || (!out.stdout.is_empty() && !out.stdout.ends_with('\n'))
        || (!out.stderr.is_empty() && !out.stderr.ends_with('\n'))
    {
        return Err(Outcome::Unknown("dry-activation output is incomplete".into()));
    }
    let text = format!("{}\n{}", out.stdout, out.stderr);
    if !text.lines().any(|line| line.trim() == "would activate the configuration...") {
        return Err(Outcome::Unknown("dry-activation protocol marker is missing".into()));
    }
    let effects = ["stop", "restart", "start", "reload"];
    for line in text.lines().map(str::trim).filter(|line| line.starts_with("would ")) {
        if line == "would activate the configuration..." {
            continue;
        }
        if let Some(list) = line.strip_prefix("would NOT stop the following changed units: ") {
            if list.is_empty() {
                return Err(Outcome::Unknown("malformed dry-activation skip list".into()));
            }
            continue;
        }
        let list = effects.iter().find_map(|verb| {
            let prefix = format!("would {verb} the following units: ");
            line.strip_prefix(prefix.as_str())
        });
        let Some(list) = list else {
            return Err(Outcome::Unknown(format!("unmodeled dry-activation effect: {line}")));
        };
        for unit in list.split(',').map(str::trim) {
            // Socket/mount/swap effects do not fit Phase A's current unit
            // schema. Refuse them rather than silently dropping their risk.
            let name = unit.strip_suffix(".service").or_else(|| unit.strip_suffix(".target"));
            if name.is_none_or(|name| name.is_empty() || name.chars().any(char::is_whitespace)) {
                return Err(Outcome::Unknown(format!("unmodeled or malformed activation unit: {unit}")));
            }
        }
    }
    Ok(parse_dry_activate(&text))
}

fn discover_activation(path: &Path, timeout: Duration) -> Result<ActivationPlan, Outcome> {
    checked_dry_activate(&run(&[&path.join("bin/switch-to-configuration").to_string_lossy(), "dry-activate"], timeout))
}

/// The Nix function given to `nix eval --apply`: the export, plus the current
/// value and highest priority of each option path the overrides touch.
pub fn apply_expr(paths: &[String]) -> String {
    let list = |p: &str| {
        let segs: Vec<String> = p.split('.').map(|s| format!("{s:?}")).collect();
        format!("[ {} ]", segs.join(" "))
    };
    let walk = |root: &str, p: &str| {
        format!(
            "(builtins.foldl' (a: k: if a != null && builtins.isAttrs a && a ? ${{k}} then a.${{k}} else null) {root} {})",
            list(p)
        )
    };
    let mut values = String::new();
    let mut prios = String::new();
    for p in paths {
        values.push_str(&format!(" {p:?} = {};", walk("c.config", p)));
        prios.push_str(&format!(
            " {p:?} = (let o = {}; in if o != null && o ? highestPrio then o.highestPrio else 100);",
            walk("c.options", p)
        ));
    }
    format!("c: {{ export = c.config.services.planarian.export; values = {{{values} }}; prios = {{{prios} }}; }}")
}

/// The total size of the union of the closures of `paths`.
fn closure_bytes(paths: &[&str]) -> Result<u64, Outcome> {
    if paths.is_empty() {
        return Ok(0);
    }
    let mut args = vec!["path-info", "--recursive", "--json"];
    args.extend(paths);
    let o = nix(&args, QUICK);
    if !o.ok() {
        return Err(err(&o));
    }
    closure_bytes_of(&o.stdout).ok_or_else(|| Outcome::Failed("nix path-info: unexpected output".into()))
}

/// Sum `narSize` over the paths `nix path-info --json` lists, in either of
/// its shapes: an object keyed by path, or an array of objects with `path`.
pub fn closure_bytes_of(json: &str) -> Option<u64> {
    let v: serde_json::Value = serde_json::from_str(json).ok()?;
    let sizes: Vec<u64> = match &v {
        serde_json::Value::Object(m) => m.values().map(|x| x["narSize"].as_u64().unwrap_or(0)).collect(),
        serde_json::Value::Array(a) => a.iter().map(|x| x["narSize"].as_u64().unwrap_or(0)).collect(),
        _ => return None,
    };
    Some(sizes.iter().sum())
}

fn value_from_json(v: &serde_json::Value) -> Option<Value> {
    Some(match v {
        serde_json::Value::Bool(b) => Value::Bool(*b),
        serde_json::Value::Number(n) => match n.as_i64() {
            Some(i) => Value::Int(i),
            None => Value::Str(n.to_string()),
        },
        serde_json::Value::String(s) => Value::Str(s.clone()),
        serde_json::Value::Array(a) => Value::List(a.iter().filter_map(value_from_json).collect()),
        _ => return None,
    })
}

#[derive(Clone, Debug)]
pub struct Nixos {
    paths: Paths,
    lock: Arc<Mutex<()>>,
    budget: gc::GcBudget,
}

fn sha(text: &str) -> Hash {
    Hash::of(text.as_bytes())
}

fn err(o: &Output) -> Outcome {
    if o.timed_out { Outcome::Unknown("timed out".into()) } else { Outcome::Failed(o.tail()) }
}

fn nix(args: &[&str], timeout: Duration) -> Output {
    let mut argv = vec!["nix", "--extra-experimental-features", "nix-command flakes"];
    argv.extend_from_slice(args);
    run(&argv, timeout)
}

/// NAR hash of a directory.
fn nar_hash(dir: &Path) -> Result<Hash, Outcome> {
    let o = run(&["nix-hash", "--type", "sha256", "--base16", &dir.to_string_lossy()], NIX);
    if !o.ok() {
        return Err(err(&o));
    }
    Hash::from_hex(o.stdout.trim())
        .ok_or_else(|| Outcome::Failed(format!("unexpected nix-hash output {:?}", o.stdout.trim())))
}

fn copy_file(src: &Path, dst: &Path) -> std::io::Result<()> {
    if let Some(p) = dst.parent() {
        std::fs::create_dir_all(p)?;
    }
    let meta = std::fs::symlink_metadata(src)?;
    if meta.file_type().is_symlink() {
        std::os::unix::fs::symlink(std::fs::read_link(src)?, dst)
    } else {
        std::fs::copy(src, dst).map(|_| ())
    }
}

fn walk(root: &Path, dir: &Path, out: &mut Vec<PathBuf>) -> std::io::Result<()> {
    for e in std::fs::read_dir(dir)? {
        let e = e?;
        let p = e.path();
        if p.file_name().is_some_and(|n| n == ".git") {
            continue;
        }
        if e.file_type()?.is_dir() {
            walk(root, &p, out)?;
        } else {
            out.push(p.strip_prefix(root).expect("under root").to_path_buf());
        }
    }
    Ok(())
}

impl Nixos {
    /// `slow` (gym hooks only): the activation unit first sleeps this long,
    /// and if `uncancellable`, ignores being stopped; it is the unit that is
    /// slow, so it outlives the daemon like a real long activation.
    fn activate_live_inner(&self, g: GenerationId, op: &OpId, slow: Option<(std::time::Duration, bool)>) -> Outcome {
        if !admitted(&self.paths.txn_dir(), op) {
            return Outcome::fenced();
        }
        let path = match self.path_of(g) {
            Ok(p) => p,
            Err(o) => return o,
        };
        let unit = format!("--unit={}", Self::unit_name(op));
        let switch = format!("{}/bin/switch-to-configuration", path.0);
        let mut cmd: Vec<String> = [
            "systemd-run",
            &unit,
            "--slice=planarian-monitor.slice",
            "--wait",
            "--collect",
            "--quiet",
            "--service-type=oneshot",
            "--property=TimeoutStartSec=15min",
        ]
        .map(String::from)
        .to_vec();
        match slow {
            None => cmd.extend([switch, "test".into()]),
            Some((d, uncancellable)) => {
                if uncancellable {
                    cmd.extend(
                        [
                            "--property=KillSignal=SIGWINCH",
                            "--property=SendSIGKILL=no",
                            "--property=TimeoutStopSec=infinity",
                        ]
                        .map(String::from),
                    );
                }
                // A transient unit's PATH is systemd's default, empty on NixOS.
                cmd.extend([
                    "/bin/sh".into(),
                    "-c".into(),
                    format!("PATH=/run/current-system/sw/bin; sleep {}; exec {switch} test", d.as_secs()),
                ]);
            }
        }
        let args: Vec<&str> = cmd.iter().map(String::as_str).collect();
        let o = run(&args, ACTIVATION);
        if o.ok() { Outcome::Succeeded } else { err(&o) }
    }

    pub fn new(paths: Paths) -> Nixos {
        Nixos { paths, lock: Arc::new(Mutex::new(())), budget: gc::GcBudget::default() }
    }

    /// The §12b bounds (`services.planarian.gc`).
    pub fn with_budget(mut self, budget: gc::GcBudget) -> Nixos {
        self.budget = budget;
        self
    }

    /// The system profile's generations: (profile number, store path).
    fn profile_generations(&self) -> Vec<(u64, String)> {
        let dir = self.paths.profile.parent().expect("profile dir");
        let prefix = format!("{}-", self.paths.profile.file_name().expect("name").to_string_lossy());
        let mut gens: Vec<(u64, String)> = std::fs::read_dir(dir)
            .map(|rd| {
                rd.flatten()
                    .filter_map(|e| {
                        let n = e.file_name().to_string_lossy().into_owned();
                        let num = n.strip_prefix(&prefix)?.strip_suffix("-link")?.parse().ok()?;
                        Some((num, std::fs::canonicalize(e.path()).ok()?.to_string_lossy().into_owned()))
                    })
                    .collect()
            })
            .unwrap_or_default();
        gens.sort();
        gens
    }

    /// Roots that no longer hold anything Planarian needs, removed before a
    /// collection so it can free what the profile no longer keeps (§9 step 5,
    /// §12b): a build root whose candidate is a profile generation (the
    /// profile link roots it from commit on, and a collected one must go),
    /// and a `gen-<n>` root for a generation no longer protected.
    fn prune_roots(&self, profile: &[(u64, String)], protect: &[GenerationId]) {
        let in_profile: BTreeSet<&str> = profile.iter().map(|(_, p)| p.as_str()).collect();
        let entries = |d: &Path| std::fs::read_dir(d).map(|rd| rd.flatten().collect::<Vec<_>>()).unwrap_or_default();
        for e in entries(&self.paths.gcroots.join("builds")) {
            let target = std::fs::read_link(e.path()).ok().map(|t| t.to_string_lossy().into_owned());
            if target.is_some_and(|t| in_profile.contains(t.as_str())) {
                let _ = std::fs::remove_file(e.path());
            }
        }
        for e in entries(&self.paths.gcroots) {
            let name = e.file_name().to_string_lossy().into_owned();
            let Some(n) = name.strip_prefix("gen-").and_then(|n| n.parse::<u64>().ok()) else { continue };
            if !protect.contains(&GenerationId(n)) {
                let _ = std::fs::remove_file(e.path());
            }
        }
    }

    /// Plan over profile numbers. Protected generations are the profile
    /// entries whose store path is a protected generation's.
    fn plan_profile(
        &self,
        protect: &[GenerationId],
        emergency: bool,
    ) -> Result<(gc::GcPlan, Vec<(u64, String)>), Outcome> {
        let protected_paths: BTreeSet<String> =
            protect.iter().filter_map(|g| self.path_of(*g).ok()).map(|p| p.0).collect();
        let gens = self.profile_generations();
        let ids: Vec<GenerationId> = gens.iter().map(|(n, _)| GenerationId(*n)).collect();
        let keep: Vec<GenerationId> =
            gens.iter().filter(|(_, p)| protected_paths.contains(p)).map(|(n, _)| GenerationId(*n)).collect();
        let fs_bytes = match rustix::fs::statvfs("/nix/store") {
            Ok(v) => v.f_blocks.saturating_mul(v.f_frsize),
            Err(e) => return Err(Outcome::Failed(format!("statvfs /nix/store: {e}"))),
        };
        let count = if emergency { self.budget.keep_emergency } else { self.budget.keep_generations };
        let mut failure = None;
        let keep = self.budget.protected(&ids, &keep);
        let plan = gc::plan(&ids, &keep, count, self.budget.max_bytes(fs_bytes), |set| {
            let paths: Vec<&str> =
                gens.iter().filter(|(n, _)| set.contains(&GenerationId(*n))).map(|(_, p)| p.as_str()).collect();
            closure_bytes(&paths).unwrap_or_else(|o| {
                failure = Some(o);
                0
            })
        });
        match failure {
            Some(o) => Err(o),
            None => Ok((plan, gens)),
        }
    }

    /// The store path the boot menu was last installed for.
    fn boot_menu_path(&self) -> PathBuf {
        self.paths.state.join("boot-menu")
    }

    /// The boot menu is the one for `path`: as recorded after the last
    /// successful install, or, before any (a machine installed before this
    /// record existed), when `path` is the system that booted.
    /// The number of the profile generation the profile link points at
    /// (`system-<n>-link`).
    fn profile_generation(&self) -> Option<u64> {
        let l = std::fs::read_link(&self.paths.profile).ok()?;
        let name = l.file_name()?.to_string_lossy().into_owned();
        name.strip_suffix("-link")?.rsplit('-').next()?.parse().ok()
    }

    fn generation_for_entry(&self, name: &str) -> Result<GenerationId, Outcome> {
        let n = profile_number_for_entry(name)?;
        let link = self.paths.profile.with_file_name(format!("system-{n}-link"));
        self.id_of_link(&link)
    }

    fn systemd_boot_default(&self, loader: &Path, efivars: &Path) -> Result<GenerationId, Outcome> {
        let selected = |name: &str| {
            profile_number_for_entry(name)?;
            let entry = loader.parent().expect("loader.conf has a parent").join("entries").join(name);
            if !entry.is_file() {
                return Err(Outcome::Unknown("selected boot entry is not installed".into()));
            }
            self.generation_for_entry(name)
        };
        let variable = efivars.join("LoaderEntryDefault-4a67b082-0a4c-41cf-b6c7-440b29bb8c4f");
        if let Some(name) = efi_entry_at(&variable)? {
            return selected(&name);
        }
        let text = std::fs::read_to_string(loader)
            .map_err(|e| Outcome::Unknown(format!("cannot read systemd-boot default: {e}")))?;
        let defaults: Vec<&str> = text
            .lines()
            .filter_map(|line| {
                let mut parts = line.split_whitespace();
                if parts.next() == Some("default") { Some((parts.next(), parts.next())) } else { None }
            })
            .map(|(entry, extra)| if extra.is_none() { entry.unwrap_or("") } else { "" })
            .collect();
        if defaults.len() != 1 {
            return Err(Outcome::Unknown("no unique installed boot default".into()));
        }
        selected(defaults[0])
    }

    /// A persistent EFI default overrides NixOS's loader.conf. Establish the
    /// authorized profile entry explicitly so a vulnerable manual fallback
    /// cannot remain the automatic choice after publishing a security fix.
    fn select_systemd_boot_default(&self, generation: GenerationId) -> Outcome {
        let Some(number) = self.profile_generation() else {
            return Outcome::Unknown("cannot identify installed boot default entry".into());
        };
        let name = format!("nixos-generation-{number}.conf");
        if self.generation_for_entry(&name) != Ok(generation) {
            return Outcome::Unknown("profile changed before selecting the boot default".into());
        }
        let o = run(&["bootctl", "set-default", &name], QUICK);
        if !o.ok() {
            return Outcome::Unknown(format!("cannot establish persistent boot default: {}", o.tail()));
        }
        match self.systemd_boot_default(Path::new("/boot/loader/loader.conf"), Path::new("/sys/firmware/efi/efivars")) {
            Ok(actual) if actual == generation => Outcome::Succeeded,
            _ => Outcome::Unknown("persistent boot default did not verify".into()),
        }
    }

    fn boot_menu_for(&self, path: &str) -> bool {
        match std::fs::read_to_string(self.boot_menu_path()) {
            Ok(p) => p.trim() == path,
            Err(_) => {
                std::fs::canonicalize("/run/booted-system").ok().map(|p| p.to_string_lossy().into_owned())
                    == Some(path.to_string())
            }
        }
    }

    fn report_path(&self) -> PathBuf {
        self.paths.state.join("gc-report.json")
    }

    fn registry_path(&self) -> PathBuf {
        self.paths.state.join("generations.json")
    }

    fn with_registry<R>(&self, f: impl FnOnce(&mut Registry) -> R) -> Result<R, Outcome> {
        let _g = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        let p = self.registry_path();
        let mut reg: Registry = match std::fs::read(&p) {
            Ok(b) => serde_json::from_slice(&b).map_err(|e| Outcome::Failed(format!("generations.json: {e}")))?,
            Err(_) => Registry::default(),
        };
        let before = serde_json::to_vec(&reg).expect("serializes");
        let r = f(&mut reg);
        let after = serde_json::to_vec(&reg).expect("serializes");
        if after != before {
            let tmp = p.with_extension("json.tmp");
            std::fs::create_dir_all(&self.paths.state).map_err(|e| Outcome::Failed(e.to_string()))?;
            std::fs::write(&tmp, &after)
                .and_then(|_| std::fs::rename(&tmp, &p))
                .map_err(|e| Outcome::Failed(e.to_string()))?;
        }
        Ok(r)
    }

    fn id_of_link(&self, link: &Path) -> Result<GenerationId, Outcome> {
        let target = std::fs::canonicalize(link).map_err(|e| Outcome::Failed(format!("{}: {e}", link.display())))?;
        let t = target.to_string_lossy().into_owned();
        self.with_registry(|r| r.id_for(&t))
    }

    fn override_file(&self, root: &Path) -> PathBuf {
        root.join("planarian/overrides.nix")
    }

    fn store_dir(&self) -> PathBuf {
        self.paths.state.join("overrides")
    }

    /// The owner's Nix-visible files, and the untracked files left out.
    fn visible_files(&self, root: &Path) -> Result<(Vec<PathBuf>, Vec<String>), Outcome> {
        let r = root.to_string_lossy().into_owned();
        if root.join(".git").exists() {
            let safe = format!("safe.directory={r}");
            let tracked = run(&["git", "-c", &safe, "-C", &r, "ls-files", "-z", "--cached"], QUICK);
            if !tracked.ok() {
                return Err(err(&tracked));
            }
            let untracked =
                run(&["git", "-c", &safe, "-C", &r, "ls-files", "-z", "--others", "--exclude-standard"], QUICK);
            let files = tracked
                .stdout
                .split('\0')
                .filter(|s| !s.is_empty())
                .map(PathBuf::from)
                .filter(|p| root.join(p).exists())
                .collect();
            let skipped = untracked.stdout.split('\0').filter(|s| !s.is_empty()).map(String::from).collect();
            Ok((files, skipped))
        } else {
            let mut out = vec![];
            walk(root, root, &mut out).map_err(|e| Outcome::Failed(e.to_string()))?;
            Ok((out, vec![]))
        }
    }

    /// Copy the owner's visible files into a fresh directory.
    fn copy_owner(&self, root: &Path) -> Result<(PathBuf, Vec<String>), Outcome> {
        let (files, skipped) = self.visible_files(root)?;
        let rel = Path::new("planarian/overrides.nix");
        if !files.iter().any(|f| f == rel) {
            return Err(Outcome::Failed(
                "planarian/overrides.nix is not part of your configuration (for a git flake: `git add planarian/overrides.nix`)".into(),
            ));
        }
        let stage = self.paths.state.join("stage");
        let tmp = stage.join(format!("tmp-{}-{}", std::process::id(), Timestamp_now()));
        for f in &files {
            copy_file(&root.join(f), &tmp.join(f)).map_err(|e| Outcome::Failed(format!("{}: {e}", f.display())))?;
        }
        Ok((tmp, skipped))
    }

    fn flake_ref(&self, dir: &Path) -> String {
        format!("path:{}#{}", dir.display(), self.paths.flake_attr)
    }

    fn staged_dir(&self, source: &Hash) -> PathBuf {
        self.paths.state.join("stage").join(source.to_hex())
    }

    fn unit_name(op: &OpId) -> String {
        format!("planarian-op-{}-{}-{}", op.txn.0, op.epoch, op.seq)
    }

    fn preflight_path(&self, generation: GenerationId, path: StorePath, root: String) -> Result<Built, Outcome> {
        let current = std::fs::canonicalize("/run/current-system")
            .map_err(|e| Outcome::Unknown(format!("cannot identify preflight base: {e}")))?;
        let mut activation = discover_activation(Path::new(&path.0), Duration::from_secs(120))?;
        let differs = |name: &str| -> Result<bool, Outcome> {
            let candidate = std::fs::read_link(Path::new(&path.0).join(name))
                .map_err(|e| Outcome::Unknown(format!("candidate {name}: {e}")))?;
            let base =
                std::fs::read_link(current.join(name)).map_err(|e| Outcome::Unknown(format!("current {name}: {e}")))?;
            Ok(candidate != base)
        };
        let params = |base: &Path| {
            std::fs::read(base.join("kernel-params")).map_err(|e| Outcome::Unknown(format!("kernel-params: {e}")))
        };
        activation.needs_reboot_to_confirm =
            differs("kernel")? || differs("initrd")? || params(Path::new(&path.0))? != params(&current)?;
        if std::fs::canonicalize("/run/current-system").ok().as_ref() != Some(&current) {
            return Err(Outcome::Unknown("running generation changed during preflight".into()));
        }
        Ok(Built { generation, path, root, activation })
    }

    /// The callback exposes the final comparison/replacement boundary to the
    /// negative R11 regression. The production caller supplies a no-op: this
    /// does not make check-then-rename atomic against arbitrary editors.
    fn swap_override_after_comparison<F: FnOnce()>(
        &self,
        from: &Hash,
        to: &Hash,
        op: &OpId,
        after_comparison: F,
    ) -> Outcome {
        if !admitted(&self.paths.txn_dir(), op) {
            return Outcome::fenced();
        }
        let live = self.override_file(&self.paths.owner);
        // All supported writers lock this same directory inode. Keep the guard
        // through comparison, rename and directory fsync; non-cooperating root
        // editors remain the explicitly accepted X-12 bypass.
        let _writer_lock = match std::fs::File::open(live.parent().expect("override has a parent")).and_then(|lock| {
            rustix::fs::flock(&lock, rustix::fs::FlockOperation::NonBlockingLockExclusive)?;
            Ok(lock)
        }) {
            Ok(lock) => lock,
            Err(e) => return Outcome::Unknown(format!("override writer lock unavailable: {e}")),
        };
        if !admitted(&self.paths.txn_dir(), op) {
            return Outcome::fenced();
        }
        let current = match std::fs::read_to_string(&live) {
            Ok(t) => sha(&t),
            Err(e) => return Outcome::Failed(e.to_string()),
        };
        if current == *to {
            return Outcome::Succeeded;
        }
        if current != *from {
            return Outcome::Failed("planarian/overrides.nix was changed by someone else".into());
        }
        let text = match std::fs::read_to_string(self.store_dir().join(format!("{}.nix", to.to_hex()))) {
            Ok(t) if sha(&t) == *to => t,
            _ => return Outcome::Failed("override content for this transaction is missing".into()),
        };
        after_comparison();
        if !admitted(&self.paths.txn_dir(), op) {
            return Outcome::fenced();
        }
        match Self::write_atomically(&live, &text) {
            Ok(()) => Outcome::Succeeded,
            Err(e) => Outcome::Failed(e.to_string()),
        }
    }

    fn write_atomically(target: &Path, text: &str) -> std::io::Result<()> {
        use std::io::Write;
        let dir = target.parent().expect("has a parent");
        let meta = std::fs::metadata(target).ok();
        let tmp = dir.join(".overrides.nix.planarian-tmp");
        {
            let mut f = std::fs::File::create(&tmp)?;
            f.write_all(text.as_bytes())?;
            f.sync_all()?;
        }
        if let Some(m) = meta {
            use std::os::unix::fs::MetadataExt;
            let _ = rustix::fs::chown(
                &tmp,
                Some(rustix::fs::Uid::from_raw(m.uid())),
                Some(rustix::fs::Gid::from_raw(m.gid())),
            );
        }
        std::fs::rename(&tmp, target)?;
        std::fs::File::open(dir)?.sync_all()
    }
}

#[allow(non_snake_case)]
fn Timestamp_now() -> u128 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0)
}

impl GenerationBackend for Nixos {
    fn current(&self) -> Result<GenerationId, Outcome> {
        self.id_of_link(Path::new("/run/current-system"))
    }

    fn boot_entries(&self) -> Result<Vec<GenerationId>, Outcome> {
        let dir = self.paths.profile.parent().expect("profile has a directory");
        let prefix = format!("{}-", self.paths.profile.file_name().expect("profile name").to_string_lossy());
        let mut out = vec![];
        for e in std::fs::read_dir(dir).map_err(|e| Outcome::Failed(e.to_string()))?.flatten() {
            let n = e.file_name().to_string_lossy().into_owned();
            if n.starts_with(&prefix) && n.ends_with("-link") {
                out.push(self.id_of_link(&e.path())?);
            }
        }
        out.sort();
        out.dedup();
        Ok(out)
    }

    fn boot_default(&self) -> Result<GenerationId, Outcome> {
        let loader = Path::new("/boot/loader/loader.conf");
        let efivars = Path::new("/sys/firmware/efi/efivars");
        if loader.is_file() && efivars.is_dir() {
            return self.systemd_boot_default(loader, efivars);
        }
        self.id_of_link(&self.paths.profile)
    }

    fn last_booted(&self) -> Result<GenerationId, Outcome> {
        self.id_of_link(Path::new("/run/booted-system"))
    }

    /// The profile link's owner and modification time (`nixos-rebuild` as
    /// root, or Planarian, which also runs as root: the journal tells those
    /// apart; this answers for rebuilds outside Planarian).
    fn created_by(&self, g: GenerationId) -> Option<(u32, Timestamp)> {
        use std::os::unix::fs::MetadataExt;
        let dir = self.paths.profile.parent()?;
        // Planarian's generation ids are not profile numbers: find the
        // profile link that holds this generation's system path (the newest,
        // if several do).
        let path = self.path_of(g).ok()?;
        let number = self.profile_generations().into_iter().filter(|(_, p)| *p == path.0).map(|(n, _)| n).max()?;
        let name = format!("{}-{}-link", self.paths.profile.file_name()?.to_string_lossy(), number);
        let m = std::fs::symlink_metadata(dir.join(name)).ok()?;
        Some((m.uid(), Timestamp(u64::try_from(m.mtime()).ok()? * 1000)))
    }

    fn stage(&self, owner: &PinnedSource, overrides: &OverrideSet) -> Result<StagedSource, Outcome> {
        let root = PathBuf::from(&owner.root);
        let (tmp, excluded) = self.copy_owner(&root)?;
        let live = std::fs::read_to_string(self.override_file(&tmp)).map_err(|e| Outcome::Failed(e.to_string()))?;
        let base_source = nar_hash(&tmp)?;
        let candidate = render(overrides);
        std::fs::write(self.override_file(&tmp), &candidate).map_err(|e| Outcome::Failed(e.to_string()))?;
        let staged_source = nar_hash(&tmp)?;
        #[cfg(feature = "gym-hooks")]
        eprintln!("gym: staged {}: base {} candidate {}", owner.root, base_source.to_hex(), staged_source.to_hex());
        let dir = self.staged_dir(&staged_source);
        if dir.exists() {
            let _ = std::fs::remove_dir_all(&tmp);
        } else {
            std::fs::rename(&tmp, &dir).map_err(|e| Outcome::Failed(e.to_string()))?;
        }
        self.remember_override(overrides)?;
        Ok(StagedSource {
            dir: dir.to_string_lossy().into_owned(),
            base_source,
            staged_source,
            base_override: sha(&live),
            candidate_override: sha(&candidate),
            excluded,
        })
    }

    fn source_hash(&self, owner: &PinnedSource) -> Result<Hash, Outcome> {
        let (tmp, _) = self.copy_owner(Path::new(&owner.root))?;
        let h = nar_hash(&tmp);
        let _ = std::fs::remove_dir_all(&tmp);
        #[cfg(feature = "gym-hooks")]
        eprintln!("gym: source hash of {} now {:?}", owner.root, h.as_ref().map(|h| h.to_hex()));
        h
    }

    fn untracked(&self, owner: &PinnedSource) -> Vec<String> {
        self.visible_files(Path::new(&owner.root)).map(|(_, skipped)| skipped).unwrap_or_default()
    }

    fn evaluate(&self, src: &StagedSource) -> Result<EvaluatedGeneration, Outcome> {
        let dir = PathBuf::from(&src.dir);
        let text = std::fs::read_to_string(self.override_file(&dir)).map_err(|e| Outcome::Failed(e.to_string()))?;
        let set = parse_overrides(&text).unwrap_or_default();
        let paths: Vec<String> = set.assignments.keys().cloned().collect();
        let o = nix(
            &["eval", "--json", "--option", "pure-eval", "true", &self.flake_ref(&dir), "--apply", &apply_expr(&paths)],
            NIX,
        );
        if !o.ok() {
            return Err(err(&o));
        }
        #[derive(Deserialize)]
        struct Out {
            export: Export,
            values: BTreeMap<String, serde_json::Value>,
            prios: BTreeMap<String, i64>,
        }
        let out: Out =
            serde_json::from_str(&o.stdout).map_err(|e| Outcome::Failed(format!("evaluation output: {e}")))?;
        let mut eval = out.export.into_eval(src.staged_source);
        eval.options = out.values.iter().filter_map(|(k, v)| value_from_json(v).map(|v| (k.clone(), v))).collect();
        // mkOverride 90 loses to anything with a lower number (mkForce is 50).
        eval.locked = out.prios.into_iter().filter(|(_, p)| *p < 90).map(|(k, _)| k).collect();
        Ok(eval)
    }

    fn build(&self, eval: &EvaluatedGeneration) -> Result<Built, Outcome> {
        #[cfg(feature = "gym-hooks")]
        crate::gym::pause_point("build");
        let dir = self.staged_dir(&eval.source);
        let root = self.paths.gcroots.join("builds").join(eval.source.to_hex());
        std::fs::create_dir_all(root.parent().expect("parent")).map_err(|e| Outcome::Failed(e.to_string()))?;
        let attr = format!("{}.config.system.build.toplevel", self.flake_ref(&dir));
        let o = nix(&["build", "--out-link", &root.to_string_lossy(), "--print-out-paths", &attr], NIX);
        if !o.ok() {
            return Err(err(&o));
        }
        let printed = o.stdout.lines().last().unwrap_or_default().trim().to_string();
        // Resolve symlinks, so a generation has one name whichever way it was
        // reached (`/run/current-system` is resolved the same way).
        let path = std::fs::canonicalize(&printed).map(|p| p.to_string_lossy().into_owned()).unwrap_or(printed);
        let generation = self.with_registry(|r| r.id_for(&path))?;
        let result = self.preflight_path(generation, StorePath(path), root.to_string_lossy().into_owned());
        if result.is_err() {
            let _ = std::fs::remove_file(&root);
        }
        result
    }

    fn preflight_existing(&self, g: GenerationId, path: &StorePath) -> Result<Built, Outcome> {
        if self.path_of(g)? != *path {
            return Err(Outcome::Unknown("selected generation path changed".into()));
        }
        let root = self.paths.gcroots.join("builds").join(format!("existing-{}-{}", g.0, Timestamp_now()));
        std::fs::create_dir_all(root.parent().expect("parent")).map_err(|e| Outcome::Failed(e.to_string()))?;
        std::os::unix::fs::symlink(&path.0, &root).map_err(|e| Outcome::Failed(e.to_string()))?;
        if let Err(e) = std::fs::File::open(root.parent().expect("parent")).and_then(|dir| dir.sync_all()) {
            let _ = std::fs::remove_file(&root);
            return Err(Outcome::Failed(e.to_string()));
        }
        let result = self.preflight_path(g, path.clone(), root.to_string_lossy().into_owned());
        if result.is_err() {
            let _ = std::fs::remove_file(&root);
        }
        result
    }

    fn read_override(&self, hash: &Hash) -> Result<OverrideSet, Outcome> {
        let text = std::fs::read_to_string(self.store_dir().join(format!("{}.nix", hash.to_hex())))
            .map_err(|e| Outcome::Unknown(format!("override evidence: {e}")))?;
        if sha(&text) != *hash {
            return Err(Outcome::Unknown("override evidence hash mismatch".into()));
        }
        parse_overrides(&text).ok_or_else(|| Outcome::Unknown("invalid remembered override".into()))
    }

    fn verify_candidate(&self, path: &StorePath, _expected: &Hash) -> Result<bool, Outcome> {
        Ok(Path::new(&path.0).join("bin/switch-to-configuration").exists())
    }

    fn pending_jobs(&self) -> Result<Vec<JobId>, Outcome> {
        let o = run(
            &[
                "systemctl",
                "list-units",
                "--plain",
                "--no-legend",
                "--state=activating,active,deactivating,reloading",
                "planarian-op-*",
            ],
            QUICK,
        );
        if !o.ok() {
            return Err(err(&o));
        }
        Ok(o.stdout.lines().filter_map(|l| l.split_whitespace().next()).map(|n| JobId(n.into())).collect())
    }

    fn jobs_tagged(&self, op: &OpId) -> Result<Option<Vec<JobId>>, Outcome> {
        #[cfg(feature = "gym-hooks")]
        if crate::gym::hook("jobs_tagged", None).result.as_deref() == Some("None") {
            return Ok(None);
        }
        let name = format!("{}.service", Self::unit_name(op));
        let o = run(&["systemctl", "show", "--property=ActiveState,LoadState", &name], QUICK);
        if !o.ok() {
            return Ok(None);
        }
        let props = crate::systemd::parse_show(&o.stdout);
        let active = matches!(
            props.get("ActiveState").map(String::as_str),
            Some("active" | "activating" | "deactivating" | "reloading")
        );
        Ok(Some(if active { vec![JobId(name)] } else { vec![] }))
    }

    fn override_hash(&self) -> Result<Hash, Outcome> {
        std::fs::read_to_string(self.override_file(&self.paths.owner))
            .map(|t| sha(&t))
            .map_err(|e| Outcome::Failed(e.to_string()))
    }

    fn activate_live(&self, g: GenerationId, op: &OpId) -> Outcome {
        // Gym hooks: the delay goes into the activation unit, not the daemon.
        #[cfg(feature = "gym-hooks")]
        let (h, slow) = {
            let mut h = crate::gym::hook("activate_live", Some(g));
            let slow = h.delay.take().map(|d| (d, h.uncancellable));
            (h, slow)
        };
        #[cfg(feature = "gym-hooks")]
        return crate::gym::apply(h, || self.activate_live_inner(g, op, slow));
        #[cfg(not(feature = "gym-hooks"))]
        self.activate_live_inner(g, op, None)
    }

    fn publish_boot(&self, g: GenerationId, op: &OpId) -> Outcome {
        #[cfg(feature = "gym-hooks")]
        crate::gym::pause_point("publish_boot");
        if !admitted(&self.paths.txn_dir(), op) {
            return Outcome::fenced();
        }
        let path = match self.path_of(g) {
            Ok(p) => p,
            Err(o) => return o,
        };
        let profile = self.paths.profile.to_string_lossy().into_owned();
        let already = std::fs::canonicalize(&self.paths.profile).ok().map(|p| p.to_string_lossy().into_owned())
            == Some(path.0.clone());
        // Idempotent: the profile points at g and the boot menu was installed
        // for it (a revert after a publish that failed and was undone, or a
        // retry after a crash past the install).
        if already && self.boot_menu_for(&path.0) && self.boot_default() == Ok(g) {
            return Outcome::Succeeded;
        }
        if !already {
            let o = run(&["nix-env", "-p", &profile, "--set", &path.0], QUICK);
            if !o.ok() {
                return err(&o);
            }
        }
        let o = run(&[&format!("{}/bin/switch-to-configuration", path.0), "boot"], Duration::from_secs(300));
        if o.ok() {
            let _ = std::fs::write(self.boot_menu_path(), &path.0);
            if Path::new("/boot/loader/loader.conf").is_file() && Path::new("/sys/firmware/efi/efivars").is_dir() {
                return self.select_systemd_boot_default(g);
            }
            return Outcome::Succeeded;
        }
        // Best-effort profile cleanup after an installer failure. A failed
        // installer may have changed boot files: rollback of the profile does
        // not establish that the previous menu was restored. The transaction
        // must retain its mutation/reconciliation obligation.
        if !already {
            let added = std::fs::read_link(&self.paths.profile)
                .ok()
                .and_then(|l| l.file_name().map(|n| n.to_string_lossy().into_owned()))
                .and_then(|n| n.rsplit('-').nth(1).map(String::from));
            let _ = run(&["nix-env", "-p", &profile, "--rollback"], QUICK);
            if let Some(n) = added {
                let _ = run(&["nix-env", "-p", &profile, "--delete-generations", &n], QUICK);
            }
        }
        err(&o)
    }

    /// The boot-only path with systemd-boot (§12f): `g` gets its own profile
    /// generation and boot entry, `keep` is made the newest profile
    /// generation again (so the menu's default stays `keep`), and the entry
    /// for `g` is set to boot once (`bootctl set-oneshot`). Any failed or lost
    /// reply may follow partial effects; PublishingBoot owns reconciliation.
    fn publish_boot_once(&self, g: GenerationId, keep: GenerationId, op: &OpId) -> Outcome {
        if !admitted(&self.paths.txn_dir(), op) {
            return Outcome::fenced();
        }
        if !Path::new("/boot/loader/loader.conf").is_file() || !Path::new("/sys/firmware/efi/efivars").is_dir() {
            return Outcome::Unknown(
                "boot-only publication requires installed systemd-boot at /boot and writable EFI variables".into(),
            );
        }
        let (Ok(path), Ok(kept)) = (self.path_of(g), self.path_of(keep)) else {
            return Outcome::Failed("unknown generation".into());
        };
        let profile = self.paths.profile.to_string_lossy().into_owned();
        let set = |p: &str| run(&["nix-env", "-p", &profile, "--set", p], QUICK);
        let o = set(&path.0);
        if !o.ok() {
            return err(&o);
        }
        let Some(n) = self.profile_generation() else {
            let _ = set(&kept.0);
            return Outcome::Failed("cannot read the profile generation".into());
        };
        let o = set(&kept.0);
        if !o.ok() {
            return err(&o);
        }
        let o = run(&[&format!("{}/bin/switch-to-configuration", kept.0), "boot"], Duration::from_secs(300));
        if !o.ok() {
            return err(&o);
        }
        let _ = std::fs::write(self.boot_menu_path(), &kept.0);
        let selected = self.select_systemd_boot_default(keep);
        if !selected.is_success() {
            return selected;
        }
        let o = run(&["bootctl", "set-oneshot", &format!("nixos-generation-{n}.conf")], QUICK);
        if !o.ok() {
            return err(&o);
        }
        match self.one_shot_pending() {
            Ok(Some(actual)) if actual == g => Outcome::Succeeded,
            _ => Outcome::Unknown("one-shot selection did not verify after publication".into()),
        }
    }

    fn withdraw_boot_once(&self, keep: GenerationId, op: &OpId) -> Outcome {
        if !admitted(&self.paths.txn_dir(), op) {
            return Outcome::fenced();
        }
        // Clear even after a lost publication reply: lack of acknowledgment
        // says nothing about whether the EFI mutation took effect.
        let cleared = run(&["bootctl", "set-oneshot", ""], QUICK);
        if !cleared.ok() {
            return Outcome::Unknown(format!("cannot establish one-shot cancellation: {}", cleared.tail()));
        }
        match self.one_shot_pending() {
            Ok(None) => {}
            Ok(Some(_)) => return Outcome::Unknown("one-shot entry remains selected".into()),
            Err(o) => return o,
        }
        let published = self.publish_boot(keep, op);
        if published != Outcome::Succeeded {
            return published;
        }
        match self.boot_default() {
            Ok(g) if g == keep => Outcome::Succeeded,
            _ => Outcome::Unknown("fallback boot default could not be verified".into()),
        }
    }

    /// The pending one-shot entry, from systemd-boot's `LoaderEntryOneShot`
    /// EFI variable: `nixos-generation-<n>.conf` → the profile generation's path.
    fn one_shot_pending(&self) -> Result<Option<GenerationId>, Outcome> {
        let efivars = Path::new("/sys/firmware/efi/efivars");
        if !efivars.is_dir() {
            return Err(Outcome::Unknown("no EFI variables".into()));
        }
        let var = efivars.join("LoaderEntryOneShot-4a67b082-0a4c-41cf-b6c7-440b29bb8c4f");
        match efi_entry_at(&var)? {
            Some(name) => {
                profile_number_for_entry(&name)?;
                if !Path::new("/boot/loader/entries").join(&name).is_file() {
                    return Err(Outcome::Unknown("one-shot entry is not installed".into()));
                }
                self.generation_for_entry(&name).map(Some)
            }
            None => Ok(None),
        }
    }

    fn protect(&self, g: GenerationId, op: &OpId) -> Outcome {
        if !admitted(&self.paths.txn_dir(), op) {
            return Outcome::fenced();
        }
        let path = match self.path_of(g) {
            Ok(p) => p,
            Err(o) => return o,
        };
        let link = self.paths.gcroots.join(format!("gen-{}", g.0));
        let _ = std::fs::create_dir_all(&self.paths.gcroots);
        let _ = std::fs::remove_file(&link);
        match std::os::unix::fs::symlink(&path.0, &link) {
            Ok(()) => Outcome::Succeeded,
            Err(e) => Outcome::Failed(e.to_string()),
        }
    }

    fn cancel(&self, job: &JobId, op: &OpId) -> Outcome {
        if !admitted(&self.paths.txn_dir(), op) {
            return Outcome::fenced();
        }
        let o = run(&["systemctl", "stop", &job.0], Duration::from_secs(90));
        if o.ok() { Outcome::Succeeded } else { err(&o) }
    }

    fn swap_override(&self, from: &Hash, to: &Hash, op: &OpId) -> Outcome {
        self.swap_override_after_comparison(from, to, op, || {})
    }

    fn path_of(&self, g: GenerationId) -> Result<StorePath, Outcome> {
        self.with_registry(|r| r.paths.get(&g.0).cloned())?
            .map(StorePath)
            .ok_or_else(|| Outcome::Failed(format!("unknown generation {}", g.0)))
    }

    fn evaluate_built(&self, path: &StorePath) -> Result<EvaluatedGeneration, Outcome> {
        let p = Path::new(&path.0).join("etc/planarian/export.json");
        let text = std::fs::read_to_string(&p).map_err(|e| Outcome::Failed(format!("{}: {e}", p.display())))?;
        let export: Export =
            serde_json::from_str(&text).map_err(|e| Outcome::Failed(format!("{}: {e}", p.display())))?;
        Ok(export.into_eval(Hash::ZERO))
    }

    fn read_overrides(&self) -> Result<(OverrideSet, Hash), Outcome> {
        let text = std::fs::read_to_string(self.override_file(&self.paths.owner))
            .map_err(|e| Outcome::Failed(e.to_string()))?;
        let set = parse_overrides(&text).ok_or_else(|| {
            Outcome::Failed(
                "planarian/overrides.nix was edited by hand; restore it from `git` or remove the edits".into(),
            )
        })?;
        Ok((set, sha(&text)))
    }

    fn remember_override(&self, set: &OverrideSet) -> Result<Hash, Outcome> {
        let text = render(set);
        let h = sha(&text);
        let dir = self.store_dir();
        std::fs::create_dir_all(&dir).map_err(|e| Outcome::Failed(e.to_string()))?;
        std::fs::write(dir.join(format!("{}.nix", h.to_hex())), text).map_err(|e| Outcome::Failed(e.to_string()))?;
        Ok(h)
    }

    fn override_for(&self, g: GenerationId) -> Result<Option<Hash>, Outcome> {
        self.with_registry(|r| r.overrides.get(&g.0).copied())
    }

    fn record_override(&self, g: GenerationId, hash: &Hash) -> Result<(), Outcome> {
        self.with_registry(|r| {
            r.overrides.insert(g.0, *hash);
        })
    }

    fn gc_plan(&self, protect: &[GenerationId], emergency: bool) -> Result<gc::GcPlan, Outcome> {
        self.plan_profile(protect, emergency).map(|(p, _)| p)
    }

    fn space_report(&self) -> Option<gc::SpaceReport> {
        std::fs::read(self.report_path()).ok().and_then(|b| serde_json::from_slice(&b).ok())
    }

    fn release_root(&self, root: &str) -> bool {
        Path::new(root).starts_with(&self.paths.gcroots) && std::fs::remove_file(root).is_ok()
    }

    fn collect_garbage(&self, protect: &[GenerationId], emergency: bool, op: &OpId) -> Outcome {
        if !admitted(&self.paths.txn_dir(), op) {
            return Outcome::fenced();
        }
        let (plan, gens) = match self.plan_profile(protect, emergency) {
            Ok(p) => p,
            Err(o) => return o,
        };
        // Protected generations stay in the profile, so they stay in the boot menu (I1, I3).
        let delete: Vec<String> = plan.delete.iter().map(|g| g.0.to_string()).collect();
        if !delete.is_empty() {
            let profile = self.paths.profile.to_string_lossy().into_owned();
            let mut argv = vec!["nix-env", "-p", &profile, "--delete-generations"];
            argv.extend(delete.iter().map(String::as_str));
            let o = run(&argv, QUICK);
            if !o.ok() {
                return err(&o);
            }
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let report = gc::SpaceReport::of(&plan, Timestamp(now));
        if let Ok(json) = serde_json::to_vec_pretty(&report) {
            let _ = std::fs::write(self.report_path(), json);
        }
        for g in protect {
            if let Ok(p) = self.path_of(*g) {
                let link = self.paths.gcroots.join(format!("gen-{}", g.0));
                let _ = std::fs::create_dir_all(&self.paths.gcroots);
                if std::fs::read_link(&link).ok().map(|l| l.to_string_lossy().into_owned()) != Some(p.0.clone()) {
                    let _ = std::fs::remove_file(&link);
                    let _ = std::os::unix::fs::symlink(&p.0, &link);
                }
            }
        }
        self.prune_roots(&gens, protect);
        let o = run(&["nix-store", "--gc"], NIX);
        if !o.ok() {
            return err(&o);
        }
        if !delete.is_empty() {
            let _ = run(
                &[&format!("{}/bin/switch-to-configuration", self.paths.profile.display()), "boot"],
                Duration::from_secs(300),
            );
        }
        Outcome::Succeeded
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// §12b: a committed candidate's build root and a no-longer-protected
    /// generation's root go before a collection; a pending candidate's and a
    /// protected generation's stay.
    #[test]
    fn stale_roots_are_pruned_before_a_collection() {
        let d = tempfile::tempdir().unwrap();
        let paths = Paths { gcroots: d.path().join("gcroots"), ..Default::default() };
        let builds = paths.gcroots.join("builds");
        std::fs::create_dir_all(&builds).unwrap();
        std::os::unix::fs::symlink("/nix/store/aaa-committed", builds.join("a")).unwrap();
        std::os::unix::fs::symlink("/nix/store/bbb-pending", builds.join("b")).unwrap();
        std::os::unix::fs::symlink("/nix/store/aaa-committed", paths.gcroots.join("gen-5")).unwrap();
        std::os::unix::fs::symlink("/nix/store/ccc", paths.gcroots.join("gen-6")).unwrap();
        let n = Nixos::new(paths.clone());
        n.prune_roots(&[(1, "/nix/store/aaa-committed".into())], &[GenerationId(6)]);
        assert!(std::fs::symlink_metadata(builds.join("a")).is_err(), "committed: the profile roots it");
        assert!(std::fs::symlink_metadata(builds.join("b")).is_ok(), "pending: still the build's");
        assert!(std::fs::symlink_metadata(paths.gcroots.join("gen-5")).is_err(), "no longer protected");
        assert!(std::fs::symlink_metadata(paths.gcroots.join("gen-6")).is_ok(), "protected");
    }

    #[test]
    fn closure_sizes_from_both_json_shapes() {
        let object = r#"{"/nix/store/a": {"narSize": 100}, "/nix/store/b": {"narSize": 23}}"#;
        let array = r#"[{"path": "/nix/store/a", "narSize": 100}, {"path": "/nix/store/b", "narSize": 23}]"#;
        assert_eq!(closure_bytes_of(object), Some(123));
        assert_eq!(closure_bytes_of(array), Some(123));
        assert_eq!(closure_bytes_of("nonsense"), None);
    }

    #[test]
    fn cooperating_override_editor_waits_until_promotion_or_restoration_finishes() {
        use std::sync::mpsc::sync_channel;

        for restoration in [false, true] {
            let d = tempfile::tempdir().unwrap();
            let paths = Paths { state: d.path().join("state"), owner: d.path().join("owner"), ..Default::default() };
            let live = paths.owner.join("planarian/overrides.nix");
            std::fs::create_dir_all(live.parent().unwrap()).unwrap();
            std::fs::create_dir_all(paths.txn_dir().join("7")).unwrap();
            std::fs::write(paths.txn_dir().join("7/lease"), "1").unwrap();
            let n = Nixos::new(paths);
            let base = OverrideSet::default();
            let mut candidate = base.clone();
            candidate.assignments.insert("a.b".into(), Value::Bool(true));
            let base_hash = n.remember_override(&base).unwrap();
            let candidate_hash = n.remember_override(&candidate).unwrap();
            let (from, to, initial, replacement) = if restoration {
                (candidate_hash, base_hash, render(&candidate), render(&base))
            } else {
                (base_hash, candidate_hash, render(&base), render(&candidate))
            };
            std::fs::write(&live, initial).unwrap();
            let editor_live = live.clone();
            let (compared_tx, compared_rx) = sync_channel(0);
            let (blocked_tx, blocked_rx) = sync_channel(0);
            let third_party = "# cooperating editor's later source\n";
            let editor = std::thread::spawn(move || {
                compared_rx.recv_timeout(Duration::from_secs(2)).unwrap();
                let lock = std::fs::File::open(editor_live.parent().unwrap()).unwrap();
                assert_eq!(
                    rustix::fs::flock(&lock, rustix::fs::FlockOperation::NonBlockingLockExclusive),
                    Err(rustix::io::Errno::WOULDBLOCK)
                );
                blocked_tx.send(()).unwrap();
                rustix::fs::flock(&lock, rustix::fs::FlockOperation::LockExclusive).unwrap();
                assert_eq!(std::fs::read_to_string(&editor_live).unwrap(), replacement);
                Nixos::write_atomically(&editor_live, third_party).unwrap();
            });
            let op = OpId { txn: TxnId(7), epoch: 1, seq: 1 };
            let outcome = n.swap_override_after_comparison(&from, &to, &op, || {
                compared_tx.send(()).unwrap();
                blocked_rx.recv_timeout(Duration::from_secs(2)).unwrap();
            });
            assert_eq!(outcome, Outcome::Succeeded);
            editor.join().unwrap();
            assert_eq!(std::fs::read_to_string(&live).unwrap(), third_party);
        }
    }

    /// X-12: a root editor that ignores the directory lock is outside the
    /// adopted writer model. Characterize both promotion/restoration races
    /// without pretending advisory locking gives arbitrary-editor CAS.
    #[test]
    fn noncooperating_override_editors_remain_the_explicit_x12_bypass() {
        use std::io::{Seek, SeekFrom, Write};
        use std::sync::mpsc::sync_channel;

        for restoration in [false, true] {
            for rename_editor in [false, true] {
                let d = tempfile::tempdir().unwrap();
                let paths =
                    Paths { state: d.path().join("state"), owner: d.path().join("owner"), ..Default::default() };
                let live = paths.owner.join("planarian/overrides.nix");
                std::fs::create_dir_all(live.parent().unwrap()).unwrap();
                std::fs::create_dir_all(paths.txn_dir().join("7")).unwrap();
                std::fs::write(paths.txn_dir().join("7/lease"), "1").unwrap();
                let n = Nixos::new(paths);
                let base = OverrideSet::default();
                let mut candidate = base.clone();
                candidate.assignments.insert("a.b".into(), Value::Bool(true));
                let base_hash = n.remember_override(&base).unwrap();
                let candidate_hash = n.remember_override(&candidate).unwrap();
                let (from, to, initial, replacement) = if restoration {
                    (candidate_hash, base_hash, render(&candidate), render(&base))
                } else {
                    (base_hash, candidate_hash, render(&base), render(&candidate))
                };
                std::fs::write(&live, initial).unwrap();
                // Opening before the comparison also exercises an editor whose
                // write permission cannot be revoked merely by chmod afterward.
                let mut preopened = std::fs::OpenOptions::new().write(true).open(&live).unwrap();
                let editor_live = live.clone();
                let (compared_tx, compared_rx) = sync_channel(0);
                let (edited_tx, edited_rx) = sync_channel(0);
                let third_party = "# unrelated editor's source\n";
                let editor = std::thread::spawn(move || {
                    compared_rx.recv_timeout(Duration::from_secs(2)).unwrap();
                    if rename_editor {
                        let renamed = editor_live.with_extension("external");
                        let mut f = std::fs::File::create(&renamed).unwrap();
                        f.write_all(third_party.as_bytes()).unwrap();
                        f.sync_all().unwrap();
                        std::fs::rename(&renamed, &editor_live).unwrap();
                        std::fs::File::open(editor_live.parent().unwrap()).unwrap().sync_all().unwrap();
                    } else {
                        preopened.set_len(0).unwrap();
                        preopened.seek(SeekFrom::Start(0)).unwrap();
                        preopened.write_all(third_party.as_bytes()).unwrap();
                        preopened.sync_all().unwrap();
                    }
                    assert_eq!(std::fs::read_to_string(&editor_live).unwrap(), third_party);
                    edited_tx.send(()).unwrap();
                });
                let op = OpId { txn: TxnId(7), epoch: 1, seq: 1 };
                let outcome = n.swap_override_after_comparison(&from, &to, &op, || {
                    compared_tx.send(()).unwrap();
                    edited_rx.recv_timeout(Duration::from_secs(2)).unwrap();
                });
                editor.join().unwrap();
                assert_eq!(outcome, Outcome::Succeeded);
                assert_eq!(std::fs::read_to_string(&live).unwrap(), replacement);
                assert_ne!(
                    std::fs::read_to_string(&live).unwrap(),
                    third_party,
                    "non-cooperating root edits are the accepted X-12 bypass"
                );
            }
        }
    }

    /// R10: nonzero exit, timeout and truncated output each refuse the plan.
    #[test]
    fn a_failed_dry_activation_is_no_plan() {
        let o = |status, timed_out, truncated| Output {
            status,
            stdout: "would start the following units: a.service\n".into(),
            stderr: String::new(),
            timed_out,
            truncated,
        };
        assert!(dry_activate_failure(&o(Some(0), false, false)).is_none());
        assert!(dry_activate_failure(&o(Some(1), false, false)).is_some());
        assert!(dry_activate_failure(&o(None, true, false)).is_some());
        assert!(dry_activate_failure(&o(Some(0), false, true)).is_some());
    }

    #[test]
    fn dry_activate() {
        let text = "would stop the following units: gym-web.service, foo.socket\n\
                    would NOT stop the following changed units: getty@tty1.service\n\
                    would restart the following units: sshd.service\n\
                    would start the following units: avahi-daemon.service, graphical-session.target\n";
        let p = parse_dry_activate(text);
        assert_eq!(p.stop, [UnitId::service("gym-web")].into());
        assert_eq!(p.restart, [UnitId::service("sshd")].into());
        assert!(p.start.contains(&UnitId::target("graphical-session")));
    }

    #[test]
    fn registry_ids_are_stable() {
        let mut r = Registry::default();
        let a = r.id_for("/nix/store/a");
        let b = r.id_for("/nix/store/b");
        assert_eq!(r.id_for("/nix/store/a"), a);
        assert!(b > a);
    }

    /// A manually selected EFI default wins over loader.conf; the profile
    /// link alone is therefore not evidence of the next automatic boot.
    #[test]
    fn boot_default_evidence_includes_persistent_efi_selection() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().unwrap();
        let profiles = dir.path().join("profiles");
        let efivars = dir.path().join("efivars");
        let loader = dir.path().join("loader.conf");
        std::fs::create_dir_all(&profiles).unwrap();
        std::fs::create_dir_all(&efivars).unwrap();
        std::fs::create_dir(dir.path().join("entries")).unwrap();
        std::fs::write(dir.path().join("entries/nixos-generation-1.conf"), "test G1").unwrap();
        std::fs::write(dir.path().join("entries/nixos-generation-2.conf"), "test G2").unwrap();
        let g1path = dir.path().join("g1");
        let g2path = dir.path().join("g2");
        std::fs::create_dir(&g1path).unwrap();
        std::fs::create_dir(&g2path).unwrap();
        symlink(&g1path, profiles.join("system-1-link")).unwrap();
        symlink(&g2path, profiles.join("system-2-link")).unwrap();
        symlink("system-2-link", profiles.join("system")).unwrap();
        let backend = Nixos::new(Paths {
            state: dir.path().join("state"),
            profile: profiles.join("system"),
            ..Default::default()
        });
        std::fs::create_dir_all(&backend.paths.state).unwrap();
        let g1 = backend.id_of_link(&profiles.join("system-1-link")).unwrap();
        let g2 = backend.id_of_link(&profiles.join("system-2-link")).unwrap();
        std::fs::write(&loader, "timeout 0\ndefault nixos-generation-2.conf\n").unwrap();
        assert_eq!(backend.systemd_boot_default(&loader, &efivars), Ok(g2));
        std::fs::remove_file(dir.path().join("entries/nixos-generation-2.conf")).unwrap();
        assert!(
            backend.systemd_boot_default(&loader, &efivars).is_err(),
            "profile links cannot invent an installed entry"
        );
        std::fs::write(dir.path().join("entries/nixos-generation-2.conf"), "test G2").unwrap();
        let variable = efivars.join("LoaderEntryDefault-4a67b082-0a4c-41cf-b6c7-440b29bb8c4f");
        let encode = |name: &str| {
            let mut bytes = vec![7, 0, 0, 0];
            for word in name.encode_utf16().chain([0]) {
                bytes.extend_from_slice(&word.to_le_bytes());
            }
            bytes
        };
        std::fs::write(&variable, encode("nixos-generation-1.conf")).unwrap();
        assert_eq!(backend.systemd_boot_default(&loader, &efivars), Ok(g1));
        for unknown in [
            "@saved",
            "nixos-generation-0.conf",
            "nixos-generation-+1.conf",
            "nixos-generation-01.conf",
            "nixos-generation-999.conf",
            "third-party.conf",
            "nixos-generation-1.conf\0trailing",
        ] {
            std::fs::write(&variable, encode(unknown)).unwrap();
            assert!(backend.systemd_boot_default(&loader, &efivars).is_err(), "{unknown:?}");
        }
        std::fs::write(&variable, [7, 0, 0, 0, 65]).unwrap();
        assert!(backend.systemd_boot_default(&loader, &efivars).is_err());
        let mut unterminated = encode("nixos-generation-1.conf");
        unterminated.truncate(unterminated.len() - 2);
        std::fs::write(&variable, unterminated).unwrap();
        assert!(backend.systemd_boot_default(&loader, &efivars).is_err());
        std::fs::remove_file(&variable).unwrap();
        std::fs::write(&loader, "default nixos-generation-1.conf\ndefault nixos-generation-2.conf\n").unwrap();
        assert!(backend.systemd_boot_default(&loader, &efivars).is_err());
    }

    #[test]
    fn apply_expression_shape() {
        let e = apply_expr(&["services.openssh.enable".into()]);
        assert!(e.starts_with("c: { export = c.config.services.planarian.export;"));
        assert!(e.contains(r#"[ "services" "openssh" "enable" ]"#));
        assert!(e.contains("highestPrio"));
    }

    #[test]
    fn export_roundtrip() {
        let e = Export {
            units: vec![UnitDef {
                id: UnitId::service("sshd"),
                desired: Desired { status: DesiredStatus::Running, when: Condition::Always },
                edges: vec![],
                sensitivity: Sensitivities::of(&[Sensitivity::Security]),
                restart_disruption: Disruption::Brief,
                probes: vec![],
                synonyms: vec!["ssh".into()],
                systemd_restart: None,
                startup_grace: None,
                runtime_repair: None,
                stops_are_faults: false,
            }],
            ..Default::default()
        };
        let j = serde_json::to_string(&e).unwrap();
        assert!(j.contains("\"userUnits\""), "{j}");
        assert_eq!(serde_json::from_str::<Export>(&j).unwrap(), e);
    }

    #[test]
    fn stage_copies_tracked_files_and_hashes_like_nix() {
        if run(&["nix-hash", "--version"], QUICK).status != Some(0) {
            eprintln!("SKIPPED: nix-hash not on PATH");
            return;
        }
        let d = tempfile::tempdir().unwrap();
        let owner = d.path().join("owner");
        std::fs::create_dir_all(owner.join("planarian")).unwrap();
        std::fs::write(owner.join("flake.nix"), "{ }").unwrap();
        std::fs::write(owner.join("planarian/overrides.nix"), render(&OverrideSet::default())).unwrap();
        let paths = Paths { state: d.path().join("state"), owner: owner.clone(), ..Default::default() };
        let n = Nixos::new(paths);
        let src = PinnedSource { root: owner.to_string_lossy().into_owned(), kind: SourceKind::Directory };
        let mut set = OverrideSet::default();
        set.assignments.insert("a.b".into(), Value::Bool(true));
        let s = n.stage(&src, &set).unwrap();
        assert_ne!(s.base_source, s.staged_source);
        assert_eq!(n.source_hash(&src).unwrap(), s.base_source, "owner tree unchanged → not stale");
        std::fs::write(owner.join("flake.nix"), "{ edited = 1; }").unwrap();
        assert_ne!(n.source_hash(&src).unwrap(), s.base_source, "owner edit → stale");
        assert_eq!(
            std::fs::read_to_string(PathBuf::from(&s.dir).join("planarian/overrides.nix")).unwrap(),
            render(&set)
        );
        assert_eq!(
            std::fs::read_to_string(owner.join("planarian/overrides.nix")).unwrap(),
            render(&OverrideSet::default()),
            "owner's file untouched"
        );
    }

    #[test]
    fn git_owner_edit_after_staging_is_stale() {
        if run(&["nix-hash", "--version"], QUICK).status != Some(0)
            || run(&["git", "--version"], QUICK).status != Some(0)
        {
            eprintln!("SKIPPED: nix-hash or git not on PATH");
            return;
        }
        let d = tempfile::tempdir().unwrap();
        let owner = d.path().join("owner");
        std::fs::create_dir_all(owner.join("planarian")).unwrap();
        std::fs::write(owner.join("flake.nix"), "{ }").unwrap();
        std::fs::write(owner.join("configuration.nix"), "{ }\n").unwrap();
        std::fs::write(owner.join("planarian/overrides.nix"), render(&OverrideSet::default())).unwrap();
        let o = owner.to_string_lossy().into_owned();
        let git = |args: &[&str]| {
            let mut a = vec!["git", "-c", "user.email=t@t", "-c", "user.name=t", "-C", &o];
            a.extend_from_slice(args);
            assert!(run(&a, QUICK).ok(), "{args:?}");
        };
        git(&["init", "-q"]);
        git(&["add", "-A"]);
        git(&["commit", "-qm", "owner"]);
        let paths = Paths { state: d.path().join("state"), owner: owner.clone(), ..Default::default() };
        let n = Nixos::new(paths);
        let src = PinnedSource { root: o.clone(), kind: SourceKind::Directory };
        let mut set = OverrideSet::default();
        set.assignments.insert("a.b".into(), Value::Bool(true));
        let s = n.stage(&src, &set).unwrap();
        assert_eq!(n.source_hash(&src).unwrap(), s.base_source, "owner tree unchanged → not stale");
        // As the gym's edit_owner_source does: edit a tracked file, stage it, don't commit.
        std::fs::write(owner.join("configuration.nix"), "{ }\n# edited by the gym\n").unwrap();
        git(&["add", "configuration.nix"]);
        assert_ne!(n.source_hash(&src).unwrap(), s.base_source, "tracked edit → stale");
    }
    #[test]
    fn discovery_checks_real_command_exit_timeout_and_protocol() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("bin");
        std::fs::create_dir(&bin).unwrap();
        let script = bin.join("switch-to-configuration");
        for body in [
            "echo 'would activate the configuration...'; exit 7",
            "sleep 5",
            "echo 'would restart the following units: sshd.service'",
            "echo 'would activate the configuration...'; echo 'would restart the following units: '",
            "echo 'would activate the configuration...'; echo 'would restart systemd'",
        ] {
            std::fs::write(&script, format!("#!/bin/sh\n{body}\n")).unwrap();
            std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
            assert!(discover_activation(dir.path(), Duration::from_millis(50)).is_err(), "{body}");
        }
        std::fs::write(&script, "#!/bin/sh\necho 'would activate the configuration...'\necho 'would restart the following units: sshd.service'\n").unwrap();
        let plan = discover_activation(dir.path(), Duration::from_secs(1)).unwrap();
        assert!(plan.restart.contains(&UnitId::service("sshd")));
    }
}
