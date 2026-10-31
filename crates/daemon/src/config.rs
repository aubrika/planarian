//! `/etc/planarian/config.json`, written by the NixOS module, and the
//! canonical probes shipped in the core package (I10).

use planarian_changes::CatalogConfig;
use planarian_policy::{Settings, Tables};
use planarian_schema::{ChangeId, ProbeDef, Sensitivities, Tier};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

pub const CONFIG: &str = "/etc/planarian/config.json";

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct RuntimeOptionConfig {
    pub path: String,
    pub keywords: Vec<String>,
    pub current: Option<String>,
    pub step: String,
    pub min: String,
    pub max: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct FileConfig {
    pub owner: PathBuf,
    pub flake_attr: String,
    pub state_dir: PathBuf,
    pub max_tier: Tier,
    pub user_controllable_units: BTreeSet<String>,
    pub user_controllable_changes: BTreeSet<String>,
    pub user_controllable_options: BTreeSet<String>,
    pub runtime_allowlist: BTreeSet<String>,
    pub option_sensitivity: BTreeMap<String, Sensitivities>,
    pub catalog: CatalogConfig,
    pub runtime_options: Vec<RuntimeOptionConfig>,
    /// Device unit name → sysfs path.
    pub devices: BTreeMap<String, PathBuf>,
    pub admin_group: String,
    /// §12b collection bounds (`services.planarian.gc`).
    pub gc: planarian_schema::gc::GcBudget,
    /// Seconds after a unit comes up during which a failing health probe is
    /// not yet a fault (`services.planarian.startupGrace`).
    pub startup_grace_secs: u64,
    /// Compositor process names for the per-session desktop check (§9).
    #[serde(default)]
    pub session_compositors: Vec<String>,
    /// The failure posture (§12d). Phase A ships Standard.
    #[serde(default)]
    pub posture: planarian_schema::Posture,
    pub journal_bytes: u64,
    /// The signed external desired-state source (§9 hook); none by default.
    #[serde(default)]
    pub external_source: Option<crate::hooks::ExternalSourceConfig>,
    /// Seconds between signed health reports (§10 hook); 0 turns them off.
    #[serde(default = "default_health_secs")]
    pub health_report_secs: u64,
    /// This configuration is the gym's own VM test, which may run the test
    /// build (§15, B-13). Anywhere else, a test build is an Integrity failure.
    #[serde(default)]
    pub allow_test_build: bool,
    /// Limits on launched agents (`services.planarian.agents.limits`, §12d).
    #[serde(default)]
    pub agent_limits: planarian_schema::backend::AgentLimits,
}

fn default_health_secs() -> u64 {
    3600
}

impl Default for FileConfig {
    fn default() -> Self {
        let s = Settings::default();
        FileConfig {
            owner: "/etc/nixos".into(),
            flake_attr: "nixosConfigurations.default".into(),
            state_dir: "/var/lib/planarian".into(),
            max_tier: Tier::Tested,
            user_controllable_units: s.user_controllable_units.into_iter().collect(),
            user_controllable_changes: s.user_controllable_changes.into_iter().map(|c| c.0).collect(),
            user_controllable_options: s.user_controllable_options.into_iter().collect(),
            runtime_allowlist: ["font.scale", "wifi.network"].map(String::from).into(),
            option_sensitivity: BTreeMap::new(),
            catalog: CatalogConfig::default(),
            runtime_options: vec![],
            devices: BTreeMap::new(),
            admin_group: "planarian-admin".into(),
            gc: Default::default(),
            startup_grace_secs: planarian_incident::STARTUP_GRACE.0 / 1000,
            journal_bytes: planarian_txn::store::DEFAULT_CAPACITY,
            posture: Default::default(),
            session_compositors: vec![],
            external_source: None,
            health_report_secs: default_health_secs(),
            allow_test_build: false,
            agent_limits: Default::default(),
        }
    }
}

impl FileConfig {
    pub fn load(path: &Path) -> Result<FileConfig, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        serde_json::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))
    }

    pub fn settings(&self) -> Settings {
        Settings {
            max_tier: self.max_tier.min(Tier::Tested),
            user_controllable_units: self.user_controllable_units.iter().cloned().collect(),
            user_controllable_changes: self.user_controllable_changes.iter().map(|c| ChangeId(c.clone())).collect(),
            user_controllable_options: self.user_controllable_options.iter().cloned().collect(),
        }
    }

    pub fn tables(&self) -> Tables {
        let catalog = planarian_changes::entries(&self.catalog).into_iter().map(|e| e.id).collect();
        Tables {
            catalog,
            runtime_allowlist: self.runtime_allowlist.iter().cloned().collect(),
            option_sensitivity: self.option_sensitivity.iter().map(|(k, v)| (k.clone(), *v)).collect(),
            model_catalog: Default::default(),
        }
    }

    pub fn runtime_options(&self) -> Vec<planarian_intent::RuntimeOption> {
        let milli = |s: &str| -> i64 {
            let (i, f) = s.split_once('.').unwrap_or((s, ""));
            i.parse::<i64>().unwrap_or(0) * 1000 + format!("{f:0<3}").get(..3).and_then(|x| x.parse().ok()).unwrap_or(0)
        };
        self.runtime_options
            .iter()
            .map(|o| planarian_intent::RuntimeOption {
                path: o.path.clone(),
                keywords: o.keywords.clone(),
                current: o.current.clone().map(planarian_schema::Value::Str),
                step_milli: milli(&o.step),
                min_milli: milli(&o.min),
                max_milli: milli(&o.max),
            })
            .collect()
    }
}

/// Canonical probes from the core package: `<prefix>/share/planarian/canonical.json`
/// next to the running binary, never from the generation (I10).
pub fn load_canonical() -> Result<BTreeMap<String, Vec<ProbeDef>>, String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let prefix = exe.parent().and_then(Path::parent).ok_or("no install prefix")?;
    let p = prefix.join("share/planarian/canonical.json");
    let text = std::fs::read_to_string(&p).map_err(|e| format!("{}: {e}", p.display()))?;
    serde_json::from_str(&text).map_err(|e| format!("{}: {e}", p.display()))
}

/// Is `uid` root or a member of `group` (by /etc/group and /etc/passwd)?
pub fn is_admin(uid: u32, group: &str) -> bool {
    if uid == 0 {
        return true;
    }
    let passwd = std::fs::read_to_string("/etc/passwd").unwrap_or_default();
    let user = passwd.lines().find_map(|l| {
        let f: Vec<&str> = l.split(':').collect();
        (f.len() > 3 && f[2].parse::<u32>().ok() == Some(uid)).then(|| (f[0].to_string(), f[3].to_string()))
    });
    let Some((name, primary_gid)) = user else { return false };
    let groups = std::fs::read_to_string("/etc/group").unwrap_or_default();
    groups.lines().any(|l| {
        let f: Vec<&str> = l.split(':').collect();
        f.len() > 3 && f[0] == group && (f[2] == primary_gid || f[3].split(',').any(|m| m == name))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The shipped canonical probes parse and keep the probe contract (§10, §18.4).
    #[test]
    fn shipped_canonical_probes_are_valid() {
        let text = include_str!("../../../share/canonical.json");
        let c: BTreeMap<String, Vec<ProbeDef>> = serde_json::from_str(text).unwrap();
        for (unit, probes) in &c {
            for p in probes {
                assert_eq!(p.origin, planarian_schema::ProbeOrigin::Canonical, "{unit}");
                p.check_contract().unwrap_or_else(|e| panic!("{unit}: {e:?}"));
            }
        }
        assert!(c.contains_key("sshd") && c.contains_key("graphical-session") && c.contains_key("fs-journal"));
    }

    #[test]
    fn default_config_roundtrips() {
        let c = FileConfig::default();
        let j = serde_json::to_string(&c).unwrap();
        let back: FileConfig = serde_json::from_str(&j).unwrap();
        assert_eq!(back.max_tier, c.max_tier);
        assert!(serde_json::from_str::<FileConfig>("{}").is_ok(), "every field has a default");
    }
}
