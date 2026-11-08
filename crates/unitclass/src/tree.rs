//! Unit directories: finding the units, the drop-ins systemd applies to them,
//! and checking that the hold is in force in a merged tree.

use crate::rule::is_network_tool;
use crate::syntax::{self, Assignment, Error, Settings};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

pub const HOLD_ONFAILURE: &str = "planarian-hold@%N.service";
pub const NETWATCH_UNIT: &str = "planarian-netwatch.service";
/// The file name of the hold's own drop-in (nix/posture.nix `holdDropins`).
pub const HOLD_DROPIN_NAME: &str = "50-planarian-hold.conf";

/// A package's unit directories that exist.
pub fn package_roots(pkg: &Path) -> Vec<PathBuf> {
    ["lib/systemd/system", "etc/systemd/system"].iter().map(|r| pkg.join(r)).filter(|p| p.is_dir()).collect()
}

/// The drop-in directories systemd reads for `unit` (a name with its
/// `.service`), most specific first: its own, a template's for an instance,
/// each `-` prefix (the longest first), and the type-wide one.
pub fn dropin_dir_names(unit: &str) -> Vec<String> {
    let stem = unit.strip_suffix(".service").unwrap_or(unit);
    let mut dirs = vec![format!("{stem}.service.d")];
    if let Some((tmpl, inst)) = stem.split_once('@')
        && !inst.is_empty()
    {
        dirs.push(format!("{tmpl}@.service.d"));
    }
    let mut prefixes: Vec<String> =
        stem.match_indices('-').map(|(i, _)| format!("{}-.service.d", &stem[..i])).collect();
    prefixes.reverse();
    dirs.extend(prefixes);
    dirs.push("service.d".to_string());
    dirs
}

fn read(path: &Path) -> Result<String, Error> {
    fs::read_to_string(path).map_err(|e| Error::Unreadable { file: path.display().to_string(), why: e.to_string() })
}

/// The drop-in files for `unit` across `roots`, as systemd applies them: a
/// file name in several of the unit's directories is read from the most
/// specific one (own, then template, then the longer prefix, then the
/// type-wide one), and the files are then applied sorted by file name. The
/// same file name in the *same* directory of two roots (two packages) is a
/// [`Error::Collision`]: which package's file is kept is not established.
pub fn dropins(roots: &[PathBuf], unit: &str) -> Result<Vec<(String, PathBuf)>, Error> {
    let mut chosen: BTreeMap<String, PathBuf> = BTreeMap::new();
    for d in dropin_dir_names(unit) {
        let mut here: BTreeMap<String, PathBuf> = BTreeMap::new();
        for root in roots {
            let Ok(rd) = fs::read_dir(root.join(&d)) else { continue };
            for e in rd.flatten() {
                let name = e.file_name().to_string_lossy().into_owned();
                if name.ends_with(".conf") && here.insert(name.clone(), e.path()).is_some() {
                    return Err(Error::Collision { name });
                }
            }
        }
        for (name, path) in here {
            chosen.entry(name).or_insert(path); // a more specific level already chose
        }
    }
    Ok(chosen.into_iter().collect())
}

/// The effective settings of `unit` whose main file is `main`, with the
/// drop-ins found under `roots`.
pub fn effective(roots: &[PathBuf], unit: &str, main: &Path) -> Result<Settings, Error> {
    let mut all: Vec<Assignment> = syntax::parse(&main.display().to_string(), &read(main)?)?;
    for (_, p) in dropins(roots, unit)? {
        all.extend(syntax::parse(&p.display().to_string(), &read(&p)?)?);
    }
    let mut s = Settings::default();
    s.apply(&all)?;
    Ok(s)
}

/// The effective `OnFailure=` and `After=` of `unit`, read leniently.
pub fn effective_hold(roots: &[PathBuf], unit: &str, main: &Path) -> Result<Settings, Error> {
    let mut s = Settings::default();
    s.apply_hold(&syntax::parse_lenient(&main.display().to_string(), &read(main)?));
    for (_, p) in dropins(roots, unit)? {
        s.apply_hold(&syntax::parse_lenient(&p.display().to_string(), &read(&p)?));
    }
    Ok(s)
}

/// The name Planarian lists a unit under: `foo.service` is `foo`, a template
/// `foo@.service` is `foo@`.
pub fn tool_name(unit_file: &str) -> Option<String> {
    unit_file.strip_suffix(".service").map(str::to_string)
}

/// `/dev/null` symlinks are masked units.
fn masked(path: &Path) -> bool {
    fs::read_link(path).is_ok_and(|t| t == Path::new("/dev/null"))
}

/// Every unit file of `roots`, by name.
pub fn units(roots: &[PathBuf]) -> Result<Vec<(String, PathBuf)>, Error> {
    let mut out = Vec::new();
    for root in roots {
        let rd = fs::read_dir(root)
            .map_err(|e| Error::Unreadable { file: root.display().to_string(), why: e.to_string() })?;
        for e in rd.flatten() {
            let file = e.file_name().to_string_lossy().into_owned();
            if !file.ends_with(".service") || !e.path().is_file() {
                continue;
            }
            out.push((file, e.path()));
        }
    }
    out.sort();
    Ok(out)
}

/// One classified unit.
#[derive(Debug, PartialEq, Eq)]
pub struct Classified {
    pub name: String,
    pub tool: bool,
    /// Why, when the unit is a tool only because it could not be read.
    pub unreadable: Option<String>,
}

/// Classify the units in `roots`. A unit that cannot be read exactly is a
/// tool. A unit present in two roots is a tool if either file says so.
pub fn classify(roots: &[PathBuf], skip: &dyn Fn(&str) -> bool) -> Result<Vec<Classified>, Error> {
    let mut by_name: BTreeMap<String, Classified> = BTreeMap::new();
    for (file, path) in units(roots)? {
        let Some(name) = tool_name(&file) else { continue };
        if skip(&name) {
            continue;
        }
        let (tool, unreadable) = match effective(roots, &file, &path) {
            Ok(s) => (is_network_tool(&s), None),
            Err(e) => (true, Some(e.to_string())),
        };
        let slot = by_name.entry(name.clone()).or_insert(Classified { name, tool: false, unreadable: None });
        slot.tool |= tool;
        slot.unreadable = slot.unreadable.take().or(unreadable);
    }
    Ok(by_name.into_values().filter(|c| c.tool).collect())
}

/// The drop-in `holdDropins` in nix/posture.nix writes for a declared tool.
pub fn hold_dropin(netwatch: bool, ordered_after_netwatch: bool) -> String {
    let mut s = format!("[Unit]\nOnFailure={HOLD_ONFAILURE}\n");
    if netwatch && ordered_after_netwatch {
        s.push_str(&format!("After={NETWATCH_UNIT}\n"));
    }
    s
}

/// What is wrong with the hold of one tool in a merged tree, if anything.
pub fn hold_problem(root: &Path, tool: &str, want_after_netwatch: bool) -> Option<String> {
    let unit = format!("{tool}.service");
    let main = root.join(&unit);
    let template_main;
    // A unit with no file in the tree (a disabled service) or a masked one
    // cannot run or fail, so there is nothing to hold.
    let main = if fs::symlink_metadata(&main).is_ok() {
        &main
    } else if let Some((t, _)) = tool.split_once('@').filter(|(_, i)| !i.is_empty()) {
        template_main = root.join(format!("{t}@.service"));
        &template_main
    } else {
        return None;
    };
    if fs::symlink_metadata(main).is_err() || masked(main) {
        return None;
    }
    // Only OnFailure= and After= are read, leniently: a unit file the classifier
    // cannot parse must not fail a build here; its hold is still checked.
    let s = match effective_hold(&[root.to_path_buf()], &unit, main) {
        Ok(s) => s,
        Err(e) => return Some(format!("{tool}: {e}")),
    };
    let missing_onfailure = !s.on_failure.iter().any(|u| u == HOLD_ONFAILURE);
    let missing_after = want_after_netwatch && !s.after.iter().any(|u| u == NETWATCH_UNIT);
    if !missing_onfailure && !missing_after {
        return None;
    }
    let what = match (missing_onfailure, missing_after) {
        (true, true) => format!("OnFailure={HOLD_ONFAILURE} and After={NETWATCH_UNIT}"),
        (true, false) => format!("OnFailure={HOLD_ONFAILURE}"),
        _ => format!("After={NETWATCH_UNIT}"),
    };
    // Which hold drop-in applies to this unit? systemd reads one file of that name, from the most specific directory.
    let winner =
        dropins(&[root.to_path_buf()], &unit).ok().and_then(|d| d.into_iter().find(|(n, _)| n == HOLD_DROPIN_NAME));
    Some(match winner {
        None => format!(
            "the hold for {tool} is missing: no {HOLD_DROPIN_NAME} applies to {unit}, so the merged unit lacks {what}"
        ),
        Some((_, path)) => format!(
            "the hold for {tool} is missing, or shadowed by {}: that is the {HOLD_DROPIN_NAME} systemd reads for {unit}, and the merged unit lacks {what}",
            path.display()
        ),
    })
}
