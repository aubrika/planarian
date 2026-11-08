//! What the watch needs from the running machine, as pure functions where it
//! can be (tested), reading `/etc`, `/sys` and `/proc` only in `read_*`.

use planarian_schema::UnitId;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

/// The export's top-level `networkTools` (`/etc/planarian/export.json`):
/// unit names, a template ending in `@`. `None`: missing or unparsable,
/// which the caller treats as fail closed (the watch is not attached).
pub fn network_tools(export_json: &str) -> Option<Vec<String>> {
    let v: serde_json::Value = serde_json::from_str(export_json).ok()?;
    v.get("networkTools")?.as_array()?.iter().map(|t| t.as_str().map(str::to_string)).collect()
}

/// The unit a cgroup path belongs to: the first `<name>.service` under
/// `system.slice`, past any slices (a template's instances sit in its own
/// slice; a service's sub-cgroups are its own). `None` for user sessions,
/// the root, slices: changes from there are unattributed.
pub fn unit_of_cgroup(rel: &str) -> Option<UnitId> {
    let mut parts = rel.trim_start_matches('/').split('/');
    if parts.next()? != "system.slice" {
        return None;
    }
    // A template's instances sit in the template's own slice
    // (`system.slice/system-openvpn.slice/openvpn@work.service`): skip
    // slices; the first service below them is the unit.
    let svc = parts.find(|p| !p.ends_with(".slice"))?.strip_suffix(".service")?;
    (!svc.is_empty()).then(|| UnitId::service(svc))
}

/// Whether the watch still writes `unit`'s footprint while it is not running:
/// a plain tool's always is (and it keeps what the unit changed, so a stopped
/// tool that steered still reads as protecting), a template instance's only
/// while it runs, so a stopped instance has none (and, with none, counts as
/// protecting: fail closed). `expand_tools` is this rule.
pub fn footprint_outlives_the_unit(unit: &UnitId) -> bool {
    !unit.name.contains('@')
}

/// The network tools now: plain names as they are, a template (`name@`)
/// as each running instance (`name@inst`) among `running`.
pub fn expand_tools(tools: &[String], running: &BTreeSet<String>) -> Vec<UnitId> {
    let mut out = BTreeSet::new();
    for t in tools {
        if t.ends_with('@') {
            out.extend(running.iter().filter(|r| r.starts_with(t.as_str()) && r.len() > t.len()).cloned());
        } else {
            out.insert(t.trim_end_matches(".service").to_string());
        }
    }
    out.into_iter().map(|n| UnitId::service(&n)).collect()
}

/// CLOCK_BOOTTIME whole seconds: the integer part of `/proc/uptime`.
pub fn boottime_secs() -> Option<u64> {
    let s = std::fs::read_to_string("/proc/uptime").ok()?;
    s.split(['.', ' ']).next()?.parse().ok()
}

/// cgroup id (the cgroup directory's inode) → unit, for every service
/// cgroup under `root` (`/sys/fs/cgroup`), and the running services' names.
pub fn read_cgroups(root: &Path) -> (BTreeMap<u64, UnitId>, BTreeSet<String>) {
    use std::os::unix::fs::MetadataExt;
    let mut ids = BTreeMap::new();
    let mut running = BTreeSet::new();
    let mut stack = vec![root.join("system.slice")];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else { continue };
        if let (Ok(meta), Ok(rel)) = (std::fs::metadata(&dir), dir.strip_prefix(root))
            && let Some(u) = unit_of_cgroup(&rel.to_string_lossy())
        {
            running.insert(u.name.clone());
            ids.insert(meta.ino(), u);
        }
        stack.extend(entries.flatten().filter(|e| e.file_type().is_ok_and(|t| t.is_dir())).map(|e| e.path()));
    }
    (ids, running)
}

/// The virtual links standing: those whose `/sys/class/net/<name>`
/// resolves under `/sys/devices/virtual/` (tun, tap, wireguard, dummy,
/// veth, bridges, `lo`). A physical NIC's resolves under its bus device.
pub fn read_virtual_ifaces(class_net: &Path) -> BTreeSet<String> {
    std::fs::read_dir(class_net)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| std::fs::read_link(e.path()).is_ok_and(|t| t.to_string_lossy().contains("/devices/virtual/")))
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect()
}

/// Interface index → name, from `dir` (`/sys/class/net`), or an error: a
/// failed scan is never "no such device" (rule 21). A device that goes
/// between the listing and its `ifindex` (`NotFound`) is simply gone; any
/// other failure, or an index that does not parse, fails the whole scan.
pub fn try_read_ifnames_in(dir: &Path) -> Result<BTreeMap<u32, String>, String> {
    let mut out = BTreeMap::new();
    let rd = std::fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    for e in rd {
        let e = e.map_err(|e| format!("{}: {e}", dir.display()))?;
        let name = e.file_name().to_string_lossy().into_owned();
        match std::fs::read_to_string(e.path().join("ifindex")) {
            Ok(s) => {
                let i = s.trim().parse().map_err(|_| format!("{name}: ifindex {:?} is not a number", s.trim()))?;
                out.insert(i, name);
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(format!("{name}: ifindex: {e}")),
        }
    }
    Ok(out)
}

/// [`try_read_ifnames_in`] for the host's `/sys/class/net`.
pub fn try_read_ifnames() -> Result<BTreeMap<u32, String>, String> {
    try_read_ifnames_in(Path::new("/sys/class/net"))
}

/// Interface index → name, from `/sys/class/net`.
pub fn read_ifnames() -> BTreeMap<u32, String> {
    let mut out = BTreeMap::new();
    for e in std::fs::read_dir("/sys/class/net").into_iter().flatten().flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        if let Some(i) = std::fs::read_to_string(e.path().join("ifindex")).ok().and_then(|s| s.trim().parse().ok()) {
            out.insert(i, name);
        }
    }
    out
}
