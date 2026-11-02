//! The aya loader (feature `loader`).

use aya::programs::FEntry;
use aya::{Btf, Ebpf};
use std::path::Path;

/// The probes and the kernel functions they attach to.
/// nftables sends its changes as a batch, which `nfnetlink_rcv_batch`
/// dispatches itself, never through `nfnetlink_rcv_msg`; legacy iptables
/// and its kin use `setsockopt`, all through `nf_setsockopt`.
pub const PROBES: [(&str, &str); 5] = [
    ("rtnetlink", "rtnetlink_rcv_msg"),
    ("nfnetlink", "nfnetlink_rcv_msg"),
    ("nfbatch", "nfnetlink_rcv_batch"),
    ("sockopt", "nf_setsockopt"),
    ("genl", "genl_rcv_msg"),
];

/// Refuse an object that lacks any of the [`PROBES`] (checked on the ELF,
/// before the kernel is asked): a missing program must never pass as an
/// attached watch.
pub fn check_object(bytes: &[u8]) -> Result<(), String> {
    let obj = aya_obj::Object::parse(bytes).map_err(|e| format!("not an eBPF object: {e}"))?;
    let missing: Vec<&str> = PROBES.iter().map(|(p, _)| *p).filter(|p| !obj.programs.contains_key(*p)).collect();
    if missing.is_empty() { Ok(()) } else { Err(format!("the object lacks {}", missing.join(", "))) }
}

/// `<prefix>/share/planarian/netwatch.bpf.o`, next to the running binary.
pub fn default_object() -> String {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent()?.parent().map(|d| d.join("share/planarian/netwatch.bpf.o")))
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "/run/current-system/sw/share/planarian/netwatch.bpf.o".into())
}

/// Load the object and attach every probe; any failure is an error.
pub fn load(object: &Path) -> Result<Ebpf, String> {
    let bytes = std::fs::read(object).map_err(|e| format!("read {}: {e}", object.display()))?;
    check_object(&bytes)?;
    let mut ebpf = Ebpf::load(&bytes).map_err(|e| format!("load {}: {e}", object.display()))?;
    let btf = Btf::from_sys_fs().map_err(|e| format!("kernel BTF: {e}"))?;
    for (prog, func) in PROBES {
        let p: &mut FEntry = ebpf
            .program_mut(prog)
            .ok_or_else(|| format!("no program {prog} in the object"))?
            .try_into()
            .map_err(|e| format!("{prog}: {e}"))?;
        p.load(func, &btf).map_err(|e| format!("load fentry {func}: {e:?}"))?;
        p.attach().map_err(|e| format!("attach fentry {func}: {e}"))?;
    }
    Ok(ebpf)
}

/// Attach, then report the first event seen within 5 s (a netlink request
/// is made to produce one).
pub fn attach_test(object: &Path) -> Result<String, String> {
    let mut ebpf = load(object)?;
    let mut ring = aya::maps::RingBuf::try_from(ebpf.take_map("EVENTS").ok_or("no EVENTS map")?)
        .map_err(|e| format!("EVENTS: {e}"))?;
    // Any rtnetlink request will do: list links.
    let _ = std::process::Command::new("ip").args(["link", "show"]).output();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        if let Some(item) = ring.next() {
            let ev = crate::ebpf::Event::parse(&item).ok_or("short event")?;
            return Ok(format!(
                "attached {} probes; first event: hook {} cgroup {} tgid {} nlmsg_len {} captured {} type {}",
                PROBES.len(),
                ev.hook,
                ev.cgroup,
                ev.tgid,
                ev.len,
                ev.data.len(),
                ev.nlmsg_type().unwrap_or(0)
            ));
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    Err("attached, but no event within 5 s".into())
}

/// Write `.watch` as `failed <reason>` (best effort: if even this fails, the
/// heartbeat goes stale, which the hold also reads as not attached).
pub fn write_failed(dir: &Path, reason: &str) {
    let view =
        crate::FootprintView { watch: crate::WatchState::Failed { reason: reason.into() }, ..Default::default() };
    // Keep any footprints already there: only the heartbeat changes.
    let mut current = crate::read(dir);
    current.watch = view.watch;
    let _ = crate::write(dir, &current);
}

/// The watch (crate docs): attach, then keep and write the footprints every
/// [`crate::TICK_SECS`] until SIGTERM or SIGINT, which writes `failed
/// stopped`. Returns only with an error to report (also written to
/// `.watch`), for a nonzero exit.
pub fn run(export: &Path, object: &Path, dir: &Path) -> Result<(), String> {
    use crate::host::{boottime_secs, expand_tools, network_tools, read_cgroups, read_ifnames};
    use crate::parse::{Parsed, parse};
    use crate::{Owner, Tracker, WatchState};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::{Duration, Instant};

    let fail = |why: String| {
        write_failed(dir, &why);
        Err(why)
    };
    let tools = match std::fs::read_to_string(export).ok().as_deref().and_then(network_tools) {
        Some(t) => t,
        None => return fail(format!("{}: no networkTools", export.display())),
    };
    let mut ebpf = match load(object) {
        Ok(e) => e,
        Err(e) => return fail(e),
    };
    let mut ring = match ebpf.take_map("EVENTS").map(aya::maps::RingBuf::try_from) {
        Some(Ok(r)) => r,
        _ => return fail("no EVENTS ring buffer".into()),
    };
    let lost_map = match ebpf.take_map("LOST").map(aya::maps::Array::<_, u64>::try_from) {
        Some(Ok(m)) => m,
        _ => return fail("no LOST map".into()),
    };
    let stop = Arc::new(AtomicBool::new(false));
    for sig in [signal_hook::consts::SIGTERM, signal_hook::consts::SIGINT] {
        signal_hook::flag::register(sig, Arc::clone(&stop)).map_err(|e| format!("signal: {e}"))?;
    }

    let root = Path::new("/sys/fs/cgroup");
    let mut cgroups = read_cgroups(root).0;
    let mut ifnames = read_ifnames();
    let mut tracker = Tracker::default();
    let mut lost_seen = 0u64;
    let mut next_tick = Instant::now();
    while !stop.load(Ordering::Relaxed) {
        let mut drained = 0;
        while let Some(item) = ring.next() {
            drained += 1;
            let Some(ev) = crate::ebpf::Event::parse(&item) else {
                tracker.lost(None);
                continue;
            };
            if !cgroups.contains_key(&ev.cgroup) {
                // A service started since the last walk.
                cgroups = read_cgroups(root).0;
            }
            let unit = cgroups.get(&ev.cgroup).cloned();
            let owner = unit.clone().map(Owner::Unit).unwrap_or(Owner::Unattributed);
            let mut name = |i: u32| {
                if !ifnames.contains_key(&i) {
                    ifnames = read_ifnames();
                }
                ifnames.get(&i).cloned()
            };
            match parse(&ev, &owner, &mut name) {
                Parsed::Nothing => {}
                Parsed::Changes(cs) => cs.iter().for_each(|c| tracker.apply(c)),
                Parsed::Unreadable(_) => tracker.lost(unit.as_ref()),
            }
        }
        // Events the ring buffer had no room for: a loss nothing can place.
        if let Ok(n) = lost_map.get(&0, 0)
            && n > lost_seen
        {
            lost_seen = n;
            tracker.lost(None);
        }
        if Instant::now() >= next_tick {
            next_tick += Duration::from_secs(crate::TICK_SECS);
            let Some(now) = boottime_secs() else { return fail("no /proc/uptime".into()) };
            let running;
            (cgroups, running) = read_cgroups(root);
            let view = tracker.view(WatchState::Attached { at: now }, &expand_tools(&tools, &running), now);
            if let Err(e) = crate::write(dir, &view) {
                return fail(format!("write {}: {e}", dir.display()));
            }
        }
        if drained == 0 {
            std::thread::sleep(Duration::from_millis(100));
        }
    }
    write_failed(dir, "stopped (signal)");
    Ok(())
}
