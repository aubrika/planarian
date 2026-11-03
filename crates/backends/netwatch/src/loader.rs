//! The aya loader (feature `loader`).

use aya::programs::{FEntry, FExit, KProbe};
use aya::{Btf, Ebpf};
use std::path::Path;

/// How a probe attaches: fentry needs its function in vmlinux's BTF; a
/// module's functions (nfnetlink is `=m` on NixOS kernels) are kprobes, by
/// symbol, once the module is loaded (coordinator, Nov 2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    FEntry,
    /// At the function's return, with its result (`register_netdevice`:
    /// the name is final only then).
    FExit,
    KProbe,
}

/// The probes: program name, the kernel function, how it attaches.
/// nftables sends its changes as a batch, which `nfnetlink_rcv_batch`
/// dispatches itself, never through `nfnetlink_rcv_msg`; legacy iptables
/// and its kin use `setsockopt`, all through `nf_setsockopt`.
/// `register_netdevice` sees every interface registered, in its creator's
/// context, including a tun made by ioctl, which no netlink message
/// announces (coordinator, Nov 2).
pub const PROBES: [(&str, &str, Kind); 6] = [
    ("rtnetlink", "rtnetlink_rcv_msg", Kind::FEntry),
    ("nfnetlink", "nfnetlink_rcv_msg", Kind::KProbe),
    ("nfbatch", "nfnetlink_rcv_batch", Kind::KProbe),
    ("sockopt", "nf_setsockopt", Kind::FEntry),
    ("genl", "genl_rcv_msg", Kind::FEntry),
    ("netdev", "register_netdevice", Kind::FExit),
];

/// Why the watch could not start (crate docs, "Starting"): an unusable
/// object or input, which no retry can fix (exit 1), or something the
/// kernel refused, which can change (stay up and retry).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Start {
    Unusable(String),
    Kernel(String),
}

impl Start {
    pub fn reason(&self) -> &str {
        match self {
            Start::Unusable(r) | Start::Kernel(r) => r,
        }
    }
}

/// How often, at most, the running units are re-read between ticks.
pub const RUNNING_MS: u64 = 250;

/// How long the loop waits for a new event when the ring buffer is empty
/// (a new cgroup wakes it at once).
pub const IDLE_MS: i64 = 50;

/// The inode of this process's netns, if it is the host's (pid 1's);
/// refused otherwise: netwatch in another netns would watch the wrong one.
pub fn host_netns(proc: &Path) -> Result<u32, String> {
    use std::os::unix::fs::MetadataExt;
    let ns = |p: &str| std::fs::metadata(proc.join(p)).map(|m| (m.dev(), m.ino())).map_err(|e| format!("{p}: {e}"));
    let (own, init) = (ns("self/ns/net")?, ns("1/ns/net")?);
    if own != init {
        return Err(format!("not in the host's network namespace (net:[{}], pid 1 is in net:[{}])", own.1, init.1));
    }
    u32::try_from(own.1).map_err(|_| format!("netns inode {} is not 32-bit", own.1))
}

/// How long a refused attach waits before the next try.
pub const RETRY_SECS: u64 = 30;

/// Try `attempt` until it succeeds or the input proves unusable: after each
/// kernel refusal, `on_refused` is told why (write `failed <reason>`, tell
/// systemd once) and `wait` sleeps (false: asked to stop).
pub fn retry<T>(
    mut attempt: impl FnMut() -> Result<T, Start>,
    mut on_refused: impl FnMut(&str),
    mut wait: impl FnMut() -> bool,
) -> Result<T, Start> {
    loop {
        match attempt() {
            Ok(t) => return Ok(t),
            Err(Start::Unusable(why)) => return Err(Start::Unusable(why)),
            Err(Start::Kernel(why)) => {
                on_refused(&why);
                if !wait() {
                    return Err(Start::Kernel(format!("stopped while retrying: {why}")));
                }
            }
        }
    }
}

/// Refuse an object that lacks any of the [`PROBES`] (checked on the ELF,
/// before the kernel is asked): a missing program must never pass as an
/// attached watch.
pub fn check_object(bytes: &[u8]) -> Result<(), String> {
    let obj = aya_obj::Object::parse(bytes).map_err(|e| format!("not an eBPF object: {e}"))?;
    let mut missing: Vec<&str> = PROBES.iter().map(|(p, _, _)| *p).filter(|p| !obj.programs.contains_key(*p)).collect();
    // The netns offsets the loader sets (an object from before them would
    // read every netns as 0: everything unattributed). Their names are in
    // the ELF string table, NUL-terminated.
    for g in NETNS_GLOBALS.iter().chain(&CG_GLOBALS).chain(&NETDEV_GLOBALS) {
        let name = [g.as_bytes(), b"\0"].concat();
        if !bytes.windows(name.len()).any(|w| w == name) {
            missing.push(g);
        }
    }
    if missing.is_empty() { Ok(()) } else { Err(format!("the object lacks {}", missing.join(", "))) }
}

/// The globals the loader sets from the kernel's BTF before load.
pub const NETNS_GLOBALS: [&str; 3] = ["NETNS_SKB_SK", "NETNS_SK_NET", "NETNS_NET_INUM"];
pub const CG_GLOBALS: [&str; 5] = ["CG_TASK_CGROUPS", "CG_CSS_DFL", "CG_CGROUP_KN", "CG_KN_NAME", "CG_KN_PARENT"];
pub const NETDEV_GLOBALS: [&str; 3] = ["NETDEV_SET", "NETDEV_NAME", "NETDEV_NET"];

/// `<prefix>/share/planarian/netwatch.bpf.o`, next to the running binary.
pub fn default_object() -> String {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent()?.parent().map(|d| d.join("share/planarian/netwatch.bpf.o")))
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "/run/current-system/sw/share/planarian/netwatch.bpf.o".into())
}

/// Read the object and check it has every program: unusable otherwise.
pub fn read_object(object: &Path) -> Result<Vec<u8>, Start> {
    let bytes = std::fs::read(object).map_err(|e| Start::Unusable(format!("read {}: {e}", object.display())))?;
    check_object(&bytes).map_err(Start::Unusable)?;
    Ok(bytes)
}

/// Load the object and attach every probe. A program of the wrong type is
/// an unusable object; anything the kernel refuses is [`Start::Kernel`].
pub fn load_bytes(bytes: &[u8]) -> Result<Ebpf, Start> {
    let kernel = |what: String| Start::Kernel(what);
    // Where the probes find a request's netns on this kernel (no CO-RE).
    let raw = std::fs::read("/sys/kernel/btf/vmlinux").map_err(|e| kernel(format!("kernel BTF: {e}")))?;
    let parsed = crate::btf::Btf::parse(&raw).map_err(kernel)?;
    let off = crate::btf::NetnsOffsets::from_btf(&parsed).map_err(kernel)?;
    let dev = crate::btf::NetdevOffsets::from_btf(&parsed).map_err(kernel)?;
    // The cgroup names are a help, not a need: without them (0s), userspace
    // attributes by cgroup id alone.
    let cg = crate::btf::CgroupOffsets::from_btf(&parsed).unwrap_or(crate::btf::CgroupOffsets {
        task_cgroups: 0,
        css_dfl: 0,
        cgroup_kn: 0,
        kn_name: 0,
        kn_parent: 0,
    });
    let mut ebpf = aya::EbpfLoader::new()
        .set_global(NETNS_GLOBALS[0], &off.skb_sk, true)
        .set_global(NETNS_GLOBALS[1], &off.sk_net, true)
        .set_global(NETNS_GLOBALS[2], &off.net_inum, true)
        .set_global(CG_GLOBALS[0], &cg.task_cgroups, true)
        .set_global(CG_GLOBALS[1], &cg.css_dfl, true)
        .set_global(CG_GLOBALS[2], &cg.cgroup_kn, true)
        .set_global(CG_GLOBALS[3], &cg.kn_name, true)
        .set_global(CG_GLOBALS[4], &cg.kn_parent, true)
        .set_global(NETDEV_GLOBALS[0], &1u32, true)
        .set_global(NETDEV_GLOBALS[1], &dev.name, true)
        .set_global(NETDEV_GLOBALS[2], &dev.net, true)
        .load(bytes)
        .map_err(|e| kernel(format!("load the object: {e}")))?;
    let btf = Btf::from_sys_fs().map_err(|e| kernel(format!("kernel BTF: {e}")))?;
    for (prog, func, kind) in PROBES {
        let p = ebpf.program_mut(prog).ok_or_else(|| Start::Unusable(format!("no program {prog} in the object")))?;
        match kind {
            Kind::FEntry => {
                let p: &mut FEntry = p.try_into().map_err(|e| Start::Unusable(format!("{prog}: {e}")))?;
                p.load(func, &btf).map_err(|e| kernel(format!("load fentry {func}: {e:?}")))?;
                p.attach().map_err(|e| kernel(format!("attach fentry {func}: {e}")))?;
            }
            Kind::FExit => {
                let p: &mut FExit = p.try_into().map_err(|e| Start::Unusable(format!("{prog}: {e}")))?;
                p.load(func, &btf).map_err(|e| kernel(format!("load fexit {func}: {e:?}")))?;
                p.attach().map_err(|e| kernel(format!("attach fexit {func}: {e}")))?;
            }
            Kind::KProbe => {
                let p: &mut KProbe = p.try_into().map_err(|e| Start::Unusable(format!("{prog}: {e}")))?;
                p.load().map_err(|e| kernel(format!("load kprobe {func}: {e:?}")))?;
                p.attach(func, 0).map_err(|e| kernel(format!("attach kprobe {func}: {e}")))?;
            }
        }
    }
    Ok(ebpf)
}

/// [`read_object`] then [`load_bytes`].
pub fn load(object: &Path) -> Result<Ebpf, Start> {
    load_bytes(&read_object(object)?)
}

/// Attach, then report the first event seen within 5 s (a netlink request
/// is made to produce one).
pub fn attach_test(object: &Path) -> Result<String, String> {
    let mut ebpf = load(object).map_err(|e| e.reason().to_string())?;
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
/// Tell systemd the watch has started (`READY=1` to `$NOTIFY_SOCKET`; the
/// unit is `Type=notify`). Sent once: after the probes are attached, the
/// attach snapshot is taken and the first files are written, so a unit
/// ordered after netwatch (the firewall, `network-pre.target`) only starts
/// once its changes will be attributed; or after `.watch` says `failed`, so
/// boot never waits on a watch that cannot start. Best effort: without a
/// socket (not started by systemd) it does nothing.
pub fn notify_ready(socket: Option<&Path>) {
    use std::os::unix::net::UnixDatagram;
    let Some(path) = socket else { return };
    let Ok(sock) = UnixDatagram::unbound() else { return };
    let name = path.as_os_str().as_encoded_bytes();
    let _ = if let Some(abstract_name) = name.strip_prefix(b"@") {
        use std::os::linux::net::SocketAddrExt;
        std::os::unix::net::SocketAddr::from_abstract_name(abstract_name)
            .and_then(|a| sock.send_to_addr(b"READY=1", &a))
    } else {
        sock.send_to(b"READY=1", path)
    };
}

pub fn run(export: &Path, object: &Path, dir: &Path, notify: Option<&Path>) -> Result<(), String> {
    use crate::host::{boottime_secs, expand_tools, network_tools, read_ifnames, read_virtual_ifaces, unit_of_cgroup};
    use crate::parse::take;
    use crate::{Tracker, WatchState};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::{Duration, Instant};

    // Started or not, systemd hears once; `failed` is written first.
    let ready = std::cell::Cell::new(false);
    let tell = |why: &str| {
        write_failed(dir, why);
        if !ready.replace(true) {
            notify_ready(notify);
        }
    };
    // An unusable object or input: no retry can fix it.
    let tools = match std::fs::read_to_string(export).ok().as_deref().and_then(network_tools) {
        Some(t) => t,
        None => {
            let why = format!("{}: no networkTools", export.display());
            tell(&why);
            return Err(why);
        }
    };
    let bytes = match read_object(object) {
        Ok(b) => b,
        Err(e) => {
            tell(e.reason());
            return Err(e.reason().to_string());
        }
    };
    // Changes count only in this netns, which must be the host's: the
    // unit runs with no PrivateNetwork= (crate docs, "Namespaces").
    let own_netns = match host_netns(Path::new("/proc")) {
        Ok(n) => n,
        Err(why) => {
            tell(&why);
            return Err(why);
        }
    };
    let stop = Arc::new(AtomicBool::new(false));
    for sig in [signal_hook::consts::SIGTERM, signal_hook::consts::SIGINT] {
        signal_hook::flag::register(sig, Arc::clone(&stop)).map_err(|e| format!("signal: {e}"))?;
    }
    let wait = || {
        for _ in 0..RETRY_SECS {
            if stop.load(Ordering::Relaxed) {
                return false;
            }
            std::thread::sleep(Duration::from_secs(1));
        }
        !stop.load(Ordering::Relaxed)
    };

    let root = Path::new("/sys/fs/cgroup");
    let mut cgroups = crate::cgroups::Cgroups::new(root);
    let mut ifnames = read_ifnames();
    // Attach and reconcile (§12d, on every attach: what was claimed before
    // against what stands now; steering nobody claims was made unwatched).
    // What the kernel refuses is retried every RETRY_SECS, saying why.
    let attach = || -> Result<_, Start> {
        let mut ebpf = load_bytes(&bytes)?;
        let ring = match ebpf.take_map("EVENTS").map(aya::maps::RingBuf::try_from) {
            Some(Ok(r)) => r,
            _ => return Err(Start::Unusable("no EVENTS ring buffer".into())),
        };
        let lost_map = match ebpf.take_map("LOST").map(aya::maps::Array::<_, u64>::try_from) {
            Some(Ok(m)) => m,
            _ => return Err(Start::Unusable("no LOST map".into())),
        };
        let names = read_ifnames();
        let (standing, virtual_ifaces) = crate::snapshot::standing(&mut |i| names.get(&i).cloned())
            .map_err(|e| Start::Kernel(format!("snapshot: {e}")))?;
        let mut virtual_ifaces = virtual_ifaces;
        virtual_ifaces.extend(read_virtual_ifaces(Path::new("/sys/class/net")));
        let tracker = Tracker::attach(&crate::read_claims(dir), &standing, &virtual_ifaces);
        Ok((ebpf, ring, lost_map, tracker))
    };
    let (_ebpf, mut ring, lost_map, mut tracker) = match retry(attach, tell, wait) {
        Ok(t) => t,
        Err(Start::Unusable(why)) => {
            tell(&why);
            return Err(why);
        }
        // Asked to stop while the kernel kept refusing.
        Err(Start::Kernel(_)) => {
            write_failed(dir, "stopped (signal)");
            return Ok(());
        }
    };
    let fail = |why: String| {
        tell(&why);
        Err(why)
    };
    let mut lost_seen = 0u64;
    // WireGuard's generic netlink family id, once known (read each tick).
    let mut wg_family: Option<u16> = crate::snapshot::wireguard_family().unwrap_or(None);
    let mut next_tick = Instant::now();
    // Between ticks, the running units are refreshed at most this often.
    let mut running = std::collections::BTreeSet::new();
    let mut running_at: Option<Instant> = None;
    while !stop.load(Ordering::Relaxed) {
        let mut changed = false;
        // Cgroups made and removed since the last pass first, so a unit's
        // events find it, and so an invocation seen gone now is `ended` only
        // after the ring drain below (crate docs, "The hold's order").
        cgroups.drain();
        for (u, inv) in cgroups.invocations() {
            changed |= tracker.set_invocation(u, inv);
        }
        let mut drained = 0;
        // A generic netlink request may have configured a WireGuard peer.
        let mut genl = false;
        let mut family_checked = false;
        while let Some(item) = ring.next() {
            drained += 1;
            let Some(ev) = crate::ebpf::Event::parse(&item) else {
                tracker.lost(None);
                continue;
            };
            if ev.hook == crate::ebpf::HOOK_GENL {
                genl = true;
                // WireGuard's family id is assigned when its module loads:
                // an id this watch does not know is looked up again (once a
                // drain) before the request is set aside as another family's.
                if ev.nlmsg_type().is_some_and(|t| Some(t) != wg_family) && !family_checked {
                    family_checked = true;
                    match crate::snapshot::wireguard_family() {
                        Ok(f) => wg_family = f,
                        Err(why) => {
                            eprintln!("netwatch: {why}");
                            tracker.lost(None);
                        }
                    }
                }
                if let Some(family) = wg_family {
                    let unit = ev.cgpath.as_deref().and_then(unit_of_cgroup).or_else(|| cgroups.unit(ev.cgroup));
                    match (crate::wg::classify(&ev, family), unit) {
                        // A request from no unit (an administrator's `wg set`)
                        // has no one to charge: the tunnel's own unit simply
                        // carries no endpoint it did not configure (fail closed).
                        (crate::wg::Genl::Other, _) | (_, None) => {}
                        (crate::wg::Genl::Set(dev), Some(u)) => tracker.bind_wireguard(&u, &dev),
                        (crate::wg::Genl::SetIndex(i), Some(u)) => {
                            match ifnames.get(&i).cloned().or_else(|| {
                                ifnames = read_ifnames();
                                ifnames.get(&i).cloned()
                            }) {
                                Some(dev) => tracker.bind_wireguard(&u, &dev),
                                None => tracker.lost(Some(&u)),
                            }
                        }
                        (crate::wg::Genl::SetUnnamed, Some(u)) => tracker.lost(Some(&u)),
                    }
                }
            }
            let mut name = |i: u32| {
                if !ifnames.contains_key(&i) {
                    ifnames = read_ifnames();
                }
                ifnames.get(&i).cloned()
            };
            // The path the kernel had at the request, else the id's record.
            let unit = || ev.cgpath.as_deref().and_then(unit_of_cgroup).or_else(|| cgroups.unit(ev.cgroup));
            take(&mut tracker, &ev, own_netns, unit, &mut name);
        }
        changed |= drained > 0;
        // Events the ring buffer had no room for: a loss nothing can place.
        let mut lost_rose = false;
        if let Ok(n) = lost_map.get(&0, 0)
            && n > lost_seen
        {
            lost_seen = n;
            lost_rose = true;
            tracker.lost(None);
            changed = true;
        }
        // Everything the invocations seen gone did is in the tracker now.
        // A loss in this drain may have been theirs: each is unattributed,
        // so `protecting yes`, and its hold holds.
        for e in cgroups.finish() {
            if lost_rose {
                tracker.lost(Some(&e.unit));
            }
            // One line per invocation ended (to the journal): how its
            // removal was seen, and the ring drain it waited for.
            eprintln!(
                "netwatch: {}.service invocation {} ended via {} after {} ms{}",
                crate::file_name(&e.unit),
                e.id.as_deref().unwrap_or("unknown"),
                e.via.as_str(),
                e.after.as_millis(),
                if lost_rose { " (events lost: unattributed)" } else { "" },
            );
        }
        for (u, inv) in cgroups.invocations() {
            changed |= tracker.set_invocation(u, inv);
        }
        let tick = Instant::now() >= next_tick;
        // B-22 (b): the peers' endpoints are read as the kernel has them,
        // after any generic netlink request and at every tick (a peer set
        // by anything else, or a tunnel that came up since). A read that
        // fails is a loss nothing can place: nothing is derived from a
        // failed tool.
        if genl || tick {
            match crate::snapshot::wireguard() {
                Ok((family, devices)) => {
                    wg_family = family;
                    changed |= tracker.set_wireguard(&devices);
                }
                Err(why) => {
                    eprintln!("netwatch: {why}");
                    tracker.lost(None);
                    changed = true;
                }
            }
        }
        if tick || changed {
            // A change is written at once, not at the next tick: a tool that
            // steers and dies between ticks must not read as before.
            let Some(now) = boottime_secs() else { return fail("no /proc/uptime".into()) };
            tracker.set_virtual(read_virtual_ifaces(Path::new("/sys/class/net")));
            let claims = tracker.claims();
            if tick {
                next_tick += Duration::from_secs(crate::TICK_SECS);
                running = cgroups.walk(&claims.units());
                running_at = Some(Instant::now());
            } else if running_at.is_none_or(|t| t.elapsed() >= Duration::from_millis(RUNNING_MS)) {
                running = cgroups.running();
                running_at = Some(Instant::now());
            }
            for (u, inv) in cgroups.invocations() {
                tracker.set_invocation(u, inv);
            }
            let view = tracker.view(WatchState::Attached { at: now }, &expand_tools(&tools, &running), now);
            if let Err(e) = crate::write_state(dir, &claims).and_then(|()| crate::write(dir, &view)) {
                return fail(format!("write {}: {e}", dir.display()));
            }
            if !ready.replace(true) {
                // Attached, reconciled, and the first files written.
                notify_ready(notify);
            }
        }
        if drained == 0 {
            // Wake at once when a cgroup is made (a unit starting), else
            // after IDLE_MS to read the ring buffer again.
            match cgroups.fd() {
                Some(fd) => {
                    let mut fds = [rustix::event::PollFd::new(fd, rustix::event::PollFlags::IN)];
                    let t = rustix::event::Timespec { tv_sec: 0, tv_nsec: IDLE_MS * 1_000_000 };
                    let _ = rustix::event::poll(&mut fds, Some(&t));
                }
                None => std::thread::sleep(Duration::from_millis(IDLE_MS as u64)),
            }
        }
    }
    write_failed(dir, "stopped (signal)");
    Ok(())
}
