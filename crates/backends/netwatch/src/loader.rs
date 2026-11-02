//! The aya loader (feature `loader`).

use aya::programs::FEntry;
use aya::{Btf, Ebpf};
use std::path::Path;

/// The probes and the kernel functions they attach to.
pub const PROBES: [(&str, &str); 3] =
    [("rtnetlink", "rtnetlink_rcv_msg"), ("nfnetlink", "nfnetlink_rcv_msg"), ("genl", "genl_rcv_msg")];

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
    let mut ebpf = Ebpf::load_file(object).map_err(|e| format!("load {}: {e}", object.display()))?;
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
