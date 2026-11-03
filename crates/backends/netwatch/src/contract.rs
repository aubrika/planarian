//! The files the hold reads (see the crate docs, the single source).

use crate::model::{Endpoint, Footprint, FootprintView, Proto, WatchState};
use planarian_schema::{Scope, UnitId, UnitKind};
use std::io::{self, Write};
use std::path::Path;

/// Where the footprints live.
pub const DIR: &str = "/run/planarian/footprint";
/// The clock every `<t>` is on: seconds since boot, suspend included (the
/// first field of `/proc/uptime`), so a wall-clock step cannot make a stale
/// file look fresh.
pub const CLOCK: &str = "CLOCK_BOOTTIME";
/// A file confirmed longer ago than this is stale.
pub const FRESH_SECS: u64 = 30;
/// A stamp further ahead than this is not trusted either (the hold's script).
pub const AHEAD_SECS: u64 = 5;
/// How often netwatch rewrites every file.
pub const TICK_SECS: u64 = 5;

const WATCH: &str = ".watch";
/// netwatch's own record of who claimed what, across its restarts (a
/// dot-file: the hold reads only `.watch` and `.unattributed`).
const STATE: &str = ".state";
const UNATTRIBUTED: &str = ".unattributed";
const DRAINED: &str = ".drained";

/// The ring buffer's watermark (`.drained`): both clocks, read together
/// *before* a drain began, written once that drain's changes were applied
/// and the footprint files written. So every event submitted before
/// `monotonic_us` is in the files (crate docs, "The hold's order").
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Drained {
    pub boottime_us: u64,
    pub monotonic_us: u64,
}

/// Write `.drained` atomically: `<boottime_us> <monotonic_us>`.
pub fn write_drained(dir: &Path, d: Drained) -> io::Result<()> {
    put(dir, DRAINED, &format!("{} {}\n", d.boottime_us, d.monotonic_us))
}

/// `.drained`, if it reads.
pub fn read_drained(dir: &Path) -> Option<Drained> {
    parse_drained(&std::fs::read_to_string(dir.join(DRAINED)).ok()?)
}

pub(crate) fn parse_drained(s: &str) -> Option<Drained> {
    match s.split_whitespace().collect::<Vec<_>>().as_slice() {
        [b, m] => Some(Drained { boottime_us: b.parse().ok()?, monotonic_us: m.parse().ok()? }),
        _ => None,
    }
}

/// The hold's condition on a failure, as lane-nix's script implements it
/// (crate docs, "The hold's order"): it may release only when (a) the ring
/// was drained past the unit's death (`death_monotonic_us`, systemd's
/// `InactiveEnterTimestampMonotonic`), (b) the footprint describes the
/// invocation that died (`invocation`, systemd's `InvocationID`), and (c)
/// the footprint reads not protecting at `now`. Anything else holds. The
/// reference the property tests check the files against.
pub fn hold_may_release(
    view: &FootprintView,
    drained: Option<Drained>,
    unit: &UnitId,
    death_monotonic_us: u64,
    invocation: Option<&str>,
    now: u64,
) -> bool {
    let name = file_name(unit);
    drained.is_some_and(|d| d.monotonic_us >= death_monotonic_us)
        && invocation.is_some()
        && view.units.get(&name).and_then(|f| f.invocation.as_deref()) == invocation
        && !view.protecting_now(&name, now)
}

/// The file name of a unit's footprint: systemd's `%N` (the unit name with
/// any `@instance`, without `.service`). Network tools are system services.
pub fn file_name(u: &UnitId) -> String {
    debug_assert!(u.kind == UnitKind::Service && u.scope == Scope::System, "{u}");
    u.name.trim_end_matches(".service").to_string()
}

fn proto(p: Proto) -> &'static str {
    match p {
        Proto::Tcp => "tcp",
        Proto::Udp => "udp",
    }
}

pub(crate) fn render(f: &Footprint) -> String {
    let mut s = format!("protecting {}\nat {}\n", if f.protecting { "yes" } else { "no" }, f.at);
    if let Some(i) = &f.invocation {
        s.push_str(&format!("invocation {i}\n"));
    }
    for i in &f.ifaces {
        s.push_str(&format!("iface {i}\n"));
    }
    for e in &f.endpoints {
        s.push_str(&format!("endpoint {} {} {}\n", proto(e.proto), e.addr, e.port));
    }
    if f.unattributed {
        s.push_str("unattributed\n");
    }
    s
}

/// Write `name` in `dir` atomically: a temporary file, synced, renamed over it.
fn put(dir: &Path, name: &str, body: &str) -> io::Result<()> {
    let tmp = dir.join(format!(".{name}.tmp"));
    let mut f = std::fs::File::create(&tmp)?;
    f.write_all(body.as_bytes())?;
    f.sync_all()?;
    std::fs::rename(&tmp, dir.join(name))
}

/// Write `view` to `dir`: `.watch`, `.unattributed` (present or removed),
/// and one file per unit; a unit's file that is no longer in the view is
/// removed, so a reader never trusts a footprint netwatch no longer keeps.
pub fn write(dir: &Path, view: &FootprintView) -> io::Result<()> {
    std::fs::create_dir_all(dir)?;
    for (name, f) in &view.units {
        put(dir, name, &render(f))?;
    }
    for e in std::fs::read_dir(dir)? {
        let name = e?.file_name().to_string_lossy().into_owned();
        if !name.starts_with('.') && !view.units.contains_key(&name) {
            std::fs::remove_file(dir.join(&name))?;
        }
    }
    if !view.unattributed.is_empty() {
        let why: String = view.unattributed.iter().map(|r| format!("{}\n", one_line(r))).collect();
        put(dir, UNATTRIBUTED, &why)?;
    } else {
        match std::fs::remove_file(dir.join(UNATTRIBUTED)) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e),
            _ => {}
        }
    }
    // Last: the heartbeat confirms everything written before it.
    let watch = match &view.watch {
        WatchState::Attached { at } => format!("attached {at}\n"),
        WatchState::Failed { reason } => format!("failed {}\n", one_line(reason)),
        WatchState::Unknown => "unknown\n".to_string(),
    };
    put(dir, WATCH, &watch)
}

fn one_line(s: &str) -> String {
    let s: String = s.chars().map(|c| if c.is_control() { ' ' } else { c }).collect();
    if s.trim().is_empty() { "unknown".into() } else { s.trim().to_string() }
}

pub(crate) fn parse_footprint(text: &str) -> Option<Footprint> {
    let mut f = Footprint::default();
    let mut at = None;
    for line in text.lines() {
        let w: Vec<&str> = line.split_whitespace().collect();
        match w.as_slice() {
            ["at", t] => at = Some(t.parse().ok()?),
            ["invocation", i] if i.len() == 32 && i.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f')) => {
                f.invocation = Some((*i).to_string());
            }
            ["protecting", "yes"] => f.protecting = true,
            ["protecting", "no"] => f.protecting = false,
            ["iface", i] => {
                f.ifaces.insert((*i).to_string());
            }
            ["endpoint", p, a, port] => {
                let proto = match *p {
                    "tcp" => Proto::Tcp,
                    "udp" => Proto::Udp,
                    _ => return None,
                };
                f.endpoints.insert(Endpoint { proto, addr: a.parse().ok()?, port: port.parse().ok()? });
            }
            ["unattributed"] => f.unattributed = true,
            [] => {}
            // A line this reader does not know: not a footprint it can trust.
            _ => return None,
        }
    }
    f.at = at?;
    Some(f)
}

/// Read what `dir` holds. Fail closed: a footprint that does not parse is
/// left out (so it reads as missing, which counts as protecting), and an
/// unreadable or unknown `.watch` is [`WatchState::Unknown`].
pub fn read(dir: &Path) -> FootprintView {
    let mut view = FootprintView::default();
    let Ok(entries) = std::fs::read_dir(dir) else { return view };
    view.watch = match std::fs::read_to_string(dir.join(WATCH)) {
        Ok(s) => match s.split_whitespace().collect::<Vec<_>>().as_slice() {
            ["attached", t] => t.parse().map(|at| WatchState::Attached { at }).unwrap_or(WatchState::Unknown),
            ["failed", why @ ..] => WatchState::Failed { reason: why.join(" ") },
            _ => WatchState::Unknown,
        },
        Err(_) => WatchState::Unknown,
    };
    view.unattributed = match std::fs::read_to_string(dir.join(UNATTRIBUTED)) {
        // Present: it stands, with its reasons (or one saying none was given).
        Ok(s) => {
            let why: Vec<String> = s.lines().filter(|l| !l.trim().is_empty()).map(str::to_string).collect();
            if why.is_empty() { vec!["unattributed".into()] } else { why }
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => vec![],
        // Unreadable: fail closed, as if it stood.
        Err(e) => vec![format!("unreadable: {e}")],
    };
    for e in entries.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        if name.starts_with('.') {
            continue;
        }
        if let Some(f) = std::fs::read_to_string(e.path()).ok().and_then(|t| parse_footprint(&t)) {
            view.units.insert(name, f);
        }
    }
    view
}

/// Keep the tracker's claims in `dir/.state`, atomically.
pub fn write_state(dir: &Path, claims: &crate::Claims) -> io::Result<()> {
    let json = serde_json::to_string(claims).map_err(io::Error::other)?;
    put(dir, STATE, &json)
}

/// The claims kept before a restart: `.state` if it reads, else the
/// footprint files' `iface` lines (`Tracker::claims_from_files`).
pub fn read_claims(dir: &Path) -> crate::Claims {
    std::fs::read_to_string(dir.join(STATE))
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_else(|| crate::Tracker::claims_from_files(&read(dir)))
}
