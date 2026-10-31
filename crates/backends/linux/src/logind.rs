//! `SessionBackend` over logind (`loginctl`) and the kernel's power-supply class.

use crate::cmd::run;
use planarian_schema::{Outcome, PowerSource, SessionBackend, SessionInfo, Timestamp};
use std::path::PathBuf;
use std::time::Duration;

#[derive(Clone, Debug)]
pub struct Logind {
    /// Process names that are a compositor (`comm`), for the per-session
    /// readiness check (§9). Empty: the backend does not judge compositors.
    pub compositors: Vec<String>,
    pub cgroup_root: PathBuf,
}

impl Default for Logind {
    fn default() -> Logind {
        Logind { compositors: vec![], cgroup_root: PathBuf::from("/sys/fs/cgroup") }
    }
}

impl Logind {
    /// The `comm` of every process in a session's scope; None if the scope
    /// cannot be read.
    fn session_comms(&self, s: &SessionInfo) -> Option<Vec<String>> {
        let scope = self
            .cgroup_root
            .join("user.slice")
            .join(format!("user-{}.slice", s.uid))
            .join(format!("session-{}.scope", s.id));
        let procs = std::fs::read_to_string(scope.join("cgroup.procs")).ok()?;
        Some(
            procs
                .lines()
                .filter_map(|pid| std::fs::read_to_string(format!("/proc/{}/comm", pid.trim())).ok())
                .map(|c| c.trim().to_string())
                .collect(),
        )
    }
}

/// `ClientCount` of Feral GameMode on the user's bus, read through the user
/// manager (`--machine=<uid>@.host --user`); 0 if GameMode is not there.
fn gamemode_clients(uid: u32) -> u32 {
    let m = format!("--machine={uid}@.host");
    let o = run(
        &[
            "busctl",
            &m,
            "--user",
            "get-property",
            "com.feralinteractive.GameMode",
            "/com/feralinteractive/GameMode",
            "com.feralinteractive.GameMode",
            "ClientCount",
        ],
        Duration::from_secs(2),
    );
    if !o.ok() {
        return 0;
    }
    // "i 1"
    o.stdout.split_whitespace().nth(1).and_then(|n| n.parse().ok()).unwrap_or(0)
}

/// Parse `loginctl show-session` key=value output into a session.
pub fn parse_session(id: &str, text: &str) -> Option<SessionInfo> {
    let props = crate::systemd::parse_show(text);
    let get = |k: &str| props.get(k).cloned().unwrap_or_default();
    Some(SessionInfo {
        id: id.into(),
        uid: get("User").parse().ok()?,
        class: get("Class"),
        seat: Some(get("Seat")).filter(|s| !s.is_empty()),
        remote: get("Remote") == "yes",
        graphical: matches!(get("Type").as_str(), "x11" | "wayland")
            && matches!(get("State").as_str(), "active" | "online"),
        active: get("State") == "active",
        idle: get("IdleHint") == "yes",
        // `Timestamp` is printed; `TimestampMonotonic` is not wall time. Use the
        // realtime microseconds logind exports in `--value` form when present.
        created: Timestamp(get("TimestampUSec").parse::<u64>().map(|us| us / 1000).unwrap_or(0)),
    })
}

/// One `--property` per property: systemd 260's loginctl prints nothing (and
/// exits 0) for a comma-separated list, so every session went unseen.
pub fn show_session_argv(id: &str) -> Vec<String> {
    let mut a: Vec<String> = ["loginctl", "show-session", id].map(String::from).to_vec();
    a.extend(["User", "Class", "Seat", "Remote", "Type", "State", "IdleHint"].map(|p| format!("--property={p}")));
    a
}

/// Session ids from `loginctl list-sessions --no-legend` (first column).
pub fn parse_list(text: &str) -> Vec<String> {
    text.lines().filter_map(|l| l.split_whitespace().next()).map(String::from).collect()
}

fn read_power() -> Option<PowerSource> {
    let dir = std::fs::read_dir("/sys/class/power_supply").ok()?;
    let mut saw_mains = false;
    for e in dir.flatten() {
        let p = e.path();
        let kind = std::fs::read_to_string(p.join("type")).unwrap_or_default();
        if kind.trim() == "Mains" {
            saw_mains = true;
            if std::fs::read_to_string(p.join("online")).unwrap_or_default().trim() == "1" {
                return Some(PowerSource::Ac);
            }
        }
    }
    saw_mains.then_some(PowerSource::Battery)
}

impl SessionBackend for Logind {
    fn sessions(&self) -> Result<Vec<SessionInfo>, Outcome> {
        let t = Duration::from_secs(5);
        let list = run(&["loginctl", "list-sessions", "--no-legend", "--no-pager"], t);
        if !list.ok() {
            return Err(Outcome::Failed(list.tail()));
        }
        let mut out = vec![];
        for id in parse_list(&list.stdout) {
            // Creation time is left 0 (unknown): `state` measures the session
            // deadline from when it first saw the session, at most one tick late,
            // rather than depend on loginctl's timestamp formatting.
            let o = run(&show_session_argv(&id).iter().map(String::as_str).collect::<Vec<_>>(), t);
            if !o.ok() {
                continue;
            }
            if let Some(s) = parse_session(&id, &o.stdout) {
                out.push(s);
            }
        }
        Ok(out)
    }

    fn power(&self) -> Option<PowerSource> {
        read_power()
    }

    fn compositor_running(&self, s: &SessionInfo) -> Option<bool> {
        if self.compositors.is_empty() {
            return None;
        }
        let comms = self.session_comms(s)?;
        Some(comms.iter().any(|c| self.compositors.contains(c)))
    }

    /// §10 foreground signals: a GameMode client for the uid of an active
    /// local session, or a gamescope in the session. (The idle-inhibitor and
    /// Do Not Disturb signals have no session-independent source yet.)
    fn foreground(&self) -> Vec<String> {
        let Ok(sessions) = self.sessions() else { return vec![] };
        sessions
            .into_iter()
            .filter(|s| s.establishes() && s.active && s.seat.is_some())
            .filter(|s| {
                self.session_comms(s).is_some_and(|c| c.iter().any(|n| n == "gamescope")) || gamemode_clients(s.uid) > 0
            })
            .map(|s| s.id)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compositor_in_the_session_scope() {
        let root = std::env::temp_dir().join(format!("planarian-cg-{}", std::process::id()));
        let scope = root.join("user.slice/user-1000.slice/session-7.scope");
        std::fs::create_dir_all(&scope).unwrap();
        // This test process stands in for the session's only process.
        std::fs::write(scope.join("cgroup.procs"), format!("{}\n", std::process::id())).unwrap();
        let me = std::fs::read_to_string("/proc/self/comm").unwrap().trim().to_string();
        let s = SessionInfo {
            id: "7".into(),
            uid: 1000,
            class: "user".into(),
            seat: Some("seat0".into()),
            remote: false,
            graphical: true,
            created: Timestamp(0),
            active: true,
            idle: false,
        };
        let l = Logind { compositors: vec![], cgroup_root: root.clone() };
        assert_eq!(l.compositor_running(&s), None, "no list: cannot judge");
        let l = Logind { compositors: vec![me], cgroup_root: root.clone() };
        assert_eq!(l.compositor_running(&s), Some(true));
        let l = Logind { compositors: vec!["cosmic-comp".into()], cgroup_root: root.clone() };
        assert_eq!(l.compositor_running(&s), Some(false));
        let other = SessionInfo { id: "8".into(), ..s };
        assert_eq!(l.compositor_running(&other), None, "no such scope");
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn one_property_flag_each() {
        let a = show_session_argv("2");
        assert!(a.iter().all(|x| !x.starts_with("--property=") || !x.contains(',')), "{a:?}");
        assert!(a.iter().any(|x| x == "--property=Type"), "graphical eligibility comes from logind");
        // What systemd 260 prints for that form, in its own order.
        let s = parse_session("2", "User=1000\nSeat=seat0\nRemote=no\nClass=user\n").unwrap();
        assert!(s.establishes());
    }

    #[test]
    fn parses() {
        assert_eq!(parse_list("  2 1000 alice seat0 tty2\nc1 990 greeter seat0 tty1\n"), vec!["2", "c1"]);
        let s = parse_session("2", "User=1000\nClass=user\nSeat=seat0\nRemote=no\nTimestampUSec=1700000000000000\n")
            .unwrap();
        assert!(s.establishes());
        assert_eq!(s.created, Timestamp(1_700_000_000_000));
        let g = parse_session("c1", "User=990\nClass=greeter\nSeat=seat0\nRemote=no\n").unwrap();
        assert!(!g.establishes());
        let r = parse_session("5", "User=1000\nClass=user\nSeat=\nRemote=yes\n").unwrap();
        assert!(r.establishes() && r.seat.is_none());
    }

    #[test]
    fn desktop_eligibility_requires_graphical_type_and_live_lifecycle() {
        let base = "User=1000\nClass=user\nSeat=seat0\nRemote=no\n";
        let graphical = |kind: &str, state: &str| {
            parse_session("2", &format!("{base}Type={kind}\nState={state}\nIdleHint=yes\n")).unwrap()
        };
        assert!(graphical("wayland", "active").graphical_establishes());
        let locked = graphical("x11", "online");
        assert!(locked.graphical_establishes() && !locked.active && locked.idle);
        assert!(!graphical("wayland", "closing").graphical_establishes());
        assert!(!graphical("tty", "active").graphical_establishes());
        assert!(!parse_session("2", base).unwrap().graphical_establishes(), "missing type is no desktop evidence");
        let remote = parse_session("ssh", "User=1000\nClass=user\nRemote=yes\nType=tty\nState=active\n").unwrap();
        assert!(remote.establishes() && !remote.graphical_establishes());
        let greeter = parse_session("g", "User=990\nClass=greeter\nSeat=seat0\nType=wayland\nState=active\n").unwrap();
        assert!(!greeter.graphical_establishes());
    }

    #[test]
    fn old_session_records_do_not_gain_graphical_evidence() {
        let old = r#"{"id":"2","uid":1000,"class":"user","seat":"seat0","remote":false,"created":0}"#;
        let session: SessionInfo = serde_json::from_str(old).unwrap();
        assert!(session.establishes());
        assert!(!session.graphical_establishes());
    }
}
