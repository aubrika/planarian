//! `SessionBackend` over logind (`loginctl`) and the kernel's power-supply class.

use crate::cmd::run;
use planarian_schema::{Outcome, PowerSource, SessionBackend, SessionInfo, Timestamp};
use std::time::Duration;

#[derive(Clone, Copy, Debug, Default)]
pub struct Logind;

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
        // `Timestamp` is printed; `TimestampMonotonic` is not wall time. Use the
        // realtime microseconds logind exports in `--value` form when present.
        created: Timestamp(get("TimestampUSec").parse::<u64>().map(|us| us / 1000).unwrap_or(0)),
    })
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
            let o = run(
                &["loginctl", "show-session", &id, "--property=User,Class,Seat,Remote,Timestamp", "--timestamp=unix"],
                t,
            );
            if !o.ok() {
                continue;
            }
            // With --timestamp=unix, Timestamp is "@<seconds>".
            let text = o.stdout.replace("Timestamp=@", "TimestampUSec=");
            let text: String = text
                .lines()
                .map(|l| match l.strip_prefix("TimestampUSec=") {
                    Some(secs) => format!("TimestampUSec={}", secs.trim().parse::<u64>().unwrap_or(0) * 1_000_000),
                    None => l.to_string(),
                })
                .collect::<Vec<_>>()
                .join("\n");
            if let Some(s) = parse_session(&id, &text) {
                out.push(s);
            }
        }
        Ok(out)
    }

    fn power(&self) -> Option<PowerSource> {
        read_power()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
