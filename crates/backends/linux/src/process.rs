//! `ProcessBackend` and `Clock` on the real system.

use planarian_schema::{Clock, Millis, ProcessBackend, Timestamp};
use rustix::process::{Pid, Signal, kill_process_group, test_kill_process};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[derive(Clone, Copy, Debug, Default)]
pub struct Processes;

pub const KILL_GRACE: Duration = Duration::from_secs(5);

impl ProcessBackend for Processes {
    /// SIGTERM the group, wait up to 5 s, then SIGKILL; true once the leader is gone.
    fn kill_group(&self, pid: u32) -> bool {
        let Some(p) = Pid::from_raw(pid as i32) else { return true };
        if test_kill_process(p).is_err() {
            return true;
        }
        let _ = kill_process_group(p, Signal::TERM);
        let deadline = Instant::now() + KILL_GRACE;
        while Instant::now() < deadline {
            if test_kill_process(p).is_err() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let _ = kill_process_group(p, Signal::KILL);
        std::thread::sleep(Duration::from_millis(200));
        test_kill_process(p).is_err()
    }

    fn alive(&self, pid: u32) -> bool {
        Pid::from_raw(pid as i32).is_some_and(|p| test_kill_process(p).is_ok())
    }
}

impl Clock for Processes {
    fn now(&self) -> Timestamp {
        Timestamp(SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0))
    }

    fn sleep(&self, d: Millis) {
        std::thread::sleep(Duration::from_millis(d.0));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kills_a_group() {
        let mut c = std::process::Command::new("sh");
        c.args(["-c", "sleep 30 & sleep 30"]);
        std::os::unix::process::CommandExt::process_group(&mut c, 0);
        let mut child = c.spawn().unwrap();
        let pid = child.id();
        assert!(Processes.alive(pid));
        let reaper = std::thread::spawn(move || child.wait());
        assert!(Processes.kill_group(pid));
        let _ = reaper.join();
        assert!(!Processes.alive(pid));
    }
}
