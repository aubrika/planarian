//! Running a command with a timeout and bounded output.

use std::io::Read;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Output {
    pub status: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub timed_out: bool,
}

impl Output {
    pub fn ok(&self) -> bool {
        self.status == Some(0) && !self.timed_out
    }

    /// The last few lines of stderr (or stdout), for an error message.
    pub fn tail(&self) -> String {
        let src = if self.stderr.trim().is_empty() { &self.stdout } else { &self.stderr };
        let lines: Vec<&str> = src.lines().collect();
        lines[lines.len().saturating_sub(4)..].join(" | ")
    }
}

pub const MAX_OUTPUT: usize = 1 << 20;

/// Run `argv` with a total timeout, including output collection. Kill the
/// process group on completion or timeout so inherited pipes cannot keep
/// reader threads or helpers alive after the command returns.
pub fn run(argv: &[&str], timeout: Duration) -> Output {
    run_limited(argv, timeout, MAX_OUTPUT)
}

pub fn run_limited(argv: &[&str], timeout: Duration, max_output: usize) -> Output {
    let deadline = Instant::now() + timeout;
    let max_output = max_output.min(MAX_OUTPUT);
    let fail = |e: String| Output { status: None, stdout: String::new(), stderr: e, timed_out: false };
    let Some((prog, args)) = argv.split_first() else { return fail("empty command".into()) };
    let mut cmd = Command::new(prog);
    cmd.args(args).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
    std::os::unix::process::CommandExt::process_group(&mut cmd, 0);
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => return fail(format!("{prog}: {e}")),
    };
    let mut out = child.stdout.take().expect("piped");
    let mut err = child.stderr.take().expect("piped");
    // Nonblocking reads keep the same deadline in force after the leader has
    // exited, even when a helper still owns a pipe. There are no reader threads
    // to detach or join outside that deadline.
    if rustix::fs::fcntl_setfl(&out, rustix::fs::OFlags::NONBLOCK).is_err()
        || rustix::fs::fcntl_setfl(&err, rustix::fs::OFlags::NONBLOCK).is_err()
    {
        kill_group(&mut child);
        return fail("cannot make command pipes nonblocking".into());
    }
    let (mut stdout, mut stderr) = (Vec::new(), Vec::new());
    let (mut out_done, mut err_done) = (false, false);
    let mut exited = None;
    let mut timed_out = false;
    loop {
        out_done |= drain(&mut out, &mut stdout, max_output);
        err_done |= drain(&mut err, &mut stderr, max_output);
        if exited.is_none() {
            match child.try_wait() {
                Ok(Some(s)) => exited = Some(s.code()),
                Ok(None) => {}
                Err(e) => {
                    kill_group(&mut child);
                    return fail(e.to_string());
                }
            }
        }
        if exited.is_some() && out_done && err_done {
            break;
        }
        if Instant::now() >= deadline {
            timed_out = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    kill_group(&mut child);
    let status = exited.unwrap_or_else(|| child.wait().ok().and_then(|s| s.code()));
    let stdout = String::from_utf8_lossy(&stdout).into_owned();
    let stderr = String::from_utf8_lossy(&stderr).into_owned();
    Output { status, stdout, stderr, timed_out }
}

fn kill_group(child: &mut std::process::Child) {
    if let Some(pid) = rustix::process::Pid::from_raw(child.id() as i32) {
        let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::KILL);
    }
    let _ = child.kill();
    let _ = child.wait();
}

/// Drain a bounded amount per iteration so a continuously writing process
/// cannot postpone checking the deadline. Retain at most `max_output` bytes.
fn drain<R: Read>(pipe: &mut R, kept: &mut Vec<u8>, max_output: usize) -> bool {
    let mut chunk = [0u8; 8192];
    for _ in 0..16 {
        match pipe.read(&mut chunk) {
            Ok(0) => return true,
            Ok(n) => {
                let take = n.min(max_output.saturating_sub(kept.len()));
                kept.extend_from_slice(&chunk[..take]);
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return false,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return true,
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runs_and_times_out() {
        let o = run(&["sh", "-c", "echo hi; echo err >&2; exit 3"], Duration::from_secs(5));
        assert_eq!(o.status, Some(3));
        assert_eq!(o.stdout.trim(), "hi");
        assert_eq!(o.tail(), "err");
        let o = run(&["sh", "-c", "sleep 5 & sleep 5"], Duration::from_millis(200));
        assert!(o.timed_out && !o.ok());
        let o = run_limited(&["sh", "-c", "yes | head -c 100000"], Duration::from_secs(5), 10);
        assert_eq!(o.stdout.len(), 10);
        assert!(!run(&["/nonexistent"], Duration::from_secs(1)).ok());
    }
    #[test]
    fn inherited_output_pipe_is_inside_the_deadline() {
        // The leader exits immediately while its helper keeps both pipes open.
        // Waiting for reader threads used to outlive the declared timeout.
        let start = Instant::now();
        let o = run(&["sh", "-c", "sleep 5 & exit 0"], Duration::from_millis(100));
        assert!(o.timed_out);
        assert!(start.elapsed() < Duration::from_secs(1));
    }

}
