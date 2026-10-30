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
    /// More output than `max_output` came and was dropped: what is here is
    /// incomplete, and never a basis for a plan (rule 21).
    pub truncated: bool,
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

/// Run `argv` with a timeout; kill it (and, through its process group, its
/// children) when the timeout expires.
pub fn run(argv: &[&str], timeout: Duration) -> Output {
    run_limited(argv, timeout, MAX_OUTPUT)
}

pub fn run_limited(argv: &[&str], timeout: Duration, max_output: usize) -> Output {
    let fail =
        |e: String| Output { status: None, stdout: String::new(), stderr: e, timed_out: false, truncated: false };
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
    let out_t = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = (&mut out).take(max_output as u64).read_to_end(&mut buf);
        let dropped = std::io::copy(&mut out, &mut std::io::sink()).unwrap_or(0);
        (buf, dropped > 0)
    });
    let err_t = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = (&mut err).take(max_output as u64).read_to_end(&mut buf);
        let dropped = std::io::copy(&mut err, &mut std::io::sink()).unwrap_or(0);
        (buf, dropped > 0)
    });
    let deadline = Instant::now() + timeout;
    let mut timed_out = false;
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break s.code(),
            Ok(None) if Instant::now() >= deadline => {
                timed_out = true;
                if let Some(pid) = rustix::process::Pid::from_raw(child.id() as i32) {
                    let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::KILL);
                }
                let _ = child.kill();
                break child.wait().ok().and_then(|s| s.code());
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(20)),
            Err(e) => return fail(e.to_string()),
        }
    };
    let (out, out_cut) = out_t.join().unwrap_or_default();
    let (err, err_cut) = err_t.join().unwrap_or_default();
    let stdout = String::from_utf8_lossy(&out).into_owned();
    let stderr = String::from_utf8_lossy(&err).into_owned();
    Output { status, stdout, stderr, timed_out, truncated: out_cut || err_cut }
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
}
