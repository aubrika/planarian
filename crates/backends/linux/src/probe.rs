//! `ProbeBackend`: TCP, HTTP, sandboxed exec and free-space probes (§10 probe
//! contract). All the probes in a batch run concurrently, and each has its own
//! timeout. Output is data: it is truncated and logged, never interpreted as
//! instructions.
//!
//! Exec probes run under `systemd-run` with a dedicated dynamic user, no
//! capabilities, NoNewPrivileges, a CPU quota, a runtime limit and, unless
//! declared, no network.

use crate::cmd::run_limited;
use planarian_schema::{ProbeBackend, ProbeDef, ProbeKind, ProbeResult, ProbeSandbox, SideEffects, UnitId};
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, Default)]
pub struct Probes;

fn io_result(e: std::io::Error) -> ProbeResult {
    match e.kind() {
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => ProbeResult::Timeout,
        _ => ProbeResult::Fail(e.to_string()),
    }
}

fn connect(addr: &str, timeout: Duration) -> Result<TcpStream, ProbeResult> {
    let sa = addr
        .to_socket_addrs()
        .map_err(|e| ProbeResult::Error(format!("{addr}: {e}")))?
        .next()
        .ok_or_else(|| ProbeResult::Error(format!("{addr}: no address")))?;
    TcpStream::connect_timeout(&sa, timeout).map_err(io_result)
}

pub fn tcp(addr: &str, timeout: Duration) -> ProbeResult {
    match connect(addr, timeout) {
        Ok(_) => ProbeResult::Pass,
        Err(r) => r,
    }
}

/// `http://host[:port]/path` → (host:port, host, path).
pub fn parse_url(url: &str) -> Option<(String, String, String)> {
    let rest = url.strip_prefix("http://")?;
    let (hostport, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let host = hostport.split(':').next()?.to_string();
    let addr = if hostport.contains(':') { hostport.to_string() } else { format!("{hostport}:80") };
    Some((addr, host, path.to_string()))
}

/// The status code from an HTTP/1.x status line.
pub fn status_of(head: &str) -> Option<u16> {
    let line = head.lines().next()?;
    let mut parts = line.split_whitespace();
    if !parts.next()?.starts_with("HTTP/1.") {
        return None;
    }
    parts.next()?.parse().ok()
}

pub fn http(url: &str, want: u16, timeout: Duration, bytes_max: usize) -> ProbeResult {
    let Some((addr, host, path)) = parse_url(url) else {
        return ProbeResult::Error(format!("unsupported URL {url:?} (only http:// in Phase A)"));
    };
    let deadline = Instant::now() + timeout;
    let mut s = match connect(&addr, timeout) {
        Ok(s) => s,
        Err(r) => return r,
    };
    let left = deadline.saturating_duration_since(Instant::now()).max(Duration::from_millis(1));
    let _ = s.set_read_timeout(Some(left));
    let _ = s.set_write_timeout(Some(left));
    let req =
        format!("GET {path} HTTP/1.0\r\nHost: {host}\r\nUser-Agent: planarian-probe\r\nConnection: close\r\n\r\n");
    if let Err(e) = s.write_all(req.as_bytes()) {
        return io_result(e);
    }
    let mut buf = vec![0u8; bytes_max.clamp(64, 65536)];
    let mut n = 0;
    while n < buf.len() {
        match s.read(&mut buf[n..]) {
            Ok(0) => break,
            Ok(k) => {
                n += k;
                if buf[..n].windows(2).any(|w| w == b"\r\n") {
                    break;
                }
            }
            Err(e) => return io_result(e),
        }
    }
    match status_of(&String::from_utf8_lossy(&buf[..n])) {
        Some(code) if code == want => ProbeResult::Pass,
        Some(code) => ProbeResult::Fail(format!("HTTP {code} (want {want})")),
        None => ProbeResult::Fail("no HTTP status line".into()),
    }
}

/// The `systemd-run` argv for an exec probe in its sandbox.
pub fn sandbox_argv(argv: &[String], sb: &ProbeSandbox, timeout: Duration) -> Vec<String> {
    let mut a: Vec<String> =
        ["systemd-run", "--wait", "--pipe", "--quiet", "--collect", "--service-type=exec"].map(String::from).into();
    if sb.uid == 0 {
        a.push("--property=DynamicUser=yes".into());
    } else {
        a.push(format!("--uid={}", sb.uid));
    }
    a.push("--property=NoNewPrivileges=yes".into());
    a.push(format!("--property=CapabilityBoundingSet={}", sb.caps.join(" ")));
    a.push(format!("--property=AmbientCapabilities={}", sb.caps.join(" ")));
    a.push(format!("--property=RuntimeMaxSec={}", timeout.as_secs().max(1)));
    a.push(format!(
        "--property=CPUQuota={}%",
        (sb.cpu_ms as u64 * 100 / timeout.as_millis().max(1) as u64).clamp(1, 100)
    ));
    a.push("--property=ProtectSystem=strict".into());
    a.push("--property=ProtectHome=yes".into());
    a.push("--property=PrivateTmp=yes".into());
    if !sb.network {
        a.push("--property=PrivateNetwork=yes".into());
    }
    a.push("--".into());
    a.extend(argv.iter().cloned());
    a
}

pub fn exec(argv: &[String], sb: &ProbeSandbox, timeout: Duration) -> ProbeResult {
    let full = sandbox_argv(argv, sb, timeout);
    let refs: Vec<&str> = full.iter().map(String::as_str).collect();
    let o = run_limited(&refs, timeout + Duration::from_secs(2), sb.max_output as usize);
    if o.timed_out {
        ProbeResult::Timeout
    } else if o.ok() {
        ProbeResult::Pass
    } else if o.status.is_none() {
        ProbeResult::Error(o.tail())
    } else {
        ProbeResult::Fail(o.tail())
    }
}

pub fn free_space(path: &str, min_bytes: u64, min_permille: u16) -> ProbeResult {
    match rustix::fs::statvfs(path) {
        Ok(s) => {
            let free = s.f_bavail * s.f_frsize;
            let size = s.f_blocks * s.f_frsize;
            if free >= min_bytes && (size == 0 || free * 1000 >= size * min_permille as u64) {
                ProbeResult::Pass
            } else {
                ProbeResult::Fail(format!("{} MB free of {} MB on {path}", free >> 20, size >> 20))
            }
        }
        Err(e) => ProbeResult::Error(format!("{path}: {e}")),
    }
}

fn run_one(p: &ProbeDef) -> ProbeResult {
    let timeout = Duration::from_millis(p.timeout.0.max(1));
    let bytes_max = match p.side_effects {
        SideEffects::Measurement { bytes_max, .. } => bytes_max as usize,
        _ => 4096,
    };
    match &p.kind {
        ProbeKind::Tcp { addr } => tcp(addr, timeout),
        ProbeKind::Http { url, status } => http(url, *status, timeout, bytes_max),
        ProbeKind::Exec { argv, sandbox } => exec(argv, sandbox, timeout),
        ProbeKind::FreeSpace { path, min_bytes, min_permille } => free_space(path, *min_bytes, *min_permille),
        ProbeKind::SystemdActive | ProbeKind::SessionTarget { .. } => {
            ProbeResult::Error("evaluated by state, not the probe backend".into())
        }
    }
}

impl ProbeBackend for Probes {
    fn run_batch(&self, jobs: &[(UnitId, ProbeDef)]) -> Vec<ProbeResult> {
        std::thread::scope(|s| {
            let handles: Vec<_> = jobs.iter().map(|(_, p)| s.spawn(move || run_one(p))).collect();
            handles
                .into_iter()
                .map(|h| h.join().unwrap_or_else(|_| ProbeResult::Error("probe panicked".into())))
                .collect()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn url_and_status() {
        assert_eq!(
            parse_url("http://127.0.0.1:8080/health"),
            Some(("127.0.0.1:8080".into(), "127.0.0.1".into(), "/health".into()))
        );
        assert_eq!(parse_url("http://example"), Some(("example:80".into(), "example".into(), "/".into())));
        assert_eq!(parse_url("https://x/"), None);
        assert_eq!(status_of("HTTP/1.1 503 Service Unavailable\r\n"), Some(503));
        assert_eq!(status_of("garbage"), None);
    }

    #[test]
    fn tcp_and_http_against_a_local_server() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        std::thread::spawn(move || {
            for (i, s) in l.incoming().enumerate() {
                let mut s = s.unwrap();
                let mut buf = [0u8; 512];
                let _ = s.read(&mut buf);
                let body = if i == 0 { "HTTP/1.1 200 OK\r\n\r\nok" } else { "HTTP/1.1 503 Busy\r\n\r\n" };
                let _ = s.write_all(body.as_bytes());
            }
        });
        let url = format!("http://{addr}/health");
        assert_eq!(http(&url, 200, Duration::from_secs(2), 4096), ProbeResult::Pass);
        assert!(matches!(http(&url, 200, Duration::from_secs(2), 4096), ProbeResult::Fail(m) if m.contains("503")));
        assert_eq!(tcp(&addr.to_string(), Duration::from_secs(1)), ProbeResult::Pass);
        let closed = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
        assert!(matches!(tcp(&closed.to_string(), Duration::from_secs(1)), ProbeResult::Fail(_)));
    }

    #[test]
    fn sandbox_and_free_space() {
        let sb = ProbeSandbox { uid: 0, caps: vec![], max_output: 4096, cpu_ms: 500, network: false };
        let a = sandbox_argv(&["true".into()], &sb, Duration::from_secs(10));
        assert!(a.contains(&"--property=DynamicUser=yes".to_string()));
        assert!(a.contains(&"--property=PrivateNetwork=yes".to_string()));
        assert_eq!(a.last().unwrap(), "true");
        assert_eq!(free_space("/", 0, 0), ProbeResult::Pass);
        assert!(matches!(free_space("/", u64::MAX, 0), ProbeResult::Fail(_)));
    }
}
