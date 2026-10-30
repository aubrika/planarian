//! `ProbeBackend`: TCP, HTTP, sandboxed exec and free-space probes (§10 probe
//! contract). Admission and concurrency are bounded; each probe has one total
//! deadline, including name resolution and queue time. Output is bounded data,
//! logged without being interpreted as instructions.
//!
//! Exec probes run under `systemd-run` with a dedicated dynamic user, no
//! capabilities, NoNewPrivileges, a CPU quota, a runtime limit and, unless
//! declared, no network.

use crate::cmd::run_limited;
use planarian_schema::{ProbeBackend, ProbeDef, ProbeKind, ProbeResult, ProbeSandbox, SideEffects, UnitId};
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, Default)]
pub struct Probes;

fn io_result(e: std::io::Error) -> ProbeResult {
    match e.kind() {
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => ProbeResult::Timeout,
        _ => ProbeResult::Fail(e.to_string()),
    }
}

/// The process-based resolver is cancellable: timing out joins no detached
/// libc resolver thread. `getent` is supplied in both installed service PATHs.
/// The command runner kills and reaps its entire process group on timeout.
fn resolve_with(program: &str, host: &str, deadline: Instant) -> Result<Vec<IpAddr>, ProbeResult> {
    let left = remaining(deadline)?;
    let out = run_limited(&[program, "ahosts", "--", host], left, 16 * 1024);
    if out.timed_out {
        return Err(ProbeResult::Timeout);
    }
    if !out.ok() {
        return Err(ProbeResult::Error(format!("resolution of {host}: {}", out.tail())));
    }
    let mut addresses = Vec::new();
    for line in out.stdout.lines() {
        if let Some(ip) = line.split_whitespace().next().and_then(|s| s.parse::<IpAddr>().ok())
            && !addresses.contains(&ip)
        {
            addresses.push(ip);
        }
        if addresses.len() >= 16 {
            break;
        }
    }
    if addresses.is_empty() { Err(ProbeResult::Error(format!("{host}: no usable address"))) } else { Ok(addresses) }
}

fn remaining(deadline: Instant) -> Result<Duration, ProbeResult> {
    deadline.checked_duration_since(Instant::now()).filter(|d| !d.is_zero()).ok_or(ProbeResult::Timeout)
}

fn connect(addr: &str, deadline: Instant) -> Result<TcpStream, ProbeResult> {
    if addr.len() > 1024 {
        return Err(ProbeResult::Error("probe address exceeds 1024 bytes".into()));
    }
    let addresses = if let Ok(sa) = addr.parse::<SocketAddr>() {
        vec![sa]
    } else {
        let (host, port) = addr.rsplit_once(':').ok_or_else(|| ProbeResult::Error("missing TCP port".into()))?;
        let port = port.parse::<u16>().map_err(|_| ProbeResult::Error("invalid TCP port".into()))?;
        resolve_with("getent", host, deadline)?.into_iter().map(|ip| SocketAddr::new(ip, port)).collect()
    };
    let mut last = ProbeResult::Error("no usable address".into());
    for address in addresses {
        match TcpStream::connect_timeout(&address, remaining(deadline)?) {
            Ok(s) => return Ok(s),
            Err(e) => last = io_result(e),
        }
    }
    Err(last)
}

pub fn tcp(addr: &str, timeout: Duration) -> ProbeResult {
    match connect(addr, Instant::now() + timeout) {
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
    let (line, _) = head.split_once("\r\n")?;
    let mut parts = line.split_whitespace();
    if !matches!(parts.next()?, "HTTP/1.0" | "HTTP/1.1") {
        return None;
    }
    let code = parts.next()?;
    if code.len() != 3 || !code.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    code.parse().ok().filter(|code| (100..=599).contains(code))
}

pub fn http(url: &str, want: u16, timeout: Duration, bytes_max: usize) -> ProbeResult {
    if url.len() > 8192 || url.contains('\r') || url.contains('\n') {
        return ProbeResult::Error("HTTP probe URL is oversized or contains a line break".into());
    }
    let Some((addr, host, path)) = parse_url(url) else {
        return ProbeResult::Error(format!("unsupported URL {url:?} (only http:// in Phase A)"));
    };
    let deadline = Instant::now() + timeout;
    let mut s = match connect(&addr, deadline) {
        Ok(s) => s,
        Err(r) => return r,
    };
    let req =
        format!("GET {path} HTTP/1.0\r\nHost: {host}\r\nUser-Agent: planarian-probe\r\nConnection: close\r\n\r\n");
    let mut sent = 0;
    while sent < req.len() {
        let left = match remaining(deadline) {
            Ok(t) => t,
            Err(r) => return r,
        };
        if let Err(e) = s.set_write_timeout(Some(left)) {
            return ProbeResult::Error(e.to_string());
        }
        match s.write(&req.as_bytes()[sent..]) {
            Ok(0) => return ProbeResult::Error("HTTP request write returned zero".into()),
            Ok(n) => sent += n,
            Err(e) => return io_result(e),
        }
    }
    let mut buf = vec![0u8; bytes_max.clamp(64, 65536)];
    let mut n = 0;
    while n < buf.len() {
        let left = match remaining(deadline) {
            Ok(t) => t,
            Err(r) => return r,
        };
        if let Err(e) = s.set_read_timeout(Some(left)) {
            return ProbeResult::Error(e.to_string());
        }
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
    // Keep transient work in the same persistent accounting parent as the
    // daemon/watchdog; its CPU remains counted after --collect removes it.
    a.push("--slice=planarian-monitor.slice".into());
    if sb.uid == 0 {
        a.push("--property=DynamicUser=yes".into());
    } else {
        a.push(format!("--uid={}", sb.uid));
    }
    a.push("--property=NoNewPrivileges=yes".into());
    a.push(format!("--property=CapabilityBoundingSet={}", sb.caps.join(" ")));
    a.push(format!("--property=AmbientCapabilities={}", sb.caps.join(" ")));
    a.push(format!("--property=RuntimeMaxSec={}ms", timeout.as_millis().max(1)));
    // Bound time before RuntimeMaxSec starts as well. Job timeout cancels
    // queued starts; TimeoutStartSec bounds a start already in progress. With
    // the 100ms kill grace, both fit within the command's 2s scheduling margin.
    let startup_ms = timeout.as_millis().clamp(1, 500);
    a.push(format!("--property=JobTimeoutSec={startup_ms}ms"));
    a.push(format!("--property=TimeoutStartSec={startup_ms}ms"));
    a.push("--property=TimeoutStopSec=100ms".into());
    a.push("--property=KillMode=control-group".into());
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
    } else if o.truncated {
        ProbeResult::Error("probe output is incomplete".into())
    } else if o.ok() {
        ProbeResult::Pass
    } else if o.status.is_none() {
        ProbeResult::Error(o.tail())
    } else {
        ProbeResult::Fail(o.tail())
    }
}

/// Calls `method` (`interface.Member`, no arguments) on `service` at `path` on
/// the system bus; any reply passes. A missing name or an error reply fails.
pub fn dbus(service: &str, path: &str, method: &str, timeout: Duration) -> ProbeResult {
    let Some((iface, member)) = method.rsplit_once('.') else {
        return ProbeResult::Error(format!("method {method:?} is not interface.Member"));
    };
    let secs = format!("--timeout={}ms", timeout.as_millis().max(1));
    let argv = ["busctl", "--system", "--quiet", secs.as_str(), "call", service, path, iface, member];
    let o = run_limited(&argv, timeout + Duration::from_secs(2), 4096);
    if o.timed_out {
        ProbeResult::Timeout
    } else if o.truncated {
        ProbeResult::Error("probe output is incomplete".into())
    } else if o.ok() {
        ProbeResult::Pass
    } else if o.status.is_none() {
        ProbeResult::Error(o.tail())
    } else {
        ProbeResult::Fail(o.tail())
    }
}

pub fn file_present(path: &str) -> ProbeResult {
    match std::fs::symlink_metadata(path) {
        Ok(_) => ProbeResult::Pass,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => ProbeResult::Fail(format!("{path}: absent")),
        Err(e) => ProbeResult::Error(format!("{path}: {e}")),
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

fn run_one(p: &ProbeDef, enqueued: Instant) -> ProbeResult {
    let deadline = enqueued + Duration::from_millis(p.timeout.0.max(1));
    let timeout = match remaining(deadline) {
        Ok(t) => t,
        Err(r) => return r,
    };
    let bytes_max = match p.side_effects {
        SideEffects::Measurement { bytes_max, .. } => bytes_max as usize,
        _ => 4096,
    };
    match &p.kind {
        ProbeKind::Tcp { addr } => tcp(addr, timeout),
        ProbeKind::Http { url, status } => http(url, *status, timeout, bytes_max),
        ProbeKind::Exec { argv, sandbox } => exec(argv, sandbox, timeout),
        ProbeKind::DBus { service, path, method } => dbus(service, path, method, timeout),
        ProbeKind::FilePresent { path } => file_present(path),
        ProbeKind::FreeSpace { path, min_bytes, min_permille } => free_space(path, *min_bytes, *min_permille),
        ProbeKind::SystemdActive | ProbeKind::SessionTarget { .. } => {
            ProbeResult::Error("evaluated by state, not the probe backend".into())
        }
    }
}

/// No persistent queue: reject overflow as Unknown evidence. These limits
/// apply across concurrent callers in this process, not just within one batch.
const MAX_CONCURRENT: usize = 16;
const MAX_BATCH: usize = 128;
static ACTIVE: AtomicUsize = AtomicUsize::new(0);

struct Permit;
impl Permit {
    fn acquire() -> Option<Self> {
        ACTIVE
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| (n < MAX_CONCURRENT).then_some(n + 1))
            .ok()
            .map(|_| Self)
    }
}
impl Drop for Permit {
    fn drop(&mut self) {
        ACTIVE.fetch_sub(1, Ordering::AcqRel);
    }
}

impl ProbeBackend for Probes {
    fn run_batch(&self, jobs: &[(UnitId, ProbeDef)]) -> Vec<ProbeResult> {
        let enqueued = Instant::now();
        let mut results = Vec::with_capacity(jobs.len());
        for chunk in jobs.iter().take(MAX_BATCH).collect::<Vec<_>>().chunks(MAX_CONCURRENT) {
            results.extend(std::thread::scope(|s| {
                let handles: Vec<_> = chunk
                    .iter()
                    .map(|(_, p)| {
                        // A caller cannot create unbounded workers while another
                        // batch is still running. There is no wait for a permit.
                        Permit::acquire().map(|permit| {
                            s.spawn(move || {
                                let _permit = permit;
                                run_one(p, enqueued)
                            })
                        })
                    })
                    .collect();
                handles
                    .into_iter()
                    .map(|h| match h {
                        Some(h) => h.join().unwrap_or_else(|_| ProbeResult::Error("probe panicked".into())),
                        None => ProbeResult::Error("probe concurrency limit reached".into()),
                    })
                    .collect::<Vec<_>>()
            }));
        }
        results.extend((MAX_BATCH..jobs.len()).map(|_| ProbeResult::Error("probe batch limit reached".into())));
        results
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn file_present_passes_and_fails() {
        let d = std::env::temp_dir().join(format!("planarian-fp-{}", std::process::id()));
        let path = d.to_str().unwrap();
        assert!(matches!(file_present(path), ProbeResult::Fail(_)));
        std::fs::write(&d, b"").unwrap();
        assert_eq!(file_present(path), ProbeResult::Pass);
        std::fs::remove_file(&d).unwrap();
    }

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
        assert_eq!(status_of("HTTP/1.1 200 incomplete status line"), None);
        assert_eq!(status_of("HTTP/1.garbage 200 OK\r\n"), None);
        assert_eq!(status_of("HTTP/1.1 20 OK\r\n"), None);
    }

    #[test]
    fn tcp_and_http_against_a_local_server() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            for i in 0..3 {
                let (mut s, _) = l.accept().unwrap();
                if i == 2 {
                    break; // The last connection tests TCP readiness only.
                }
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
        server.join().unwrap();
        // Port 1 is closed in any test environment; a freshly released
        // ephemeral port is not (another test may have taken it).
        assert!(matches!(tcp("127.0.0.1:1", Duration::from_secs(1)), ProbeResult::Fail(_)));
    }

    #[test]
    fn sandbox_and_free_space() {
        let sb = ProbeSandbox { uid: 0, caps: vec![], max_output: 4096, cpu_ms: 500, network: false };
        let a = sandbox_argv(&["true".into()], &sb, Duration::from_secs(10));
        assert!(a.contains(&"--property=DynamicUser=yes".to_string()));
        assert!(a.contains(&"--property=PrivateNetwork=yes".to_string()));
        assert!(a.contains(&"--slice=planarian-monitor.slice".to_string()));
        assert_eq!(a.last().unwrap(), "true");
        assert_eq!(free_space("/", 0, 0), ProbeResult::Pass);
        assert!(matches!(free_space("/", u64::MAX, 0), ProbeResult::Fail(_)));
    }
    #[test]
    fn trickling_http_has_one_total_deadline() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap());
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            for b in b"HTTP/1.1 200 OK\r\n" {
                if stream.write_all(&[*b]).is_err() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        });
        let start = Instant::now();
        assert_eq!(http(&url, 200, Duration::from_millis(70), 4096), ProbeResult::Timeout);
        assert!(start.elapsed() < Duration::from_millis(500));
        server.join().unwrap();
    }

    #[test]
    fn resolver_process_is_cancelled_inside_the_total_deadline() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let resolver = dir.path().join("resolver");
        std::fs::write(&resolver, "#!/bin/sh\nsleep 5\n").unwrap();
        std::fs::set_permissions(&resolver, std::fs::Permissions::from_mode(0o755)).unwrap();
        for _ in 0..3 {
            let start = Instant::now();
            assert_eq!(
                resolve_with(resolver.to_str().unwrap(), "stalled.invalid", start + Duration::from_millis(50)),
                Err(ProbeResult::Timeout)
            );
            assert!(start.elapsed() < Duration::from_millis(500));
        }
    }
}
