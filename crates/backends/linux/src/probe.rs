//! `ProbeBackend`: TCP, HTTP, sandboxed exec and free-space probes (§10 probe
//! contract). A probe's timeout is a deadline for the whole probe: name
//! resolution, connection, writing and every read count against the one
//! budget (R06). A batch runs on a bounded pool and returns by its deadline;
//! a probe still running then is recorded `Timeout` (Unknown, never Failed)
//! and abandoned. Output is data: it is truncated and logged, never
//! interpreted as instructions.
//!
//! Exec probes run under `systemd-run` with a dedicated dynamic user, no
//! capabilities, NoNewPrivileges, a CPU quota, a runtime limit and, unless
//! declared, no network.

use crate::cmd::run_limited;
use planarian_schema::{ProbeBackend, ProbeDef, ProbeKind, ProbeResult, ProbeSandbox, SideEffects, UnitId};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

/// At most this many probes run at once.
const WORKERS: usize = 16;
/// How long past the longest probe timeout a batch waits for its stragglers.
const BATCH_ALLOWANCE: Duration = Duration::from_secs(1);

#[derive(Clone, Copy, Debug, Default)]
pub struct Probes;

fn io_result(e: std::io::Error) -> ProbeResult {
    match e.kind() {
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => ProbeResult::Timeout,
        _ => ProbeResult::Fail(e.to_string()),
    }
}

/// The time left before `deadline`, or `Timeout` if none is.
fn left(deadline: Instant) -> Result<Duration, ProbeResult> {
    match deadline.checked_duration_since(Instant::now()) {
        Some(d) if d >= Duration::from_millis(1) => Ok(d),
        _ => Err(ProbeResult::Timeout),
    }
}

/// `host:port` to an address within the deadline. A literal address needs
/// no lookup; a name is resolved by `resolver` (`getent ahosts`) as a
/// subprocess that is killed at the deadline, so a stalled resolver costs
/// the probe its budget and no more.
fn resolve(addr: &str, deadline: Instant, resolver: &[&str]) -> Result<SocketAddr, ProbeResult> {
    if let Ok(sa) = addr.parse::<SocketAddr>() {
        return Ok(sa);
    }
    let (host, port) = addr.rsplit_once(':').ok_or_else(|| ProbeResult::Error(format!("{addr}: no port")))?;
    let port: u16 = port.parse().map_err(|_| ProbeResult::Error(format!("{addr}: bad port")))?;
    let mut argv = resolver.to_vec();
    argv.push(host);
    let o = run_limited(&argv, left(deadline)?, 4096);
    if o.timed_out {
        return Err(ProbeResult::Timeout);
    }
    if !o.ok() {
        return Err(ProbeResult::Error(format!("{host}: does not resolve")));
    }
    let ip = o
        .stdout
        .lines()
        .filter_map(|l| l.split_whitespace().next())
        .find_map(|t| t.parse::<std::net::IpAddr>().ok())
        .ok_or_else(|| ProbeResult::Error(format!("{host}: no address")))?;
    Ok(SocketAddr::new(ip, port))
}

const RESOLVER: &[&str] = &["getent", "ahosts"];

fn connect(addr: &str, deadline: Instant, resolver: &[&str]) -> Result<TcpStream, ProbeResult> {
    let sa = resolve(addr, deadline, resolver)?;
    TcpStream::connect_timeout(&sa, left(deadline)?).map_err(io_result)
}

pub fn tcp(addr: &str, timeout: Duration) -> ProbeResult {
    match connect(addr, Instant::now() + timeout, RESOLVER) {
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
    http_with(url, want, Instant::now() + timeout, bytes_max, RESOLVER)
}

fn http_with(url: &str, want: u16, deadline: Instant, bytes_max: usize, resolver: &[&str]) -> ProbeResult {
    let Some((addr, host, path)) = parse_url(url) else {
        return ProbeResult::Error(format!("unsupported URL {url:?} (only http:// in Phase A)"));
    };
    let mut s = match connect(&addr, deadline, resolver) {
        Ok(s) => s,
        Err(r) => return r,
    };
    let req =
        format!("GET {path} HTTP/1.0\r\nHost: {host}\r\nUser-Agent: planarian-probe\r\nConnection: close\r\n\r\n");
    match left(deadline) {
        Ok(l) => {
            let _ = s.set_write_timeout(Some(l));
        }
        Err(r) => return r,
    }
    if let Err(e) = s.write_all(req.as_bytes()) {
        return io_result(e);
    }
    let mut buf = vec![0u8; bytes_max.clamp(64, 65536)];
    let mut n = 0;
    while n < buf.len() {
        // Each read gets only what is left of the one budget, so a server
        // that trickles bytes cannot stretch the probe.
        match left(deadline) {
            Ok(l) => {
                let _ = s.set_read_timeout(Some(l));
            }
            Err(r) => return r,
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

/// P10: what is read is bounded by the probe's `bytes_max` as well as the
/// sandbox's `max_output`, whichever is smaller.
fn read_limit(sb: &ProbeSandbox, bytes_max: usize) -> usize {
    (sb.max_output as usize).min(bytes_max)
}

pub fn exec(argv: &[String], sb: &ProbeSandbox, timeout: Duration, bytes_max: usize) -> ProbeResult {
    let full = sandbox_argv(argv, sb, timeout);
    let refs: Vec<&str> = full.iter().map(String::as_str).collect();
    let o = run_limited(&refs, timeout + Duration::from_secs(2), read_limit(sb, bytes_max));
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

/// Calls `method` (`interface.Member`, no arguments) on `service` at `path` on
/// the system bus; any reply passes. A missing name or an error reply fails.
pub fn dbus(service: &str, path: &str, method: &str, timeout: Duration, bytes_max: usize) -> ProbeResult {
    let Some((iface, member)) = method.rsplit_once('.') else {
        return ProbeResult::Error(format!("method {method:?} is not interface.Member"));
    };
    let secs = format!("--timeout={}ms", timeout.as_millis().max(1));
    let argv = ["busctl", "--system", "--quiet", secs.as_str(), "call", service, path, iface, member];
    let o = run_limited(&argv, timeout + Duration::from_secs(2), bytes_max);
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

fn run_one(p: &ProbeDef) -> ProbeResult {
    let timeout = Duration::from_millis(p.timeout.0.max(1));
    let bytes_max = match p.side_effects {
        SideEffects::Measurement { bytes_max, .. } => bytes_max as usize,
        _ => 4096,
    };
    match &p.kind {
        ProbeKind::Tcp { addr } => tcp(addr, timeout),
        ProbeKind::Http { url, status } => http(url, *status, timeout, bytes_max),
        ProbeKind::Exec { argv, sandbox } => exec(argv, sandbox, timeout, bytes_max),
        ProbeKind::DBus { service, path, method } => dbus(service, path, method, timeout, bytes_max),
        ProbeKind::FilePresent { path } => file_present(path),
        ProbeKind::FreeSpace { path, min_bytes, min_permille } => free_space(path, *min_bytes, *min_permille),
        ProbeKind::SystemdActive | ProbeKind::SessionTarget { .. } => {
            ProbeResult::Error("evaluated by state, not the probe backend".into())
        }
    }
}

/// Run `jobs` on at most `WORKERS` threads and return by the batch deadline
/// (the longest timeout plus `allowance`): a probe not finished by then, or
/// not started, is `Timeout`, and its thread is abandoned, never waited for.
fn run_batch_with(
    jobs: &[(UnitId, ProbeDef)],
    run: fn(&ProbeDef) -> ProbeResult,
    allowance: Duration,
) -> Vec<ProbeResult> {
    let longest = jobs.iter().map(|(_, p)| p.timeout.0.max(1)).max().unwrap_or(0);
    let deadline = Instant::now() + Duration::from_millis(longest) + allowance;
    let queue: Arc<Mutex<Vec<(usize, ProbeDef)>>> =
        Arc::new(Mutex::new(jobs.iter().map(|(_, p)| p.clone()).enumerate().rev().collect()));
    let over = Arc::new(AtomicBool::new(false));
    let (tx, rx) = mpsc::channel();
    for _ in 0..jobs.len().min(WORKERS) {
        let (queue, over, tx) = (queue.clone(), over.clone(), tx.clone());
        std::thread::spawn(move || {
            while !over.load(Ordering::Relaxed) {
                let Some((i, p)) = queue.lock().ok().and_then(|mut q| q.pop()) else { break };
                let r = std::panic::catch_unwind(|| run(&p))
                    .unwrap_or_else(|_| ProbeResult::Error("probe panicked".into()));
                if tx.send((i, r)).is_err() {
                    break;
                }
            }
        });
    }
    drop(tx);
    let mut out: Vec<Option<ProbeResult>> = vec![None; jobs.len()];
    let mut got = 0;
    while got < jobs.len() {
        let Some(wait) = deadline.checked_duration_since(Instant::now()) else { break };
        match rx.recv_timeout(wait) {
            Ok((i, r)) => {
                out[i] = Some(r);
                got += 1;
            }
            Err(_) => break,
        }
    }
    over.store(true, Ordering::Relaxed);
    out.into_iter().map(|r| r.unwrap_or(ProbeResult::Timeout)).collect()
}

impl ProbeBackend for Probes {
    fn run_batch(&self, jobs: &[(UnitId, ProbeDef)]) -> Vec<ProbeResult> {
        run_batch_with(jobs, run_one, BATCH_ALLOWANCE)
    }
}

#[cfg(test)]
mod tests {
    /// P10: an exec probe reads no more than its bytes_max, even under a
    /// larger sandbox max_output; a dbus probe's cap is its bytes_max.
    #[test]
    fn every_reader_is_bounded_by_bytes_max() {
        let sb = ProbeSandbox { uid: 0, caps: vec![], max_output: 65536, cpu_ms: 500, network: false };
        assert_eq!(read_limit(&sb, 4096), 4096);
        let small = ProbeSandbox { max_output: 1024, ..sb };
        assert_eq!(read_limit(&small, 4096), 1024);
        let o = run_limited(&["sh", "-c", "head -c 100000 /dev/zero"], Duration::from_secs(5), 4096);
        assert!(o.stdout.len() <= 4096, "{}", o.stdout.len());
    }

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
        // Port 1 is closed in any test environment; a freshly released
        // ephemeral port is not (another test may have taken it).
        assert!(matches!(tcp("127.0.0.1:1", Duration::from_secs(1)), ProbeResult::Fail(_)));
    }

    /// R06: a server that sends one byte just before each read would time
    /// out still costs the probe no more than its one deadline.
    #[test]
    fn trickling_http_has_one_total_deadline() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        std::thread::spawn(move || {
            for s in l.incoming() {
                let mut s = s.unwrap();
                let mut buf = [0u8; 512];
                let _ = s.read(&mut buf);
                for _ in 0..100 {
                    if s.write_all(b"H").is_err() {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(150));
                }
            }
        });
        let t = Instant::now();
        let r = http(&format!("http://{addr}/health"), 200, Duration::from_millis(700), 4096);
        assert_eq!(r, ProbeResult::Timeout);
        assert!(t.elapsed() < Duration::from_millis(1200), "took {:?}", t.elapsed());
    }

    /// R06: name resolution counts against the probe's deadline; a stalled
    /// resolver is killed at it.
    #[test]
    fn a_stalled_resolver_is_inside_the_deadline() {
        let t = Instant::now();
        let stalled = ["sh", "-c", "sleep 5", "resolver"];
        let r =
            http_with("http://gym.invalid/health", 200, Instant::now() + Duration::from_millis(400), 4096, &stalled);
        assert_eq!(r, ProbeResult::Timeout);
        assert!(t.elapsed() < Duration::from_millis(1000), "took {:?}", t.elapsed());
        // A resolver that answers is used; a literal address needs none.
        let answers = ["sh", "-c", "echo '127.0.0.1 STREAM localhost'", "resolver"];
        assert_eq!(
            resolve("localhost:80", Instant::now() + Duration::from_secs(2), &answers),
            Ok("127.0.0.1:80".parse().unwrap())
        );
        assert_eq!(resolve("10.0.0.1:443", Instant::now(), &stalled), Ok("10.0.0.1:443".parse().unwrap()));
    }

    fn job(id: &str, timeout_ms: u64) -> (UnitId, ProbeDef) {
        use planarian_schema::{Cadence, Millis, ProbeCost, ProbeId, ProbeOrigin, ProbeRole};
        (
            UnitId::service("gym-web"),
            ProbeDef {
                id: ProbeId(id.into()),
                kind: ProbeKind::FilePresent { path: "/".into() },
                timeout: Millis(timeout_ms),
                origin: ProbeOrigin::User,
                role: ProbeRole::Readiness,
                cadence: Cadence::EveryTick,
                cost: ProbeCost::Trivial,
                side_effects: SideEffects::None,
                establishes: String::new(),
            },
        )
    }

    /// R06: the batch returns by its deadline; a wedged probe is recorded
    /// Timeout (Unknown) and abandoned, and the others keep their results.
    #[test]
    fn a_wedged_probe_does_not_hold_the_batch() {
        fn run(p: &ProbeDef) -> ProbeResult {
            if p.id.0 == "wedged" {
                std::thread::sleep(Duration::from_secs(10));
            }
            ProbeResult::Pass
        }
        let jobs = vec![job("fast", 200), job("wedged", 200), job("also-fast", 200)];
        let t = Instant::now();
        let r = run_batch_with(&jobs, run, Duration::from_millis(300));
        assert!(t.elapsed() < Duration::from_millis(900), "took {:?}", t.elapsed());
        assert_eq!(r, vec![ProbeResult::Pass, ProbeResult::Timeout, ProbeResult::Pass]);
        // More jobs than workers still all run.
        let many: Vec<_> = (0..WORKERS * 2 + 3).map(|i| job(&format!("p{i}"), 500)).collect();
        assert!(run_batch_with(&many, run, Duration::from_millis(500)).iter().all(|r| *r == ProbeResult::Pass));
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
