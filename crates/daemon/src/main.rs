//! planariad: runs the core loop over the real backends and serves the socket.

use planarian_backend_linux::{Paths, Real};
use planarian_daemon::config::{CONFIG, FileConfig, is_admin, load_canonical};
use planarian_daemon::core::Resume;
use planarian_daemon::hooks::{self, ExternalSource, Poll};
use planarian_daemon::snapshot::{self, Busy, Snapshot};
use planarian_daemon::{Core, CoreConfig, Peer};
use planarian_exec::Config as ExecConfig;
use planarian_exec::{PrebuildJob, Prebuilt};
use planarian_ipc::{Request, Response, SOCKET};
use planarian_schema::{Backends, Clock, Hash, OwnerId, PinnedSource, SourceKind};
use planarian_txn::journal::{Journal, JournalError};
use planarian_txn::ledger::Record;
use planarian_txn::store::FileStore;
use std::collections::VecDeque;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

const TICK: Duration = Duration::from_secs(5);
const RENEW_EVERY: Duration = Duration::from_secs(20);
const LOG_ROTATE_BYTES: u64 = 50 * 1024 * 1024;

fn boot_id() -> (Hash, String) {
    let s = std::fs::read_to_string("/proc/sys/kernel/random/boot_id").unwrap_or_default();
    (Hash::of(s.trim().as_bytes()), s.trim().to_string())
}

/// True the first time the daemon starts on this boot.
fn fresh_boot(state: &Path, boot: &str) -> bool {
    std::fs::read_to_string(state.join("boot_id")).map(|s| s.trim() != boot).unwrap_or(true)
}

/// This boot's start-up is done (the boot report was clean): a restart later
/// in the boot is not a fresh boot. Until then every start is.
fn mark_boot(state: &Path, boot: &str) {
    let _ = std::fs::write(state.join("boot_id"), boot);
}

/// `sd_notify(3)`: one datagram to `$NOTIFY_SOCKET`, if systemd gave one.
fn sd_notify(msg: &str) {
    let Some(path) = std::env::var_os("NOTIFY_SOCKET") else { return };
    let Ok(s) = std::os::unix::net::UnixDatagram::unbound() else { return };
    let path = std::path::PathBuf::from(path);
    // An abstract socket is written with a leading '@'.
    let sent = match path.to_str().and_then(|p| p.strip_prefix('@')) {
        Some(name) => {
            use std::os::linux::net::SocketAddrExt;
            std::os::unix::net::SocketAddr::from_abstract_name(name.as_bytes())
                .and_then(|a| s.send_to_addr(msg.as_bytes(), &a))
        }
        None => s.send_to(msg.as_bytes(), &path),
    };
    if let Err(e) = sent {
        eprintln!("planariad: sd_notify: {e}");
    }
}

/// Exit status for an `Integrity` failure (§12d). The response lives in
/// `nix/posture.nix`, never here: this only reports what was found and stops.
pub const EXIT_INTEGRITY: i32 = 78;
/// Where the reason goes, for the boot report and the posture units.
const INTEGRITY_NOTE: &str = "/run/planarian/integrity";

/// Report an integrity finding and stop with 78 (§12d).
fn integrity_failure(who: &str, what: &str) -> ! {
    eprintln!("{who}: INTEGRITY: {what}");
    let _ = std::fs::create_dir_all("/run/planarian");
    let _ = std::fs::write(INTEGRITY_NOTE, format!("{what}\n"));
    std::process::exit(EXIT_INTEGRITY);
}

fn journal_failure(who: &str, e: &JournalError) -> ! {
    match e {
        JournalError::Integrity(why) => integrity_failure(who, &format!("journal: the hash chain is broken: {why}")),
        JournalError::Legacy => {
            eprintln!(
                "{who}: the journal under /var/lib/planarian/journal was written by an earlier Planarian (format 1, \
                 before the hash chain). Move it aside to keep it for inspection, then restart: \
                 sudo mv /var/lib/planarian/journal /var/lib/planarian/journal.v1"
            );
            std::process::exit(74);
        }
        e => {
            eprintln!("{who}: journal: {e:?}");
            std::process::exit(74);
        }
    }
}

/// The largest request line, and the connection limits (see `main`).
const MAX_REQUEST: u64 = 64 * 1024;
const PER_UID: usize = 16;
const MAX_CONNS: usize = 64;

/// One request line, bounded in size and in total time (10 s), not per read.
fn read_request(conn: &UnixStream) -> Option<String> {
    use std::io::Read;
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let mut r = conn.take(MAX_REQUEST);
    loop {
        let left = deadline.checked_duration_since(Instant::now())?;
        conn.set_read_timeout(Some(left.max(Duration::from_millis(1)))).ok()?;
        let n = r.read(&mut chunk).ok()?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(i) = buf.iter().position(|b| *b == b'\n') {
            buf.truncate(i);
            break;
        }
    }
    String::from_utf8(buf).ok()
}

fn peer_of(s: &UnixStream, admin_group: &str) -> Option<Peer> {
    let cred = rustix::net::sockopt::socket_peercred(s).ok()?;
    let uid = cred.uid.as_raw();
    let pid = cred.pid.as_raw_nonzero();
    let cgroup = std::fs::read_to_string(format!("/proc/{pid}/cgroup")).unwrap_or_default();
    // The pid could have been reused since the connect: a session read from
    // a process of another uid counts as none.
    let same_uid = std::fs::read_to_string(format!("/proc/{pid}/status")).ok().is_some_and(|st| {
        st.lines()
            .find_map(|l| l.strip_prefix("Uid:"))
            .and_then(|r| r.split_whitespace().next())
            .and_then(|u| u.parse::<u32>().ok())
            == Some(uid)
    });
    // A process in an agent's unit is that agent, whatever uid it runs as
    // (§11): never an administrator, never in a session.
    if let Some(name) = agent_of_cgroup(&cgroup) {
        return Some(Peer::agent(uid, &name));
    }
    let session = if same_uid { session_of_cgroup(&cgroup, uid) } else { None };
    Some(Peer { uid, admin: is_admin(uid, admin_group), session, agent: None })
}

/// The agent whose unit (`/system.slice/planarian-agent-<name>.service`,
/// or below it) holds this cgroup, if any.
fn agent_of_cgroup(cgroup: &str) -> Option<String> {
    let line = cgroup.lines().find_map(|l| l.strip_prefix("0::"))?;
    let mut parts = line.split('/').filter(|c| !c.is_empty());
    if parts.next()? != "system.slice" {
        return None;
    }
    let name = parts.next()?.strip_prefix("planarian-agent-")?.strip_suffix(".service")?;
    planarian_schema::backend::valid_agent_name(name).then(|| name.to_string())
}

/// `sd_pid_get_session` (systemd's `cg_path_get_session`): the logind
/// session is a `session-<id>.scope` reached through `.slice` components
/// only, and here it must be under the caller's own `user-<uid>.slice`
/// (§10). A cgroup a user created under their own manager (delegated, below
/// `user@<uid>.service`) is no session, whatever it is named.
fn session_of_cgroup(cgroup: &str, uid: u32) -> Option<String> {
    let line = cgroup.lines().find_map(|l| l.strip_prefix("0::"))?;
    let mut user_slice = false;
    for c in line.split('/').filter(|c| !c.is_empty()) {
        if c.ends_with(".slice") {
            user_slice |= c == format!("user-{uid}.slice");
            continue;
        }
        let id = c.strip_prefix("session-")?.strip_suffix(".scope")?;
        return user_slice.then(|| id.to_string());
    }
    None
}

fn append_log(state: &Path, lines: &[String]) {
    if lines.is_empty() {
        return;
    }
    let dir = state.join("log");
    let _ = std::fs::create_dir_all(&dir);
    let p = dir.join("executor.jsonl");
    if std::fs::metadata(&p).map(|m| m.len() > LOG_ROTATE_BYTES).unwrap_or(false) {
        let _ = std::fs::rename(&p, dir.join("executor.jsonl.1"));
    }
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&p) {
        for l in lines {
            let _ = writeln!(f, "{l}");
        }
    }
}

/// Keep the leases this daemon holds fresh while it is busy in a long
/// backend call, so the watchdog does not take over from a live daemon.
fn renewer(store_dir: PathBuf, txn_dir: PathBuf, capacity: u64, me: OwnerId) {
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(RENEW_EVERY);
            let Ok(store) = FileStore::open(&store_dir, &txn_dir, capacity) else { continue };
            let Ok(mut j) = Journal::open(store) else { continue };
            let Ok(l) = j.sync_ledger().cloned() else { continue };
            let now = planarian_backend_linux::process::Processes.now();
            for t in l.live.values() {
                if t.txn.lease.owner == me && !t.txn.state.is_pre_mutation() {
                    let _ = j.append(
                        now,
                        Record::Renew { txn: t.txn.id, epoch: t.txn.lease.epoch, worker_pid: t.txn.lease.worker_pid },
                    );
                }
            }
        }
    });
}

type Reply = mpsc::Sender<Response>;

/// The gym's VM harness: a crash point from `/run/planarian-gym/crash`
/// (`State:Activating`, `OpBegun:activate_live`, `OpCalled:activate_live`),
/// armed for the next request. The file is consumed.
#[cfg(feature = "gym-hooks")]
fn gym_arm(core: &mut Core<Real, FileStore>) {
    use planarian_txn::kernel::CrashPoint;
    let path = "/run/planarian-gym/crash";
    let Ok(text) = std::fs::read_to_string(path) else { return };
    let _ = std::fs::remove_file(path);
    let (kind, name) = text.trim().split_once(':').unwrap_or(("", ""));
    let name: &'static str = Box::leak(name.to_string().into_boxed_str());
    core.ex.kernel.crash_at = match kind {
        "State" => Some(CrashPoint::State(name)),
        "OpBegun" => Some(CrashPoint::OpBegun(name)),
        "OpCalled" => Some(CrashPoint::OpCalled(name)),
        _ => None,
    };
}

/// The crash point fired: die the way SIGKILL would, with no cleanup.
#[cfg(feature = "gym-hooks")]
fn gym_crash(resp: &Response) {
    if matches!(resp, Response::Error { message } if message.contains("Crashed")) {
        eprintln!("planariad: gym crash point reached; aborting");
        std::process::abort();
    }
}

enum Event {
    /// A request from the socket.
    Request(Peer, Request, Reply),
    /// A deferred change's stage, evaluate and build finished.
    Built(Resume, Box<Prebuilt>, Reply),
}

fn main() {
    let cfg_path = std::env::var("PLANARIAN_CONFIG").unwrap_or_else(|_| CONFIG.into());
    let file = match FileConfig::load(Path::new(&cfg_path)) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("planariad: {e}");
            std::process::exit(78);
        }
    };
    let canonical = match load_canonical() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("planariad: canonical probes: {e}");
            std::process::exit(78);
        }
    };
    let paths = Paths {
        state: file.state_dir.clone(),
        owner: file.owner.clone(),
        flake_attr: file.flake_attr.clone(),
        ..Default::default()
    };
    let _ = std::fs::create_dir_all(&paths.state);
    let store = match FileStore::open(&paths.journal_dir(), &paths.txn_dir(), file.journal_bytes) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("planariad: journal: {e}");
            std::process::exit(74);
        }
    };
    let journal = match Journal::open(store) {
        Ok(j) => j,
        Err(e) => journal_failure("planariad", &e),
    };
    let (boot_hash, boot) = boot_id();
    let me = OwnerId::Daemon { pid: std::process::id(), boot_id: boot_hash };
    let mut real = Real::new(paths.clone(), file.devices.clone());
    real.logind.compositors = file.session_compositors.clone();
    real.runtime.wifi_permitted = file.catalog.wifi_networks.clone();
    real.nixos = real.nixos.with_budget(file.gc);
    let core_cfg = CoreConfig {
        exec: ExecConfig {
            settings: file.settings(),
            tables: file.tables(),
            catalog: file.catalog.clone(),
            owner: PinnedSource {
                root: file.owner.to_string_lossy().into_owned(),
                kind: if file.owner.join(".git").exists() { SourceKind::Git } else { SourceKind::Directory },
            },
            canonical,
        },
        runtime_options: file.runtime_options(),
        fresh_boot: fresh_boot(&paths.state, &boot),
        startup_grace: planarian_schema::Millis::secs(file.startup_grace_secs),
        posture: file.posture,
    };
    let mut core = Core::start(journal, real, me.clone(), core_cfg);
    // §9 hook: the external desired-state source, from its verified cache
    // first; an altered cache is an integrity finding like any other.
    let mut external = match &file.external_source {
        None => None,
        Some(c) => match ExternalSource::new(c, &paths.state) {
            Ok(mut src) => {
                if let Err(e) = src.load_cache() {
                    integrity_failure("planariad", &e);
                }
                if let Some(v) = &src.current {
                    core.set_external(Some(v.doc.clone()));
                }
                Some(src)
            }
            Err(e) => {
                eprintln!("planariad: {e}");
                std::process::exit(78);
            }
        },
    };
    // §10 hook: the signed health report, locally, on the declared cadence.
    let health = match file.health_report_secs {
        0 => None,
        secs => match hooks::health_key(&paths.state) {
            Ok(k) => Some((k, Duration::from_secs(secs))),
            Err(e) => {
                eprintln!("planariad: health report key: {e}; no health reports");
                None
            }
        },
    };
    let mut next_report = Instant::now();
    // Catalog changes stage, evaluate and build on a worker thread while the
    // core keeps observing, repairing and answering.
    core.defer = true;
    renewer(paths.journal_dir(), paths.txn_dir(), file.journal_bytes, me);

    // The socket: any local user may connect; identity comes from SO_PEERCRED.
    let sock = std::env::var("PLANARIAN_SOCKET").unwrap_or_else(|_| SOCKET.into());
    if let Some(dir) = Path::new(&sock).parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let _ = std::fs::remove_file(&sock);
    let listener = match UnixListener::bind(&sock) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("planariad: {sock}: {e}");
            std::process::exit(71);
        }
    };
    let _ = std::fs::set_permissions(&sock, std::fs::Permissions::from_mode(0o666));
    // Ready (§12d): the journal is open and reconciled and the socket is up.
    // systemd then reaches planarian-ready.target, after which the units that
    // admit principals start.
    // §10: the boot report before ready, so the units ordered after
    // planarian-ready.target (logins, agents) never start before it is clean.
    if let Some(why) = core.boot_report() {
        integrity_failure("planariad", &why);
    }
    mark_boot(&paths.state, &boot);
    sd_notify("READY=1");
    let (tx, rx) = mpsc::channel::<Event>();
    let built_tx = tx.clone();
    let group = file.admin_group.clone();
    // Set while the core handles a request that may take long; read-only
    // requests are answered from the snapshot meanwhile (snapshot.rs).
    let busy: Arc<Mutex<Option<(Busy, Snapshot)>>> = Arc::new(Mutex::new(None));
    let shared = busy.clone();
    std::thread::spawn(move || {
        // Bounded per caller (any local user may connect): a request is one
        // line of at most MAX_REQUEST bytes, read within 10 s in all, and a
        // uid has at most PER_UID connections in flight, all at most MAX_CONNS.
        let in_flight: Arc<Mutex<std::collections::BTreeMap<u32, usize>>> = Arc::default();
        for conn in listener.incoming().flatten() {
            let Some(uid) = rustix::net::sockopt::socket_peercred(&conn).ok().map(|c| c.uid.as_raw()) else {
                continue;
            };
            {
                let mut m = in_flight.lock().unwrap_or_else(|e| e.into_inner());
                let total: usize = m.values().sum();
                let mine = m.entry(uid).or_insert(0);
                if *mine >= PER_UID || total >= MAX_CONNS {
                    continue;
                }
                *mine += 1;
            }
            let tx = tx.clone();
            let group = group.clone();
            let shared = shared.clone();
            let in_flight = in_flight.clone();
            std::thread::spawn(move || {
                struct Release(Arc<Mutex<std::collections::BTreeMap<u32, usize>>>, u32);
                impl Drop for Release {
                    fn drop(&mut self) {
                        let mut m = self.0.lock().unwrap_or_else(|e| e.into_inner());
                        if let Some(n) = m.get_mut(&self.1) {
                            *n = n.saturating_sub(1);
                        }
                    }
                }
                let _release = Release(in_flight, uid);
                let Some(peer) = peer_of(&conn, &group) else { return };
                let Some(line) = read_request(&conn) else { return };
                let resp = match serde_json::from_str::<Request>(&line) {
                    Ok(req) if snapshot::read_only(&req) && shared.lock().is_ok_and(|b| b.is_some()) => {
                        let b = shared.lock().unwrap_or_else(|e| e.into_inner());
                        match b.as_ref().and_then(|(busy, snap)| snap.answer(&req, busy)) {
                            Some(r) => r,
                            None => Response::Error { message: "the daemon is busy".into() },
                        }
                    }
                    Ok(req) => {
                        let (rtx, rrx) = mpsc::channel();
                        if tx.send(Event::Request(peer, req, rtx)).is_err() {
                            return;
                        }
                        rrx.recv().unwrap_or(Response::Error { message: "the daemon stopped".into() })
                    }
                    Err(e) => Response::Error { message: format!("bad request: {e}") },
                };
                let mut w = &conn;
                let _ = w.write_all(resp.encode().as_bytes());
            });
        }
    });

    eprintln!("planariad: started (pid {})", std::process::id());
    let mut printed = 0u64;
    let mut next_tick = Instant::now();
    // One build at a time; later ones wait their turn.
    let mut building = false;
    let mut queued: VecDeque<(PrebuildJob<<Real as Backends>::Gens>, Resume, Reply)> = VecDeque::new();
    let start = |job: PrebuildJob<_>, resume: Resume, reply: Reply, core: &mut Core<Real, FileStore>| {
        let what = resume.describe();
        core.building = Some((what, core.b.clock().now()));
        let tx = built_tx.clone();
        std::thread::spawn(move || {
            let pre = job.run();
            let _ = tx.send(Event::Built(resume, Box::new(pre), reply));
        });
    };
    loop {
        // A steady stream of requests must not starve the repair loop.
        if Instant::now() >= next_tick {
            core.tick();
            next_tick = Instant::now() + TICK;
        }
        if let Some(why) = core.integrity.take() {
            integrity_failure("planariad", &why);
        }
        hooks_tick(&mut core, &mut external, &health, &paths.state, &mut next_report);
        let wait = next_tick.saturating_duration_since(Instant::now());
        match rx.recv_timeout(wait) {
            Ok(Event::Request(peer, req, reply)) => {
                // Answered from a snapshot while this runs: anything that
                // may mutate can hold the core (activation, checks).
                let long = !snapshot::read_only(&req);
                if long && let Some(snap) = Snapshot::take(&mut core) {
                    let b = Busy { with: snapshot::describe(&req), since: Instant::now() };
                    *busy.lock().unwrap_or_else(|e| e.into_inner()) = Some((b, snap));
                }
                #[cfg(feature = "gym-hooks")]
                gym_arm(&mut core);
                let resp = core.handle(peer, req);
                #[cfg(feature = "gym-hooks")]
                gym_crash(&resp);
                if long {
                    *busy.lock().unwrap_or_else(|e| e.into_inner()) = None;
                }
                match core.take_deferred() {
                    Some((job, resume)) if building => queued.push_back((job, resume, reply)),
                    Some((job, resume)) => {
                        building = true;
                        start(job, resume, reply, &mut core);
                    }
                    None => {
                        let _ = reply.send(resp);
                    }
                }
            }
            Ok(Event::Built(resume, pre, reply)) => {
                core.building = None;
                if let Some(snap) = Snapshot::take(&mut core) {
                    let b = Busy { with: resume.describe(), since: Instant::now() };
                    *busy.lock().unwrap_or_else(|e| e.into_inner()) = Some((b, snap));
                }
                #[cfg(feature = "gym-hooks")]
                gym_arm(&mut core);
                let resp = core.resume(resume, *pre);
                #[cfg(feature = "gym-hooks")]
                gym_crash(&resp);
                *busy.lock().unwrap_or_else(|e| e.into_inner()) = None;
                let _ = reply.send(resp);
                match queued.pop_front() {
                    Some((job, resume, reply)) => start(job, resume, reply, &mut core),
                    None => building = false,
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                core.tick();
                next_tick = Instant::now() + TICK;
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
        let lines: Vec<String> = core.log.drain(..).filter_map(|r| serde_json::to_string(&r).ok()).collect();
        append_log(&paths.state, &lines);
        // Notices go to the journal (stderr), once each.
        for s in core.notices_since(printed) {
            eprintln!("planariad: {s}");
        }
        printed = core.notices_total;
    }
}

/// The hooks, once per loop: poll the external source; emit the report when due.
fn hooks_tick(
    core: &mut Core<Real, FileStore>,
    external: &mut Option<ExternalSource>,
    health: &Option<(ed25519_dalek::SigningKey, Duration)>,
    state: &Path,
    next_report: &mut Instant,
) {
    if let Some(src) = external.as_mut() {
        match src.poll() {
            Poll::Unchanged => {}
            Poll::Accepted(v) => core.set_external(Some(v.doc)),
            Poll::Refused(why) => {
                core.notice(format!("external desired state not taken: {why}; the one in force stays"))
            }
            Poll::Stale(why) => {
                eprintln!("planariad: external desired state unreadable ({why}); the one in force stays")
            }
            Poll::Integrity(why) => integrity_failure("planariad", &why),
        }
    }
    if let Some((key, every)) = health
        && Instant::now() >= *next_report
    {
        *next_report = Instant::now() + *every;
        if let Err(e) = hooks::emit(state, key, &core.health_report()) {
            eprintln!("planariad: health report: {e}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_from_cgroup() {
        assert_eq!(agent_of_cgroup("0::/system.slice/planarian-agent-coder.service\n"), Some("coder".into()));
        assert_eq!(agent_of_cgroup("0::/system.slice/planarian-agent-coder.service/sub\n"), Some("coder".into()));
        assert_eq!(agent_of_cgroup("0::/system.slice/cron.service\n"), None);
        // Only systemd's own unit counts: a user's delegated cgroup named like
        // an agent unit is not one, and neither is a bad name.
        assert_eq!(agent_of_cgroup("0::/user.slice/user-1000.slice/planarian-agent-coder.service\n"), None);
        assert_eq!(agent_of_cgroup("0::/system.slice/planarian-agent-Coder.service\n"), None);
    }

    #[test]
    fn session_from_cgroup() {
        assert_eq!(session_of_cgroup("0::/user.slice/user-1000.slice/session-3.scope\n", 1000), Some("3".into()));
        assert_eq!(session_of_cgroup("0::/system.slice/cron.service\n", 1000), None);
        // Another uid's session, and a user-made cgroup named like a session.
        assert_eq!(session_of_cgroup("0::/user.slice/user-1001.slice/session-3.scope\n", 1000), None);
        let forged = "0::/user.slice/user-1000.slice/user@1000.service/app.slice/session-2.scope\n";
        assert_eq!(session_of_cgroup(forged, 1000), None);
        let user_manager = "0::/user.slice/user-1000.slice/user@1000.service/app.slice/x.scope\n";
        assert_eq!(session_of_cgroup(user_manager, 1000), None);
    }
}
