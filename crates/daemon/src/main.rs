//! planariad: runs the core loop over the real backends and serves the socket.

use planarian_backend_linux::{Paths, Real};
use planarian_daemon::config::{CONFIG, FileConfig, is_admin, load_canonical};
use planarian_daemon::core::Resume;
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
use std::io::{BufRead, BufReader, Write};
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
    let p = state.join("boot_id");
    let fresh = std::fs::read_to_string(&p).map(|s| s.trim() != boot).unwrap_or(true);
    let _ = std::fs::write(&p, boot);
    fresh
}

/// Exit status for an `Integrity` failure (§12d). The response lives in
/// `nix/posture.nix`, never here: this only reports what was found and stops.
pub const EXIT_INTEGRITY: i32 = 78;
/// Where the reason goes, for the boot report and the posture units.
const INTEGRITY_NOTE: &str = "/run/planarian/integrity";

fn journal_failure(who: &str, e: &JournalError) -> ! {
    match e {
        JournalError::Integrity(why) => {
            eprintln!("{who}: INTEGRITY: the journal's hash chain is broken: {why}");
            let _ = std::fs::create_dir_all("/run/planarian");
            let _ = std::fs::write(INTEGRITY_NOTE, format!("journal: {why}\n"));
            std::process::exit(EXIT_INTEGRITY);
        }
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

fn peer_of(s: &UnixStream, admin_group: &str) -> Option<Peer> {
    let cred = rustix::net::sockopt::socket_peercred(s).ok()?;
    let uid = cred.uid.as_raw();
    let cgroup = std::fs::read_to_string(format!("/proc/{}/cgroup", cred.pid.as_raw_nonzero())).unwrap_or_default();
    Some(Peer { uid, admin: is_admin(uid, admin_group), session: session_of_cgroup(&cgroup) })
}

/// `sd_pid_get_session`: the logind session is the `session-<id>.scope` in the
/// process's cgroup path (§10). None for a process outside any session.
fn session_of_cgroup(cgroup: &str) -> Option<String> {
    cgroup.lines().filter_map(|l| l.rsplit_once(':')).find_map(|(_, path)| {
        path.split('/')
            .find_map(|c| c.strip_prefix("session-").and_then(|c| c.strip_suffix(".scope")).map(String::from))
    })
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
    let (tx, rx) = mpsc::channel::<Event>();
    let built_tx = tx.clone();
    let group = file.admin_group.clone();
    // Set while the core handles a request that may take long; read-only
    // requests are answered from the snapshot meanwhile (snapshot.rs).
    let busy: Arc<Mutex<Option<(Busy, Snapshot)>>> = Arc::new(Mutex::new(None));
    let shared = busy.clone();
    std::thread::spawn(move || {
        for conn in listener.incoming().flatten() {
            let tx = tx.clone();
            let group = group.clone();
            let shared = shared.clone();
            std::thread::spawn(move || {
                let Some(peer) = peer_of(&conn, &group) else { return };
                let _ = conn.set_read_timeout(Some(Duration::from_secs(10)));
                let mut line = String::new();
                if BufReader::new(&conn).read_line(&mut line).is_err() {
                    return;
                }
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
            journal_failure("planariad", &JournalError::Integrity(why));
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_from_cgroup() {
        assert_eq!(session_of_cgroup("0::/user.slice/user-1000.slice/session-3.scope\n"), Some("3".into()));
        assert_eq!(session_of_cgroup("0::/system.slice/cron.service\n"), None);
        let user_manager = "0::/user.slice/user-1000.slice/user@1000.service/app.slice/x.scope\n";
        assert_eq!(session_of_cgroup(user_manager), None);
    }
}
