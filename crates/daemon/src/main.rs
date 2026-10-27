//! planariad: runs the core loop over the real backends and serves the socket.

use planarian_backend_linux::{Paths, Real};
use planarian_daemon::config::{CONFIG, FileConfig, is_admin, load_canonical};
use planarian_daemon::{Core, CoreConfig, Peer};
use planarian_exec::Config as ExecConfig;
use planarian_ipc::{Request, Response, SOCKET};
use planarian_schema::{Clock, Hash, OwnerId, PinnedSource, SourceKind};
use planarian_txn::journal::Journal;
use planarian_txn::ledger::Record;
use planarian_txn::store::FileStore;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
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

fn peer_of(s: &UnixStream, admin_group: &str) -> Option<Peer> {
    let cred = rustix::net::sockopt::socket_peercred(s).ok()?;
    let uid = cred.uid.as_raw();
    Some(Peer { uid, admin: is_admin(uid, admin_group) })
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
        Err(e) => {
            eprintln!("planariad: journal: {e:?}");
            std::process::exit(74);
        }
    };
    let (boot_hash, boot) = boot_id();
    let me = OwnerId::Daemon { pid: std::process::id(), boot_id: boot_hash };
    let real = Real::new(paths.clone(), file.devices.clone());
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
    };
    let mut core = Core::start(journal, real, me.clone(), core_cfg);
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
    type Job = (Peer, Request, mpsc::Sender<Response>);
    let (tx, rx) = mpsc::channel::<Job>();
    let group = file.admin_group.clone();
    std::thread::spawn(move || {
        for conn in listener.incoming().flatten() {
            let tx = tx.clone();
            let group = group.clone();
            std::thread::spawn(move || {
                let Some(peer) = peer_of(&conn, &group) else { return };
                let _ = conn.set_read_timeout(Some(Duration::from_secs(10)));
                let mut line = String::new();
                if BufReader::new(&conn).read_line(&mut line).is_err() {
                    return;
                }
                let resp = match serde_json::from_str::<Request>(&line) {
                    Ok(req) => {
                        let (rtx, rrx) = mpsc::channel();
                        if tx.send((peer, req, rtx)).is_err() {
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
    let mut printed = 0usize;
    let mut next_tick = Instant::now();
    loop {
        let wait = next_tick.saturating_duration_since(Instant::now());
        match rx.recv_timeout(wait) {
            Ok((peer, req, reply)) => {
                let resp = core.handle(peer, req);
                let _ = reply.send(resp);
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
        let n = core.notices.len();
        if n < printed {
            printed = 0;
        }
        for s in core.notices.iter().skip(printed) {
            eprintln!("planariad: {s}");
        }
        printed = n;
    }
}
