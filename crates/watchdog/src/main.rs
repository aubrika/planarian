//! planarian-recovery (§12 recovery watchdog). A separate unit with
//! `Restart=always`, started before planariad and independent of it. Every
//! 10 s it reads the journal. A transaction in Activating, Checking,
//! PublishingBoot, Published, Promoted or Reverting whose owner is dead, or whose lease went
//! unrenewed past its deadline, is taken over: fence, confirm quiescence, then
//! run the crash-recovery table. From Checking that means the entire
//! authorized commit path, or a revert; never a partial path. When the
//! daemon is alive and renewing, the watchdog does nothing.

use planarian_backend_linux::{Paths, Real};
use planarian_daemon::config::{CONFIG, FileConfig, load_canonical};
use planarian_exec::host::ExecHost;
use planarian_schema::{Hash, OwnerId};
use planarian_txn::journal::{Journal, JournalError};
use planarian_txn::kernel::Kernel;
use planarian_txn::store::FileStore;
use std::path::Path;
use std::time::Duration;

const PERIOD: Duration = Duration::from_secs(10);

fn main() {
    let cfg_path = std::env::var("PLANARIAN_CONFIG").unwrap_or_else(|_| CONFIG.into());
    let file = FileConfig::load(Path::new(&cfg_path)).unwrap_or_else(|e| {
        eprintln!("planarian-recovery: {e}; using defaults");
        FileConfig::default()
    });
    let canonical = load_canonical().unwrap_or_else(|e| {
        eprintln!("planarian-recovery: canonical probes: {e}");
        Default::default()
    });
    let paths = Paths {
        state: file.state_dir.clone(),
        owner: file.owner.clone(),
        flake_attr: file.flake_attr.clone(),
        ..Default::default()
    };
    let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id").unwrap_or_default();
    let me = OwnerId::Watchdog { pid: std::process::id(), boot_id: Hash::of(boot.trim().as_bytes()) };
    core_hash_check();
    eprintln!("planarian-recovery: watching {}", paths.journal_dir().display());
    loop {
        if let Err(e) = pass(&paths, &file, &canonical, &me) {
            eprintln!("planarian-recovery: {e}");
        }
        std::thread::sleep(PERIOD);
    }
}

fn pass(
    paths: &Paths,
    file: &FileConfig,
    canonical: &std::collections::BTreeMap<String, Vec<planarian_schema::ProbeDef>>,
    me: &OwnerId,
) -> Result<(), String> {
    let store = FileStore::open(&paths.journal_dir(), &paths.txn_dir(), file.journal_bytes)
        .map_err(|e| format!("journal: {e}"))?;
    let journal = match Journal::open(store) {
        Ok(j) => j,
        // planarian-recovery's independent check (§12d): report and stop with
        // the Integrity status; the posture units respond.
        Err(JournalError::Integrity(why)) => {
            eprintln!("planarian-recovery: INTEGRITY: the journal's hash chain is broken: {why}");
            let _ = std::fs::create_dir_all("/run/planarian");
            let _ = std::fs::write("/run/planarian/integrity", format!("journal: {why}\n"));
            std::process::exit(78);
        }
        Err(e) => return Err(format!("journal: {e:?}")),
    };
    let real = Real::new(paths.clone(), file.devices.clone());
    let host = ExecHost::new(real, canonical.clone());
    // Recovery uses the same durable applicability context as the daemon,
    // including authorized suppressions and the floor, never an empty default
    // that would revive intentionally stopped units during probe checks.
    {
        let l = journal.ledger();
        let mut ctx = host.ctx.lock().unwrap_or_else(|e| e.into_inner());
        ctx.known_good = l.known_good.unwrap_or_default();
        ctx.live_tested = l.live_tested;
        ctx.accepted_baseline = l.accepted_baseline;
        ctx.security_floor = l.security_floor;
        ctx.overrides = l.overrides.clone();
    }
    let mut k = Kernel::new(journal, host, me.clone());
    let live: Vec<_> = k.journal.ledger().live.values().map(|l| l.txn.clone()).collect();
    for txn in live {
        if !k.watchdog_should_take_over(&txn) {
            continue;
        }
        eprintln!("planarian-recovery: taking over transaction {} (found in {:?})", txn.id.0, txn.state);
        match k.recover(txn.id, txn.lease.epoch) {
            Ok(end) => eprintln!("planarian-recovery: transaction {} → {end:?}", txn.id.0),
            Err(e) => eprintln!("planarian-recovery: transaction {}: {e:?}", txn.id.0),
        }
    }
    Ok(())
}

/// I2 in Phase A-D (§12d's independent check, B-12): every Planarian
/// binary and script the generation installs hashes to what was recorded at
/// build (`<sha256> <path>` per line). A mismatch, a missing file or a
/// record that is not in that form is an Integrity failure: report it and
/// stop with status 78; the posture units respond.
fn core_hash_check() {
    let Ok(record) = std::env::var("PLANARIAN_CORE_HASH") else { return };
    let text = std::fs::read_to_string(&record).unwrap_or_default();
    let mut problems = vec![];
    let mut checked = 0;
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        let Some((want, path)) = line.split_once(' ') else {
            problems.push(format!("{record}: malformed line {line:?}"));
            continue;
        };
        let have = std::fs::read(path).map(|b| Hash::of(&b).to_hex()).unwrap_or_default();
        if have != want {
            problems.push(format!("{path} hashes to {have:?}, but {record} records {want:?}"));
        }
        checked += 1;
    }
    if checked == 0 && problems.is_empty() {
        problems.push(format!("{record} records nothing"));
    }
    if !problems.is_empty() {
        let why = format!("core: {}", problems.join("; "));
        eprintln!("planarian-recovery: INTEGRITY: {why}");
        let _ = std::fs::create_dir_all("/run/planarian");
        let _ = std::fs::write("/run/planarian/integrity", format!("{why}\n"));
        std::process::exit(78);
    }
}
