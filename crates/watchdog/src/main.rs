//! planarian-recovery (§12 recovery watchdog). A separate unit with
//! `Restart=always`, started before planariad and independent of it. Every
//! 10 s it reads the journal. A transaction in Activating, Checking,
//! Published, Promoted or Reverting whose owner is dead, or whose lease went
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
    let mut k = Kernel::new(journal, ExecHost::new(real, canonical.clone()), me.clone());
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

/// I2 in Phase A (§12d's independent check): the installed core binary's
/// SHA-256 equals the hash recorded at build time. A mismatch is an Integrity
/// failure: report it and stop with status 78; the posture units respond.
fn core_hash_check() {
    let (Ok(record), Ok(binary)) = (std::env::var("PLANARIAN_CORE_HASH"), std::env::var("PLANARIAN_CORE_BINARY"))
    else {
        return;
    };
    let want = std::fs::read_to_string(&record).unwrap_or_default().trim().to_string();
    let have = std::fs::read(&binary).map(|b| Hash::of(&b).to_hex()).unwrap_or_default();
    if want.is_empty() || have != want {
        let why = format!("core: {binary} hashes to {have:?}, but {record} records {want:?}");
        eprintln!("planarian-recovery: INTEGRITY: {why}");
        let _ = std::fs::create_dir_all("/run/planarian");
        let _ = std::fs::write("/run/planarian/integrity", format!("{why}\n"));
        std::process::exit(78);
    }
}
