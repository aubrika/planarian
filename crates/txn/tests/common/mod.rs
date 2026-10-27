//! Shared rig for the fake-harness tests: one fake machine, one shared journal
//! store, and kernels for the daemon and the watchdog over them.

#![allow(dead_code)]

use planarian_schema::*;
use planarian_txn::fake::{FakeHost, World};
use planarian_txn::journal::Journal;
use planarian_txn::kernel::Kernel;
use planarian_txn::store::MemStore;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, MutexGuard};

pub const DAEMON: u32 = 100;
pub const DAEMON2: u32 = 101;
pub const WATCHDOG: u32 = 200;
pub const WORKER: u32 = 300;
pub const ALICE: u32 = 1000;
pub const ADMIN: u32 = 1001;

pub const G1: GenerationId = GenerationId(1);
pub const G2: GenerationId = GenerationId(2);

pub fn base_override() -> Hash {
    Hash::of(b"overrides.nix: base")
}

pub fn cand_override() -> Hash {
    Hash::of(b"overrides.nix: candidate")
}

pub fn path(g: GenerationId) -> StorePath {
    StorePath(format!("/nix/store/{}-nixos-system", g.0))
}

pub fn snd() -> UnitId {
    UnitId::device("snd-hda0")
}

pub fn hda() -> DriverRef {
    DriverRef { name: "snd_hda_intel".into(), module: None }
}

pub fn web() -> UnitId {
    UnitId::service("gym-web")
}

pub type K = Kernel<MemStore, FakeHost>;

pub struct Rig {
    pub store: MemStore,
    pub world: Arc<Mutex<World>>,
}

impl Rig {
    pub fn new() -> Rig {
        Rig::with_capacity(1 << 20)
    }

    pub fn with_capacity(capacity: u64) -> Rig {
        let mut w = World {
            now: Timestamp(1_000_000),
            current: G1,
            boot_default: G1,
            override_hash: base_override(),
            ..Default::default()
        };
        w.boot_entries.insert(G1);
        w.generations.insert(G1, path(G1));
        w.generations.insert(G2, path(G2));
        w.units.insert(web(), Observed::Active);
        w.devices.insert(snd(), Some(hda()));
        w.alive.extend([DAEMON, DAEMON2, WATCHDOG, WORKER]);
        w.gc_roots.insert("/nix/var/nix/gcroots/planarian/builds/cand".into());
        Rig { store: MemStore::new(capacity), world: Arc::new(Mutex::new(w)) }
    }

    pub fn w(&self) -> MutexGuard<'_, World> {
        self.world.lock().unwrap()
    }

    pub fn host(&self) -> FakeHost {
        FakeHost::new(self.world.clone(), self.store.clone())
    }

    fn kernel(&self, owner: OwnerId) -> K {
        Kernel::new(Journal::open(self.store.clone()).expect("journal opens"), self.host(), owner)
    }

    pub fn daemon(&self) -> K {
        self.kernel(OwnerId::Daemon { pid: DAEMON, boot_id: Hash::ZERO })
    }

    /// The daemon after a restart: same machine, new pid.
    pub fn daemon2(&self) -> K {
        self.kernel(OwnerId::Daemon { pid: DAEMON2, boot_id: Hash::ZERO })
    }

    pub fn watchdog(&self) -> K {
        self.kernel(OwnerId::Watchdog { pid: WATCHDOG, boot_id: Hash::ZERO })
    }

    pub fn kill(&self, pid: u32) {
        self.w().alive.remove(&pid);
    }

    /// Running generation, boot default and override source all describe the
    /// same outcome (catalog `journal_agrees`).
    pub fn assert_agrees(&self, generation: GenerationId, over: Hash) {
        let w = self.w();
        assert_eq!(w.current, generation, "running generation");
        assert_eq!(w.boot_default, generation, "boot default");
        assert_eq!(w.override_hash, over, "override source");
    }
}

pub fn facts(caller: Actor) -> DerivedFacts {
    DerivedFacts {
        affected_units: Vec::new(),
        sensitivity: Sensitivities::default(),
        disruption: Disruption::Brief,
        recovery: Recovery::Revertible,
        touches_manifest: false,
        touches_canonical_probe: false,
        changes_desired: false,
        touches_core: false,
        caller,
        config_diff: None,
    }
}

/// A transaction as exec would hand it to `Kernel::prepare`.
pub fn txn(transition: Transition, caller: Actor) -> Transaction {
    Transaction {
        id: TxnId(0),
        state: TxnState::Prepared,
        lease: Lease {
            txn: TxnId(0),
            owner: OwnerId::Daemon { pid: 0, boot_id: Hash::ZERO },
            epoch: 1,
            worker_pid: None,
            renewed: Timestamp(0),
            jobs: vec![],
        },
        base_source: None,
        staged_source: None,
        base_override: None,
        candidate_override: None,
        gc_root: None,
        recovery: transition.recovery(),
        transition,
        facts: facts(caller),
        base: G1,
        candidate: None,
        policy: PolicyVersion(Hash::ZERO),
        approval: None,
        snapshot: None,
        expected: Expectation {
            units: BTreeMap::new(),
            generation: None,
            may_change: BTreeSet::new(),
            others_unchanged: true,
            settle: Settle::Duration(Millis::secs(15)),
        },
        started: Timestamp(1_000_000),
        deadline: Timestamp(1_000_000 + 15 * 60 * 1000),
        revert_to: G1,
        prior_driver: None,
        check: CheckContext::default(),
    }
}

/// An `ApplyChange` from G1 to G2 that swaps the override file base → candidate.
pub fn change(name: &str) -> Transaction {
    let mut t = txn(
        Transition::ApplyChange { change: ChangeId(name.into()), args: BTreeMap::new() },
        Actor::User { uid: ADMIN },
    );
    t.candidate = Some((G2, path(G2)));
    t.base_override = Some(base_override());
    t.candidate_override = Some(cand_override());
    t.gc_root = Some("/nix/var/nix/gcroots/planarian/builds/cand".into());
    t
}

/// font-scale 1.25: probes pass on G2.
pub fn good_change() -> Transaction {
    change("font-scale")
}

/// listen-address 192.0.2.10: probes fail on G2 (the caller marks G2 bad).
pub fn bad_change(rig: &Rig) -> Transaction {
    rig.w().bad.insert(G2);
    change("listen-address")
}

pub fn path_of(k: &mut K, id: TxnId) -> Vec<String> {
    k.journal.sync_ledger().unwrap().path(id).unwrap().to_vec()
}

pub fn state_of(k: &mut K, id: TxnId) -> TxnState {
    k.journal.sync_ledger().unwrap().state(id).unwrap()
}

pub fn strs(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| s.to_string()).collect()
}
