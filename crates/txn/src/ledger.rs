//! Journal records and the ledger they build (§12, §12c).
//!
//! The ledger is the live state the journal establishes. A checkpoint is the
//! serialized ledger, so replaying (checkpoint + tail) and replaying the full
//! history produce equal ledgers by construction.
//!
//! `validate` runs before a record is written (write-ahead) and again on
//! replay. It enforces I6, I15 and the recovery interlock at the journal
//! itself, so no caller can journal a step that breaks them.
//!
//! Verified with Verus (docs/verification.md): `validate` accepts a record
//! only when `rules` hold, and `apply` preserves `inv` (I6 among the live
//! transactions, unique ids, leases naming their transaction). Bookkeeping no
//! invariant reads (the terminal archive, overrides, incidents, tokens) is
//! done by small unverified helpers that cannot reach the verified fields.

use crate::machine::{step_allowed, tag};
use planarian_schema::{
    Actor, GenerationId, Hash, Incident, IncidentId, Lease, OpId, Outcome, Override, OwnerId, Resolution, Timestamp,
    Transaction, Transition, TxnId, TxnState, UnitId,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::BTreeMap;
use vstd::prelude::*;

verus! {

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[verifier::external_derive]
pub struct Entry {
    pub seq: u64,
    pub at: Timestamp,
    pub record: Record,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[verifier::external_derive]
pub enum Record {
    /// The transaction exists from this record on (§12 step 4).
    Prepared(Box<Transaction>),
    Advance {
        txn: TxnId,
        epoch: u64,
        to: TxnState,
        note: String,
    },
    /// Compare-and-swap on the epoch: valid only if `from_epoch` is current.
    Takeover {
        txn: TxnId,
        from_epoch: u64,
        lease: Lease,
    },
    Renew {
        txn: TxnId,
        epoch: u64,
        worker_pid: Option<u32>,
        /// The renewal's time on the boot clock (§12h); 0 in records written
        /// before v4.5, which then read as long ago.
        #[serde(default)]
        boot_at: Timestamp,
    },
    /// Written and fsynced before the backend call it names.
    OpBegin {
        op: OpId,
        call: String,
    },
    OpAck {
        op: OpId,
        outcome: Outcome,
    },
    OverrideSet(Override),
    OverrideLifted(UnitId),
    Incident(Incident),
    KnownGood(GenerationId),
    LiveTested(Option<GenerationId>),
    AcceptedBaseline(Option<GenerationId>),
    /// The security floor (§12e): derived when a generation commits, or set by
    /// an administrator's `mark-security-floor`; never by a proposal.
    SecurityFloor(Option<GenerationId>),
    /// The external desired-state document accepted (§9 hook, §12c, B-16):
    /// its sequence number and the hash of its bytes. Replay protection
    /// lives here, in the journal and its checkpoint, not in a cache file.
    ExternalAccepted {
        seq: u64,
        digest: Hash,
    },
    /// An approval used (§12 step 4, I7): by whom, for which transaction.
    TokenUsed {
        nonce: [u8; 16],
        expires: Timestamp,
        /// The approver's PrincipalId (a human's is their uid); 0 in records
        /// from before v4.6.
        #[serde(default)]
        approver: u64,
        #[serde(default)]
        txn: u64,
    },
    /// `planarian agent run <name>` by this uid (§11, I24): the started
    /// unit's instance (its InvocationID) acts with that user's permissions,
    /// attributed to the agent. Journaled once the unit has started, so a
    /// failed or refused start binds nothing; covered by the chain.
    AgentStarted {
        name: String,
        /// Zero in records written before v4.6, which then match no peer.
        #[serde(default)]
        instance: [u8; 16],
        by: u32,
    },
    Resolved {
        txn: TxnId,
        resolution: Resolution,
        by: Actor,
    },
    Reconciliation(Reconciliation),
}

/// What a restarted owner found and did (§12 daemon restart reconciliation).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[verifier::external_derive]
pub struct Reconciliation {
    pub by: OwnerId,
    pub found: Vec<(TxnId, TxnState)>,
    pub actions: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[verifier::external_derive]
pub struct OpRecord {
    pub op: OpId,
    pub call: String,
    pub ack: Option<Outcome>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[verifier::external_derive]
pub struct LiveTxn {
    pub txn: Transaction,
    pub ops: Vec<OpRecord>,
    /// Journal states this transaction has passed through, in order.
    pub path: Vec<String>,
    /// The most recent non-empty note on an Advance.
    #[serde(default)]
    pub why: String,
}

/// What remains of a terminal transaction: enough to refuse stale epochs and
/// to show the outcome. Bounded to the most recent `TERMINAL_KEEP`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[verifier::external_derive]
pub struct TerminalTxn {
    pub state: TxnState,
    pub epoch: u64,
    pub owner: OwnerId,
    pub path: Vec<String>,
    pub transition: Transition,
    /// The most recent reason journaled with a step (why it reverted, …).
    pub why: String,
}

/// An unresolved RecoveryFailed (§12c). While any exists, autonomous mutation is blocked.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[verifier::external_derive]
pub struct InterlockEntry {
    pub txn: TxnId,
    pub transition: Transition,
    pub failed_from: String,
    pub base_override: Option<Hash>,
    pub candidate_override: Option<Hash>,
    pub revert_to: GenerationId,
    pub note: String,
}

/// A map from transaction id, stored as a vector sorted by id; vstd
/// specifies `BTreeMap` only for keys with an ordering spec, which `TxnId`
/// lacks. Serialized as the JSON object the `BTreeMap` was.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdMap<V> {
    /// Sorted by id, ids unique. Read freely; change through the methods.
    pub entries: Vec<(TxnId, V)>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[verifier::external_derive]
pub struct Ledger {
    pub last_seq: u64,
    pub next_txn: u64,
    pub live: IdMap<LiveTxn>,
    pub terminal: BTreeMap<TxnId, TerminalTxn>,
    pub overrides: Vec<Override>,
    pub incidents: BTreeMap<IncidentId, Incident>,
    pub tokens_used: Vec<([u8; 16], Timestamp)>,
    pub known_good: Option<GenerationId>,
    pub live_tested: Option<GenerationId>,
    pub accepted_baseline: Option<GenerationId>,
    #[serde(default)]
    pub security_floor: Option<GenerationId>,
    /// The last accepted external document's (sequence, digest) (B-16).
    #[serde(default)]
    pub external: Option<(u64, Hash)>,
    pub interlock: IdMap<InterlockEntry>,
    pub last_reconciliation: Option<Reconciliation>,
    /// Every agent started, in order: (name, instance, the uid that started
    /// it). A peer is matched by its instance, never its name (I24).
    #[serde(default)]
    pub agents: Vec<(String, [u8; 16], u32)>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LedgerError {
    Sequence {
        expected: u64,
        got: u64,
    },
    DuplicateTxn(TxnId),
    NotLive(TxnId),
    /// I15: only the current lease holder's epoch may advance the journal.
    StaleEpoch {
        txn: TxnId,
        current: u64,
        got: u64,
    },
    IllegalStep {
        txn: TxnId,
        from: &'static str,
        to: &'static str,
    },
    /// I6: a generation-changing transaction overlaps another in-flight one.
    Exclusive {
        txn: TxnId,
        blocker: TxnId,
    },
    /// §12c: autonomous mutation while the recovery interlock is set.
    Interlocked {
        txn: TxnId,
    },
    UnknownOp(OpId),
    DuplicateOp(OpId),
    NotInterlocked(TxnId),
    BadPrepared(&'static str),
    /// B-16: an external document no newer than the one in force.
    ExternalReplay {
        have: u64,
        got: u64,
    },
}

// ---------- Specifications ----------

/// Anyone but a user: the daemon, the watchdog, the model.
pub open spec fn autonomous(a: Actor) -> bool {
    !(a is User)
}

pub open spec fn in_flight(x: LiveTxn) -> bool {
    !x.txn.state.pre_mutation()
}

pub open spec fn generation(x: LiveTxn) -> bool {
    x.txn.transition.changes_generation_spec()
}

/// A state in which a transaction may have mutated and has not finished.
pub open spec fn flying(s: TxnState) -> bool {
    !s.pre_mutation() && !s.terminal()
}

/// I6 (v4.4) for a pair of states, `g` saying whether each transaction
/// changes the generation. A generation transaction in flight excludes every
/// other in-flight transaction, except while it is `AwaitingBoot` (unit and
/// device repairs may run then); and at most one generation transaction is
/// active, where waiting in `Built` and `AwaitingBoot` count as active.
pub open spec fn compatible(s1: TxnState, g1: bool, s2: TxnState, g2: bool) -> bool {
    let excl1 = g1 && flying(s1) && !(s1 is AwaitingBoot);
    let excl2 = g2 && flying(s2) && !(s2 is AwaitingBoot);
    let act1 = g1 && (flying(s1) || s1 is Built);
    let act2 = g2 && (flying(s2) || s2 is Built);
    &&& excl1 ==> !flying(s2)
    &&& excl2 ==> !flying(s1)
    &&& !(act1 && act2)
}

pub open spec fn has_id<V>(s: Seq<(TxnId, V)>, id: TxnId) -> bool {
    exists|i: int| 0 <= i < s.len() && (#[trigger] s[i]).0 == id
}

pub open spec fn interlocked(l: Ledger) -> bool {
    l.interlock.entries@.len() > 0
}

/// One live transaction is well formed: keyed by its id, its lease names it,
/// its id was issued, it is not terminal, its recovery strategy is the one
/// its transition fixes.
pub open spec fn live_ok(x: (TxnId, LiveTxn), next_txn: u64) -> bool {
    &&& x.0 == x.1.txn.id
    &&& x.1.txn.lease.txn == x.0
    &&& x.0.0 < next_txn
    &&& !x.1.txn.state.terminal()
    &&& x.1.txn.recovery == x.1.txn.transition.recovery_spec()
}

/// Two distinct live transactions: different ids, and compatible (I6).
pub open spec fn pair_ok(a: (TxnId, LiveTxn), b: (TxnId, LiveTxn)) -> bool {
    &&& a.0 != b.0
    &&& compatible(a.1.txn.state, generation(a.1), b.1.txn.state, generation(b.1))
}

/// The ledger invariant. I6: at most one generation-changing transaction is
/// active, and while one is in flight (other than awaiting a boot), no other
/// transaction is.
pub open spec fn inv(l: Ledger) -> bool {
    let e = l.live.entries@;
    &&& forall|i: int| 0 <= i < e.len() ==> live_ok(#[trigger] e[i], l.next_txn)
    &&& forall|i: int, j: int| 0 <= i < e.len() && 0 <= j < e.len() && i != j ==> pair_ok(#[trigger] e[i], #[trigger] e[j])
}

pub open spec fn prepared_rule(l: Ledger, t: Transaction) -> bool {
    &&& !has_id(l.live.entries@, t.id)
    &&& l.next_txn <= t.id.0 < u64::MAX
    &&& t.state == TxnState::Prepared
    &&& t.lease.epoch == 1
    &&& t.lease.txn == t.id
    &&& t.recovery == t.transition.recovery_spec()
    &&& !(interlocked(l) && autonomous(t.facts.caller))
}

pub open spec fn advance_rule(l: Ledger, txn: TxnId, epoch: u64, to: TxnState) -> bool {
    exists|i: int| 0 <= i < l.live.entries@.len() && (#[trigger] l.live.entries@[i]).0 == txn && advance_ok(l, i, epoch, to)
}

pub open spec fn takeover_rule(l: Ledger, txn: TxnId, from_epoch: u64, lease: Lease) -> bool {
    exists|i: int|
        0 <= i < l.live.entries@.len() && (#[trigger] l.live.entries@[i]).0 == txn && l.live.entries@[i].1.txn.lease.epoch
            == from_epoch && lease.epoch > from_epoch && lease.txn == txn
}

pub open spec fn renew_rule(l: Ledger, txn: TxnId, epoch: u64) -> bool {
    exists|i: int|
        0 <= i < l.live.entries@.len() && (#[trigger] l.live.entries@[i]).0 == txn && l.live.entries@[i].1.txn.lease.epoch
            == epoch
}

pub open spec fn op_begin_rule(l: Ledger, op: OpId) -> bool {
    exists|i: int|
        0 <= i < l.live.entries@.len() && (#[trigger] l.live.entries@[i]).0 == op.txn && l.live.entries@[i].1.txn.lease.epoch
            == op.epoch && forall|k: int| 0 <= k < l.live.entries@[i].1.ops@.len() ==> (
        #[trigger] l.live.entries@[i].1.ops@[k]).op != op
}

pub open spec fn op_ack_rule(l: Ledger, op: OpId) -> bool {
    exists|i: int, k: int|
        0 <= i < l.live.entries@.len() && (#[trigger] l.live.entries@[i]).0 == op.txn && 0 <= k
            < l.live.entries@[i].1.ops@.len() && (#[trigger] l.live.entries@[i].1.ops@[k]).op == op
            && l.live.entries@[i].1.ops@[k].ack is None
}

/// What `validate` checks, per record. I15 is in the epoch conditions; I6 in
/// the exclusivity condition; §12c in the interlock conditions.
pub open spec fn rules(l: Ledger, e: Entry) -> bool {
    &&& e.seq == l.last_seq + 1
    &&& match e.record {
        Record::Prepared(t) => prepared_rule(l, *t),
        Record::Advance { txn, epoch, to, .. } => advance_rule(l, txn, epoch, to),
        Record::Takeover { txn, from_epoch, lease } => takeover_rule(l, txn, from_epoch, lease),
        Record::Renew { txn, epoch, .. } => renew_rule(l, txn, epoch),
        Record::OpBegin { op, .. } => op_begin_rule(l, op),
        Record::OpAck { op, .. } => op_ack_rule(l, op),
        Record::Resolved { txn, .. } => has_id(l.interlock.entries@, txn),
        Record::ExternalAccepted { seq, .. } => external_rule(l, seq),
        _ => true,
    }
}

/// B-16: an external document is accepted only with a sequence number above
/// the last one the journal accepted, so a replayed or rewound document
/// cannot come back into force.
pub open spec fn external_rule(l: Ledger, seq: u64) -> bool {
    match l.external {
        None => true,
        Some(p) => seq > p.0,
    }
}

/// An Advance of the live transaction at `i`: by its lease holder (I15),
/// along the state machine; if it starts mutating, not while the interlock
/// holds for an autonomous caller; and its new state compatible with every
/// other live transaction (I6).
pub open spec fn advance_ok(l: Ledger, i: int, epoch: u64, to: TxnState) -> bool {
    let live = l.live.entries@;
    let x = live[i].1;
    &&& x.txn.lease.epoch == epoch
    &&& crate::machine::step_spec(x.txn.state, to, x.txn.recovery)
    &&& (x.txn.state.pre_mutation() && !to.pre_mutation() && !to.terminal()) ==> !(interlocked(l) && autonomous(
        x.txn.facts.caller,
    ))
    &&& forall|j: int| 0 <= j < live.len() && j != i ==> compatible(
        to,
        generation(x),
        (#[trigger] live[j]).1.txn.state,
        generation(live[j].1),
    )
}

// ---------- Small verified helpers ----------

fn flying_exec(s: &TxnState) -> (r: bool)
    ensures
        r == flying(*s),
{
    !s.is_pre_mutation() && !s.is_terminal()
}

fn compatible_exec(s1: &TxnState, g1: bool, s2: &TxnState, g2: bool) -> (r: bool)
    ensures
        r == compatible(*s1, g1, *s2, g2),
{
    let awaiting1 = match s1 {
        TxnState::AwaitingBoot => true,
        _ => false,
    };
    let awaiting2 = match s2 {
        TxnState::AwaitingBoot => true,
        _ => false,
    };
    let built1 = match s1 {
        TxnState::Built => true,
        _ => false,
    };
    let built2 = match s2 {
        TxnState::Built => true,
        _ => false,
    };
    let f1 = flying_exec(s1);
    let f2 = flying_exec(s2);
    let excl1 = g1 && f1 && !awaiting1;
    let excl2 = g2 && f2 && !awaiting2;
    let act1 = g1 && (f1 || built1);
    let act2 = g2 && (f2 || built2);
    !(excl1 && f2 || excl2 && f1 || act1 && act2)
}

fn find<V>(m: &IdMap<V>, id: TxnId) -> (r: Option<usize>)
    ensures
        match r {
            Some(i) => i < m.entries@.len() && m.entries@[i as int].0 == id,
            None => !has_id(m.entries@, id),
        },
{
    let mut i: usize = 0;
    while i < m.entries.len()
        invariant
            i <= m.entries@.len(),
            forall|k: int| 0 <= k < i ==> (#[trigger] m.entries@[k]).0 != id,
        decreases m.entries.len() - i,
    {
        if m.entries[i].0.0 == id.0 {
            return Some(i);
        }
        i += 1;
    }
    None
}

fn is_autonomous(a: &Actor) -> (r: bool)
    ensures
        r == autonomous(*a),
{
    match a {
        Actor::User { .. } => false,
        _ => true,
    }
}

fn op_eq(a: OpId, b: OpId) -> (r: bool)
    ensures
        r == (a == b),
{
    a.txn.0 == b.txn.0 && a.epoch == b.epoch && a.seq == b.seq
}

fn stale(txn: TxnId, current: u64, got: u64) -> LedgerError {
    LedgerError::StaleEpoch { txn, current, got }
}

impl Ledger {
    /// The ledger invariant, checked: used on a checkpoint read from disk.
    pub fn well_formed(&self) -> (r: bool)
        ensures
            r == inv(*self),
    {
        let n = self.live.entries.len();
        let mut i: usize = 0;
        while i < n
            invariant
                n == self.live.entries@.len(),
                i <= n,
                forall|k: int| 0 <= k < i ==> live_ok(#[trigger] self.live.entries@[k], self.next_txn),
            decreases n - i,
        {
            let x = &self.live.entries[i];
            let ok = x.0.0 == x.1.txn.id.0 && x.1.txn.lease.txn.0 == x.0.0 && x.0.0 < self.next_txn
                && !x.1.txn.state.is_terminal() && recovery_eq(x.1.txn.recovery, x.1.txn.transition.recovery());
            if !ok {
                assert(!live_ok(self.live.entries@[i as int], self.next_txn));
                return false;
            }
            i += 1;
        }
        let mut i: usize = 0;
        while i < n
            invariant
                n == self.live.entries@.len(),
                i <= n,
                forall|a: int, b: int|
                    0 <= a < i && 0 <= b < n && a != b ==> pair_ok(
                        #[trigger] self.live.entries@[a],
                        #[trigger] self.live.entries@[b],
                    ),
            decreases n - i,
        {
            let mut j: usize = 0;
            while j < n
                invariant
                    n == self.live.entries@.len(),
                    i < n,
                    j <= n,
                    forall|a: int, b: int|
                        0 <= a < i && 0 <= b < n && a != b ==> pair_ok(
                            #[trigger] self.live.entries@[a],
                            #[trigger] self.live.entries@[b],
                        ),
                    forall|b: int|
                        0 <= b < j && b != i ==> pair_ok(self.live.entries@[i as int], #[trigger] self.live.entries@[b]),
                decreases n - j,
            {
                if j != i {
                    let a = &self.live.entries[i];
                    let b = &self.live.entries[j];
                    let ok = a.0.0 != b.0.0 && compatible_exec(
                        &a.1.txn.state,
                        a.1.txn.transition.changes_generation(),
                        &b.1.txn.state,
                        b.1.txn.transition.changes_generation(),
                    );
                    if !ok {
                        assert(!pair_ok(self.live.entries@[i as int], self.live.entries@[j as int]));
                        return false;
                    }
                }
                j += 1;
            }
            i += 1;
        }
        true
    }

    #[verifier::loop_isolation(false)]
    pub fn validate(&self, e: &Entry) -> (r: Result<(), LedgerError>)
        ensures
            r is Ok ==> rules(*self, *e),
    {
        if self.last_seq == u64::MAX || e.seq != self.last_seq + 1 {
            return Err(LedgerError::Sequence { expected: self.last_seq.wrapping_add(1), got: e.seq });
        }
        match &e.record {
            Record::Prepared(t) => {
                if find(&self.live, t.id).is_some() || t.id.0 < self.next_txn || t.id.0 == u64::MAX {
                    return Err(LedgerError::DuplicateTxn(t.id));
                }
                let prepared = match t.state {
                    TxnState::Prepared => true,
                    _ => false,
                };
                if !prepared || t.lease.epoch != 1 || t.lease.txn.0 != t.id.0 {
                    return Err(LedgerError::BadPrepared("state Prepared, lease epoch 1 for this txn"));
                }
                if !recovery_eq(t.recovery, t.transition.recovery()) {
                    return Err(LedgerError::BadPrepared("recovery strategy is fixed by the transition"));
                }
                if !self.interlock.entries.is_empty() && is_autonomous(&t.facts.caller) {
                    return Err(LedgerError::Interlocked { txn: t.id });
                }
                Ok(())
            },
            Record::Advance { txn, epoch, to, .. } => {
                let i = match find(&self.live, *txn) {
                    Some(i) => i,
                    None => return Err(LedgerError::NotLive(*txn)),
                };
                let l = &self.live.entries[i].1;
                if l.txn.lease.epoch != *epoch {
                    return Err(stale(*txn, l.txn.lease.epoch, *epoch));
                }
                if !step_allowed(&l.txn.state, to, l.txn.recovery) {
                    return Err(LedgerError::IllegalStep { txn: *txn, from: tag(&l.txn.state), to: tag(to) });
                }
                if l.txn.state.is_pre_mutation() && !to.is_pre_mutation() && !to.is_terminal() {
                    // Starting to mutate.
                    if !self.interlock.entries.is_empty() && is_autonomous(&l.txn.facts.caller) {
                        return Err(LedgerError::Interlocked { txn: *txn });
                    }
                }
                let mine = l.txn.transition.changes_generation();
                let mut j: usize = 0;
                while j < self.live.entries.len()
                    invariant
                        j <= self.live.entries@.len(),
                        mine == generation(self.live.entries@[i as int].1),
                        forall|k: int|
                            0 <= k < j && k != i ==> compatible(
                                *to,
                                mine,
                                (#[trigger] self.live.entries@[k]).1.txn.state,
                                generation(self.live.entries@[k].1),
                            ),
                    decreases self.live.entries.len() - j,
                {
                    let o = &self.live.entries[j].1;
                    if j != i && !compatible_exec(to, mine, &o.txn.state, o.txn.transition.changes_generation()) {
                        return Err(LedgerError::Exclusive { txn: *txn, blocker: o.txn.id });
                    }
                    j += 1;
                }
                assert(advance_ok(*self, i as int, *epoch, *to));
                Ok(())
            },
            Record::Takeover { txn, from_epoch, lease } => {
                let i = match find(&self.live, *txn) {
                    Some(i) => i,
                    None => return Err(LedgerError::NotLive(*txn)),
                };
                let l = &self.live.entries[i].1;
                if l.txn.lease.epoch != *from_epoch {
                    return Err(stale(*txn, l.txn.lease.epoch, *from_epoch));
                }
                if lease.epoch <= *from_epoch || lease.txn.0 != txn.0 {
                    return Err(stale(*txn, *from_epoch, lease.epoch));
                }
                Ok(())
            },
            Record::Renew { txn, epoch, .. } => {
                let i = match find(&self.live, *txn) {
                    Some(i) => i,
                    None => return Err(LedgerError::NotLive(*txn)),
                };
                let l = &self.live.entries[i].1;
                if l.txn.lease.epoch != *epoch {
                    return Err(stale(*txn, l.txn.lease.epoch, *epoch));
                }
                Ok(())
            },
            Record::OpBegin { op, .. } => {
                let i = match find(&self.live, op.txn) {
                    Some(i) => i,
                    None => return Err(LedgerError::NotLive(op.txn)),
                };
                let l = &self.live.entries[i].1;
                if l.txn.lease.epoch != op.epoch {
                    return Err(stale(op.txn, l.txn.lease.epoch, op.epoch));
                }
                let mut k: usize = 0;
                while k < l.ops.len()
                    invariant
                        k <= l.ops@.len(),
                        forall|m: int| 0 <= m < k ==> (#[trigger] l.ops@[m]).op != *op,
                    decreases l.ops.len() - k,
                {
                    if op_eq(l.ops[k].op, *op) {
                        return Err(LedgerError::DuplicateOp(*op));
                    }
                    k += 1;
                }
                Ok(())
            },
            Record::OpAck { op, .. } => {
                let i = match find(&self.live, op.txn) {
                    Some(i) => i,
                    None => return Err(LedgerError::NotLive(op.txn)),
                };
                let l = &self.live.entries[i].1;
                let mut k: usize = 0;
                while k < l.ops.len()
                    invariant
                        k <= l.ops@.len(),
                    decreases l.ops.len() - k,
                {
                    if op_eq(l.ops[k].op, *op) {
                        return match &l.ops[k].ack {
                            None => {
                                assert(self.live.entries@[i as int].1.ops@[k as int].op == *op);
                                Ok(())
                            },
                            Some(_) => Err(LedgerError::DuplicateOp(*op)),
                        };
                    }
                    k += 1;
                }
                Err(LedgerError::UnknownOp(*op))
            },
            Record::Resolved { txn, .. } => {
                if find(&self.interlock, *txn).is_none() {
                    return Err(LedgerError::NotInterlocked(*txn));
                }
                Ok(())
            },
            Record::ExternalAccepted { seq, .. } => match self.external {
                Some((have, _)) if *seq <= have => Err(LedgerError::ExternalReplay { have, got: *seq }),
                _ => Ok(()),
            },
            _ => Ok(()),
        }
    }
}

fn recovery_eq(a: planarian_schema::RecoveryStrategy, b: planarian_schema::RecoveryStrategy) -> (r: bool)
    ensures
        r == (a == b),
{
    use planarian_schema::RecoveryStrategy as R;
    match (a, b) {
        (R::ReobserveOnly, R::ReobserveOnly) => true,
        (R::RevertGeneration, R::RevertGeneration) => true,
        (R::UnbindDevice, R::UnbindDevice) => true,
        (R::RestoreSnapshotThenRevert, R::RestoreSnapshotThenRevert) => true,
        _ => false,
    }
}

/// The transaction a record marks RecoveryFailed, if it does.
pub open spec fn fails(r: Record) -> Option<TxnId> {
    match r {
        Record::Advance { txn, to: TxnState::RecoveryFailed, .. } => Some(txn),
        _ => None,
    }
}

/// No live transaction's lease epoch went down (I15: epochs only grow).
pub open spec fn epochs_grow(a: Ledger, b: Ledger) -> bool {
    forall|i: int, j: int|
        0 <= i < a.live.entries@.len() && 0 <= j < b.live.entries@.len() && (#[trigger] a.live.entries@[i]).0
            == (#[trigger] b.live.entries@[j]).0 ==> a.live.entries@[i].1.txn.lease.epoch
            <= b.live.entries@[j].1.txn.lease.epoch
}

// Bookkeeping no invariant reads. Unverified: each touches only the field it
// is given (docs/assumptions.md).

#[verifier::external_body]
fn push_tag(path: &mut Vec<String>, s: &TxnState) {
    path.push(tag(s).into());
}

#[verifier::external_body]
fn tag_string(s: &TxnState) -> String {
    tag(s).into()
}

#[verifier::external_body]
fn note_why(why: &mut String, note: &String) {
    if !note.is_empty() && !note.starts_with("observed: ") && !note.starts_with("Succeeded") {
        *why = note.clone();
    }
}

#[verifier::external_body]
fn archive(terminal: &mut BTreeMap<TxnId, TerminalTxn>, id: TxnId, l: LiveTxn) {
    terminal.insert(
        id,
        TerminalTxn {
            state: l.txn.state,
            epoch: l.txn.lease.epoch,
            owner: l.txn.lease.owner,
            path: l.path,
            transition: l.txn.transition,
            why: l.why,
        },
    );
    while terminal.len() > TERMINAL_KEEP {
        let oldest = *terminal.keys().next().expect("non-empty");
        terminal.remove(&oldest);
    }
}

#[verifier::external_body]
fn set_override(list: &mut Vec<Override>, s: Override) {
    list.retain(|x| x.unit != s.unit);
    list.push(s);
}

#[verifier::external_body]
fn lift_override(list: &mut Vec<Override>, u: &UnitId) {
    list.retain(|x| &x.unit != u);
}

#[verifier::external_body]
fn record_incident(incidents: &mut BTreeMap<IncidentId, Incident>, i: Incident) {
    if i.state == planarian_schema::IncidentState::Closed {
        incidents.remove(&i.id);
    } else {
        incidents.insert(i.id, i);
    }
}

#[verifier::external_body]
fn use_token(tokens: &mut Vec<([u8; 16], Timestamp)>, at: Timestamp, nonce: [u8; 16], expires: Timestamp) {
    tokens.retain(|(_, exp)| *exp > at);
    tokens.push((nonce, expires));
}

/// Insert or replace, keeping the entries sorted by id.
fn put<V>(m: &mut IdMap<V>, id: TxnId, v: V)
    ensures
        has_id(final(m).entries@, id),
{
    match find(m, id) {
        Some(i) => {
            m.entries.remove(i);
            m.entries.insert(i, (id, v));
            assert(final(m).entries@[i as int].0 == id);
        },
        None => {
            let mut p: usize = 0;
            while p < m.entries.len() && m.entries[p].0.0 < id.0
                invariant
                    p <= m.entries@.len(),
                decreases m.entries.len() - p,
            {
                p += 1;
            }
            m.entries.insert(p, (id, v));
            assert(final(m).entries@[p as int].0 == id);
        },
    }
}

/// Under the invariant, ids identify live transactions.
proof fn lemma_unique_index(l: Ledger, i: int, j: int)
    requires
        inv(l),
        0 <= i < l.live.entries@.len(),
        0 <= j < l.live.entries@.len(),
        l.live.entries@[i].0 == l.live.entries@[j].0,
    ensures
        i == j,
{
    if i != j {
        assert(pair_ok(l.live.entries@[i], l.live.entries@[j]));
    }
}

impl Ledger {
    /// Validate, then apply. The record is consumed: the ledger keeps its parts.
    pub fn apply(&mut self, e: Entry) -> (r: Result<(), LedgerError>)
        ensures
            r is Ok ==> rules(*old(self), e),
            r is Err ==> *final(self) == *old(self),
            r is Ok ==> final(self).last_seq == e.seq,
            (r is Ok && inv(*old(self))) ==> inv(*final(self)),
            (r is Ok && inv(*old(self))) ==> epochs_grow(*old(self), *final(self)),
            (r is Ok && fails(e.record) is Some) ==> has_id(final(self).interlock.entries@, fails(e.record)->Some_0),
    {
        match self.validate(&e) {
            Err(x) => return Err(x),
            Ok(()) => {},
        }
        self.apply_valid(e);
        Ok(())
    }

    /// Mark a transaction RecoveryFailed from the sentinel, when the journal
    /// itself could not take the record (§12c).
    pub fn add_interlock(&mut self, entry: InterlockEntry)
        ensures
            inv(*old(self)) ==> inv(*final(self)),
            has_id(final(self).interlock.entries@, entry.txn),
    {
        let id = entry.txn;
        put(&mut self.interlock, id, entry);
    }

    fn apply_valid(&mut self, e: Entry)
        requires
            rules(*old(self), e),
        ensures
            final(self).last_seq == e.seq,
            inv(*old(self)) ==> inv(*final(self)),
            inv(*old(self)) ==> epochs_grow(*old(self), *final(self)),
            fails(e.record) is Some ==> has_id(final(self).interlock.entries@, fails(e.record)->Some_0),
    {
        self.last_seq = e.seq;
        let at = e.at;
        match e.record {
            Record::Prepared(t) => self.apply_prepared(*t),
            Record::Advance { txn, epoch, to, note } => self.apply_advance(txn, epoch, to, note),
            Record::Takeover { txn, from_epoch, lease } => self.apply_takeover(txn, from_epoch, lease),
            Record::Renew { txn, epoch, worker_pid, boot_at } => self.apply_renew(txn, epoch, boot_at, worker_pid),
            Record::OpBegin { op, call } => self.apply_op_begin(op, call),
            Record::OpAck { op, outcome } => self.apply_op_ack(op, outcome),
            Record::OverrideSet(s) => set_override(&mut self.overrides, s),
            Record::OverrideLifted(u) => lift_override(&mut self.overrides, &u),
            Record::Incident(i) => record_incident(&mut self.incidents, i),
            Record::KnownGood(g) => self.known_good = Some(g),
            Record::LiveTested(g) => self.live_tested = g,
            Record::AcceptedBaseline(g) => self.accepted_baseline = g,
            Record::SecurityFloor(g) => self.security_floor = g,
            Record::ExternalAccepted { seq, digest } => self.external = Some((seq, digest)),
            Record::TokenUsed { nonce, expires, .. } => use_token(&mut self.tokens_used, at, nonce, expires),
            Record::Resolved { txn, .. } => {
                if let Some(k) = find(&self.interlock, txn) {
                    self.interlock.entries.remove(k);
                }
            },
            Record::Reconciliation(r) => self.last_reconciliation = Some(r),
            Record::AgentStarted { name, instance, by } => self.agents.push((name, instance, by)),
        }
    }

    fn apply_prepared(&mut self, t: Transaction)
        requires
            prepared_rule(*old(self), t),
        ensures
            final(self).last_seq == old(self).last_seq,
            inv(*old(self)) ==> inv(*final(self)),
            inv(*old(self)) ==> epochs_grow(*old(self), *final(self)),
    {
        let ghost pre = *self;
        let id = t.id;
        self.next_txn = id.0 + 1;
        let mut path = Vec::new();
        push_tag(&mut path, &t.state);
        let why = String::new();
        self.live.entries.push((id, LiveTxn { txn: t, ops: Vec::new(), path, why }));
        proof {
            let n = pre.live.entries@.len();
            assert(self.live.entries@ =~= pre.live.entries@.push(self.live.entries@[n as int]));
            if inv(pre) {
                lemma_push(pre, *self);
            }
        }
    }

    #[allow(unused_variables)] // used in the specification
    fn apply_advance(&mut self, txn: TxnId, epoch: u64, to: TxnState, note: String)
        requires
            advance_rule(*old(self), txn, epoch, to),
        ensures
            final(self).last_seq == old(self).last_seq,
            inv(*old(self)) ==> inv(*final(self)),
            inv(*old(self)) ==> epochs_grow(*old(self), *final(self)),
            to == TxnState::RecoveryFailed ==> has_id(final(self).interlock.entries@, txn),
    {
        let ghost pre = *self;
        let i = match find(&self.live, txn) {
            Some(i) => i,
            None => {
                proof {
                    assert(false);
                }
                return;
            },
        };
        proof {
            if inv(pre) {
                let j = choose|j: int|
                    0 <= j < pre.live.entries@.len() && (#[trigger] pre.live.entries@[j]).0 == txn && advance_ok(
                        pre,
                        j,
                        epoch,
                        to,
                    );
                lemma_unique_index(pre, i as int, j);
            }
        }
        let (id, mut l) = self.live.entries.remove(i);
        let failed = match to {
            TxnState::RecoveryFailed => true,
            _ => false,
        };
        if failed {
            let entry = InterlockEntry {
                txn,
                transition: l.txn.transition.clone(),
                failed_from: tag_string(&l.txn.state),
                base_override: l.txn.base_override,
                candidate_override: l.txn.candidate_override,
                revert_to: l.txn.revert_to,
                note: note.clone(),
            };
            put(&mut self.interlock, txn, entry);
        }
        push_tag(&mut l.path, &to);
        note_why(&mut l.why, &note);
        l.txn.state = to;
        if l.txn.state.is_terminal() {
            archive(&mut self.terminal, id, l);
            proof {
                assert(self.live.entries@ =~= pre.live.entries@.remove(i as int));
                if inv(pre) {
                    lemma_remove(pre, *self, i as int);
                }
            }
        } else {
            self.live.entries.insert(i, (id, l));
            proof {
                assert(self.live.entries@ =~= pre.live.entries@.update(i as int, self.live.entries@[i as int]));
                if inv(pre) {
                    let x = pre.live.entries@[i as int].1;
                    let y = self.live.entries@[i as int].1;
                    assert(generation(y) == generation(x));
                    lemma_update(pre, *self, i as int);
                }
            }
        }
    }

    #[allow(unused_variables)] // used in the specification
    fn apply_takeover(&mut self, txn: TxnId, from_epoch: u64, lease: Lease)
        requires
            takeover_rule(*old(self), txn, from_epoch, lease),
        ensures
            final(self).last_seq == old(self).last_seq,
            inv(*old(self)) ==> inv(*final(self)),
            inv(*old(self)) ==> epochs_grow(*old(self), *final(self)),
    {
        let ghost pre = *self;
        let i = match find(&self.live, txn) {
            Some(i) => i,
            None => {
                proof {
                    assert(false);
                }
                return;
            },
        };
        proof {
            if inv(pre) {
                let j = choose|j: int|
                    0 <= j < pre.live.entries@.len() && (#[trigger] pre.live.entries@[j]).0 == txn
                        && pre.live.entries@[j].1.txn.lease.epoch == from_epoch && lease.epoch > from_epoch
                        && lease.txn == txn;
                lemma_unique_index(pre, i as int, j);
            }
        }
        let (id, mut l) = self.live.entries.remove(i);
        l.txn.lease = lease;
        self.live.entries.insert(i, (id, l));
        proof {
            assert(self.live.entries@ =~= pre.live.entries@.update(i as int, self.live.entries@[i as int]));
            if inv(pre) {
                lemma_update(pre, *self, i as int);
            }
        }
    }

    #[allow(unused_variables)] // used in the specification
    fn apply_renew(&mut self, txn: TxnId, epoch: u64, at: Timestamp, worker_pid: Option<u32>)
        requires
            renew_rule(*old(self), txn, epoch),
        ensures
            final(self).last_seq == old(self).last_seq,
            inv(*old(self)) ==> inv(*final(self)),
            inv(*old(self)) ==> epochs_grow(*old(self), *final(self)),
    {
        let ghost pre = *self;
        let i = match find(&self.live, txn) {
            Some(i) => i,
            None => {
                proof {
                    assert(false);
                }
                return;
            },
        };
        let (id, mut l) = self.live.entries.remove(i);
        l.txn.lease.renewed = at;
        l.txn.lease.worker_pid = worker_pid;
        self.live.entries.insert(i, (id, l));
        proof {
            assert(self.live.entries@ =~= pre.live.entries@.update(i as int, self.live.entries@[i as int]));
            if inv(pre) {
                lemma_update(pre, *self, i as int);
            }
        }
    }

    fn apply_op_begin(&mut self, op: OpId, call: String)
        requires
            op_begin_rule(*old(self), op),
        ensures
            final(self).last_seq == old(self).last_seq,
            inv(*old(self)) ==> inv(*final(self)),
            inv(*old(self)) ==> epochs_grow(*old(self), *final(self)),
    {
        let ghost pre = *self;
        let i = match find(&self.live, op.txn) {
            Some(i) => i,
            None => {
                proof {
                    assert(false);
                }
                return;
            },
        };
        let (id, mut l) = self.live.entries.remove(i);
        l.ops.push(OpRecord { op, call, ack: None });
        self.live.entries.insert(i, (id, l));
        proof {
            assert(self.live.entries@ =~= pre.live.entries@.update(i as int, self.live.entries@[i as int]));
            if inv(pre) {
                lemma_update(pre, *self, i as int);
            }
        }
    }

    fn apply_op_ack(&mut self, op: OpId, outcome: Outcome)
        requires
            op_ack_rule(*old(self), op),
        ensures
            final(self).last_seq == old(self).last_seq,
            inv(*old(self)) ==> inv(*final(self)),
            inv(*old(self)) ==> epochs_grow(*old(self), *final(self)),
    {
        let ghost pre = *self;
        let i = match find(&self.live, op.txn) {
            Some(i) => i,
            None => {
                proof {
                    assert(false);
                }
                return;
            },
        };
        let (id, mut l) = self.live.entries.remove(i);
        let ghost before = l;
        let mut k: usize = 0;
        while k < l.ops.len()
            invariant
                k <= l.ops@.len(),
                l.txn == before.txn,
            decreases l.ops.len() - k,
        {
            if op_eq(l.ops[k].op, op) {
                let mut o = l.ops.remove(k);
                o.ack = Some(outcome);
                l.ops.insert(k, o);
                break;
            }
            k += 1;
        }
        self.live.entries.insert(i, (id, l));
        proof {
            assert(self.live.entries@ =~= pre.live.entries@.update(i as int, self.live.entries@[i as int]));
            if inv(pre) {
                lemma_update(pre, *self, i as int);
            }
        }
    }
}

/// I6, as SPEC §7 states it, from the invariant: of two live generation
/// transactions at most one is active (in flight, or waiting in `Built`);
/// and while a generation transaction is in flight other than awaiting a
/// boot, no other transaction is in flight.
pub proof fn i6_one_generation_active(l: Ledger, a: int, b: int)
    requires
        inv(l),
        0 <= a < l.live.entries@.len(),
        0 <= b < l.live.entries@.len(),
        a != b,
    ensures
        ({
            let x = l.live.entries@[a].1;
            let y = l.live.entries@[b].1;
            &&& (generation(x) && generation(y)) ==> !((flying(x.txn.state) || x.txn.state is Built) && (flying(
                y.txn.state,
            ) || y.txn.state is Built))
            &&& (generation(x) && flying(x.txn.state) && !(x.txn.state is AwaitingBoot)) ==> !flying(y.txn.state)
        }),
{
    assert(pair_ok(l.live.entries@[a], l.live.entries@[b]));
}

/// Changing one live transaction keeps the invariant when its id, its
/// lease's transaction, its transition and recovery stay, its epoch does not
/// drop, and its state stays or is compatible with every other live
/// transaction, as `advance_ok` requires (I6).
proof fn lemma_update(pre: Ledger, post: Ledger, i: int)
    requires
        inv(pre),
        0 <= i < pre.live.entries@.len(),
        post.next_txn == pre.next_txn,
        post.live.entries@ == pre.live.entries@.update(i, post.live.entries@[i]),
        live_ok(post.live.entries@[i], post.next_txn),
        post.live.entries@[i].0 == pre.live.entries@[i].0,
        generation(post.live.entries@[i].1) == generation(pre.live.entries@[i].1),
        post.live.entries@[i].1.txn.lease.epoch >= pre.live.entries@[i].1.txn.lease.epoch,
        post.live.entries@[i].1.txn.state == pre.live.entries@[i].1.txn.state || forall|j: int|
            0 <= j < pre.live.entries@.len() && j != i ==> compatible(
                post.live.entries@[i].1.txn.state,
                generation(post.live.entries@[i].1),
                (#[trigger] pre.live.entries@[j]).1.txn.state,
                generation(pre.live.entries@[j].1),
            ),
    ensures
        inv(post),
        epochs_grow(pre, post),
{
    let a = pre.live.entries@;
    let b = post.live.entries@;
    assert forall|x: int, y: int| 0 <= x < b.len() && 0 <= y < b.len() && x != y implies pair_ok(
        #[trigger] b[x],
        #[trigger] b[y],
    ) by {
        assert(pair_ok(a[x], a[y]));
        if x == i {
            assert(pair_ok(a[i], a[y]));
        } else if y == i {
            assert(pair_ok(a[x], a[i]));
        }
    }
    assert forall|x: int| 0 <= x < b.len() implies live_ok(#[trigger] b[x], post.next_txn) by {
        if x != i {
            assert(live_ok(a[x], pre.next_txn));
        }
    }
    assert forall|x: int, y: int| 0 <= x < a.len() && 0 <= y < b.len() && (#[trigger] a[x]).0 == (#[trigger] b[y]).0 implies a[x].1.txn.lease.epoch <= b[y].1.txn.lease.epoch by {
        lemma_unique_index(pre, x, y);
    }
}

/// Removing a live transaction keeps the invariant.
proof fn lemma_remove(pre: Ledger, post: Ledger, i: int)
    requires
        inv(pre),
        0 <= i < pre.live.entries@.len(),
        post.next_txn == pre.next_txn,
        post.live.entries@ == pre.live.entries@.remove(i),
    ensures
        inv(post),
        epochs_grow(pre, post),
{
    let a = pre.live.entries@;
    let b = post.live.entries@;
    assert forall|x: int| 0 <= x < b.len() implies #[trigger] b[x] == a[if x < i { x } else { x + 1 }] by {}
    assert forall|x: int, y: int| 0 <= x < b.len() && 0 <= y < b.len() && x != y implies pair_ok(
        #[trigger] b[x],
        #[trigger] b[y],
    ) by {
        let x2 = if x < i { x } else { x + 1 };
        let y2 = if y < i { y } else { y + 1 };
        assert(pair_ok(a[x2], a[y2]));
    }
    assert forall|x: int| 0 <= x < b.len() implies live_ok(#[trigger] b[x], post.next_txn) by {
        let x2 = if x < i { x } else { x + 1 };
        assert(live_ok(a[x2], pre.next_txn));
    }
    assert forall|x: int, y: int| 0 <= x < a.len() && 0 <= y < b.len() && (#[trigger] a[x]).0 == (#[trigger] b[y]).0 implies a[x].1.txn.lease.epoch <= b[y].1.txn.lease.epoch by {
        let y2 = if y < i { y } else { y + 1 };
        lemma_unique_index(pre, x, y2);
    }
}

/// Adding a newly Prepared transaction keeps the invariant.
proof fn lemma_push(pre: Ledger, post: Ledger)
    requires
        inv(pre),
        post.live.entries@.len() == pre.live.entries@.len() + 1,
        post.live.entries@ == pre.live.entries@.push(post.live.entries@[pre.live.entries@.len() as int]),
        post.next_txn > pre.next_txn,
        ({
            let x = post.live.entries@[pre.live.entries@.len() as int];
            &&& live_ok(x, post.next_txn)
            &&& x.1.txn.state is Prepared
            &&& x.0.0 >= pre.next_txn
        }),
    ensures
        inv(post),
        epochs_grow(pre, post),
{
    let a = pre.live.entries@;
    let b = post.live.entries@;
    let n = a.len() as int;
    assert forall|x: int| 0 <= x < b.len() implies live_ok(#[trigger] b[x], post.next_txn) by {
        if x < n {
            assert(live_ok(a[x], pre.next_txn));
        }
    }
    assert forall|x: int, y: int| 0 <= x < b.len() && 0 <= y < b.len() && x != y implies pair_ok(
        #[trigger] b[x],
        #[trigger] b[y],
    ) by {
        if x < n && y < n {
            assert(pair_ok(a[x], a[y]));
        } else if x < n {
            assert(live_ok(a[x], pre.next_txn));
        } else {
            assert(live_ok(a[y], pre.next_txn));
        }
    }
    assert forall|x: int, y: int| 0 <= x < a.len() && 0 <= y < b.len() && (#[trigger] a[x]).0 == (#[trigger] b[y]).0 implies a[x].1.txn.lease.epoch <= b[y].1.txn.lease.epoch by {
        if y < n {
            lemma_unique_index(pre, x, y);
        } else {
            assert(live_ok(a[x], pre.next_txn));
        }
    }
}

} // verus!

pub const TERMINAL_KEEP: usize = 256;

impl Ledger {
    pub fn epoch(&self, txn: TxnId) -> Option<u64> {
        self.live.get(&txn).map(|l| l.txn.lease.epoch).or_else(|| self.terminal.get(&txn).map(|t| t.epoch))
    }

    pub fn state(&self, txn: TxnId) -> Option<TxnState> {
        self.live.get(&txn).map(|l| l.txn.state.clone()).or_else(|| self.terminal.get(&txn).map(|t| t.state.clone()))
    }

    pub fn path(&self, txn: TxnId) -> Option<&[String]> {
        self.live.get(&txn).map(|l| &l.path[..]).or_else(|| self.terminal.get(&txn).map(|t| &t.path[..]))
    }

    pub fn interlocked(&self) -> bool {
        !self.interlock.is_empty()
    }

    /// The uid the agent `name`'s running `instance` acts for (§11, I24):
    /// the start that journaled that very instance under that name. A zero
    /// instance matches nothing.
    pub fn agent_for(&self, name: &str, instance: [u8; 16]) -> Option<u32> {
        if instance == [0; 16] {
            return None;
        }
        self.agents.iter().rev().find(|(n, i, _)| *i == instance && n == name).map(|(_, _, by)| *by)
    }

    /// Who started the last instance under `name`, for a refusal's message.
    pub fn agent_owner(&self, name: &str) -> Option<u32> {
        self.agents.iter().rev().find(|(n, _, _)| n == name).map(|(_, _, by)| *by)
    }
}

impl LiveTxn {
    pub fn unacked_ops(&self) -> impl Iterator<Item = &OpRecord> {
        self.ops.iter().filter(|o| o.ack.is_none())
    }
}

impl<V> Default for IdMap<V> {
    fn default() -> Self {
        IdMap { entries: Vec::new() }
    }
}

impl<V> IdMap<V> {
    fn find_index(&self, id: &TxnId) -> Result<usize, usize> {
        self.entries.binary_search_by(|(k, _)| k.cmp(id))
    }

    pub fn get(&self, id: &TxnId) -> Option<&V> {
        self.find_index(id).ok().map(|i| &self.entries[i].1)
    }

    pub fn contains_key(&self, id: &TxnId) -> bool {
        self.find_index(id).is_ok()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn keys(&self) -> impl DoubleEndedIterator<Item = &TxnId> {
        self.entries.iter().map(|(k, _)| k)
    }

    pub fn values(&self) -> impl DoubleEndedIterator<Item = &V> {
        self.entries.iter().map(|(_, v)| v)
    }

    pub fn iter(&self) -> impl DoubleEndedIterator<Item = (&TxnId, &V)> {
        self.entries.iter().map(|(k, v)| (k, v))
    }
}

impl<V> std::ops::Index<&TxnId> for IdMap<V> {
    type Output = V;

    fn index(&self, id: &TxnId) -> &V {
        self.get(id).expect("no entry for this transaction")
    }
}

impl<V: Serialize> Serialize for IdMap<V> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_map(self.iter())
    }
}

impl<'de, V: Deserialize<'de>> Deserialize<'de> for IdMap<V> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        // A BTreeMap is already sorted and unique.
        Ok(IdMap { entries: BTreeMap::<TxnId, V>::deserialize(d)?.into_iter().collect() })
    }
}
