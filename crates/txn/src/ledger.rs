//! Journal records and the ledger they build (§12, §12c).
//!
//! The ledger is the live state the journal establishes. A checkpoint is the
//! serialized ledger, so replaying (checkpoint + tail) and replaying the full
//! history produce equal ledgers by construction.
//!
//! `validate` runs before a record is written (write-ahead) and again on
//! replay. It enforces I6, I15 and the recovery interlock at the journal
//! itself, so no caller can journal a step that breaks them.

use crate::machine::{step_allowed, tag};
use planarian_schema::{
    Actor, GenerationId, Hash, Incident, IncidentId, Lease, OpId, Outcome, OwnerId, Resolution, Suppression, Timestamp,
    Transaction, Transition, TxnId, TxnState, UnitId,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub seq: u64,
    pub at: Timestamp,
    pub record: Record,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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
    Suppressed(Suppression),
    Unsuppressed(UnitId),
    Incident(Incident),
    KnownGood(GenerationId),
    LiveTested(Option<GenerationId>),
    AcceptedBaseline(Option<GenerationId>),
    TokenUsed {
        nonce: [u8; 16],
        expires: Timestamp,
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
pub struct Reconciliation {
    pub by: OwnerId,
    pub found: Vec<(TxnId, TxnState)>,
    pub actions: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpRecord {
    pub op: OpId,
    pub call: String,
    pub ack: Option<Outcome>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiveTxn {
    pub txn: Transaction,
    pub ops: Vec<OpRecord>,
    /// Journal states this transaction has passed through, in order.
    pub path: Vec<String>,
}

impl LiveTxn {
    pub fn unacked_ops(&self) -> impl Iterator<Item = &OpRecord> {
        self.ops.iter().filter(|o| o.ack.is_none())
    }
}

/// What remains of a terminal transaction: enough to refuse stale epochs and
/// to show the outcome. Bounded to the most recent `TERMINAL_KEEP`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TerminalTxn {
    pub state: TxnState,
    pub epoch: u64,
    pub owner: OwnerId,
    pub path: Vec<String>,
    pub transition: Transition,
}

pub const TERMINAL_KEEP: usize = 256;

/// An unresolved RecoveryFailed (§12c). While any exists, autonomous mutation is blocked.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterlockEntry {
    pub txn: TxnId,
    pub transition: Transition,
    pub failed_from: String,
    pub base_override: Option<Hash>,
    pub candidate_override: Option<Hash>,
    pub revert_to: GenerationId,
    pub note: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ledger {
    pub last_seq: u64,
    pub next_txn: u64,
    pub live: BTreeMap<TxnId, LiveTxn>,
    pub terminal: BTreeMap<TxnId, TerminalTxn>,
    pub suppressions: Vec<Suppression>,
    pub incidents: BTreeMap<IncidentId, Incident>,
    pub tokens_used: Vec<([u8; 16], Timestamp)>,
    pub known_good: Option<GenerationId>,
    pub live_tested: Option<GenerationId>,
    pub accepted_baseline: Option<GenerationId>,
    pub interlock: BTreeMap<TxnId, InterlockEntry>,
    pub last_reconciliation: Option<Reconciliation>,
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
        from: String,
        to: String,
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
    BadPrepared(String),
}

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

    fn autonomous(caller: &Actor) -> bool {
        !matches!(caller, Actor::User { .. })
    }

    /// Transactions past Prepared and not yet terminal: the ones that hold the
    /// machine (§12 concurrency).
    fn in_flight(&self) -> impl Iterator<Item = &LiveTxn> {
        self.live.values().filter(|l| !l.txn.state.is_pre_mutation())
    }

    pub fn validate(&self, e: &Entry) -> Result<(), LedgerError> {
        if e.seq != self.last_seq + 1 {
            return Err(LedgerError::Sequence { expected: self.last_seq + 1, got: e.seq });
        }
        match &e.record {
            Record::Prepared(t) => {
                if self.live.contains_key(&t.id) || self.terminal.contains_key(&t.id) || t.id.0 < self.next_txn {
                    return Err(LedgerError::DuplicateTxn(t.id));
                }
                if t.state != TxnState::Prepared || t.lease.epoch != 1 || t.lease.txn != t.id {
                    return Err(LedgerError::BadPrepared("state Prepared, lease epoch 1 for this txn".into()));
                }
                if t.recovery != t.transition.recovery() {
                    return Err(LedgerError::BadPrepared("recovery strategy is fixed by the transition".into()));
                }
                if self.interlocked() && Self::autonomous(&t.facts.caller) {
                    return Err(LedgerError::Interlocked { txn: t.id });
                }
            }
            Record::Advance { txn, epoch, to, .. } => {
                let l = self.live.get(txn).ok_or(LedgerError::NotLive(*txn))?;
                self.check_epoch(l, *epoch)?;
                if !step_allowed(&l.txn.state, to, l.txn.recovery) {
                    return Err(LedgerError::IllegalStep {
                        txn: *txn,
                        from: tag(&l.txn.state).into(),
                        to: tag(to).into(),
                    });
                }
                if l.txn.state.is_pre_mutation() && !to.is_pre_mutation() && !to.is_terminal() {
                    // Starting to mutate.
                    if self.interlocked() && Self::autonomous(&l.txn.facts.caller) {
                        return Err(LedgerError::Interlocked { txn: *txn });
                    }
                    let mine = l.txn.transition.changes_generation();
                    for other in self.in_flight().filter(|o| o.txn.id != *txn) {
                        if mine || other.txn.transition.changes_generation() {
                            return Err(LedgerError::Exclusive { txn: *txn, blocker: other.txn.id });
                        }
                    }
                }
            }
            Record::Takeover { txn, from_epoch, lease } => {
                let l = self.live.get(txn).ok_or(LedgerError::NotLive(*txn))?;
                self.check_epoch(l, *from_epoch)?;
                if lease.epoch <= *from_epoch || lease.txn != *txn {
                    return Err(LedgerError::StaleEpoch { txn: *txn, current: *from_epoch, got: lease.epoch });
                }
            }
            Record::Renew { txn, epoch, .. } => {
                let l = self.live.get(txn).ok_or(LedgerError::NotLive(*txn))?;
                self.check_epoch(l, *epoch)?;
            }
            Record::OpBegin { op, .. } => {
                let l = self.live.get(&op.txn).ok_or(LedgerError::NotLive(op.txn))?;
                self.check_epoch(l, op.epoch)?;
                if l.ops.iter().any(|o| o.op == *op) {
                    return Err(LedgerError::DuplicateOp(*op));
                }
            }
            Record::OpAck { op, .. } => {
                let l = self.live.get(&op.txn).ok_or(LedgerError::NotLive(op.txn))?;
                match l.ops.iter().find(|o| o.op == *op) {
                    Some(o) if o.ack.is_none() => {}
                    Some(_) => return Err(LedgerError::DuplicateOp(*op)),
                    None => return Err(LedgerError::UnknownOp(*op)),
                }
            }
            Record::Resolved { txn, .. } => {
                if !self.interlock.contains_key(txn) {
                    return Err(LedgerError::NotInterlocked(*txn));
                }
            }
            Record::Suppressed(_)
            | Record::Unsuppressed(_)
            | Record::Incident(_)
            | Record::KnownGood(_)
            | Record::LiveTested(_)
            | Record::AcceptedBaseline(_)
            | Record::TokenUsed { .. }
            | Record::Reconciliation(_) => {}
        }
        Ok(())
    }

    fn check_epoch(&self, l: &LiveTxn, got: u64) -> Result<(), LedgerError> {
        if l.txn.lease.epoch != got {
            return Err(LedgerError::StaleEpoch { txn: l.txn.id, current: l.txn.lease.epoch, got });
        }
        Ok(())
    }

    /// Validate, then apply.
    pub fn apply(&mut self, e: &Entry) -> Result<(), LedgerError> {
        self.validate(e)?;
        self.apply_valid(e);
        Ok(())
    }

    fn apply_valid(&mut self, e: &Entry) {
        self.last_seq = e.seq;
        match &e.record {
            Record::Prepared(t) => {
                self.next_txn = t.id.0 + 1;
                self.live.insert(t.id, LiveTxn { txn: (**t).clone(), ops: vec![], path: vec![tag(&t.state).into()] });
            }
            Record::Advance { txn, to, note, .. } => {
                let l = self.live.get_mut(txn).expect("validated");
                let from = tag(&l.txn.state);
                l.txn.state = to.clone();
                l.path.push(tag(to).into());
                if *to == TxnState::RecoveryFailed {
                    self.interlock.insert(
                        *txn,
                        InterlockEntry {
                            txn: *txn,
                            transition: l.txn.transition.clone(),
                            failed_from: from.into(),
                            base_override: l.txn.base_override,
                            candidate_override: l.txn.candidate_override,
                            revert_to: l.txn.revert_to,
                            note: note.clone(),
                        },
                    );
                }
                if to.is_terminal() {
                    let l = self.live.remove(txn).expect("validated");
                    self.terminal.insert(
                        *txn,
                        TerminalTxn {
                            state: l.txn.state,
                            epoch: l.txn.lease.epoch,
                            owner: l.txn.lease.owner,
                            path: l.path,
                            transition: l.txn.transition,
                        },
                    );
                    while self.terminal.len() > TERMINAL_KEEP {
                        let oldest = *self.terminal.keys().next().expect("non-empty");
                        self.terminal.remove(&oldest);
                    }
                }
            }
            Record::Takeover { txn, lease, .. } => {
                self.live.get_mut(txn).expect("validated").txn.lease = lease.clone();
            }
            Record::Renew { txn, worker_pid, .. } => {
                let l = &mut self.live.get_mut(txn).expect("validated").txn.lease;
                l.renewed = e.at;
                l.worker_pid = *worker_pid;
            }
            Record::OpBegin { op, call } => {
                self.live.get_mut(&op.txn).expect("validated").ops.push(OpRecord {
                    op: *op,
                    call: call.clone(),
                    ack: None,
                });
            }
            Record::OpAck { op, outcome } => {
                let l = self.live.get_mut(&op.txn).expect("validated");
                l.ops.iter_mut().find(|o| o.op == *op).expect("validated").ack = Some(outcome.clone());
            }
            Record::Suppressed(s) => {
                self.suppressions.retain(|x| x.unit != s.unit);
                self.suppressions.push(s.clone());
            }
            Record::Unsuppressed(u) => self.suppressions.retain(|x| &x.unit != u),
            Record::Incident(i) => {
                if i.state == planarian_schema::IncidentState::Closed {
                    self.incidents.remove(&i.id);
                } else {
                    self.incidents.insert(i.id, i.clone());
                }
            }
            Record::KnownGood(g) => self.known_good = Some(*g),
            Record::LiveTested(g) => self.live_tested = *g,
            Record::AcceptedBaseline(g) => self.accepted_baseline = *g,
            Record::TokenUsed { nonce, expires } => {
                self.tokens_used.retain(|(_, exp)| *exp > e.at);
                self.tokens_used.push((*nonce, *expires));
            }
            Record::Resolved { txn, .. } => {
                self.interlock.remove(txn);
            }
            Record::Reconciliation(r) => self.last_reconciliation = Some(r.clone()),
        }
    }
}
