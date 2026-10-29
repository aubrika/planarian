//! The executor (SPEC §12): the one path by which anything changes.
//!
//! A `Proposal` from the diagnoser, the intent matcher or a user goes through
//! the steps below, in this order:
//! 1. digest check (`Stale`);
//! 2. caller identity from the socket, overwriting any actor in the proposal;
//! 3. for `ApplyChange`: catalog handler → stage → evaluate → build (read-only);
//! 4. facts derived from the evaluated generation (I14);
//! 5. refinement check of `expected` against `predict`;
//! 6. `policy::decide`;
//! 7. stale check of the owner's source, then `Prepared` (durable);
//! 8. AskFirst parks with a token bound to the concrete candidate, and
//!    approval re-derives everything and compares the binding. Otherwise the
//!    kernel runs it to a terminal state.

#![allow(clippy::result_large_err)] // `Submitted` is the error type on purpose: a refusal is a result.

pub mod derive;
pub mod host;

use derive::{DeriveInput, derive, manifest_of};
use host::ExecHost;
use planarian_changes::CatalogConfig;
use planarian_policy::{Input, Settings, Tables, decide, may_approve, policy_version};
use planarian_schema::spec::{predict, refines};
use planarian_schema::*;
use planarian_state::Canonical;
use planarian_txn::journal::{Journal, JournalError};
use planarian_txn::kernel::{Kernel, KernelError};
use planarian_txn::ledger::{LedgerError, Record};
use planarian_txn::store::Store;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const GENERATION_DEADLINE: Millis = Millis::secs(15 * 60);
pub const NETWORK_DEADLINE: Millis = Millis::secs(90);

#[derive(Clone, Debug)]
pub struct Config {
    pub settings: Settings,
    pub tables: Tables,
    pub catalog: CatalogConfig,
    pub owner: PinnedSource,
    pub canonical: Canonical,
}

/// `Parked` carries the derived facts for display; results are rare and short-lived,
/// so the size difference between variants doesn't matter.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Submitted {
    Rejected {
        reason: RejectReason,
        detail: String,
        digest: Option<Hash>,
    },
    /// AskFirst: waiting for `planarian approve <approve>`.
    Parked {
        txn: TxnId,
        approve: Hash,
        facts: DerivedFacts,
    },
    Finished {
        txn: TxnId,
        state: TxnState,
        followup: Option<Proposal>,
    },
    Error(String),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Parked {
    pub txn: TxnId,
    pub proposal: Proposal,
    pub authz: Authorization,
    /// Who may approve it (the decision's class, §11).
    pub class: ApproverClass,
    pub bound_to: Hash,
    pub issued: Timestamp,
    pub facts: DerivedFacts,
}

/// Everything decided before a transaction exists.
struct Plan {
    transition: Transition,
    facts: DerivedFacts,
    decision: Decision,
    base_eval: EvaluatedGeneration,
    cand_eval: Option<EvaluatedGeneration>,
    built: Option<Built>,
    staged: Option<StagedSource>,
    candidate: Option<(GenerationId, StorePath)>,
    base_override: Option<Hash>,
    candidate_override: Option<Hash>,
}

pub struct Executor<B: Backends + Clone, S: Store> {
    pub kernel: Kernel<S, ExecHost<B>>,
    pub b: B,
    pub cfg: Config,
    pub session: Session,
    pub parked: BTreeMap<TxnId, Parked>,
    /// The derived facts and decision of the last submission that got that
    /// far, for the executor log (I7).
    pub last: Option<(DerivedFacts, Decision)>,
    /// Untracked owner files the last submission's staging left out (§9
    /// step 1: Nix does not see them; they are reported, never an error).
    pub excluded: Vec<String>,
    /// The result of a `PrebuildJob` run off the daemon's core thread; the
    /// next `submit` of the same transition uses it if the live override
    /// file is still the one it was built from.
    pub prebuilt: Option<Prebuilt>,
}

/// What stage, evaluate and build produced for a catalog change.
#[derive(Clone, Debug)]
pub struct Candidate {
    staged: StagedSource,
    eval: EvaluatedGeneration,
    built: Built,
    merged: OverrideSet,
}

/// A `PrebuildJob`'s result.
#[derive(Clone, Debug)]
pub struct Prebuilt {
    transition: Transition,
    live_hash: Hash,
    result: Result<Candidate, Submitted>,
}

/// The slow, pre-journal part of planning a catalog change (§9 steps 1–3:
/// stage, evaluate, build), detached from the executor so the daemon can run
/// it on another thread while its core keeps observing and repairing. It
/// touches no journal: a candidate is only a store path and a GC root until
/// a transaction is prepared for it.
pub struct PrebuildJob<G> {
    gens: G,
    owner: PinnedSource,
    catalog: CatalogConfig,
    transition: Transition,
    live: OverrideSet,
    live_hash: Hash,
}

impl<G: GenerationBackend> PrebuildJob<G> {
    pub fn run(self) -> Prebuilt {
        let result = build_candidate(&self.gens, &self.owner, &self.catalog, &self.transition, &self.live);
        Prebuilt { transition: self.transition, live_hash: self.live_hash, result }
    }
}

fn build_candidate<G: GenerationBackend>(
    gens: &G,
    owner: &PinnedSource,
    catalog: &CatalogConfig,
    transition: &Transition,
    live: &OverrideSet,
) -> Result<Candidate, Submitted> {
    let Transition::ApplyChange { change, args } = transition else {
        return Err(reject(RejectReason::Other("prebuild".into()), "not a catalog change"));
    };
    let set = planarian_changes::handle(catalog, change, args).map_err(|e| match e {
        planarian_changes::CatalogError::NotInCatalog(_) => reject(RejectReason::NotInCatalog, e.to_string()),
        e => reject(RejectReason::Other("arguments".into()), e.to_string()),
    })?;
    let merged = planarian_changes::merge(live, &set);
    let fail = |what: &str, o: Outcome| reject(RejectReason::Other(what.into()), outcome_msg(o));
    let no_space = |what: &str, o: Outcome| {
        if outcome_msg(o.clone()).contains("No space") {
            reject(RejectReason::NoSpace, outcome_msg(o))
        } else {
            fail(what, o)
        }
    };
    let staged = gens.stage(owner, &merged).map_err(|o| no_space("stage", o))?;
    let eval = gens.evaluate(&staged).map_err(|o| fail("evaluate", o))?;
    let built = gens.build(&eval).map_err(|o| no_space("build", o))?;
    Ok(Candidate { staged, eval, built, merged })
}

/// An approval token issued at `issued` has expired by `now` (§12 step 4:
/// 24 hours). Saturating: a token issued near the end of time never expires
/// early, and no clock value makes this panic.
pub fn token_expired(now: Timestamp, issued: Timestamp) -> bool {
    now > issued.plus(TOKEN_LIFETIME)
}

fn reject(reason: RejectReason, detail: impl Into<String>) -> Submitted {
    Submitted::Rejected { reason, detail: detail.into(), digest: None }
}

fn outcome_msg(o: Outcome) -> String {
    match o {
        Outcome::Succeeded => "succeeded".into(),
        Outcome::Failed(m) | Outcome::Partial(m) | Outcome::Unknown(m) => m,
    }
}

impl<B: Backends + Clone, S: Store> Executor<B, S> {
    pub fn new(journal: Journal<S>, b: B, me: OwnerId, cfg: Config) -> Self {
        let host = ExecHost::new(b.clone(), cfg.canonical.clone());
        Executor {
            kernel: Kernel::new(journal, host, me),
            b,
            cfg,
            session: Session::default(),
            parked: BTreeMap::new(),
            last: None,
            excluded: vec![],
            prebuilt: None,
        }
    }

    pub fn policy_version(&self) -> PolicyVersion {
        policy_version(&self.cfg.tables)
    }

    /// At startup: make sure the running generation's override content is
    /// recorded, so a later Rollback to it can restore it.
    pub fn adopt_current(&self) {
        let gens = self.b.generations();
        if let (Ok(g), Ok((set, hash))) = (gens.current(), gens.read_overrides())
            && gens.override_for(g).ok().flatten().is_none()
        {
            let _ = gens.remember_override(&set);
            let _ = gens.record_override(g, &hash);
        }
    }

    /// Keep the probe-run baselines and the GC protected set current.
    pub fn update_context(&mut self, ctx: planarian_state::Context, protect: Vec<GenerationId>) {
        *self.kernel.host.ctx.lock().unwrap_or_else(|e| e.into_inner()) = ctx;
        *self.kernel.host.protect.lock().unwrap_or_else(|e| e.into_inner()) = protect;
    }

    fn eval_of(&self, g: GenerationId) -> Result<EvaluatedGeneration, String> {
        let gens = self.b.generations();
        let path = gens.path_of(g).map_err(outcome_msg)?;
        gens.evaluate_built(&path).map_err(outcome_msg)
    }

    fn plan(
        &self,
        p: &Proposal,
        authz: &Authorization,
        state: &SystemState,
        defs: &UnitDefs,
        prebuilt: Option<Prebuilt>,
    ) -> Result<Plan, Submitted> {
        let gens = self.b.generations();
        // §11: actor fields inside a proposal are overwritten from the caller.
        let transition = match &p.transition {
            Transition::SetOverride(s) => Transition::SetOverride(Override { by: authz.actor.clone(), ..s.clone() }),
            t => t.clone(),
        };
        // Only generation changes need the running generation's evaluation and
        // the override file; unit operations keep working on generations that
        // predate Planarian.
        let gen_op = transition.changes_generation();
        let base_eval = match self.eval_of(state.generation) {
            Ok(e) => e,
            Err(_) if !gen_op => EvaluatedGeneration {
                source: Hash::ZERO,
                options: BTreeMap::new(),
                units: defs.clone(),
                user_units: vec![],
                activation: ActivationPlan::default(),
                locked: Default::default(),
                core_units: BTreeMap::new(),
            },
            Err(e) => {
                return Err(reject(
                    RejectReason::Other("evaluation".into()),
                    format!(
                        "the running generation's manifest is unavailable ({e}); rebuild once with Planarian enabled"
                    ),
                ));
            }
        };
        let (live, live_hash) = match gens.read_overrides() {
            Ok(x) => x,
            Err(_) if !gen_op => (OverrideSet::default(), Hash::ZERO),
            Err(o) => return Err(reject(RejectReason::Other("overrides".into()), outcome_msg(o))),
        };

        let mut plan = Plan {
            transition: transition.clone(),
            facts: derive(&DeriveInput {
                transition: &transition,
                defs,
                base: &base_eval,
                candidate: None,
                activation: None,
                base_overrides: &live,
                candidate_overrides: None,
                caller: authz.actor.clone(),
                tables: &self.cfg.tables,
                canonical: &self.cfg.canonical,
            }),
            decision: Decision::Reject(RejectReason::Other("undecided".into())),
            base_eval: base_eval.clone(),
            cand_eval: None,
            built: None,
            staged: None,
            candidate: None,
            base_override: None,
            candidate_override: None,
        };

        let mut cand_overrides: Option<OverrideSet> = None;
        match &transition {
            Transition::ApplyChange { change, args } => {
                let _ = (change, args);
                // Built off the core thread if the daemon did so for this
                // very transition from this very override file; else here.
                let pre = match prebuilt {
                    Some(p) if p.transition == transition && p.live_hash == live_hash => Some(p),
                    Some(stale) => {
                        if let Ok(c) = &stale.result {
                            gens.release_root(&c.built.root);
                        }
                        None
                    }
                    None => None,
                };
                let Candidate { staged, eval, built, merged } = match pre {
                    Some(p) => p.result?,
                    None => build_candidate(gens, &self.cfg.owner, &self.cfg.catalog, &transition, &live)?,
                };
                let fail = |what: &str, o: Outcome| reject(RejectReason::Other(what.into()), outcome_msg(o));
                gens.remember_override(&live).map_err(|o| fail("override", o))?;
                let cand_hash = gens.remember_override(&merged).map_err(|o| fail("override", o))?;
                plan.candidate = Some((built.generation, built.path.clone()));
                plan.base_override = Some(live_hash);
                plan.candidate_override = Some(cand_hash);
                plan.cand_eval = Some(eval);
                plan.built = Some(built);
                plan.staged = Some(staged);
                cand_overrides = Some(merged);
            }
            Transition::SwitchGeneration(g) | Transition::Revert { to: g } => {
                self.plan_existing(&mut plan, *g, live_hash)?;
            }
            Transition::Rollback => {
                self.plan_existing(&mut plan, state.known_good, live_hash)?;
            }
            _ => {}
        }

        plan.facts = derive(&DeriveInput {
            transition: &transition,
            defs,
            base: &base_eval,
            candidate: plan.cand_eval.as_ref(),
            activation: plan.built.as_ref().map(|b| &b.activation),
            base_overrides: &live,
            candidate_overrides: cand_overrides.as_ref(),
            caller: authz.actor.clone(),
            tables: &self.cfg.tables,
            canonical: &self.cfg.canonical,
        });

        // §12 step 3: `expected` must refine the spec's prediction.
        let predicted = predict(&transition, state, defs);
        if let Err(e) = refines(&p.expected, &predicted, Some(plan.facts.affected_units.as_slice())) {
            self.release(&plan);
            return Err(reject(RejectReason::Refinement, e));
        }

        let locked: Vec<String> =
            plan.cand_eval.as_ref().map(|e| e.locked.iter().cloned().collect()).unwrap_or_default();
        plan.decision = decide(&Input {
            transition: &transition,
            facts: &plan.facts,
            known_good: state.known_good,
            live_tested: state.live_tested,
            cumulative: &self.session.cumulative,
            authz,
            settings: &self.cfg.settings,
            tables: &self.cfg.tables,
            locked: &locked,
            revert_to: None,
        });
        Ok(plan)
    }

    fn plan_existing(&self, plan: &mut Plan, g: GenerationId, live_hash: Hash) -> Result<(), Submitted> {
        let gens = self.b.generations();
        let fail = |o: Outcome| reject(RejectReason::Other("generation".into()), outcome_msg(o));
        let path = gens.path_of(g).map_err(fail)?;
        let eval = gens.evaluate_built(&path).map_err(fail)?;
        plan.candidate = Some((g, path));
        plan.cand_eval = Some(eval);
        if let Some(h) = gens.override_for(g).map_err(fail)? {
            plan.base_override = Some(live_hash);
            plan.candidate_override = Some(h);
        }
        Ok(())
    }

    fn release(&self, plan: &Plan) {
        if let Some(b) = &plan.built {
            self.b.generations().release_root(&b.root);
        }
    }

    /// What the approval token binds (§8 `ApprovalToken.bound_to`).
    fn binding(&self, p: &Proposal, plan: &Plan, state: &SystemState) -> Hash {
        let cumulative = plan.facts.config_diff.as_ref().map(|d| self.session.cumulative.then(d)).unwrap_or_default();
        let v = serde_json::json!({
            "transition": plan.transition,
            "staged_source": plan.staged.as_ref().map(|s| s.staged_source),
            "candidate": plan.candidate,
            "base": state.generation,
            "policy": self.policy_version(),
            "cumulative": cumulative.hash(),
            "facts": plan.facts,
            "expected": p.expected,
            "revert_to": state.generation,
            "recovery": plan.transition.recovery(),
        });
        Hash::of(&serde_json::to_vec(&v).expect("binding serializes"))
    }

    fn transaction(&self, p: &Proposal, plan: &Plan, state: &SystemState, defs: &UnitDefs) -> Transaction {
        let now = self.b.clock().now();
        let network = plan.facts.disruption == Disruption::ConnectivityLoss
            || plan.facts.affected_units.iter().any(|u| u.name == "NetworkManager");
        let prior_driver = match &plan.transition {
            Transition::BindDriver { device, .. } => self.b.inventory().bound_driver(device).ok().flatten(),
            _ => None,
        };
        Transaction {
            id: TxnId(0),
            state: TxnState::Prepared,
            lease: Lease {
                txn: TxnId(0),
                owner: self.kernel.me.clone(),
                epoch: 1,
                worker_pid: None,
                renewed: now,
                jobs: vec![],
            },
            base_source: plan.staged.as_ref().map(|s| s.base_source),
            staged_source: plan.staged.as_ref().map(|s| s.staged_source),
            base_override: plan.base_override,
            candidate_override: plan.candidate_override,
            gc_root: plan.built.as_ref().map(|b| b.root.clone()),
            recovery: plan.transition.recovery(),
            transition: plan.transition.clone(),
            facts: plan.facts.clone(),
            base: state.generation,
            candidate: plan.candidate.clone(),
            policy: self.policy_version(),
            approval: None,
            snapshot: None,
            expected: p.expected.clone(),
            started: now,
            deadline: now.plus(if network { NETWORK_DEADLINE } else { GENERATION_DEADLINE }),
            revert_to: state.generation,
            prior_driver,
            check: CheckContext {
                candidate: plan.cand_eval.as_ref().map(manifest_of),
                base: manifest_of(&plan.base_eval),
                pre: defs.keys().map(|u| (u.clone(), state.status(u, defs))).collect(),
            },
        }
    }

    /// §9 step 6: the owner's Nix-visible source must still hash to `base_source`.
    fn stale(&self, plan: &Plan) -> bool {
        match &plan.staged {
            Some(s) => self.b.generations().source_hash(&self.cfg.owner).map(|h| h != s.base_source).unwrap_or(true),
            None => false,
        }
    }

    fn kernel_error(e: KernelError) -> Submitted {
        match e {
            KernelError::Journal(JournalError::Ledger(LedgerError::Exclusive { blocker, .. })) => {
                reject(RejectReason::Other("busy".into()), format!("transaction {} is in progress", blocker.0))
            }
            KernelError::Journal(JournalError::Ledger(LedgerError::Interlocked { .. })) => reject(
                RejectReason::Other("interlocked".into()),
                "the recovery interlock is set; an administrator must run `planarian resolve`",
            ),
            e => Submitted::Error(format!("{e:?}")),
        }
    }

    /// The slow part of planning `t`, to run elsewhere: `Some` for a catalog
    /// change, whose staging, evaluation and build can take minutes. Hand
    /// its result to `prebuilt` before submitting `t`.
    pub fn prebuild_job(&self, t: &Transition) -> Option<PrebuildJob<B::Gens>>
    where
        B::Gens: Clone,
    {
        if !matches!(t, Transition::ApplyChange { .. }) {
            return None;
        }
        let (live, live_hash) = self.b.generations().read_overrides().ok()?;
        Some(PrebuildJob {
            gens: self.b.generations().clone(),
            owner: self.cfg.owner.clone(),
            catalog: self.cfg.catalog.clone(),
            transition: t.clone(),
            live,
            live_hash,
        })
    }

    /// Submit a proposal. `state` and `defs` are the current observation.
    pub fn submit(&mut self, p: Proposal, authz: Authorization, state: &SystemState, defs: &UnitDefs) -> Submitted {
        let digest = state.digest();
        if p.observed != digest {
            return Submitted::Rejected {
                reason: RejectReason::Stale,
                detail: "state changed since the proposal was made".into(),
                digest: Some(digest),
            };
        }
        self.last = None;
        let pre = self.prebuilt.take();
        let plan = match self.plan(&p, &authz, state, defs, pre) {
            Ok(plan) => plan,
            Err(s) => return s,
        };
        self.last = Some((plan.facts.clone(), plan.decision.clone()));
        self.excluded = plan.staged.as_ref().map(|s| s.excluded.clone()).unwrap_or_default();
        if plan.staged.is_some() {
            // Also any added while it built: the stale check below ignores them.
            for f in self.b.generations().untracked(&self.cfg.owner) {
                if !self.excluded.contains(&f) {
                    self.excluded.push(f);
                }
            }
        }
        if let Decision::Reject(r) = &plan.decision {
            self.release(&plan);
            return reject(r.clone(), "refused by policy");
        }
        if self.stale(&plan) {
            self.release(&plan);
            return reject(RejectReason::Stale, "your configuration changed while the change was being built");
        }
        let txn = self.transaction(&p, &plan, state, defs);
        let id = match self.kernel.prepare(txn) {
            Ok(id) => id,
            Err(e) => {
                self.release(&plan);
                return Self::kernel_error(e);
            }
        };
        if let Decision::Allow { tier: Tier::AskFirst, approver: class } = plan.decision {
            let bound_to = self.binding(&p, &plan, state);
            let now = self.b.clock().now();
            self.parked.insert(
                id,
                Parked { txn: id, proposal: p, authz, class, bound_to, issued: now, facts: plan.facts.clone() },
            );
            return Submitted::Parked { txn: id, approve: bound_to, facts: plan.facts };
        }
        self.run(id, &plan)
    }

    fn run(&mut self, id: TxnId, plan: &Plan) -> Submitted {
        match self.kernel.run(id) {
            Ok(end) => {
                let followup = self.after(id, plan, &end);
                Submitted::Finished { txn: id, state: end, followup }
            }
            Err(e) => Self::kernel_error(e),
        }
    }

    /// Bookkeeping after a terminal state; returns a §12a write-back, if any.
    fn after(&mut self, id: TxnId, plan: &Plan, end: &TxnState) -> Option<Proposal> {
        if *end != TxnState::Committed {
            return None;
        }
        if let (Some((g, _)), Some(h)) = (&plan.candidate, plan.candidate_override) {
            let _ = self.b.generations().record_override(*g, &h);
        }
        self.session.applied.push(id);
        if let Some(d) = &plan.facts.config_diff {
            self.session.cumulative = self.session.cumulative.then(d);
        }
        if let Transition::SetRuntimeOption { path, value } = &plan.transition {
            let (change, args) = planarian_changes::writeback(path, value)?;
            return Some(Proposal {
                observed: Hash::ZERO, // the daemon fills in the digest it observes
                transition: Transition::ApplyChange { change, args },
                expected: Expectation {
                    units: BTreeMap::new(),
                    generation: None,
                    may_change: Default::default(),
                    others_unchanged: false,
                    settle: Settle::Duration(planarian_schema::spec::DEFAULT_SETTLE),
                },
                reason: format!("persist the runtime setting {path}"),
                source: Source::User,
            });
        }
        None
    }

    /// `planarian approve <hash>` (§12 step 4): re-derive, re-decide, rebind.
    /// The caller has checked root and an interactive TTY (Phase A).
    pub fn approve(
        &mut self,
        hash: &Hash,
        approver: &Authorization,
        state: &SystemState,
        defs: &UnitDefs,
    ) -> Submitted {
        let Some(parked) = self.parked.values().find(|p| p.bound_to == *hash).cloned() else {
            return reject(RejectReason::Other("approval".into()), "no pending change with that hash");
        };
        // I19: never the proposer; an Administrator class needs an administrator.
        // A refused approval leaves the request pending for someone who may.
        if !may_approve(approver, parked.authz.principal, parked.class) {
            let why = if approver.principal == parked.authz.principal {
                "you can't approve your own request"
            } else if parked.class == ApproverClass::Administrator {
                "this needs an administrator's approval"
            } else {
                "you can't approve requests"
            };
            return reject(RejectReason::Unauthorized, why);
        }
        let now = self.b.clock().now();
        if token_expired(now, parked.issued) {
            return self.expire_one(parked.txn);
        }
        // §9 step 6, against the source staged when the approval was requested:
        // an owner edit since then is Stale, not a reason to rebuild silently.
        let staged_base = self
            .kernel
            .journal
            .sync_ledger()
            .ok()
            .and_then(|l| l.live.get(&parked.txn).and_then(|t| t.txn.base_source));
        if let Some(base) = staged_base
            && self.b.generations().source_hash(&self.cfg.owner).map(|h| h != base).unwrap_or(true)
        {
            self.parked.remove(&parked.txn);
            let _ = self.kernel.reject(parked.txn, RejectReason::Stale);
            return reject(RejectReason::Stale, "your configuration changed after the approval was requested");
        }
        let pre = self.prebuilt.take();
        let plan = match self.plan(&parked.proposal, &parked.authz, state, defs, pre) {
            Ok(p) => p,
            Err(s) => {
                self.parked.remove(&parked.txn);
                let _ = self.kernel.reject(parked.txn, RejectReason::Other("approval invalidated".into()));
                return s;
            }
        };
        let rebound = self.binding(&parked.proposal, &plan, state);
        if rebound != parked.bound_to || !matches!(plan.decision, Decision::Allow { .. }) {
            // Something the approval covered changed: the token is void. Withdraw
            // this transaction and, if still allowed, park the new one.
            self.parked.remove(&parked.txn);
            let _ = self.kernel.reject(parked.txn, RejectReason::Other("approval invalidated".into()));
            self.release(&plan);
            let mut p = parked.proposal.clone();
            p.observed = state.digest();
            return self.submit(p, parked.authz, state, defs);
        }
        if self.stale(&plan) {
            self.parked.remove(&parked.txn);
            let _ = self.kernel.reject(parked.txn, RejectReason::Stale);
            return reject(RejectReason::Stale, "your configuration changed after the approval was requested");
        }
        // One token per binding: a second approval of the same hash is a replay.
        let mut nonce = [0u8; 16];
        nonce.copy_from_slice(&hash.0[..16]);
        if self.kernel.journal.ledger().tokens_used.iter().any(|(n, _)| *n == nonce) {
            return reject(RejectReason::Other("approval".into()), "this approval was already used");
        }
        let _ =
            self.kernel.journal.append(now, Record::TokenUsed { nonce, expires: parked.issued.plus(TOKEN_LIFETIME) });
        self.parked.remove(&parked.txn);
        self.run(parked.txn, &plan)
    }

    fn expire_one(&mut self, txn: TxnId) -> Submitted {
        self.parked.remove(&txn);
        match self.kernel.reject(txn, RejectReason::ApprovalExpired) {
            Ok(s) => Submitted::Finished { txn, state: s, followup: None },
            Err(e) => Self::kernel_error(e),
        }
    }

    /// Tokens expire after 24 h (§12 step 4); the parked transaction ends Rejected.
    pub fn expire(&mut self) -> Vec<TxnId> {
        let now = self.b.clock().now();
        let old: Vec<TxnId> = self.parked.values().filter(|p| token_expired(now, p.issued)).map(|p| p.txn).collect();
        for t in &old {
            self.expire_one(*t);
        }
        old
    }

    /// A user withdraws a parked proposal (§12 step 5).
    pub fn cancel(&mut self, txn: TxnId, by: Actor) -> Submitted {
        if self.parked.remove(&txn).is_none() {
            return reject(RejectReason::Other("cancel".into()), "no such pending change");
        }
        match self.kernel.cancel(txn, by) {
            Ok(s) => Submitted::Finished { txn, state: s, followup: None },
            Err(e) => Self::kernel_error(e),
        }
    }
}

#[cfg(kani)]
mod kani;
#[cfg(test)]
mod tests;
