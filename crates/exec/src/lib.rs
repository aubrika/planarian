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
/// §12f: an activation window cannot hold a generation transaction forever.
pub const PARKING_LIMIT: Millis = Millis::secs(24 * 3600);

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
    /// When the token was issued, on the boot clock (§12h): moving the wall
    /// clock cannot extend it, and it does not outlive the boot.
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

struct Waiting {
    plan: Plan,
    /// Boot time when this transaction entered Built. A daemon restart
    /// rejects the old Built transaction and prepares a new one (§12f).
    since: Timestamp,
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
    /// Set when the last commit raised the security floor (§12e): the
    /// generation and the packages it fixed, for the daemon to report.
    pub floor_raised: Option<(GenerationId, Vec<String>)>,
    /// Generation transactions waiting in `Built` for an activation window (§12f).
    waiting: BTreeMap<TxnId, Waiting>,
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

/// An approval token issued at `issued` has expired by `now`, both on the
/// boot clock (§12h; §12 step 4:
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
            floor_raised: None,
            waiting: BTreeMap::new(),
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

    /// Cheap admission before any staging/evaluation/build. This checks
    /// catalog membership, arguments, and the caller's catalog capability;
    /// candidate-derived scope and every risk floor remain checked later.
    pub fn admit_catalog(&self, t: &Transition, authz: &Authorization) -> Result<(), Submitted> {
        let Transition::ApplyChange { change, args } = t else { return Ok(()) };
        if !self.cfg.tables.catalog.contains(change) {
            return Err(reject(RejectReason::NotInCatalog, "not in the active catalog"));
        }
        let admitted = match &authz.actor {
            Actor::User { .. } => {
                authz.capabilities.administrator
                    || (authz.capabilities.user_controllable
                        && self.cfg.settings.user_controllable_changes.contains(change))
            }
            Actor::Agent(_) | Actor::Unattributed => false,
            _ => true,
        };
        if !admitted {
            return Err(reject(RejectReason::Unauthorized, "caller cannot apply this catalog entry"));
        }
        planarian_changes::handle(&self.cfg.catalog, change, args)
            .map_err(|e| reject(RejectReason::Other("arguments".into()), e.to_string()))?;
        Ok(())
    }

    fn plan(
        &self,
        p: &Proposal,
        authz: &Authorization,
        state: &SystemState,
        defs: &UnitDefs,
        prebuilt: Option<Prebuilt>,
    ) -> Result<Plan, Submitted> {
        self.admit_catalog(&p.transition, authz)?;
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
                packages: BTreeMap::new(),
                insecure: Default::default(),
                declarations: BTreeMap::new(),
                inputs: BTreeMap::new(),
                services: BTreeMap::new(),
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
                if let Err(o) = gens.remember_override(&live) {
                    gens.release_root(&built.root);
                    return Err(fail("override", o));
                }
                let cand_hash = match gens.remember_override(&merged) {
                    Ok(hash) => hash,
                    Err(o) => {
                        gens.release_root(&built.root);
                        return Err(fail("override", o));
                    }
                };
                plan.candidate = Some((built.generation, built.path.clone()));
                plan.base_override = Some(live_hash);
                plan.candidate_override = Some(cand_hash);
                plan.cand_eval = Some(eval);
                plan.built = Some(built);
                plan.staged = Some(staged);
                cand_overrides = Some(merged);
            }
            Transition::SwitchGeneration(g) | Transition::Revert { to: g } => {
                cand_overrides = self.plan_existing(&mut plan, *g, live_hash)?;
            }
            Transition::Rollback => {
                cand_overrides = self.plan_existing(&mut plan, state.known_good, live_hash)?;
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
        // §11: who else this reaches, and §12e: whether it goes below the floor.
        let sessions = self.b.sessions().sessions().unwrap_or_default();
        derive::session_facts(&mut plan.facts, &sessions);
        derive::floor_fact(&mut plan.facts, &transition, state);
        // §11: and whether a restart restores an unattributed stop.
        let ended = match &transition {
            Transition::RestartUnit(u) => self.b.units().ended_by(u),
            _ => None,
        };
        derive::stop_fact(&mut plan.facts, &transition, state, defs, ended);

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

    fn plan_existing(
        &self,
        plan: &mut Plan,
        g: GenerationId,
        live_hash: Hash,
    ) -> Result<Option<OverrideSet>, Submitted> {
        let gens = self.b.generations();
        let fail = |o: Outcome| reject(RejectReason::Other("generation".into()), outcome_msg(o));
        let path = gens.path_of(g).map_err(fail)?;
        let eval = gens.evaluate_built(&path).map_err(fail)?;
        // A previously vetted manifest says nothing about today's service
        // contents or activation. Obtain the same preflight as a fresh build.
        let built = gens.preflight_existing(g, &path).map_err(fail)?;
        if built.generation != g || built.path != path {
            gens.release_root(&built.root);
            return Err(reject(RejectReason::Other("generation".into()), "preflight target changed"));
        }
        let recorded = match gens.override_for(g) {
            Ok(h) => h,
            Err(o) => {
                gens.release_root(&built.root);
                return Err(fail(o));
            }
        };
        let overrides = match recorded {
            Some(h) => {
                let set = match gens.read_override(&h) {
                    Ok(s) => s,
                    Err(o) => {
                        gens.release_root(&built.root);
                        return Err(fail(o));
                    }
                };
                plan.base_override = Some(live_hash);
                plan.candidate_override = Some(h);
                Some(set)
            }
            None => {
                gens.release_root(&built.root);
                return Err(reject(
                    RejectReason::Other("generation".into()),
                    "target generation has no trustworthy override configuration; administrator recovery is required",
                ));
            }
        };
        plan.candidate = Some((g, path));
        plan.cand_eval = Some(eval);
        plan.built = Some(built);
        Ok(overrides)
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
            "activation": plan.built.as_ref().map(|b| &b.activation),
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
        // Leases and deadlines on the boot clock (§12h); `started` is shown.
        let boot = self.b.clock().boot_now();
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
                renewed: boot,
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
            deadline: boot.plus(if network { NETWORK_DEADLINE } else { GENERATION_DEADLINE }),
            revert_to: state.generation,
            prior_driver,
            check: CheckContext {
                version: CHECK_CONTEXT_VERSION,
                candidate: plan.cand_eval.as_ref().map(manifest_of),
                base: manifest_of(&plan.base_eval),
                pre: defs.keys().map(|u| (u.clone(), state.status(u, defs))).collect(),
                floor_fixes: plan.cand_eval.as_ref().map(|c| c.security_fixes(&plan.base_eval)).unwrap_or_default(),
                required_floor: plan.candidate.as_ref().and_then(|(g, _)| {
                    plan.cand_eval.as_ref().filter(|c| !c.security_fixes(&plan.base_eval).is_empty()).map(|_| *g)
                }),
                passing_readiness: Some(host::passing_readiness(state, defs)),
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
    pub fn prebuild_job(&self, t: &Transition, authz: &Authorization) -> Result<Option<PrebuildJob<B::Gens>>, Submitted>
    where
        B::Gens: Clone,
    {
        if !matches!(t, Transition::ApplyChange { .. }) {
            return Ok(None);
        }
        self.admit_catalog(t, authz)?;
        let (live, live_hash) = self
            .b
            .generations()
            .read_overrides()
            .map_err(|o| reject(RejectReason::Other("overrides".into()), outcome_msg(o)))?;
        Ok(Some(PrebuildJob {
            gens: self.b.generations().clone(),
            owner: self.cfg.owner.clone(),
            catalog: self.cfg.catalog.clone(),
            transition: t.clone(),
            live,
            live_hash,
        }))
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
        if matches!(p.transition, Transition::CollectGarbage { .. })
            && self
                .kernel
                .journal
                .ledger()
                .interlock
                .values()
                .any(|pending| pending.transition.changes_generation() && pending.evidence_version != 1)
        {
            self.prebuilt = None;
            return reject(
                RejectReason::Other("unknown protected candidate".into()),
                "historical recovery evidence does not identify every protected candidate; an administrator must reconcile and resolve it before collection",
            );
        }
        // §12c: while the recovery interlock is set, only administrators'
        // operations and a user's own overrides run (the ledger refuses the
        // autonomous callers itself).
        if self.kernel.journal.ledger().interlocked()
            && !authz.capabilities.contains(Capability::Administrator)
            && !matches!(p.transition, Transition::SetOverride(_) | Transition::LiftOverride(_))
        {
            self.prebuilt = None;
            return reject(
                RejectReason::Other("interlocked".into()),
                "the recovery interlock is set; only an administrator can change this machine until `planarian resolve`",
            );
        }
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
            let now = self.b.clock().boot_now();
            self.parked.insert(
                id,
                Parked { txn: id, proposal: p, authz, class, bound_to, issued: now, facts: plan.facts.clone() },
            );
            return Submitted::Parked { txn: id, approve: bound_to, facts: plan.facts };
        }
        self.schedule(id, plan, &p.source, state)
    }

    /// §12f: a generation candidate that takes effect only at boot takes the
    /// boot-only path; one that would disturb a session, or any while
    /// foreground work holds, waits in `Built` for an activation window
    /// (`activate_waiting`); everything else runs now.
    fn schedule(&mut self, id: TxnId, plan: Plan, source: &Source, state: &SystemState) -> Submitted {
        if !plan.transition.changes_generation() {
            return self.run(id, &plan);
        }
        if plan.built.as_ref().is_some_and(|b| b.activation.boot_only()) {
            if let Some(refusal) = self.revalidate_preflight(id, &plan) {
                return refusal;
            }
            return match self.kernel.run_boot_only(id) {
                Ok(end) => Submitted::Finished { txn: id, state: end, followup: None },
                Err(e) => Self::kernel_error(e),
            };
        }
        let foreground = state.conditions.iter().any(|c| matches!(c, Condition::Foreground { .. }));
        let user_asked = matches!(source, Source::User | Source::Intent { .. });
        let disturbs = plan.built.as_ref().is_some_and(|b| self.disturbs_a_session(&b.activation));
        if foreground || (disturbs && !user_asked && !self.sessions_idle()) {
            let why = if foreground { "waiting: foreground work holds" } else { "waiting: a session is in use" };
            return match self.kernel.wait_built(id, why) {
                Ok(end) => {
                    self.waiting.insert(id, Waiting { plan, since: self.b.clock().boot_now() });
                    Submitted::Finished { txn: id, state: end, followup: None }
                }
                Err(e) => Self::kernel_error(e),
            };
        }
        self.run(id, &plan)
    }

    /// The activation would restart or reload something an active user
    /// session uses (§12f): a user unit, or one whose restart drops a session.
    fn disturbs_a_session(&self, a: &ActivationPlan) -> bool {
        let sessions = self.b.sessions().sessions().unwrap_or_default();
        if !sessions.iter().any(|s| s.establishes() && s.active) {
            return false;
        }
        a.stop.iter().chain(&a.restart).chain(&a.reload).any(|u| {
            matches!(u.scope, Scope::User { .. }) || ["display-manager", "graphical-session"].contains(&u.name.as_str())
        })
    }

    fn sessions_idle(&self) -> bool {
        self.b.sessions().sessions().unwrap_or_default().iter().filter(|s| s.establishes() && s.active).all(|s| s.idle)
    }

    /// Cancel candidates that have waited for the activation window for
    /// 24 hours, even when foreground work still holds. AwaitingBoot is not
    /// in this map: its publication waits for a reboot without a limit.
    pub fn expire_waiting(&mut self) -> Vec<(TxnId, Submitted)> {
        let now = self.b.clock().boot_now();
        let expired: Vec<TxnId> = self
            .waiting
            .iter()
            .filter(|(_, w)| now >= w.since.plus(PARKING_LIMIT))
            .map(|(id, _)| *id)
            .collect();
        expired
            .into_iter()
            .map(|id| {
                let result = match self.kernel.cancel(id, Actor::Daemon) {
                    Ok(state) => {
                        // The terminal journal step releases the adopted GC
                        // root. Keep the plan until cancellation is durable.
                        self.waiting.remove(&id);
                        Submitted::Finished { txn: id, state, followup: None }
                    }
                    Err(e) => Self::kernel_error(e),
                };
                (id, result)
            })
            .collect()
    }

    /// Activate transactions waiting in `Built` whose window has opened: no
    /// foreground work, and the sessions idle (or the change does not disturb
    /// one). Returns what ran.
    pub fn activate_waiting(&mut self, state: &SystemState) -> Vec<(TxnId, Submitted)> {
        let mut out = self.expire_waiting();
        let foreground = state.conditions.iter().any(|c| matches!(c, Condition::Foreground { .. }));
        if foreground || self.waiting.is_empty() {
            return out;
        }
        let ready: Vec<TxnId> = self
            .waiting
            .iter()
            .filter(|(_, w)| {
                !w.plan.built.as_ref().is_some_and(|b| self.disturbs_a_session(&b.activation)) || self.sessions_idle()
            })
            .map(|(id, _)| *id)
            .collect();
        for id in ready {
            if let Some(waiting) = self.waiting.remove(&id) {
                out.push((id, self.run(id, &waiting.plan)));
            }
        }
        out
    }

    /// Immediately before mutation, require the current activation evidence
    /// to match the candidate-bound plan approved and scheduled earlier.
    /// Waiting/approval does not freeze service contents or supervisor state.
    fn revalidate_preflight(&mut self, id: TxnId, plan: &Plan) -> Option<Submitted> {
        let built = plan.built.as_ref()?;
        let gens = self.b.generations();
        let base = self.kernel.journal.ledger().live.get(&id).map(|t| t.txn.base);
        let valid = match gens.current() {
            Ok(g) if Some(g) == base => match gens.preflight_existing(built.generation, &built.path) {
                Ok(now) => {
                    let same = now.generation == built.generation
                        && now.path == built.path
                        && now.activation == built.activation;
                    if now.root != built.root {
                        gens.release_root(&now.root);
                    }
                    same
                }
                Err(_) => false,
            },
            _ => false,
        };
        if valid {
            return None;
        }
        match self.kernel.reject(id, RejectReason::Stale) {
            Ok(_) => {
                self.release(plan);
                Some(reject(
                    RejectReason::Stale,
                    "activation preflight changed or became unavailable; resubmit the change",
                ))
            }
            Err(e) => Some(Self::kernel_error(e)),
        }
    }

    fn run(&mut self, id: TxnId, plan: &Plan) -> Submitted {
        if let Some(refusal) = self.revalidate_preflight(id, plan) {
            return refusal;
        }
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
        // §12e: a committed generation that fixes a known vulnerability is the
        // new security floor. The kernel durably establishes that obligation
        // before Committed; this is notification only, never a second write.
        if let (Some((g, _)), Some(cand)) = (&plan.candidate, &plan.cand_eval) {
            let fixes = cand.security_fixes(&plan.base_eval);
            let floor = self.kernel.journal.ledger().security_floor;
            if !fixes.is_empty() && floor.is_some_and(|f| f.0 >= g.0) {
                self.floor_raised = Some((*g, fixes));
            }
        }
        self.session.applied.push(id);
        if let Some(d) = &plan.facts.config_diff {
            self.session.cumulative = self.session.cumulative.then(d);
        }
        if let Transition::SetRuntimeOption { path, value } = &plan.transition {
            // Runtime Committed records re-observation/lifecycle, including
            // Failed/Partial/Unknown backend replies. Persistence needs an
            // acknowledged successful setting, not just terminal bookkeeping.
            if !self.kernel.journal.ledger().operation_outcome(id).is_success() {
                return None;
            }
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
        let now = self.b.clock().boot_now();
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
        if let Err(e) =
            self.kernel.journal.append(now, Record::TokenUsed { nonce, expires: parked.issued.plus(TOKEN_LIFETIME) })
        {
            // The original candidate is still parked. A deterministic
            // rebuild may reuse its exact root; keep that durable obligation
            // rooted while discarding only a distinct temporary preflight.
            let held = self.kernel.journal.ledger().live.get(&parked.txn).and_then(|t| t.txn.gc_root.as_ref());
            if plan.built.as_ref().is_some_and(|b| Some(&b.root) != held) {
                self.release(&plan);
            }
            return Submitted::Error(format!("could not durably consume approval: {e:?}"));
        }
        self.parked.remove(&parked.txn);
        let source = parked.proposal.source.clone();
        self.schedule(parked.txn, plan, &source, state)
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
        let now = self.b.clock().boot_now();
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
