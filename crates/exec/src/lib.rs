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
use planarian_schema::spec::{precondition, predict, refines};
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
    /// When the token was issued, on the boot clock (§12h): moving the wall
    /// clock cannot extend it, and it does not outlive the boot.
    pub issued: Timestamp,
    pub facts: DerivedFacts,
}

/// Everything decided before a transaction exists.
#[derive(Clone)]
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
    /// An existing generation's dry activation (R04); a built candidate's
    /// is in `built`.
    existing_activation: Option<ActivationPlan>,
    /// What derive and decide read, kept to do both again when the
    /// transaction leaves Built (C2).
    authz: Authorization,
    live: OverrideSet,
    cand_overrides: Option<OverrideSet>,
}

impl Plan {
    fn activation(&self) -> Option<&ActivationPlan> {
        self.built.as_ref().map(|b| &b.activation).or(self.existing_activation.as_ref())
    }
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
    /// Generation transactions waiting in `Built` for an activation window
    /// (§12f), with when each began waiting (`CLOCK_BOOTTIME`).
    waiting: BTreeMap<TxnId, (Timestamp, Plan)>,
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
    let built = gens.build(&eval).map_err(|o| {
        if outcome_msg(o.clone()).contains("dry activation") {
            reject(RejectReason::ActivationUnknown, outcome_msg(o))
        } else {
            no_space("build", o)
        }
    })?;
    Ok(Candidate { staged, eval, built, merged })
}

/// An approval token issued at `issued` has expired by `now`, both on the
/// boot clock (§12h; §12 step 4:
/// 24 hours). Saturating: a token issued near the end of time never expires
/// early, and no clock value makes this panic.
/// Why `t`'s precondition does not hold for `by` (§12 step 5), if it does
/// not. An attested override is replaced only by its holder; anyone else
/// gets its holder named (C3).
pub fn unmet(t: &Transition, s: &SystemState, defs: &UnitDefs, by: &Actor) -> Option<String> {
    if let Transition::SetOverride(sup) = t {
        let o = s.override_of(&sup.unit)?;
        if o.attribution == Attribution::Attested && o.by.principal() != by.principal() {
            let holder = o.by.uid().map(|u| format!("uid {u}")).unwrap_or_else(|| format!("{:?}", o.by));
            return Some(format!("{} holds an override set by {holder}; they lift it (planarian release)", sup.unit));
        }
        return None;
    }
    (!precondition(t, s, defs)).then(|| format!("the precondition of {t:?} does not hold"))
}

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
        // C4: a build root left by a build that crashed goes once it is old.
        let _ = gens.age_out_build_roots();
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
            existing_activation: None,
            authz: authz.clone(),
            live: live.clone(),
            cand_overrides: None,
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
                cand_overrides = self.plan_existing(&mut plan, *g, live_hash)?;
            }
            Transition::Rollback => {
                cand_overrides = self.plan_existing(&mut plan, state.known_good, live_hash)?;
            }
            _ => {}
        }

        plan.cand_overrides = cand_overrides;
        plan.facts = self.facts_of(&plan, state, defs);

        // §12 step 3: `expected` must refine the spec's prediction.
        let predicted = predict(&transition, state, defs);
        if let Err(e) = refines(&p.expected, &predicted, Some(plan.facts.affected_units.as_slice())) {
            self.release(&plan);
            return Err(reject(RejectReason::Refinement, e));
        }

        plan.decision = self.decision_of(&plan, state);
        Ok(plan)
    }

    /// §11: the facts of a plan, from the current observation.
    fn facts_of(&self, plan: &Plan, state: &SystemState, defs: &UnitDefs) -> DerivedFacts {
        let transition = &plan.transition;
        let mut facts = derive(&DeriveInput {
            transition,
            defs,
            base: &plan.base_eval,
            candidate: plan.cand_eval.as_ref(),
            activation: plan.activation(),
            base_overrides: &plan.live,
            candidate_overrides: plan.cand_overrides.as_ref(),
            caller: plan.authz.actor.clone(),
            tables: &self.cfg.tables,
            canonical: &self.cfg.canonical,
        });
        // §11: who else this reaches, and §12e: whether it goes below the floor.
        let sessions = self.b.sessions().sessions().unwrap_or_default();
        derive::session_facts(&mut facts, &sessions);
        derive::floor_fact(&mut facts, transition, state);
        // §11: and whether a restart restores an unattributed stop.
        let ended = match transition {
            Transition::RestartUnit(u) => self.b.units().ended_by(u),
            _ => None,
        };
        derive::stop_fact(&mut facts, transition, state, defs, ended);
        facts
    }

    fn decision_of(&self, plan: &Plan, state: &SystemState) -> Decision {
        let locked: Vec<String> =
            plan.cand_eval.as_ref().map(|e| e.locked.iter().cloned().collect()).unwrap_or_default();
        decide(&Input {
            transition: &plan.transition,
            facts: &plan.facts,
            known_good: state.known_good,
            live_tested: state.live_tested,
            cumulative: &self.session.cumulative,
            authz: &plan.authz,
            settings: &self.cfg.settings,
            tables: &self.cfg.tables,
            locked: &locked,
            revert_to: None,
        })
    }

    /// C2 (§9 step 6, I8): a transaction leaving Built for Activating is
    /// checked again as on the way in: the owner's source and the override
    /// file are as it was built from, and the decision made again from the
    /// facts derived now is the one it was admitted with. Otherwise it ends Rejected
    /// (Stale) and is asked for again. `None` when it may go on.
    fn revalidate(&mut self, id: TxnId, plan: &Plan, state: &SystemState, defs: &UnitDefs) -> Option<Submitted> {
        let overrides_moved = plan
            .base_override
            .is_some_and(|b| self.b.generations().read_overrides().map(|(_, h)| h != b).unwrap_or(true));
        let mut again = plan.clone();
        again.facts = self.facts_of(&again, state, defs);
        let redecided = self.decision_of(&again, state);
        if !self.stale(plan) && !overrides_moved && redecided == plan.decision {
            return None;
        }
        self.release(plan);
        Some(match self.kernel.reject(id, RejectReason::Stale) {
            Ok(end) => Submitted::Finished { txn: id, state: end, followup: None },
            Err(e) => Self::kernel_error(e),
        })
    }

    /// Equivalent effects, equivalent facts (§11, R04): an existing
    /// generation's facts come from its dry activation and the override
    /// content recorded for it, as a built candidate's do. Returns that
    /// content, if one was recorded.
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
        let activation =
            gens.dry_activation(&path).map_err(|o| reject(RejectReason::ActivationUnknown, outcome_msg(o)))?;
        let mut content = None;
        if let Some(h) = gens.override_for(g).map_err(fail)? {
            // Without it the swap could not write it either.
            content = Some(gens.override_content(&h).map_err(|o| reject(RejectReason::Precondition, outcome_msg(o)))?);
            plan.base_override = Some(live_hash);
            plan.candidate_override = Some(h);
        }
        plan.candidate = Some((g, path));
        plan.cand_eval = Some(eval);
        plan.existing_activation = Some(activation);
        Ok(content)
    }

    fn release(&self, plan: &Plan) {
        if let Some(b) = &plan.built {
            self.b.generations().release_root(&b.root);
        }
    }

    /// What the approval token binds (§8 `ApprovalToken.bound_to`).
    /// It names the transaction too, so each request for approval has its
    /// own: an approval issued before a restart can never approve the change
    /// asked for again after it, however identical (§12 step 4, S07).
    fn binding(&self, txn: TxnId, p: &Proposal, plan: &Plan, state: &SystemState) -> Hash {
        let cumulative = plan.facts.config_diff.as_ref().map(|d| self.session.cumulative.then(d)).unwrap_or_default();
        let v = serde_json::json!({
            "txn": txn.0,
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
            candidate_nar: plan.built.as_ref().and_then(|b| b.nar),
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
                candidate: plan.cand_eval.as_ref().map(manifest_of),
                base: manifest_of(&plan.base_eval),
                pre: defs.keys().map(|u| (u.clone(), state.status(u, defs))).collect(),
                pre_passing: defs
                    .keys()
                    .map(|u| (u.clone(), state.passing_readiness(u, defs)))
                    .filter(|(_, p)| !p.is_empty())
                    .collect(),
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

    /// Admission before work (§12, R09): the checks that need no staged
    /// source, run before anything is staged, evaluated or built. Each is a
    /// necessary condition of `decide`'s authorization, so admission refuses
    /// only what policy would refuse after the build.
    pub fn admit(&self, t: &Transition, authz: &Authorization) -> Result<(), (RejectReason, &'static str)> {
        let Transition::ApplyChange { change, .. } = t else { return Ok(()) };
        if !matches!(authz.actor, Actor::User { .. } | Actor::Daemon | Actor::Watchdog) {
            return Err((RejectReason::Unauthorized, "this caller cannot change the configuration"));
        }
        if !self.cfg.tables.catalog.contains(change) {
            return Err((RejectReason::NotInCatalog, "that change is not in the catalog"));
        }
        let admin = authz.capabilities.contains(Capability::Administrator);
        if self.kernel.journal.ledger().interlocked() && !admin {
            return Err((
                RejectReason::Other("interlocked".into()),
                "the recovery interlock is set; only an administrator can change this machine until `planarian resolve`",
            ));
        }
        if matches!(authz.actor, Actor::User { .. })
            && !admin
            && !(authz.capabilities.contains(Capability::UserControllable)
                && self.cfg.settings.user_controllable_changes.contains(change))
        {
            return Err((RejectReason::Unauthorized, "that change needs an administrator"));
        }
        Ok(())
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
        if let Err((reason, why)) = self.admit(&p.transition, &authz) {
            self.prebuilt = None;
            return reject(reason, why);
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
        // §12 step 5 (C3): preconditions are the executor's, whatever the
        // source; checked once the caller is known to be authorized.
        if let Some(why) = unmet(&p.transition, state, defs, &authz.actor) {
            self.release(&plan);
            return reject(RejectReason::Precondition, why);
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
            let bound_to = self.binding(id, &p, &plan, state);
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
                    self.waiting.insert(id, (self.b.clock().boot_now(), plan));
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

    /// Activate transactions waiting in `Built` whose window has opened: no
    /// foreground work, and the sessions idle (or the change does not disturb
    /// one). Returns what ran.
    pub fn activate_waiting(&mut self, state: &SystemState, defs: &UnitDefs) -> Vec<(TxnId, Submitted)> {
        let foreground = state.conditions.iter().any(|c| matches!(c, Condition::Foreground { .. }));
        if foreground || self.waiting.is_empty() {
            return vec![];
        }
        let ready: Vec<TxnId> = self
            .waiting
            .iter()
            .filter(|(_, (_, p))| {
                !p.built.as_ref().is_some_and(|b| self.disturbs_a_session(&b.activation)) || self.sessions_idle()
            })
            .map(|(id, _)| *id)
            .collect();
        let mut out = vec![];
        for id in ready {
            if let Some((_, plan)) = self.waiting.remove(&id) {
                // C2: the stale check, re-derive and re-decide on this path
                // into Activating too.
                if let Some(refused) = self.revalidate(id, &plan, state, defs) {
                    out.push((id, refused));
                    continue;
                }
                out.push((id, self.run(id, &plan)));
            }
        }
        out
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
        // §12e, I25: the kernel derived the floor and recorded the override
        // content as part of the commit; this only says so.
        if let (Some((g, _)), Some(cand)) = (&plan.candidate, &plan.cand_eval)
            && self.kernel.journal.ledger().security_floor == Some(*g)
        {
            self.floor_raised = Some((*g, cand.security_fixes(&plan.base_eval)));
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
        let rebound = self.binding(parked.txn, &parked.proposal, &plan, state);
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
        // Journal records carry the wall clock (§12h); `now` here is the
        // boot clock, which times the token.
        let _ = self.kernel.journal.append(
            self.b.clock().now(),
            Record::TokenUsed {
                nonce,
                expires: parked.issued.plus(TOKEN_LIFETIME),
                approver: approver.principal.0,
                txn: parked.txn.0,
            },
        );
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

    /// The transaction waits in `Built` for an activation window (§12f).
    pub fn is_waiting(&self, txn: TxnId) -> bool {
        self.waiting.contains_key(&txn)
    }

    /// §12f, I12: parking in `Built` is bounded. A transaction that has
    /// waited longer than the parking limit is `Cancelled(Daemon)`; returns
    /// each one with the change it would have made, for the notice.
    pub fn expire_waiting(&mut self) -> Vec<(TxnId, Transition)> {
        let now = self.b.clock().boot_now();
        let old: Vec<TxnId> =
            self.waiting.iter().filter(|(_, (since, _))| now > since.plus(PARKING_LIMIT)).map(|(id, _)| *id).collect();
        let mut out = vec![];
        for id in old {
            if let Some((_, plan)) = self.waiting.remove(&id)
                && self.kernel.cancel(id, Actor::Daemon).is_ok()
            {
                out.push((id, plan.transition));
            }
        }
        out
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

pub mod residue;

#[cfg(kani)]
mod kani;
#[cfg(test)]
mod tests;
