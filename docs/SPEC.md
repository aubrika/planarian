# Planarian — Spec v4.3

Oct 26, 2026 · supersedes Spec v4.2 · targeted corrections from the v4.2 review (§25). Architecture settled; next artifact is the catalog and the fake-backend transaction kernel.

---

## Abstract

Planarian is a self-healing layer for declaratively configured computers. It keeps three things distinct: what the system is *meant* to be (desired state, with conditions and user overrides), what it *observes* (with explicit unknowns and stale evidence), and whether what it observes is *healthy* (probes with a contract). A divergence between desired and observed state opens an incident. Incidents are repaired deterministically first, by a planner that searches typed transitions over a dependency graph; a small local language model is consulted only when deterministic repair fails or a user's request is too fuzzy to match. Every change, whatever proposed it, passes through one executor that derives the risk classification itself, runs the change as a durable transaction with a journal that survives the daemon dying, and reverts it if health checks fail. The model never holds authority; it only submits typed proposals.

Planarian ships first as a Rust service on NixOS 26.05, where it is useful immediately and gathers real fault data. Its backends (service supervisor, configuration evaluator, snapshot filesystem, kernel) sit behind contracts and are replaced with Rust implementations over later phases, converging on an all-Rust operating system built on the Asterinas kernel. The contract stays the same at every step; what sits underneath it changes.

---

# Part I — For human readers

## 1. What it is, in one page

Most operating systems can tell you *that* something broke. Planarian is built to know *what should be true*, notice when it isn't, and close the gap without making things worse.

It can do this because the system is **declared**: a NixOS configuration says which services, drivers, and settings should exist. From that, plus a manifest that adds what NixOS doesn't say (what depends on what, how to test each thing, how risky it is to touch), Planarian derives **desired state**. Desired state has conditions: the graphical session should be running *after someone logs in*; a printer service should be running *when the printer is connected*; a service the user stopped on purpose is *suppressed until they say otherwise*. Planarian **observes** actual state continuously and runs **health probes** under a strict contract (no sudden noises, no side effects, bounded cost). When a probe times out, the answer is *Unknown*, not *Failed*.

A gap between desired and observed state opens an **incident**. Repair follows a strict order:

1. **Root-cause.** The dependency graph distinguishes "must be up for this to work" from "merely starts before" from "we suspect these are related." A failed audio service whose required sound-card driver also failed is a symptom; the driver is the target.
2. **Deterministic search.** A small planner searches the known transitions (restart this, rebind that, apply a cataloged change, roll back) for one whose preconditions hold and whose predicted result closes the gap, safest and least disruptive first.
3. **Summon the model.** Only if search finds nothing, or the incident's budget is spent, does a local model get the state, the graph, what was tried, and the manuals. It proposes in the same typed format the planner uses.
4. **Escalate.** If that also fails, the user gets a plain-language report, and the incident goes quiet with a cooldown rather than retrying forever.

User requests follow the same order: "reconnect Wi-Fi" matches a declared action directly; "stop the backup service while I work on it" becomes a suppression of desired state, so Planarian doesn't fight the user; "make it faster" is ambiguous and goes to the model, which asks before proposing.

Whoever proposes, **one executor decides**, and it decides from facts it derives itself: what the change actually touches in the evaluated configuration, how sensitive and how disruptive that is, what else changed this session. Nothing in a proposal can grant authority. Runtime actions with no lasting effect just run. Configuration changes run as a **transaction**: journaled before anything happens, activated as a candidate generation, probed, and either committed or reverted, with a watchdog that finishes the job if Planarian itself is killed halfway. Security-relevant, irreversible, or user-data changes wait for approval, and the approval is re-checked against the exact change the moment before it runs. The repair machinery itself can never be changed by any proposal, under any approval.

The model is a convenience and a fallback. If it is absent, broken, or wrong, the system still boots, runs, repairs the easy faults, and reverts the bad changes.

## 2. Component diagram

```
┌────────────────────────────────────────────────────────────────────────┐
│  USER SURFACES          console · `ask` CLI · launcher box             │
└──────────────┬──────────────────────────────────────────┬──────────────┘
               │ requests                                 │ approvals (secure path)
               ▼                                          ▼
┌────────────────────────┐                     ┌─────────────────────────┐
│  INTENT MATCHER        │  unmatched / fuzzy  │  APPROVAL BROKER        │
│  phrases → transitions ├────────────┐        │  tokens bound to the    │
│  or desired-state      │            │        │  concrete candidate     │
│  overrides             │            ▼        └────────────┬────────────┘
└──────────────┬─────────┘   ┌──────────────────┐           │ token
               │ proposal    │  MODEL SERVICE   │           │
               │             │  unprivileged;   │           │
               │             │  emits proposals │           │
               │             └────────┬─────────┘           │
               ▼                      ▼ proposal            ▼
┌────────────────────────────────────────────────────────────────────────┐
│  CORE                                                                  │
│  ┌───────────┐ ┌───────────┐ ┌─────────┐ ┌──────────────┐ ┌─────────┐ │
│  │ INCIDENT  │▶│ DIAGNOSER │▶│ POLICY  │▶│ EXECUTOR     │▶│ JOURNAL │ │
│  │ lifecycle │ │ search    │ │ derives │ │ transaction  │ │ durable │ │
│  │ budgets   │ │ over graph│ │ facts;  │ │ protocol     │ │ states  │ │
│  │ cooldowns │ │           │ │ decides │ │              │ │         │ │
│  └─────▲─────┘ └───────────┘ └─────────┘ └──────┬───────┘ └────▲────┘ │
│        │ divergences                            │               │      │
└────────┼────────────────────────────────────────┼───────────────┼──────┘
         │                                        ▼               │
┌────────┴───────────────────┐   ┌──────────────────────────┐ ┌──┴──────────┐
│  STATE                     │   │  BACKENDS (swappable)    │ │ RECOVERY    │
│  desired (conditions,      │◀──│  units: systemd          │ │ WATCHDOG    │
│   suppressions)            │   │  config: nixos-rebuild   │ │ separate    │
│  observed (unknown, stale) │   │  snapshots: btrfs/ZFS    │ │ unit; reads │
│  health (probe contract)   │   │  inventory: udev/sysfs   │ │ the journal │
│  graph (typed edges)       │   │  kernel: Linux           │ └─────────────┘
└────────────────────────────┘   └──────────────────────────┘
                                            │
                             ┌──────────────┴───────────────┐
                             │  TRAINING GYM (offline)      │
                             │  faults, lifecycle cases,    │
                             │  disruption metrics          │
                             └──────────────────────────────┘
```

Arrows into the core carry *proposals*. Only the executor calls backends. The model has exactly one write capability: submit a proposal. The recovery watchdog is a separate process that can finish or revert a transaction when the daemon is gone.

## 3. Feature overview

| Feature | What the user sees | Status at v1 (NixOS service) |
| --- | --- | --- |
| Fault detection | "audio: Failed (probe tone-playback)" within seconds; "Unknown" when evidence is stale | Yes |
| Deterministic repair | Restart-and-rebind faults fixed with no model, logged with reason | Yes |
| Incident discipline | No restart loops: cooldowns, backoff, flap detection, cooperation with systemd's own restarts | Yes |
| Respecting intent | A service the user stopped stays stopped; conditional desired state (after login, when device present) | Yes |
| Durable transactions | A config change survives Planarian being killed mid-activation; the watchdog commits or reverts | Yes |
| Automatic revert | Failed probes after activation revert without the user | Yes |
| Model-assisted repair | Harder faults diagnosed by a local 4B model; proposals previewed | Phase B |
| Natural-language operation | "reconnect wifi", "make text bigger" → matched action or cataloged change with preview | Yes |
| Risk tiers and approval | Security, external, user-data changes wait; approval re-validated at execution | Yes (console approval in A; broker in C) |
| Disruption awareness | Actions that would drop your session or connection are classed and surfaced as such | Yes |
| Snapshots | Snapshot before every switch; restore on request; space-budgeted | If btrfs or ZFS present |
| Boot-confirmed generations | A kernel change is not "good" until it has rebooted | Yes |
| Visual console | Live graph of desired vs observed vs health, timeline, generations, incidents | Yes (read-only in A) |
| Degraded mode | Everything but model-assisted repair and fuzzy requests works with no model | Yes |

## 4. Roadmap

Each phase ships something usable on its own. Later phases replace a backend; the contract does not change.

| Phase | Deliverable | Gate to exit |
| --- | --- | --- |
| **A · Contract on NixOS 26.05** | `planariad`: schema, state model (desired/observed/health/graph), policy, executor with transaction journal and recovery watchdog, systemd and nixos-rebuild backends, change catalog, deterministic diagnoser and incident manager, intent matcher, `ask` CLI, read-only visual console, fault-injection gym with lifecycle cases. Gym also runs against an Asterinas NixOS VM (non-gating; allowed to stay red; no engineering time). `schema`, `policy`, and the transaction kernel in the Verus subset. No model. | **GA:** (1) the demonstration: inject a fault → repaired; inject a bad configuration → reverted; kill `planariad` during activation → watchdog recovers; restart the daemon → it reconciles the journal and explains what happened accurately. (2) ≥ 60% of the catalog cleared deterministically; every bad generation reverted; the manifest-weakening fault rejected; zero gamed successes; unnecessary-intervention rate on the intent cases = 0. (3) `policy` proofs pass in CI. |
| **B · The model** | Model service; boot-model fine-tune via distillation; summoned only on diagnoser exhaustion; evaluation suite with held-out fault families. | **GB:** diagnoser + model clear ≥ Y% including held-out families; a worse model is rejected by the suite. |
| **C · Daily driver** | Console as a libcosmic app with approvals; approval broker; snapshot backend; hardware inventory and explain; public release as a NixOS module and flake with a COSMIC reference configuration. Real users feed the gym. | **GC:** ten external users for a month; every reported fault reproduced as a catalog entry. |
| **D · Rust system layer** | Snix-based evaluator and store; Rust init and supervisor; Rust CoW filesystem. Linux kernel. Backend contracts revised from what A–C taught. | **GD:** no systemd, no C Nix; full catalog passes. |
| **E · Asterinas** | Kernel swap; reference-laptop drivers; Smithay desktop; secure attention key; Verus on the core. | **GE:** reference laptop boots, suspends, connects, plays audio, runs the desktop, survives the catalog from cold boot. |
| **F · Acceleration** | GPU drivers, model on GPU, COSMIC migration, second machine, ARM64. | **GF:** accelerated desktop and model on both machines; planner correct under injected accelerator failure. |

**Firmware:** binary vendor firmware is loaded as data by Rust drivers and is allowed permanently.

---

# Part II — Specification for implementation

Normative unless marked *draft*. MUST/MUST NOT are requirements; SHOULD is a default the agent may deviate from with a logged reason in `docs/deviations.md`.

## 5. Scope and non-goals

**Phase A in scope:** everything in the Phase A roadmap row, on NixOS 26.05 with systemd, D-Bus, udev; btrfs/ZFS optional; root via a dedicated systemd service.

**Out of scope for A:** the model service (B), approval broker and console write paths beyond §16 (C), snapshot restore (C), Rust evaluator or init (D), kernel work (E). Interfaces to them exist as traits with one implementation.

## 6. Repository layout

```
planarian/
  Cargo.toml                 workspace
  crates/
    schema/                  types; no I/O (§8). Verus subset.
    policy/                  decision function (§11). Verus subset.
    txn/                     transaction kernel: journal states, recovery (§12). Verus subset.
    state/                   desired/observed/health/graph assembly; probe runner (§10)
    exec/                    executor protocol around txn (§12)
    incident/                incident lifecycle, budgets, cooldowns (§13)
    diagnose/                deterministic search (§13)
    changes/                 change catalog: typed handlers (§9)
    intent/                  phrase → transition or desired-state override (§14)
    backends/
      systemd/   nixos-rebuild/   udev/   snapshot-none/   snapshot-btrfs/ (C)
    watchdog/                planarian-recovery: separate binary (§12)
    daemon/                  planariad: wiring, IPC, systemd units
    cli/                     `planarian`, `ask`
    console/                 iced read-only console (§16a)
    gym/                     catalog, VM harness, scoring, metrics (§15)
    model/                   (B) stub only
  nix/
    module.nix               services.planarian
    manifest.nix             unit manifest options (§9)
    changes/                 shipped change catalog entries
    reference.nix            COSMIC + greeter + console autostart
    tests/                   NixOS VM tests used by the gym
  docs/                      SPEC.md (this), AGENTS.md (§18), deviations.md, pins.md, assumptions.md (§17a)
```

Dependency rule, enforced in CI: `schema`, `policy`, `txn`, `exec`, `diagnose`, `incident`, `state` MUST NOT depend on `backends/*`, `std::process`, or read `/proc`, `/sys`, `/nix`. Backends are passed as **generic type parameters**; in Phase A a single `enum Backends` wraps the concrete set. No `dyn Trait` in `schema`, `policy`, `txn`, `exec`.

## 7. Principles and invariants

**Principles**

1. The healer is not the patient. The repair core is outside the blast radius of anything it changes; no generation or proposal can modify it.
2. The model proposes; machinery disposes. Model output is a typed proposal, never a command.
3. Machinery before model. Deterministic code handles everything it can; the model is a fallback.
4. Desired, observed, and healthy are three different things. Never collapse them.
5. Every change is a transaction. Journaled before, probed after, reverted on failure, recoverable if the daemon dies.
6. Authority is derived, never supplied. The executor computes what a change touches and how risky it is from the evaluated configuration; proposal fields carry no authority.
7. Sensor input is data, never instructions.
8. Degrade to a working machine. Without the model, the console, or the network, the system boots, runs, repairs simple faults, and reverts.
9. Don't fight the user. A deliberate stop is a suppression, not a fault.
10. Disruption is a cost. Prefer the least disruptive repair; surface disruption before acting.
11. The oracle is protected. Nothing a proposal can do may weaken a canonical probe.
12. Grow into the hardware.

**Invariants** (checked by `txn` and `policy`; each is a test in `gym` and, where marked, a proof)

| ID | Invariant | Proof |
| --- | --- | --- |
| I1 | A boot-confirmed known-good generation always exists, is bootable, and is in the boot menu; an `accepted_baseline` never replaces it there. | D |
| I2 | The installed core package's hash equals the hash recorded in its signature. | E |
| I3 | Garbage collection never removes known-good, the previous generation, the current generation, an in-flight candidate, or the boot model. | A (test), D (proof) |
| I4 | `Running` means desired-Running under the current conditions, observed-active, and every *applicable Readiness* probe passed with fresh evidence. Diagnostic probes never determine Running. | A |
| I5 | Forbidden actions are unrepresentable as transitions; `Decision::Reject` is never converted to any tier by any setting. | A (proof) |
| I6 | At most one generation-changing transaction is active; no transition executes during `Activating`, `Published`, `Promoted`, or `Reverting`. | A (proof) |
| I7 | Every executed transition is logged with proposal, source, pre- and post-state, derived facts, policy version, probe evidence, decision, and outcome. | A |
| I8 | A tier-3 transition executes only with an approval token bound to the concrete candidate (§12), re-validated immediately before execution. | A, C (proof) |
| I9 | The model process holds exactly one write capability: submit a proposal. | E |
| I10 | No change that removes or alters a canonical probe executes below AskFirst, and canonical probes are evaluated from the installed core package regardless of the active generation. | A |
| I11 | A session's cumulative effect is classified at least as high as any single transition producing it. | A (proof) |
| I12 | Under the progress assumptions of §17a, every transaction in the journal reaches a terminal state (`Committed`, `Reverted`, `Rejected`, `Cancelled`, or `RecoveryFailed`); `RecoveryFailed` always alerts and sets the recovery interlock. | A (proof, conditional) |
| I15 | Exactly one owner (lease) per transaction; a mutating call with a stale epoch is refused; only the lease holder advances the journal. | A (proof) |
| I13 | A suppressed unit is never a repair target while its suppression holds. | A |
| I14 | Policy facts (sensitivity, affected units, manifest-touching, caller identity) are derived by the executor from the evaluated generation, never read from a proposal. | A (proof) |

## 8. Schema (crate `schema`)

*Draft; §18 lists what must be preserved.* `BTreeMap` below is the readable form; the implementation uses `vstd`-compatible structures.

```rust
pub struct Hash([u8; 32]);
pub struct GenerationId(u64);
pub struct StorePath(String);
pub struct ProbeId(String);
pub struct ChangeId(String);
pub struct IncidentId(u64);
pub struct TxnId(u64);
pub struct PolicyVersion(Hash);

pub struct UnitId { pub kind: UnitKind, pub name: String, pub scope: Scope }
pub enum UnitKind { Service, Device }
pub enum Scope { System, User { uid: u32, session: Option<String> } }

// ---------- Desired ----------
pub enum Condition {
    Always,
    SessionEstablished { uid: Option<u32> },  // logind reports a new session of class `user` on a seat (authentication
                                              // succeeded); greeter and background/`manager` sessions are excluded;
                                              // independent of whether the desktop then comes up
    DeviceConnected(UnitId),
    OnAcPower, OnBattery,
    All(Vec<Condition>), Any(Vec<Condition>),
}
pub enum DesiredStatus { Running, Stopped, Bound, Absent }
pub struct Desired { pub status: DesiredStatus, pub when: Condition }

pub struct Suppression {
    pub unit: UnitId,
    pub until: Until,                        // time, next boot, or explicit lift
    pub reason: String,
    pub by: Actor,                           // user via CLI/console, or a transaction in progress
}
pub enum Until { At(SystemTime), NextBoot, Explicit }

// ---------- Graph ----------
pub enum EdgeKind {
    Ordering,                                // After=/Before=: never followed in diagnosis
    Wants,                                   // Wants=: weak; the wanting unit runs without it; never a root cause for it
    Requires,                                // Requires=/BindsTo=/Requisite= or manifest: functional prerequisite
    Diagnostic { confidence: f32 },          // manifest or learned; may form cycles (§13)
}
pub struct Edge { pub from: UnitId, pub to: UnitId, pub kind: EdgeKind, pub origin: EdgeOrigin }
pub enum EdgeOrigin { SystemdRequires, SystemdWants, SystemdAfter, Manifest, Learned }

// ---------- Risk metadata (static, from the evaluated generation) ----------
pub enum Sensitivity { Routine, Security, UserData, External, Core }
pub struct Sensitivities(BTreeSet<Sensitivity>);       // composable
pub enum Disruption { None, Brief, SessionLoss, DataInterruption, ConnectivityLoss }
pub enum Recovery { Idempotent, Revertible, NonReversible }

pub struct UnitDef {
    pub id: UnitId,
    pub desired: Desired,
    pub edges: Vec<Edge>,
    pub sensitivity: Sensitivities,
    pub restart_disruption: Disruption,
    pub probes: Vec<ProbeDef>,
    pub synonyms: Vec<String>,
    pub systemd_restart: Option<SystemdRestartPolicy>,   // so incident mgmt can defer to it
}
pub type UnitDefs = BTreeMap<UnitId, UnitDef>;

// ---------- Health ----------
pub struct ProbeDef {
    pub id: ProbeId,
    pub kind: ProbeKind,
    pub timeout: Duration,
    pub origin: ProbeOrigin,                 // Canonical | User
    pub role: ProbeRole,                     // Readiness feeds Running/Unknown; Diagnostic never does
    pub cadence: Cadence,
    pub cost: ProbeCost,
    pub side_effects: SideEffects,           // None | Audible | Visible | Network | Disk
    pub establishes: String,                 // what a pass actually shows, in plain words
}
pub enum ProbeKind { SystemdActive, Tcp { addr: String }, Http { url: String, status: u16 }, Exec { argv: Vec<String>, sandbox: ProbeSandbox } }
pub struct ProbeSandbox { pub uid: u32, pub caps: Vec<String>, pub max_output: usize, pub cpu_ms: u32, pub network: bool }
pub enum ProbeRole { Readiness, Diagnostic }   // Readiness permits side_effects None or Measurement only; everything else MUST be Diagnostic
pub enum Cadence { EveryTick, Every(Duration), OnEvent, OnDemand }
pub enum ProbeCost { Trivial, Cheap, WakesHardware }
pub enum SideEffects {
    None,
    Measurement { bytes_max: u32, per: Duration },   // bounded read-only I/O (a TCP connect, a GET to a health endpoint);
                                                     // permitted for Readiness probes at a declared rate
    Audible, Visible, RemoteStateChange, Disk,       // Diagnostic only, OnDemand only
}
pub enum ProbeResult { Pass, Fail(String), Timeout, Error(String) }
pub struct Evidence { pub result: ProbeResult, pub at: SystemTime, pub stale_after: Duration }

// ---------- Observed ----------
pub enum Observed {
    Unknown { since: SystemTime, reason: String },   // stale evidence, probe timeout, backend error
    Transitioning { from: Box<Observed>, since: SystemTime },
    Absent, Detected, Bound, Active, Failed(Reason),
}
pub enum Reason { ExitCode(i32), DriverError(String), Backend(String) }

/// Derived, never stored as truth on its own.
pub enum UnitStatus { Running, Degraded(Vec<ProbeId>), Stopped, Suppressed, Unknown, Failed(Reason), Absent, Detected, Bound, Transitioning }

pub struct SystemState {
    pub generation: GenerationId,
    pub known_good: GenerationId,            // boot-confirmed
    pub live_tested: Option<GenerationId>,   // passed probes live, not yet rebooted
    pub units: BTreeMap<UnitId, (Observed, Vec<Evidence>)>,
    pub suppressions: Vec<Suppression>,
    pub conditions: BTreeSet<Condition>,     // which conditions currently hold
    pub resources: Resources,                // excluded from digest
    pub core_hash: Hash,
    pub observed_at: SystemTime,             // excluded from digest
}
impl SystemState { pub fn digest(&self) -> Hash; pub fn status(&self, id: &UnitId, defs: &UnitDefs) -> UnitStatus; }

// ---------- Transitions ----------
pub enum Transition {
    RestartUnit(UnitId),
    StopUnit(UnitId),
    BindDriver { device: UnitId, driver: StorePath },
    ApplyChange { change: ChangeId, args: BTreeMap<String, Value> },   // cataloged (§9); executor computes the diff
    SwitchGeneration(GenerationId),
    Revert { to: GenerationId },
    Rollback,                                // to known_good
    LoadModel(ModelId),                      // B
    RestoreSnapshot(SnapshotId),             // C
    CollectGarbage { emergency: bool },
    SetRuntimeOption { path: String, value: Value },
    Suppress(Suppression),                   // leave-alone only; does not stop anything
    Unsuppress(UnitId),
    StopAndSuppress { unit: UnitId, until: Until, reason: String },   // the user's "stop X": suppression journaled, then stop
}

/// Per-transition recovery strategy, fixed by the spec, not the proposer (§12).
pub enum RecoveryStrategy {
    ReobserveOnly,             // runtime unit actions: never a generation operation
    RevertGeneration,          // generation operations: fixed `revert_to`, full journal path
    UnbindDevice,              // BindDriver: on failure, unbind and rebind the previously bound driver
    RestoreSnapshotThenRevert,
}
/// Every transition has exactly one handler and one recovery strategy, fixed by the spec and
/// independent of its tier (§12). The crash-recovery table branches on `recovery`, never on tier.
pub enum Handler { UnitOp, GenerationOp, DeviceOp, SnapshotOp, GcOp, IntentOp }

pub enum Tier { Observe, Runtime, Tested, AskFirst }
pub enum Decision { Allow(Tier), Reject(RejectReason) }
pub enum RejectReason { Forbidden, CoreTarget, ProbeTamper, NotInCatalog, LockedOption, Stale, Other(String) }

/// Derived by the executor from the evaluated generation — never from the proposal (I14).
pub struct DerivedFacts {
    pub affected_units: BTreeSet<UnitId>,
    pub sensitivity: Sensitivities,
    pub disruption: Disruption,
    pub recovery: Recovery,
    pub touches_manifest: bool,
    pub touches_canonical_probe: bool,
    pub touches_core: bool,
    pub caller: Actor,
    pub config_diff: Option<ConfigDiff>,
}

pub trait TransitionSpec {
    fn precondition(&self, s: &SystemState, defs: &UnitDefs) -> bool;
    fn predict(&self, s: &SystemState, defs: &UnitDefs) -> Expectation;
    fn derive(&self, s: &SystemState, defs: &UnitDefs, gen: &EvaluatedGeneration, caller: Actor) -> DerivedFacts;
}

pub struct Expectation {
    pub units: BTreeMap<UnitId, UnitStatus>,
    pub generation: Option<GenerationId>,
    pub may_change: BTreeSet<UnitId>,
    pub others_unchanged: bool,
    pub settle: Settle,
}
pub enum Settle { Duration(Duration), Ready { unit: UnitId, timeout: Duration } }

pub struct Proposal {
    pub observed: Hash,
    pub transition: Transition,
    pub expected: Expectation,               // MUST refine spec.predict(); checked in §12 step 3
    pub reason: String,
    pub source: Source,
}
pub enum Source { Diagnoser { incident: IncidentId }, Model(ModelId), User, Intent { phrase: String, confidence: f32 } }
pub enum Actor { Daemon, Watchdog, User { uid: u32 }, Model(ModelId) }

// ---------- Incidents ----------
pub enum IncidentState { Open, Cooldown { until: SystemTime }, Escalated, Closed, Regressed { count: u8 } }
pub struct Incident {
    pub id: IncidentId,
    pub target: UnitId,
    pub divergence: (DesiredStatus, UnitStatus),
    pub opened: SystemTime,
    pub attempts: Vec<(TxnId, Outcome)>,
    pub budget_left: u8,                     // persisted; survives daemon restart
    pub state: IncidentState,
    pub backoff: Duration,
}

// ---------- Transactions ----------
pub enum TxnState {
    Prepared, Staged, Built, Activating, Checking,
    Published,                               // boot entry written
    Promoted,                                // override source promoted
    Committed, Reverting, Reverted, RecoveryFailed,
    Rejected(RejectReason),                  // terminal: refused after Prepared (precondition, expired/invalidated approval, policy)
    Cancelled(Actor),                        // terminal: withdrawn before any mutation
}
/// Exclusive ownership of a transaction (§12). Stored in the journal; every
/// mutating backend call carries the epoch and is refused if it is not current.
pub struct Lease { pub owner: OwnerId, pub epoch: u64, pub worker_pid: Option<u32>, pub renewed: SystemTime, pub jobs: Vec<JobId> }   // jobs: supervisor jobs this owner submitted
pub enum OwnerId { Daemon { pid: u32, boot_id: Hash }, Watchdog { pid: u32, boot_id: Hash } }

pub struct Transaction {
    pub id: TxnId,
    pub state: TxnState,
    pub lease: Lease,
    pub base_source: Option<Hash>,           // NAR hash of the owner's Nix-visible source with the BASE override, at Prepared (§9)
    pub staged_source: Option<Hash>,         // NAR hash of the candidate tree actually evaluated and built (§9)
    pub base_override: Option<Hash>,         // content hash of the override file as it was at Prepared (§9)
    pub candidate_override: Option<Hash>,    // content hash of the staged candidate override
    pub gc_root: Option<PathBuf>,            // /nix/var/nix/gcroots/planarian/<txn>, created at Built (I3)
    pub recovery: RecoveryStrategy,
    pub transition: Transition,
    pub facts: DerivedFacts,
    pub base: GenerationId,
    pub candidate: Option<(GenerationId, StorePath)>,
    pub policy: PolicyVersion,
    pub approval: Option<ApprovalToken>,
    pub snapshot: Option<SnapshotId>,
    pub expected: Expectation,
    pub started: SystemTime,
    pub deadline: SystemTime,                // watchdog acts after this
    pub revert_to: GenerationId,             // fixed at Prepared; authorized with the txn
}
pub enum Outcome { Succeeded, Failed(String), Partial(String), Unknown(String) }

pub struct ApprovalToken {
    pub bound_to: Hash,      // hash(transition, staged_source, candidate store path, base generation, policy version,
                             //      cumulative-diff hash, derived facts, expected, revert_to, recovery strategy)
    pub issued: SystemTime, pub expires: SystemTime, pub nonce: [u8; 16], pub used: bool,
}

pub struct Session { pub applied: Vec<TxnId>, pub cumulative: ConfigDiff, pub policy: PolicyVersion }

// ---------- Backends (generic, one impl each in A) ----------
pub trait UnitBackend {
    fn observe(&self, id: &UnitId) -> Result<Observed, Outcome>;
    fn restart(&self, id: &UnitId) -> Outcome;
    fn stop(&self, id: &UnitId) -> Outcome;
    fn list(&self) -> Result<Vec<UnitId>, Outcome>;
}
pub trait GenerationBackend {
    // read-only (allowed before Prepared)
    fn current(&self) -> Result<GenerationId, Outcome>;
    fn boot_entries(&self) -> Result<Vec<GenerationId>, Outcome>;
    fn last_booted(&self) -> Result<GenerationId, Outcome>;
    fn stage(&self, owner_cfg: &PinnedSource, overrides: &OverrideSet) -> Result<StagedSource, Outcome>;  // immutable copy; returns its NAR hash
    fn evaluate(&self, src: &StagedSource) -> Result<EvaluatedGeneration, Outcome>;   // pure-eval; option set, UnitDefs, activation plan
    fn build(&self, eval: &EvaluatedGeneration) -> Result<(GenerationId, StorePath, PathBuf /* build root */), Outcome>;   // store-only; roots its output under gcroots/planarian/builds/
    // mutating (require durable Prepared and a current lease epoch)
    fn activate_live(&self, g: GenerationId, lease: &Lease) -> Outcome;              // switch-to-configuration test
    fn publish_boot(&self, g: GenerationId, lease: &Lease) -> Outcome;               // boot entry only; no re-activation
    fn protect(&self, g: GenerationId, lease: &Lease) -> Outcome;
    fn pending_jobs(&self) -> Result<Vec<JobId>, Outcome>;                           // supervisor jobs still running
    fn jobs_tagged(&self, op: &OpId) -> Result<Option<Vec<JobId>>, Outcome>;         // discover jobs by durable operation id; None = backend cannot say
    fn cancel(&self, job: &JobId, lease: &Lease) -> Outcome;
    fn verify_candidate(&self, path: &StorePath, expected: &Hash) -> Result<bool, Outcome>;
}
pub trait SnapshotBackend { fn supported(&self) -> bool; fn snapshot(&self, label: &str) -> Result<SnapshotId, Outcome>; fn restore(&self, id: &SnapshotId) -> Outcome; fn usage_bytes(&self) -> u64; }
pub trait InventoryBackend {
    fn devices(&self) -> Result<Vec<DeviceInfo>, Outcome>;
    fn resources(&self) -> Result<Resources, Outcome>;
    fn bound_driver(&self, device: &UnitId) -> Result<Option<StorePath>, Outcome>;
    fn bind(&self, device: &UnitId, driver: &StorePath, lease: &Lease) -> Outcome;     // mutating; sysfs driver bind
    fn unbind(&self, device: &UnitId, lease: &Lease) -> Outcome;                        // mutating
}
```

**Status derivation** (`SystemState::status`), in order: Suppressed if a suppression holds; else if the desired condition does not hold, *not expected* (observed status reported, no incident); else **Failed** if `Observed::Failed` (a definite supervisor failure is never masked by stale probes); else Unknown if any *Readiness* probe's evidence is stale or timed out; else Running if observed Active and all Readiness probes passed fresh; Degraded if Active with a failed Readiness probe; else from `Observed`. Diagnostic probes never affect status; their evidence is shown in the console and used by the diagnoser only.

**systemd mapping:** `active` → Active; `failed` → Failed(ExitCode); `inactive`/`dead` → Bound (Stopped once desired is considered); `activating`/`deactivating`/`reloading` → Transitioning; not found → Absent; D-Bus error → Unknown. Devices via udev: present without driver → Detected; bound → Bound/Active.

## 9. Manifest, change catalog, and configuration editing

**Manifest** (`services.planarian.units.<name>`): `desired` (status + condition), `edges` (kind + target), `sensitivity` (set), `restartDisruption`, `probes`, `synonyms`. Defaults derived at build time: `Requires=`/`BindsTo=`/`Requisite=` → `Requires` edges; `Wants=` → `Wants` edges (weak, never a root cause); `After=` → `Ordering` edges only; functional prerequisites systemd cannot express come only from the manifest; `predicted` from `enable`; sensitivity from a shipped table; `restart_disruption` from a shipped table (display-manager → SessionLoss; network → ConnectivityLoss; databases → DataInterruption). `Diagnostic` edges come only from the manifest or, later, from learned data, and carry a confidence. The manifest and the override file have `Sensitivity::{Security}`.

**Canonical probes** ship in the `planarian` package for networking, sshd, pipewire, display-manager, graphical-session, storage, and the user services the reference config enables. A generation may add `User` probes; it may not remove or alter canonical ones (I10). The reference-config `graphical-session` unit has desired condition `SessionEstablished` (logind reports a new session, i.e. authentication succeeded) and a Readiness probe "`graphical-session.target` reached within 60 s of that session's creation." The condition comes from logind, the result from systemd, so a desktop that fails after a successful login opens an incident, and an idle greeter opens none. The greeter's probe is `SystemdActive`. Canonical probes are tagged `role: Readiness` where their side effects are `None` or a bounded `Measurement` (TCP connects, GETs to health endpoints); the audio tone and any `Audible`/`Visible`/`RemoteStateChange`/`Disk` probe are `Diagnostic` and OnDemand.

**Applicability of probes to authorized desired-state changes.** A probe applies only while its unit is desired-present under the *candidate's* desired state. A transaction that disables a service (authorized by policy) makes that service's probes inapplicable in the candidate; it is not probe tampering, which means changing a probe's *definition*. Both are derived facts: `touches_canonical_probe` (definition changed) versus `changes_desired` (applicability changed). Only the former is protected by I10.

**Change catalog** (`crates/changes`, `nix/changes/`): every `ApplyChange` names a catalog entry. An entry has: `id`, `args` with types and permitted values, a `handler` that produces option assignments for the override file, `affected_modules`, `description`, and `locked_if` (user `mkForce` detected). The executor evaluates the handler's output (`GenerationBackend::evaluate`) and **derives** affected units, sensitivity, disruption, and manifest/probe-touching from the evaluated generation's option set and activation plan, not from the entry's own metadata (I14); the entry's `affected_modules` is a hint for the matcher and a test assertion, not a policy input. Phase A ships entries for: enable/disable a service from an allowlist; set font scale; set keyboard layout; select Wi-Fi network; set a service's listen address from a permitted set; re-enable a manifest-predicted option observed disabled. The model (B) may propose *new catalog entries* for human review; it never writes raw Nix.

**Override source and staged evaluation.** Planarian never edits the user's own Nix. The owner's flake imports `./planarian/overrides.nix` *relative to the flake root* (the module template does this), containing flat option assignments wrapped in `lib.mkOverride 90`. A candidate is never evaluated from mutable host files:

1. **Stage.** `GenerationBackend::stage` copies the owner's configuration as Nix will see it (for a Git flake: the tracked files from the working tree, *including uncommitted modifications to tracked files*, which is what a local Git flake input exposes; untracked files are excluded and reported; for a non-Git directory: the whole directory) plus `flake.lock` into an immutable directory `/var/lib/planarian/stage/<txn>/`, computes and records **`base_source`** (the NAR hash of that copy *before* any override replacement, i.e. the owner's source with the base override), then replaces `planarian/overrides.nix` with the candidate override set and records **`staged_source`** (the NAR hash of the tree actually evaluated and built). Both identities, plus `base_override` and `candidate_override`, are bound to the transaction and the approval token. The pre-activation stale check (step 6) recomputes the NAR hash of the same Nix-visible set of bytes from the owner's working tree and compares it to **`base_source` only**; `staged_source` is what the candidate must match at `verify_candidate`. So a change that alters only the override reaches activation without `Stale`, and an uncommitted owner edit after staging produces `Stale`. Nothing is "pinned by hash and read later": the bytes evaluated are the staged bytes.
2. **Evaluate** the staged source with `pure-eval` on (it is a path input with no external state) and record the evaluated option set, `UnitDefs`, and activation plan.
3. **Build** before approval. The candidate store path is determined by the build; approval binds to it. Before `activate_live`, `verify_candidate` confirms the realized path still exists and matches.
4. **Base and candidate identities.** At `Prepared` the executor copies the live `overrides.nix` to the transaction-specific, immutable `/var/lib/planarian/txn/<txn>/base.nix` and records its content hash as `base_override`; the staged candidate's content hash is `candidate_override`. No shared `.prev` file exists. **Promote** (on the commit path, after `publish_boot`): read the live file's hash; if it equals `candidate_override`, the step is already done; if it equals `base_override`, write the candidate to a temp file, fsync, atomic rename over the live path, fsync the directory; anything else → `RecoveryFailed` (a third party changed the file). **Restore** (revert path): the same procedure with base and candidate swapped. Both are therefore idempotent by construction and cannot save the candidate over the base. The `txn/<txn>/` directory is deleted only after `Committed`/`Reverted` and a successful checkpoint (§12c).
5. **GC root.** `build` is store-only bookkeeping and roots its own output: on success it creates `/nix/var/nix/gcroots/planarian/builds/<staged_source hex>` pointing at the candidate store path, before any transaction exists and without a lease (this is the one root operation that does not require `Prepared`; `protect` is the lease-gated form used for generations). When the transaction is created in §12 step 4, it *adopts* the root (recorded as `gc_root`); the root is removed when the transaction reaches a terminal state (kept if `Committed`, since the generation's own profile link then roots it). On startup the daemon removes any `builds/*` root not adopted by a live transaction and older than 24 h. A policy record is never a root; only the symlink is. Gym case: run GC while approval is pending; the candidate survives.
6. **Stale check.** If the owner's Nix-visible source no longer hashes to `base_source` at any check between `Staged` and `Activating`, the transaction is `Rejected(Stale)` and re-prepared; the staged copy is unaffected, but the policy facts were derived against a source that no longer matches what the owner will build next. Gym cases: an override-only change with no owner edit activates without `Stale`; an uncommitted edit to a tracked owner file after staging produces `Stale`.

Options the user set with `mkForce` are `locked`. Gym cases: an override-only candidate changes the evaluated output; the owner edits the source during a build; a crash at each commit boundary (§12).

**Executor-owned requirements.** Beyond the proposer's `expected`, the executor always requires: no unit outside `may_change` that is desired-present *under the candidate* leaves Running; no Readiness probe that is applicable under the candidate and passed before fails after; the generation equals the verified candidate. A proposer can only *add* claims.

## 10. State (crate `state`)

- **Tick:** 5 s and on systemd/udev/login events. Warn if a tick exceeds 500 ms.
- **Conditions** evaluated each tick from logind (sessions), udev (devices), upower (power). `SessionEstablished` counts only sessions of class `user` with a seat or a remote user (greeter, `manager`, and background sessions are ignored), and binds the graphical-session readiness deadline to that specific session id, so a second user logging in does not reset or satisfy the first session's deadline.
- **Probe contract.** Every probe runs in a sandbox (`ProbeSandbox`: dedicated uid, dropped capabilities, bounded CPU and output, network only if declared), is killed at timeout with its process group, and its output is logged as data. Probes with `side_effects` of `Audible`, `Visible`, `RemoteStateChange`, or `Disk` are `Diagnostic`, run `OnDemand` only, and `Audible`/`Visible` require a user-initiated diagnostic. `Measurement` side effects (a bounded, read-only network or local I/O such as a TCP connect or an HTTP GET to a declared health endpoint) are permitted for Readiness probes at the declared rate; the sandbox enforces `bytes_max`/`per`. A Readiness probe whose `establishes` names an external dependency (an upstream endpoint, a gateway) MUST declare a `Requires` or `Diagnostic` edge to a unit representing that dependency (`service:external:<name>`), so an unavailable dependency is diagnosed as such and never produces a local restart. Gym cases: a process stays active while its HTTP health endpoint returns 503 (Degraded, incident opens); the external dependency is down (incident targets the external unit; no local restart). `WakesHardware` probes default `Every(60 s)`, `Every(300 s)` on battery. A `Timeout` or `Error` yields `Unknown`, never `Failed`.
- **Evidence** carries `stale_after`; the status derivation treats stale *Readiness* evidence as Unknown; stale Diagnostic evidence is displayed, never counted. An incident is not opened on Unknown; the probe is re-run with backoff and, after three consecutive Unknowns, a *diagnostic* incident is opened whose first candidate is "re-observe via a different Readiness probe," not a restart. Gym cases: Diagnostic evidence expires on a healthy machine (status stays Running); a definite `Observed::Failed` while another probe is stale (status is Failed, not Unknown).
- **Storage** is modeled per filesystem: `device:fs-root`, `device:fs-nix` (if separate), `device:fs-boot`, `device:fs-journal` (the filesystem holding the journal), each with a canonical Readiness probe (free ≥ max(2 GB, 5%) for root and nix; ≥ 64 MB for boot; journal headroom per §12c). Divergence on root/nix → `CollectGarbage` first.
- **User-scoped units** are keyed by uid and session; a user service is desired only while that user's session exists.
- **Boot confirmation:** on each boot, `GenerationBackend::last_booted()` is compared to the generation that was `live_tested`; if they match and canonical probes pass at the 10-minute checkpoint, that generation becomes `known_good`. A generation whose diff touches kernel, initrd, bootloader, or filesystem options can become `live_tested` but not `known_good` until confirmed by a reboot; the console says so.

## 11. Policy (crate `policy`)

- `decide(transition, facts: &DerivedFacts, state, defs, session, authz: &Authorization) -> Decision`. Pure. Reads nothing from `Proposal`.
- **Caller identity and authorization** are established by the daemon, not the proposal: the Unix socket peer is authenticated with `SO_PEERCRED`; `Actor::User { uid }` is set from it, and any actor field inside a proposal (e.g. `Suppression.by`) is overwritten. Authorization is a separate rule evaluated before risk: a user may act on units in their own `Scope::User` and on system units listed in `services.planarian.userControllable` (default: audio, display scaling, their own Wi-Fi selection); every other system action requires administrator authority (root, or membership in the `planarian-admin` group). Unauthorized → `Reject(Unauthorized)`, regardless of tier. The model and the daemon are never "authorized users"; their proposals follow the daemon rules.
- **Global floors**, applied before the per-transition table, to every transition kind: `recovery == NonReversible` → at least AskFirst; `disruption ∈ {SessionLoss, DataInterruption}` → at least AskFirst unless the caller is an authorized user whose own session it is; `disruption == ConnectivityLoss` → at least AskFirst unless the caller is a user with a local (non-remote) session. So a daemon-proposed `BindDriver` that would drop a session, or a `SetRuntimeOption` Wi-Fi change proposed by the diagnoser, both ask.
- Reject when: `touches_core`, forbidden transition, `touches_canonical_probe` (definition) outside AskFirst, change not in catalog, locked option, unauthorized caller.
- Tier otherwise, by table; escalations compose with the floors:

| Transition | Base | → AskFirst when |
| --- | --- | --- |
| RestartUnit / StopUnit | Runtime | sensitivity ∋ Security or External (floors cover disruption) |
| Suppress / Unsuppress / StopAndSuppress | Runtime | caller is not an authorized user; or the unit's sensitivity ∋ Security or External |
| BindDriver | Tested | sensitivity ∋ Security |
| ApplyChange | Tested | sensitivity ∌ only Routine; touches_manifest; touches_canonical_probe; cumulative diff non-Routine (I11) |
| SwitchGeneration / Revert | Tested | target not live-tested or known-good; revert target differs from the transaction's recorded `revert_to` |
| Rollback | Runtime | known_good would restore Security- or External-sensitive options that changed since (policy computes the diff) |
| LoadModel | Tested | not in hash-pinned catalog → Reject |
| RestoreSnapshot | AskFirst | always |
| CollectGarbage | Runtime | never (I3) |
| SetRuntimeOption | Runtime | not in the core allowlist → Reject |

- **Autonomy setting:** `max_tier ∈ {Observe, Runtime, Tested}`. Any `Allow(t)` with `t > max_tier` becomes `Allow(AskFirst)`. `Reject` is never affected (I5).
- **Disruption surfacing:** any Allow with disruption ≥ SessionLoss is logged and, if a console is attached, shown before execution with a 10 s cancel window for daemon-initiated actions.
- `PolicyVersion` is the hash of the policy crate build plus the shipped sensitivity tables; it is recorded in every transaction and token.

## 12. Executor and transaction kernel (crates `exec`, `txn`, `watchdog`)

**Journal:** append-only, write-ahead, fsync'd, in a preallocated file at `/var/lib/planarian/journal/` (§12c). **Read-only backend calls** (`current`, `boot_entries`, `last_booted`, `observe`, `stage`, `evaluate`, `build` — build writes only to the Nix store and activates nothing, so it is treated as read-only with respect to system state, but its output is recorded) may precede `Prepared`. **Every mutating call** (`activate_live`, `publish_boot`, `protect`, `restart`, `stop`, `snapshot`, `restore`, file promotion) requires a durably written `Prepared` record and a current lease epoch. `Prepared` is written on the Allow path as well as the AskFirst path.

**Ownership and fencing.** Each transaction has exactly one owner at a time (`Lease`). Mutating backend calls carry the lease epoch; the backend layer reads the journal's current epoch for that transaction and refuses the call if it differs (`Outcome::Failed("fenced")`). Mutations that take time (activation, revert) run in a **worker subprocess** whose pid is recorded in the lease and which inherits the epoch. Taking over a transaction means: write a new lease with `epoch + 1` (durably), send SIGTERM then SIGKILL to the previous worker's process group via pidfd, then establish **confirmed quiescence**. Every mutation attempt first journals a durable **operation id** (`OpId`, a record `{txn, epoch, seq}` written and fsynced *before* the backend call), and the backend call is tagged with it (for systemd: the job's unit is started with a transient property `X-Planarian-Op=<OpId>` via `SetUnitProperties` in the same D-Bus transaction, or, where the call cannot carry a tag, the daemon records the pre-call snapshot of `pending_jobs()` as the op's baseline). Quiescence then covers both the jobs in the old lease's `jobs` list *and* every job discovered by `jobs_tagged(op)` for each journaled `OpId` whose acknowledgment was never recorded. Every such job must be cancelled (`systemctl cancel <job>` where the supervisor supports it) and confirmed gone from `pending_jobs()`, and any activation worker's own child processes reaped; the new owner waits up to the job-drain limit (60 s) for that confirmation, and if quiescence cannot be confirmed, or `jobs_tagged` returns `None` for an unacknowledged `OpId` (the backend cannot say whether undiscovered work remains), it writes `RecoveryFailed` and blocks all further mutation rather than proceeding. A drain timeout is never permission to proceed, and neither is an empty list of *known* jobs. Gym case: accept an activation job, withhold its reply, kill the owner before the job id is journaled, start recovery; recovery must discover or fence the accepted work before any conflicting mutation. Only after confirmed quiescence may the new owner advance the journal. **Lease transfer is atomic:** the lease is a file `/var/lib/planarian/txn/<txn>/lease` replaced by atomic rename of a temp file whose name embeds the candidate epoch, after `flock` on the transaction directory; two processes attempting takeover serialize on the lock and the second sees the first's epoch and backs off. An old owner that wakes up finds its epoch stale on its next call and exits. **Only the current lease holder may advance the journal or commit.** Gym case: kill and immediately restart the daemon while a deliberately slow activation worker survives; assert activation and revert never overlap and the old owner cannot commit afterward.

**Protocol** for a `Proposal`:

1. Observe S0. If `proposal.observed != S0.digest()` → Reject `Stale`, return the current digest.
2. For `ApplyChange`: run the handler, `stage`, `evaluate`, and `build` (read-only path). Derive facts from the evaluated candidate.
3. **Refinement check:** `proposal.expected` MUST agree with `spec.predict()` on every unit the spec predicts, MUST NOT broaden `may_change`, MUST NOT set `others_unchanged = false` where the spec sets true. Violation → Reject. Executor-owned requirements (§9) are appended. The transition's `RecoveryStrategy` and `revert_to` are fixed here by the spec, not the proposer.
4. `policy.decide` (with authorization). `Reject` → log, alert if the source was the model. Otherwise create the transaction atomically: `mkdir /var/lib/planarian/txn/<txn>/` (fails if it exists), write `base.nix` and the initial lease (epoch 1, this daemon) into it, then journal **`Prepared`** (durable) with facts, expected, revert_to, recovery strategy, handler, staged_source, base/candidate override hashes, gc_root, candidate path, policy version, and the lease. The transaction does not exist until the `Prepared` record is durable; the directory alone is garbage the next startup removes. `AskFirst` → request a token bound as in §8, park. On token: **re-derive facts, re-run `decide`, recompute cumulative hash and candidate verification**; any difference in `bound_to` invalidates the token and re-requests. Tokens expire in 24 h and are single-use.
5. Check precondition against the current state. A failed precondition, an expired or invalidated approval that is not re-granted within its window, or a policy decision that changes to `Reject` on re-evaluation writes the terminal `Rejected(reason)` and releases the GC root; a user withdrawing a parked proposal writes `Cancelled`. Both are terminal and reopen the incident if one was waiting.
6. (The lease was created with the transaction in step 4.) Snapshot if facts.sensitivity ∋ UserData and supported; record. If unsupported in Phase A, log `NoSnapshot` and continue; from C, AskFirst.
7. Execute, by recovery strategy:
   Execution strategy is fixed per transition and is independent of tier:

   | Transition | Handler | Recovery | Notes |
   | --- | --- | --- | --- |
   | RestartUnit, StopUnit, StopAndSuppress, Suppress, Unsuppress | UnitOp / IntentOp | ReobserveOnly | `candidate = None`; never a generation operation |
   | SetRuntimeOption, CollectGarbage | UnitOp / GcOp | ReobserveOnly | same |
   | ApplyChange, SwitchGeneration, Revert, LoadModel | GenerationOp | RevertGeneration | full journal path below |
   | **Rollback** | GenerationOp | RevertGeneration | tier may be Runtime, but it is a generation operation: serialized (I6), owned, with `candidate = known_good` (or `accepted_baseline`), `publish_boot`, and override restoration to the override content recorded for that generation; its own `revert_to` is the generation it left |
   | BindDriver | DeviceOp | UnbindDevice | a device operation via the inventory backend (`bind`/`unbind` on the sysfs driver interface); no generation is built or activated; on failure or mismatch, unbind and rebind the previously bound driver (recorded at Prepared) |
   | RestoreSnapshot | SnapshotOp | RestoreSnapshotThenRevert | C |

   - **UnitOp / IntentOp / GcOp (`ReobserveOnly`):** journal `Activating` → backend call in-process → `Checking` → settle → observe → compare → journal `Committed` with the outcome recorded, whether or not the expectation held; a mismatch informs the incident and never triggers generation reversion. A `Partial`/`Unknown` outcome means re-observe and record, nothing more. `StopAndSuppress` journals the suppression *before* calling `stop`.
   - **GenerationOp (`RevertGeneration`):** `verify_candidate` → journal `Activating` → worker: `activate_live(candidate)` → journal `Checking` → run applicable Readiness probes from both the candidate's `UnitDefs` and the installed core, plus the expectation → **pass:** `publish_boot(candidate)` → journal `Published` → promote (§9 step 4) → journal `Promoted` → journal `Committed` (same record marks `live_tested`). **Fail:** journal `Reverting` → worker: `activate_live(revert_to)` → `publish_boot(revert_to)` → restore base override (§9 step 4) → re-probe → `Reverted`, or `RecoveryFailed` if revert probes fail (alerts; stops all autonomous action until a human acts).
   - **DeviceOp (`UnbindDevice`):** journal `Activating` with the previously bound driver recorded → `bind` → `Checking` → probes → pass: `Committed`; fail: `Reverting` → `unbind`, rebind previous → `Reverted`/`RecoveryFailed`. Gym case: a failed driver bind restores the previous driver and attempts no generation rollback.
   - **`RestoreSnapshotThenRevert`** (RestoreSnapshot): restore, then as above.
8. **Outcomes.** `Partial`/`Unknown` are never success. In `Activating` with `RevertGeneration`: re-observe; candidate active → `Checking`; else → `Reverting`. In `Checking`: probes decide. In `Published`/`Promoted`: the candidate is already live and tested; recovery *completes the commit* (re-run `publish_boot`, re-run the promotion rename — both idempotent) rather than reverting, unless probes now fail, in which case revert. The watchdog may complete these two steps because they are idempotent and were authorized by the transaction; it still cannot write `Committed` from any earlier state.
9. Log (I7) with `DerivedFacts`, `PolicyVersion`, probe evidence, decision, outcome, lease epoch.

**Crash-recovery table** (what the lease holder does on finding a transaction in each state):

| Found in | Action |
| --- | --- |
| Prepared, Staged, Built (any strategy) | Nothing was mutated; mark `Rejected(Interrupted)`, release the GC root, reopen the incident if any |
| Activating, `ReobserveOnly` | Fence; confirm quiescence; re-observe; write `Committed` with the observed outcome; inform the incident. Never a generation operation. |
| Activating, `RevertGeneration` | Fence; confirm quiescence; re-observe; candidate active → Checking, else Reverting |
| Activating, `UnbindDevice` | Fence; confirm quiescence; re-observe; bound to candidate driver → Checking, else restore previous driver → Reverted |
| Checking (generation / device) | Fence; confirm quiescence; re-run probes; pass → the complete commit path, fail → Reverting |
| Published | Promote by hash comparison (§9) → Promoted → Committed, unless probes fail → Reverting |
| Promoted | Write Committed |
| Reverting | Fence; confirm quiescence; re-run the strategy's revert steps (all idempotent) → Reverted or RecoveryFailed |
| Checking, `ReobserveOnly` | Fence; confirm quiescence; re-observe; write `Committed` with the observed outcome. Never the generation commit path. |
| RecoveryFailed | Alert; set the **recovery interlock** (§12c); refuse all autonomous transactions until an administrator records `planarian resolve <txn>` |

Gym cases: kill the daemon during a Runtime-tier `Rollback` (recovers as a generation operation) and during `StopAndSuppress` (recovers as a unit operation; no generation rollback attempted); an old backend job that outlives the 60 s drain (takeover ends in `RecoveryFailed`, never overlapping mutation); daemon and watchdog attempt takeover simultaneously (exactly one wins); daemon stays down after `Published` and after `Promoted` (watchdog completes the commit).

**Recovery watchdog.** `planarian-recovery.service`: separate unit, `Restart=always`, started before `planariad`, no dependency on it. Every 10 s it reads the journal; for a transaction in `Activating`/`Checking`/`Published`/`Promoted`/`Reverting` whose lease is unrenewed past `deadline` or whose owner pid is dead, it takes over the lease (fencing and confirmed quiescence as above) and runs the crash-recovery table. From `Checking` it does one of two complete things: if the authorized Readiness probes pass, it runs the **entire** authorized commit path (`publish_boot` → promote → `Committed`), because that path was authorized by the transaction and every step is idempotent; otherwise it reverts. It never stops partway. The earlier restriction is restated precisely: the watchdog may not write `Committed` without first having passed `Checking` itself. For a daemon that is alive and renewing its lease, the watchdog does nothing. Its binary and config are `Sensitivity::Core`.

**Daemon restart reconciliation.** On start, `planariad` reads the journal. If the watchdog holds a lease on a non-terminal transaction, the daemon **waits** until that transaction is terminal (it does not compete). Otherwise it takes over the lease (fencing) and runs the crash-recovery table. Either way it writes a reconciliation record (what it found, what it did, why) shown in the console on next open.

**Self-protection during activation.** The NixOS units for `planariad` and `planarian-recovery` are declared with `restartIfChanged = false` and `stopIfChanged = false`, which NixOS's switch honors by emitting `X-RestartIfChanged=false`/`X-StopIfChanged=false`, so no activation restarts or stops them. Independently, a candidate whose evaluated unit files for these two services differ from the running generation's is `touches_core` → Reject; upgrading Planarian itself is the core update path (Phase E), and in A–D a manual `nixos-rebuild` by root outside Planarian. Networking changes set `deadline` to 90 s because loss of the daemon's control path is likely.

**Concurrency:** I6. Runtime transitions may run during `build` but not during `Activating`/`Checking`/`Published`/`Promoted`/`Reverting`.

### 12a. Runtime-settable options

A core-owned allowlist (`Sensitivity::Core`; not extensible by manifest or model) of options whose effect can be applied immediately: font scale, volume, brightness, keyboard layout, Wi-Fi network selection. `SetRuntimeOption` applies the effect as a Runtime transition (subject to the global floors: Wi-Fi selection has `ConnectivityLoss`), then enqueues an `ApplyChange` write-back whose expectation is "no unit changes." If the write-back's build or probes fail, the runtime change stays in effect, the write-back is `Reverted` (override source untouched), the console shows "this setting will not survive reboot," and the incident manager does not retry it; the user may re-issue it. The write-back is never attempted while a generation transaction is active.

### 12b. Garbage collection and space budgets

Protected set per I3, including in-flight candidates (via their GC-root symlinks) and every `txn/<txn>/base.nix` of a non-terminal transaction. Policy: keep last 10 generations and 10 snapshots **and** space budgets (default: generations ≤ 20% of the Nix store's filesystem, snapshots ≤ 10% of their volume); whichever bound is hit first collects oldest-first down to the other. If the protected set alone exceeds a budget, `CollectGarbage` collects everything unprotected, reports `BudgetUnsatisfiable` with the shortfall, and never touches the protected set; the budget is then a target, not a guarantee, and the console says so. `CollectGarbage` is Runtime. Budgets are user settings, not manifest options.

### 12c. Journal headroom and ENOSPC

- **Format.** Records are length-prefixed and CRC-32C-checked; a torn or mismatched tail record is ignored and truncated on open, never interpreted as a transition. The journal is a preallocated file (default 64 MB) in `/var/lib/planarian/journal/`.
- **Checkpoint.** Compaction is not deletion of history; it is checkpoint-then-truncate. A checkpoint captures all live state the journal establishes: active suppressions (including `Until::Explicit` ones from long-committed `StopAndSuppress`), open and cooling incidents with their budgets and regression counts, consumed and outstanding approval tokens within their validity window, `known_good`/`accepted_baseline`/`live_tested`, every non-terminal transaction with its lease, the lease epochs of recently terminal ones, and the **recovery interlock**: the set of unresolved `RecoveryFailed` transactions with the facts needed to resolve them (what was being changed, which step failed, the observed state, the base and candidate override hashes, the revert target). The interlock is live control state, not history: while it is non-empty, autonomous mutation is blocked (only `Observe`-tier reads, user-authorized `Suppress`/`Unsuppress`, and administrator operations run), and it survives compaction and restart of both processes. It is cleared only by `planarian resolve <txn> --as-committed | --as-reverted | --manual-repaired`, an administrator-authorized operation journaled as a transition of its own; no other request clears it. Gym case: inject a failed revert, force compaction, restart daemon and watchdog; autonomous mutation stays blocked until the resolution is durably recorded. It is written to a temp file, fsynced, renamed over `checkpoint`, directory fsynced; only then is the journal truncated to records after the checkpoint's sequence number. Recovery from (checkpoint + retained journal) MUST reconstruct the same state as recovery from full history; the gym asserts this by comparing both reconstructions after forced compaction. Compaction triggers at 75% full.
- **Filesystem contract.** The preallocation guarantee holds only where in-place rewrite does not allocate: on ext4 and XFS a `fallocate`d file; on btrfs only with the journal directory marked `nodatacow` (`chattr +C` before creation) and the file preallocated; on ZFS it does not hold, and the daemon instead reserves space with a dedicated dataset `reservation`. The installer applies the layout-specific setup and the gym validates it per supported layout (ext4, btrfs, ZFS). If a recovery-path write to the preallocation fails with ENOSPC despite the contract, the daemon writes a fixed-size `RecoveryFailed` sentinel into a separate 4 KB file reserved at install and blocks all mutation. The reservation is counted in `device:fs-journal`'s Readiness probe.
- `CollectGarbage { emergency: true }` is the only transition allowed to start while `device:fs-journal` or `device:fs-nix` is below threshold; it is Runtime and its record fits the preallocation.
- ENOSPC behavior by state: in `Prepared`/`Staged`/`Built` (write to stage or store fails) → reject with `NoSpace`, open the storage incident, do not retry the original until it closes. In `Activating`/`Checking` → treat as probe failure → `Reverting`; the revert record is in the preallocation. In `Reverting` → if a revert step fails for space, mark `RecoveryFailed` via a fixed-size sentinel record and alert. Promotion (temp-write of the override file) failing for space → treat as Checking failure → revert; the live override file is untouched because the rename never happened.
- `/boot` is tracked separately: `publish_boot` failing for space → `Checking` failure → revert; the candidate is never left as the only boot entry.

Gym cases: fill the journal filesystem to the reserved-block boundary as the daemon's uid; verify that emergency collection is recorded and executed, or that mutation stops with an explicit `RecoveryFailed`/`NoSpace` status; repeat after a snapshot and after repeated journal reuse on btrfs; force compaction with a live Explicit suppression and an exhausted incident budget, then crash and restart (both survive); interrupt a record write and a checkpoint write (neither is misread).

## 13. Incidents and the diagnoser (crates `incident`, `diagnose`)

**Incident lifecycle**

- **Open** when a unit is expected (desired condition holds, not suppressed) and its derived status is Failed, Degraded, Stopped-but-desired-Running, Detected-but-desired-Bound, or Absent-but-desired-present, with fresh evidence for two consecutive ticks.
- **Defer to systemd first.** If the unit has `Restart=` and systemd is within its own `StartLimitBurst`, the incident waits for systemd's attempt (up to the unit's `RestartSec` plus settle) before Planarian acts, so two controllers don't restart the same service.
- **Attempts** are transactions; each outcome is appended. Budget 3 per incident, persisted in the journal (survives daemon restart). Backoff between attempts: 10 s, 60 s, 300 s.
- **Closed** when the target satisfies its *desired* predicate (Running, Bound, Stopped, or Absent as desired) with fresh evidence for a stabilization window (5 min).
- **Regressed:** if the same target diverges again within 30 min of Close, the incident reopens with `count+1` and a longer backoff; at `count = 3` it goes straight to **Escalated** (report to user; cooldown 1 h; no autonomous action on that target until a human acts or the cooldown ends).
- **Cooldown** after budget exhaustion: 1 h, then one more attempt, then 6 h.
- A suppression on the target closes the incident (I13).

**Diagnoser**

1. From the open incidents, walk `Requires` edges (and `Diagnostic` edges with confidence ≥ 0.7) to the deepest divergent unit; that is the target. `Ordering` and `Wants` edges are never followed: a failed wanted unit is its own incident and is never assumed to be the cause of the wanting unit's failure. **Cycles:** the walked subgraph is first collapsed into strongly connected components; "deepest" is defined on the resulting DAG; within a component, the target is the unit with the earliest definite `Observed::Failed` timestamp, else the one with the most failed Readiness probes, else lexical order. Gym case: an optional wanted service fails while its wanting service stays healthy (two incidents at most, no false root cause).
2. Enumerate candidate transitions, depth ≤ 2, whose precondition holds and whose prediction closes the divergence. Exclude exhausted and cooling targets.
3. Order by: tier ascending, then disruption ascending, then recovery (Idempotent < Revertible), then cost. `Rollback` last.
4. Submit one at a time as `Proposal { source: Diagnoser }`. Stop at the first `Committed` whose expectation held.
5. Exhausted → `DiagnoserExhausted` → model (B) or user report (A).

Phase A `ApplyChange` candidates are limited to catalog entries tagged `repair:` (re-enable a predicted option; reapply a previously-committed change for the same target).

## 14. Intent matcher (crate `intent`)

Deterministic; no language model; identical behavior in degraded mode. Not in the Verus subset.

- **Index:** every `UnitDef.synonyms`, every transition verb with a phrasing list, every change-catalog entry's description tokens, every runtime-settable option.
- **Match:** normalized token overlap plus a fixed pattern set ("restart X", "reconnect X", "turn X on/off", "make X bigger/smaller", "stop/pause X [for N minutes|until I say]", "start X again"/"done with X"). Output `(Transition, confidence)`.
- **Thresholds:** ≥ 0.8 propose with `Source::Intent`; 0.5–0.8 ask the user to confirm one of the top two; < 0.5 unmatched (A: say so; B: summon the model).
- **Stopping:** "stop X" and its variants map to `StopAndSuppress { until: parsed or Explicit }`, never to a bare `StopUnit` or a bare `Suppress`; the suppression is journaled before the stop (§12), so there is no window in which the repair loop restarts the unit. "Start X again"/"done with X" → `Unsuppress`, after which the unit is desired-Running again and is repaired if needed. A `StopUnit` issued through the CLI by an authorized user is rewritten to `StopAndSuppress { until: NextBoot }` with a notice.
- **Authorization** applies as in §11; an unauthorized match is reported as such, not silently dropped.

## 15. Gym (crate `gym`)

- Catalog entry: `Fault { id, family, inject: Transition | RawAction, required_post: Expectation, intent: Option<Intent>, tags }`. `intent` marks cases where the correct behavior is *no* intervention (user stopped the service; login screen idle; probe timed out but the service is fine).
- Phase A catalog, minimum families: service killed; service misconfigured; required dependency stopped; ordering-only predecessor stopped (must NOT be treated as cause); driver unbound; bad generation activated; **daemon killed during Activating, Checking, and Reverting**; revert fails (RecoveryFailed path); probe delayed past timeout with the service healthy; external config edit during a build; intentional service stop; suspend/resume; network unavailable at the gateway with the driver fine; flapping service (fails 30 s after each restart); storage full; manifest edited to weaken a probe; login screen idle with autologin off; boot-to-desktop failure.
- **v4-review acceptance cases (all required in Phase A):** kill and immediately restart the daemon while a deliberately slow activation worker survives (activation and revert never overlap; the old owner cannot commit); an override-only candidate changes the evaluated output; the owner edits the source during a build (transaction rejected `Stale`); a crash injected at each of `Activating`, `Checking`, `Published`, `Promoted`, `Reverting` (running state, boot selection, override source, and journal agree after recovery); disable then re-enable a service with a canonical Readiness probe (no revert of the authorized change); Diagnostic evidence expires on a healthy machine (status stays Running); a definite failed service while another unit's probe is stale (status Failed, not Unknown); authentication succeeds but the compositor never reaches its target (incident opens); idle greeter with autologin off (no intervention); a user stops a running service (stays stopped, no repair race); an unprivileged user tries to suppress a system Security unit (rejected `Unauthorized`); the daemon proposes a session-dropping driver rebind and a runtime Wi-Fi change (both AskFirst); an optional `Wants=` unit fails while its wanting unit stays healthy (no false root cause); the journal filesystem is filled to the reserved-block boundary as the daemon's uid (emergency collection recorded and executed, or explicit `NoSpace`/`RecoveryFailed`).
- Scoring per fault: pass iff `required_post` holds (or, for intent cases, iff no *autonomous* transaction was opened after the user's own setup action; the user's authorized `StopAndSuppress` or similar is the setup, not a failure). Gamed success (probe tampering, `StopUnit(target)`, suppression created by a non-user actor) fails the run.
- Metrics reported: repair rate; **unnecessary interventions** (transactions on intent cases); disruption incurred (sum of `Disruption` of executed transitions); time-to-repair; restart count per target; `RecoveryFailed` count (must be 0 unless injected).
- Phase B: fault families are split into train/held-out; GB is measured on held-out families.
- Dual target: NixOS 26.05 VM gates; Asterinas NixOS VM runs non-gating, failures classed `Driver`/`Backend`/`Core`; only `Core` failures are bugs.

## 16. CLI and console

**CLI:** `planarian status | log | incidents | approve <hash> | resolve <txn> --as-committed|--as-reverted|--manual-repaired | undo | mark-good | suppress <unit> [--until] | unsuppress <unit> | gc`, and `ask "<phrase>"`. `approve` and `mark-good` require root and an interactive TTY in Phase A (known weakness; broker in C). `mark-good` changes the recovery baseline and requires administrator authority. `known_good` is always boot-confirmed (I1); `mark-good` on a boot-confirmed generation moves `known_good` to it. `mark-good --accept-unconfirmed` instead sets a separate `accepted_baseline`, which the revert path may use as `revert_to` when it is newer than `known_good`, but which never replaces `known_good` in the boot menu until a reboot confirms it. Both are refused if any Readiness probe is failing. **Initial enrollment:** the first generation booted after install becomes `known_good` once its Readiness probes pass at the 10-minute checkpoint on that boot; until then Planarian runs with `max_tier = Runtime` and reports "no baseline yet."

**Operational limits (normative):** attempt budget 3 per incident; backoff 10 s / 60 s / 300 s; stabilization 5 min; regression window 30 min; escalation at 3 regressions; cooldowns 1 h then 6 h; token expiry 24 h; tick 5 s; probe timeouts as declared, default 10 s; settle default 15 s; generation deadline 15 min (networking 90 s); watchdog period 10 s; job-drain wait 60 s; journal preallocation 64 MB, compaction at 75%.

### 16a. Visual console (read-only in A)

iced; COSMIC reference desktop; autostart as a user service on `graphical-session.target`, minimized unless there is an open incident, a pending approval, a reconciliation record, or the last boot reverted. Views: **Graph** (desired vs observed vs health per node: three small indicators, not one color; edge style by kind; suppressed nodes hatched; Unknown nodes grey with a stale-clock mark), **Timeline** (transactions with journal states and outcomes), **Generations** (current, previous, known_good, live_tested, candidate; boot-confirmed marker), **Incidents** (state, attempts, cooldown). Buttons in A: `undo`, `suppress`/`unsuppress` (Runtime, user-actor). No approval in A. Reads only the daemon socket.

## 17. Pinned versions and conventions

NixOS **26.05** (`nixos-26.05` channel pinned to a commit in `flake.lock`; recorded in `docs/pins.md`; moves only by PR; 26.11 waits for Phase C). COSMIC from the channel module. Rust stable pinned. `zbus`, `serde`+JSON. No `unsafe` outside `backends/` and `watchdog/`. License **MPL-2.0**. CI: tests, gym Phase A catalog, dependency-boundary check, Verus proofs, Kani harnesses.

### 17a. Verification plan and trusted assumptions

Proof targets, in order: Phase A — `schema::digest`; `policy::decide` (purity; I5; I11; I14 in the sense that `decide` has no `Proposal` input; probe-tamper → AskFirst or Reject); `txn` kernel (I6; I12: every journaled transaction reaches a terminal state under the modeled outcomes; write-ahead ordering). `exec` orchestration gets Kani harnesses and proptest in A, Verus in C. Diagnoser soundness and scorer in B. Broker in C. Switch/rollback and supervisor in D (store integrity proven only for content-addressed paths; input-addressed paths are verified by signature and NAR hash, not by content). OSTD, model channel, core update path in E.

`docs/assumptions.md` lists every externally specified behavior the proofs rely on, maintained as Verus `external_body`/`assume` sites are added. Phase A entries: backend `Outcome` is honest (`Succeeded` means applied; `Unknown` means the backend cannot say); `activate_live(revert_to)` restores the activation state of `revert_to`; `publish_boot` and the promotion rename are idempotent; the journal's fsync is durable and the preallocation is writable; systemd reports unit state truthfully over D-Bus and honors `X-RestartIfChanged`/`X-StopIfChanged`; fencing is effective (a stale-epoch call is refused before it mutates); the kernel and systemd are correct. Re-observation after a backend call *detects* divergence from the assumed postcondition; it does not undo an irreversible effect, which is why the `NonReversible` floor exists.

**Progress assumptions for I12** (liveness is conditional on these, stated in the proof): some lease holder (daemon or watchdog) eventually runs; a fenced worker eventually stops issuing calls or its calls are refused; journal writes eventually succeed (guaranteed by the preallocation for recovery records); backend calls terminate. Under those, every transaction reaches a terminal state; with them violated the proof says nothing, and `RecoveryFailed` plus alerting is the designed fallback.

Verus subset applies to `schema`, `policy`, `txn` only. `exec`, `diagnose`, `incident`, `state` keep the no-`dyn` and no-`unsafe` rules so they can be brought in later; `intent`, `console`, `daemon`, `cli`, `gym` are unconstrained.

## 18. Instructions to the coding agent (AGENTS.md)

0. **First deliverable, before any other code:** the Phase A fault catalog (`crates/gym/catalog/phase-a.toml`), one entry per §15 family at minimum, each with `inject`, `required_post`, `intent`, `family`; stop for owner review.
1. **Second deliverable:** the GA demonstration script (`gym/demo.sh`): fault → repair; bad config → revert; kill `planariad` during `Activating`; watchdog reverts; restart daemon; reconciliation record printed. Build toward making it pass; everything else is in service of it.
2. Implement Phase A only; traits for B–E with one implementation.
3. Build order: `schema` → `txn` (with the journal and an in-memory fake backend) → `policy` → `state` + `backends/systemd` + `backends/udev` → `exec` + `backends/nixos-rebuild` → `watchdog` → `changes` → `incident` → `diagnose` → `gym` → `intent` → `cli` → `daemon` → `console`. The console Graph view may be built as soon as `state` works.
4. Preserve however the schema evolves: I5, I6, I10, I11, I12, I13, I14, I15; `digest()` excludes resources and timestamps; `Proposal` is the only write path; policy facts derived by the executor; gym scores on `required_post` and intent cases, never on absence of errors; diagnoser before any model; probes with side effects other than `None` or a bounded `Measurement` never on a cadence.
5. Do not resolve §19 items; `TODO(owner)` with the stated default.
6. No language model, LLM API, or prompt anywhere in Phase A.
7. Where NixOS and this spec disagree on mechanism, follow NixOS and record in `docs/deviations.md`.
8. Every executor outcome must be reproducible from the log: proposal, pre/post state, `DerivedFacts`, `PolicyVersion`, probe evidence, decision, outcome.
9. `schema`, `policy`, `txn` in the Verus subset; land `policy` proofs before starting `exec`.
10. The Asterinas gym target may stay red. Classify failures; fix only `Core`.
11. Every new `assume`/`external_body` adds a line to `docs/assumptions.md` in the same PR.

## 19. Open questions (owner decides)

- [x] GA threshold 60%; NixOS 26.05; MPL-2.0.
- [ ] Phase B threshold Y.
- [ ] Six observed states plus Unknown/Transitioning — revisit after the A catalog.
- [ ] Phase C snapshot backend: btrfs only, or btrfs + ZFS?
- [ ] Nix vs Nickel for the Phase D evaluator.
- [ ] Boot model family/size (default ~4B, 4-bit, CPU, 8 GB floor).
- [ ] Reference laptop (E). Fork Asterinas NixOS or parallel distribution (E).
- [ ] Should `Diagnostic` edges be learnable from incident history in C, or stay manifest-only?

## 20. Later phases — design notes carried forward

Not Phase A work; kept so the design is not lost.

**Model service (B).** Unprivileged systemd service; reads reports over a Unix socket; emits `Proposal`s. Boot model ~4B at 4-bit on CPU via mistral.rs or candle; RAM floor 8 GB. Loads on demand (zero steady-state memory; 5–15 s cold start), unloads after 10 min idle; `keep_warm` offered at ≥ 16 GB. Summoned only on `DiagnoserExhausted` or intent < 0.5. Tools: inventory, health report (including attempts and the incident), dependency graph, config read, local manual search, ask-user, propose (cataloged changes or new catalog entries for human review; never raw Nix). All text inputs tagged untrusted. Training: distillation in the gym, scored on diagnoser-failed and held-out faults. Model planner: largest catalog model that fits measured resources; installed as a Tested generation; switched only if it beats the **currently active** model on repair accuracy; falls back to the boot model on resource loss. Catalog models hash-pinned with training manifest and eval results.

**Approval broker and secure attention (C, E).** Separate process minting `ApprovalToken`s. C: its own socket and a confirmation surface the compositor cannot draw over. E: a kernel-intercepted secure attention key hands the display to the broker.

**Rust system layer (D).** Snix (git.snix.dev/snix/snix; crates GPL-3.0, protobuf definitions MIT) as the `GenerationBackend`, spoken to over its MIT protocols from a separate process. Rust PID 1 plus supervisor as `UnitBackend`, driven by `Requires` edges with `Wants` preserved as weak. Rust CoW filesystem as `SnapshotBackend`. relibc for Rust `std` (vendors openlibm, C; a named exception). Store integrity is proven for content-addressed paths and signature-and-NAR-hash-checked for input-addressed ones. Backend contracts are revised at the start of D from `docs/assumptions.md` and `docs/deviations.md`.

**Asterinas (E).** Fork at a pinned release (0.19.0 at writing). Driver priority for a reference laptop: NVMe, input, display → Wi-Fi, Ethernet, USB → audio, power, suspend → GPU modesetting → GPU 3D/compute (port Nova or Tyr) → Bluetooth, webcam, fingerprint. Firmware blobs allowed. Desktop: Smithay compositor with Rust software renderer; iced UI; COSMIC later. Verification: OSTD (vostd), executor, policy, diagnoser, broker, switch/rollback, store integrity, model channel, core update path. Core image: signed bundle installed only with project signature plus secure attention; previous core stays bootable.

**Trust base accepted as unproven at every phase:** firmware, bootloader, Rust compiler, CPU; plus the Linux kernel and systemd in A–D.

## 21. Expected resource profile

| Situation | Cost |
| --- | --- |
| Idle | Single-digit MB resident, < 1% CPU; watchdog sleeps on a 10 s timer |
| Fault → detection | One tick plus probe timeout (5–30 s); up to one cadence period for hardware probes |
| Fault → deterministic fix | 10–60 s per attempt plus settle; defer-to-systemd adds up to `RestartSec` + settle |
| Fault → model-assisted fix (B) | 1–3 min, plus cold start if not warm |
| Config change (Tested) | 30 s to several minutes, dominated by Nix evaluation and builds; plus the stage copy (seconds) |
| Runtime-settable option | Immediate; write-back follows in the background |
| Journal | One fsync per state change, roughly ten per generation transaction; 64 MB preallocated |
| Disk | Bounded by keep-N and space budgets; `BudgetUnsatisfiable` reported if the protected set alone exceeds them |
| Executor log | Tens of KB/day in steady state; rotated at 50 MB, kept 30 days |

## 22. Changes from v3

- Restored principles (now 12) and invariants (I1–I14) that v3 referenced but omitted.
- Desired/observed/health separated; conditions (`AfterLogin`, `DeviceConnected`, power); suppressions; `Unknown`, `Transitioning`, stale evidence; user-scoped units. Fixes the login-screen and user-stopped-service faults.
- Edges typed (`Ordering`/`Requires`/`Diagnostic`); `After=` no longer implies dependency.
- Probe contract: sandbox, limits, side effects; disruptive probes OnDemand only; `establishes` field.
- Sensitivity composable; `Disruption` and `Recovery` as separate properties; `Decision::Reject` separate from tiers; `max_tier` can no longer make a forbidden action approvable.
- Policy facts derived by the executor from the evaluated generation (I14); `OptionChange.sensitivity` removed from proposals; refinement check and executor-owned requirements made explicit.
- Approval bound to the concrete candidate, base, policy version, cumulative hash, derived facts; re-validated at execution; single-use.
- Transaction kernel with write-ahead journal, `Partial`/`Unknown` outcomes, recovery watchdog as a separate unit, daemon restart reconciliation, self-protection during activation; `live_tested` vs boot-confirmed `known_good`.
- Change catalog with handlers replaces free-form `ConfigDiff` in proposals; override file promoted only on commit; user config pinned per transaction.
- Incident lifecycle: defer to systemd, backoff, durable budgets, regression and flap handling, cooldowns, escalation.
- Gym: lifecycle and intent families; unnecessary-intervention and disruption metrics; held-out families for B; GA includes the kill-mid-activation demonstration.
- Verification narrowed to `schema`/`policy`/`txn` with `docs/assumptions.md`; re-observation claim corrected; store-integrity claim corrected for input-addressed paths.
- GC: in-flight candidates protected; space budgets.
- `mark-good` authorization; log record contents; `dyn`/generics contradiction resolved.
- Phase A scope kept full and Asterinas target kept non-gating, per owner decision.

## 23. Changes from v4 (this revision)

- §12: exclusive transaction ownership with lease epochs; worker fencing via pidfd and job draining; the watchdog may not commit before `Published`; the daemon waits for a watchdog-held lease; I15 added; gym case for overlapping owners.
- §9/§12: immutable staged source (NAR-hashed) evaluated with pure-eval; build before approval; `verify_candidate` before activation; the token binds expectation, revert target, and recovery strategy; `activate_live` and `publish_boot` separated; `Published`/`Promoted` journaled; atomic-rename-plus-dir-fsync promotion; watchdog revert restores the override source; crash-recovery table.
- §8/§9/§10: `ProbeRole` Readiness vs Diagnostic; side-effect probes are Diagnostic; status derivation puts definite `Failed` above Unknown; probe applicability follows the candidate's authorized desired state, distinct from definition tampering.
- §8/§9: `Condition::SessionEstablished` from logind replaces the circular `AfterLogin`; the session probe is the result, not the prerequisite.
- §8/§12/§14: `StopAndSuppress` composite; suppression journaled before stop; no post-hoc prompt; CLI `StopUnit` rewritten.
- §11: `SO_PEERCRED` authentication; authorization rule separate from risk; actor fields overwritten; global floors for NonReversible and disruption apply to every transition kind.
- §8/§9/§13: `Wants` edge kind preserved as weak; SCC-based root-causing for cycles.
- §10/§12c: per-filesystem storage units; preallocated journal; ENOSPC behavior by state; `CollectGarbage { emergency }`; `BudgetUnsatisfiable`.
- §12: read-only vs mutating backend calls; `Prepared` on the Allow path; per-transition `RecoveryStrategy`; Runtime outcomes never trigger generation reversion; `restartIfChanged`/`stopIfChanged` as the real self-protection mechanism.
- §16: `accepted_baseline` distinct from boot-confirmed `known_good`; initial enrollment; operational limits made normative.
- §17a: progress assumptions stated for I12; fencing and idempotence added to the trusted-assumptions list.
- §12a, §14, §20, §21 made self-contained.

## 24. Changes from v4.1

- §12: takeover requires confirmed quiescence (jobs cancelled and gone, workers reaped); a drain timeout ends in `RecoveryFailed`, never in proceeding; lease transfer is atomic via `flock` plus rename; the watchdog triggers on `Published`/`Promoted` too and, from `Checking`, completes the whole authorized commit path or reverts.
- §8/§12: per-transition `Handler` and `RecoveryStrategy` independent of tier; `Rollback` is a generation operation even at Runtime tier; `BindDriver` is a device operation with `UnbindDevice` recovery; the crash-recovery table branches on strategy.
- §9/§12b: transaction-specific `base.nix` with content-hash identities; promotion and restoration idempotent by hash comparison; no shared `.prev`; GC root created at `Built` and kept through approval; dirty-Git staging defined by Nix-visible bytes.
- §12c: length-prefixed CRC'd records with torn-tail handling; checkpoint-then-truncate compaction preserving all live state; filesystem contract for ext4/XFS/btrfs/ZFS with a sentinel fallback.
- §8/§10: `SideEffects::Measurement` permits bounded network/local I/O for Readiness probes; `RemoteStateChange` stays Diagnostic; external dependencies are units with edges.

## 25. Changes from v4.2 (this revision)

- §9: `base_source` (owner source with base override) separated from `staged_source` (candidate tree); stale check compares the working tree to `base_source` only; both bound to the token; Git-revision wording removed; step numbering fixed.
- §9/§12: `build` roots its own output under `gcroots/planarian/builds/` without a lease; the transaction adopts the root; orphan roots cleaned at startup.
- §12: durable `OpId` journaled before every mutating call and tagged onto the backend job; quiescence covers jobs discovered by `jobs_tagged` for unacknowledged ops; a backend that cannot say → `RecoveryFailed`.
- §12/§12c: `RecoveryFailed` sets a persisted **recovery interlock** carried in the checkpoint; cleared only by administrator `planarian resolve`; crash table row for `Checking, ReobserveOnly`.
- Consistency: `ProbeRole`, canonical-probe paragraph, and agent instruction 4 all carry the `Measurement` exception; I12's terminal set includes `Rejected` and `Cancelled`.
- I4 reworded to applicable Readiness probes; atomic transaction creation with initial lease; `Rejected`/`Cancelled` terminal states; incident closure on the desired predicate; `SessionEstablished` scoped to `user`-class sessions and a specific session id; intent-case scoring scoped to autonomous action.

## Sources

- [NixOS manual: what happens during a system switch](https://nixos.org/manual/nixos/stable/) · [systemd.unit: dependencies](https://www.freedesktop.org/software/systemd/man/latest/systemd.unit.html) · [Verus: trusted components](https://verus-lang.github.io/verus/guide/tcb.html) · [Nix glossary: content vs input addressing](https://nix.dev/manual/nix/2.30/glossary.html)
- [NixOS 26.05 release](https://phoronix.com/news/nixos-26.05-released) · [COSMIC on NixOS](https://smithery.ai/skills/olafkfreund/cosmic-de)
- [Asterinas](https://github.com/asterinas/asterinas) · [paper](https://arxiv.org/html/2506.03876v1) · [0.19](https://phoronix.com/news/Asterinas-0.19-Released) · [vostd](https://github.com/asterinas/vostd) · [Verus](https://www.microsoft.com/en-us/research/?p=1083954) · [Snix](https://git.snix.dev/snix/snix) · [relibc](https://github.com/redox-os/relibc) · [mistral.rs](https://www.sourcepulse.org/projects/1770767) · [Nova](https://www.phoronix.com/news/Nova-Driver-LPC-2026) · [Tyr](https://lwn.net/Articles/1055590) · [Smithay](https://smithay.github.io/smithay/smithay/backend/renderer/index.html) · [niri](https://lwn.net/Articles/1025866) · [COSMIC 1.10](https://phoronix.com/news/COSMIC-Epoch-1.10)
