# Planarian — Spec v4.6

Oct 30, 2026 · supersedes Spec v4.5 · incorporates the Phase A close-out review of Oct 30 against commit `805cd1c` (the merged findings of the 29 Oct code audits and the 30 Oct third-party handoff, with the owner decisions of 30 Oct; changes listed in §28), on top of the vulnerability review merged in v4.5 (`docs/spec-history.md` §27). Phase A stays held open: the gate is called only when §28's required changes have landed, B-20 is closed, and every doc agrees with the head (§18 rule 19). The non-normative directions from that review (fleet, remote principals, app capabilities, forecasting, Asterinas convergence, self-improvement) remain in `docs/future-work.md` and are not Phase A–C requirements.

---

## Abstract

Planarian is a self-healing layer for declaratively configured computers. It keeps three things distinct: what the system is *meant* to be (desired state, with conditions and user overrides), what it *observes* (with explicit unknowns and stale evidence), and whether what it observes is *healthy* (probes with a contract). A divergence between desired and observed state opens an incident. Incidents are repaired deterministically first, by a planner that searches typed transitions over a dependency graph; a small local language model is consulted only when deterministic repair fails or a user's request is too fuzzy to match. Every change, whatever proposed it, passes through one executor that derives the risk classification itself, runs the change as a durable transaction with a journal that survives the daemon dying, and reverts it if health checks fail. The executor is a reference monitor: always invoked, tamperproof, and small enough to verify. Everything above it is a principal with an identity and a set of things it may request, and none holds authority on its own: not a user, not root acting through Planarian, not the on-device model, not an agent (an agent acts with exactly the permissions of the person who started it, under its own name in the record, and in Phase A can approve nothing, since approval needs a person at a terminal). Each submits typed proposals.

Planarian ships first as a Rust service on NixOS 26.05, where it is useful immediately and gathers real fault data. Its backends (service supervisor, configuration evaluator, snapshot filesystem, kernel) sit behind contracts and are replaced with Rust implementations over later phases, converging on an all-Rust operating system built on the Asterinas kernel. The contract stays the same at every step; what sits underneath it changes.

---

# Part I — For human readers

## 1. What it is, in one page

Most operating systems can tell you *that* something broke. Planarian is built to know *what should be true*, notice when it isn't, and close the gap without making things worse.

It can do this because the system is **declared**: a NixOS configuration says which services, drivers, and settings should exist. From that, plus a manifest that adds what NixOS doesn't say (what depends on what, how to test each thing, how risky it is to touch), Planarian derives **desired state**. Desired state has conditions: the graphical session should be running *after someone logs in*; a printer service should be running *when the printer is connected*; a service the user stopped on purpose is *left alone until they say otherwise*. Planarian **observes** actual state continuously and runs **health probes** under a strict contract (no sudden noises, no side effects, bounded cost). When a probe times out, the answer is *Unknown*, not *Failed*.

A gap between desired and observed state opens an **incident**. Repair follows a strict order:

1. **Root-cause.** The dependency graph distinguishes "must be up for this to work" from "merely starts before" from "we suspect these are related." A failed audio service whose required sound-card driver also failed is a symptom; the driver is the target.
2. **Deterministic search.** A small planner searches the known transitions (restart this, rebind that, apply a cataloged change, roll back) for one whose preconditions hold and whose predicted result closes the gap, safest and least disruptive first.
3. **Summon the model.** Only if search finds nothing, or the incident's budget is spent, does a local model get the state, the graph, what was tried, and the manuals. It proposes in the same typed format the planner uses.
4. **Escalate.** If that also fails, the user gets a plain-language report, and the incident goes quiet with a cooldown rather than retrying forever.

User requests follow the same order: "reconnect Wi-Fi" matches a declared action directly; "stop the backup service while I work on it" becomes an attributed override of desired state, so Planarian doesn't fight the user; "make it faster" is ambiguous and goes to the model, which asks before proposing.

Whoever proposes, **one executor decides**, and it decides from facts it derives itself: what the change actually touches in the evaluated configuration, how sensitive and how disruptive that is, what else changed this session. Nothing in a proposal can grant authority. Runtime actions with no lasting effect just run. Configuration changes run as a **transaction**: journaled before anything happens, activated as a candidate generation, probed, and either committed or reverted, with a watchdog that finishes the job if Planarian itself is killed halfway. Security-relevant, irreversible, or user-data changes wait for approval, and the approval is re-checked against the exact change the moment before it runs. The repair machinery itself can never be changed by any proposal, under any approval.

The model is a convenience and a fallback. If it is absent, broken, or wrong, the system still boots, runs, repairs the easy faults, and reverts the bad changes.

Planarian is meant to be unnoticed under normal use. Its overhead, its notifications, and its effect on a game's frame time are measured, and none of them may get worse between releases. It defers non-urgent work while the user is absorbed in something, and it never undoes a deliberate choice; it only needs the choice to have a name on it.

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
│   overrides)               │   │  config: nixos-rebuild   │ │ separate    │
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

Arrows into the core carry *proposals*. Only the executor calls backends. The model has exactly one write capability: submit a proposal. The recovery watchdog is a separate process that can finish or revert a transaction when the daemon is gone. Everything drawn above the CORE box is a principal (§7, §11); the core's response to its own failure is enforced by systemd and the initrd, not by the core (§12d).

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
| Risk tiers and approval | Security, external, user-data changes wait; approval re-validated at execution | Yes (CLI approval in A, root at a terminal; broker in C) |
| Disruption awareness | Actions that would drop your session or connection are classed and surfaced as such | Yes |
| Snapshots | Snapshot before every switch; restore on request; space-budgeted | If btrfs or ZFS present |
| Boot-confirmed generations | A kernel change is not "good" until it has rebooted | Yes |
| Visual console | Live graph of desired vs observed vs health, timeline, generations, incidents | Yes (read-only in A) |
| Degraded mode | Everything but model-assisted repair and fuzzy requests works with no model | Yes |
| Attributed actions | Every deliberate stop, disable, or disconnect is recorded with who did it, before it happens; nothing deliberate is undone | Yes |
| Security floor | Automatic revert never goes back below a generation that fixed a security problem | Yes |
| Failure posture | If Planarian itself fails or the system shows signs of tampering, the machine responds as declared: alarm, agents off, restricted access, or halt | Yes (Standard posture in A; all postures in C) |
| Quiet mode | Nothing non-urgent runs while a game or fullscreen app is in the foreground; updates wait for idle | Yes |
| Sandbox tier | Proposed changes tested first in a disposable Firecracker microVM | Phase B |

## 4. Roadmap

Each phase ships something usable on its own. Later phases replace a backend; the contract does not change.

| Phase | Deliverable | Gate to exit |
| --- | --- | --- |
| **A · Contract on NixOS 26.05** | `planariad`: schema, state model (desired/observed/health/graph), policy, executor with hash-chained transaction journal and recovery watchdog, systemd and nixos-rebuild backends, change catalog, deterministic diagnoser and incident manager, intent matcher, `ask` CLI, read-only visual console, fault-injection gym with lifecycle cases. Attributed overrides and session-aware actors (§8, §11); security floor (§12e); failure-posture mechanism with the Standard posture (§12d); activation scheduling and quiet mode (§12f, §10); boot report (§10); signed external desired-state source and signed health report as hooks (§9, §10). Gym also runs non-gating against an Asterinas NixOS VM and a Firecracker microVM target (allowed to stay red; no engineering time beyond keeping them running). `schema`, `policy`, and the transaction kernel in the Verus subset. No model. | **GA:** (1) the demonstration: inject a fault → repaired; inject a bad configuration → reverted; kill `planariad` during activation → watchdog recovers; restart the daemon → it reconciles the journal and explains what happened accurately. (2) ≥ 60% of the catalog cleared deterministically; every bad generation reverted; the manifest-weakening fault rejected; zero gamed successes; unnecessary-intervention rate on the intent cases = 0; every posture and security-floor gym case passes. (3) `policy` proofs pass in CI. (4) Baselines reported: the invisibility budget (§21) and the verification ratio d:a with the trust count (§17a). |
| **B · The model** | Model service with residency rules (§20); boot-model fine-tune via distillation; summoned only on diagnoser exhaustion; evaluation suite with held-out fault families. Sandbox tier: dry-run and Firecracker-from-snapshot (§12g); a passing sandbox run is required for Tested changes where KVM is available. Non-human principals may hold catalog and model-catalog authority (§11). | **GB:** diagnoser + model clear ≥ Y% including held-out families; a worse model is rejected by the suite; no model load while `Foreground` holds; invisibility budget and d:a not degraded; the trust count not increased. |
| **C · PlanarianOS** | PlanarianOS: a NixOS distribution in which Planarian governs the machine from first boot (§9a), with three profiles: agent host, server / fleet node, personal. Installer selects profile and failure posture; all four postures (§12d); approval broker; snapshot backend; hardware inventory and explain; Flatpak as the user-scope app valve. The personal profile ships the COSMIC reference desktop and the console (a libcosmic app with approvals) as an optional frontend. Planarian also remains a standalone NixOS module and flake. Real users feed the gym. | **GC:** per-profile gates (§9a); ten external users for a month; every reported fault reproduced as a catalog entry; invisibility budget and d:a not degraded; the trust count not increased. |
| **D · Rust system layer** | Snix-based evaluator and store; Rust init and supervisor; Rust CoW filesystem. Linux kernel. Backend contracts revised from what A–C taught. | **GD:** no systemd, no C Nix; full catalog passes; d:a not degraded and the trust count not increased (§17a). |
| **E · Asterinas** | Kernel swap; reference-laptop drivers; Smithay desktop; secure attention key; Verus on the core. | **GE:** reference laptop boots, suspends, connects, plays audio, runs the desktop, survives the catalog from cold boot; d:a not degraded and the trust count not increased. |
| **F · Acceleration** | GPU drivers, model on GPU, COSMIC migration, second machine, ARM64. | **GF:** accelerated desktop and model on both machines; planner correct under injected accelerator failure. |

**Firmware:** binary vendor firmware is loaded as data by Rust drivers and is allowed permanently.

---

# Part II — Specification for implementation

Normative unless marked *draft*. MUST/MUST NOT are requirements; SHOULD is a default the agent may deviate from with a logged reason in `docs/deviations.md`.

## 5. Scope and non-goals

**Phase A in scope:** everything in the Phase A roadmap row, on NixOS 26.05 with systemd, D-Bus, udev; btrfs/ZFS optional; root via a dedicated systemd service.

**Out of scope for A:** the model service (B), the sandbox tier on the real change path (B; the Firecracker gym target runs non-gating in A), approval broker and console write paths beyond §16 (C), PlanarianOS profiles and the Relaxed, Guarded, and Sealed postures (C), snapshot restore (C), Rust evaluator or init (D), kernel work (E). Interfaces to them exist as traits with one implementation.

**Not requirements in any phase of this spec:** the directions in `docs/future-work.md` §3–§8b and §11 (remote principals and the endpoint catalog, app capabilities, fleet membership and attestation, resource governance beyond model residency, forecasting, Asterinas convergence, self-improvement). The schema hooks in §9 and §10 exist so these can be added later without reopening the proven crates.

**Bypasses.** Every known route around a guarantee, open or accepted by design, is a row in `docs/bypasses.md` (§17b) with what it breaks, its mitigation, and the phase that narrows it. A guarantee in this spec holds only as widely as its row in that file allows.

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
      linux/                 systemd, logind, sysfs/udev, nixos-rebuild, probes, processes behind the §8 traits (one crate in A; snapshot-btrfs in C)
    fake/                    the in-memory backends the kernel is tested against (§18 rule 12): a second real implementation
    ipc/                     request and response types shared by daemon, CLI, console and tray
    watchdog/                planarian-recovery: separate binary (§12)
    daemon/                  planariad: wiring, IPC, systemd units
    cli/                     `planarian`, `ask`
    console/                 iced read-only console (§16a)
    tray/                    status indicator (StatusNotifierItem); ships with the console
    gym/                     catalog, VM harness (NixOS VM, Firecracker, Asterinas NixOS), scoring, metrics, verification accounting, the guarantees site generator (§15, §17a, §17b, §17c)
    sandbox/                 (B) dry-run and Firecracker-from-snapshot tier (§12g); not present in A
    model/                   (B) not present in A
  nix/
    module.nix               services.planarian, including the unit manifest options (§9)
    posture.nix              planarian-ready.target and failure-posture targets (§12d)
    reference.nix            personal profile in A: COSMIC + greeter + console autostart; wires the shipped change catalog (§9)
    package.nix, console.nix, verus.nix, firecracker.nix
    profiles/                (C) agent-host.nix, server.nix, personal.nix (§9a)
    template/                `nix flake init -t` starting point, including planarian/overrides.nix
    vm/, live/, installer/, demo/   the demo VM, live image and installer (docs/planarian-os.md)
    tests/                   NixOS VM tests: the gym's VM harness, runtime/generations/posture/installer tests, the boundaries check, the Verus check
    gym/                     run-vm.sh (the by-hand VM catalog runner)
  share/canonical.json       canonical probes (§9)
  docs/                      SPEC.md (this), AGENTS.md (§18), deviations.md, pins.md, assumptions.md (§17a), bypasses.md (§17b), spec-history.md (changes through v4.4), verification.md and verification-ratio.toml (§17a), guarantees.md, ga-status.md, catalog-review.md, planarian-os.md, why.md (public design essay), future-work.md (non-normative)
```

The layout above is descriptive of the repository at v4.6; it replaces the aspirational v4.5 layout (separate backend crates, `nix/manifest.nix`, `nix/changes/`, stub `sandbox`/`model` crates), which `docs/deviations.md` recorded only in part.

Dependency rule, enforced in CI: `schema`, `policy`, `txn`, `exec`, `diagnose`, `incident`, `state` MUST NOT depend on `backends/*`, `std::process`, or read `/proc`, `/sys`, `/nix`. Backends are passed as **generic type parameters**; in Phase A a single `enum Backends` wraps the concrete set. No `dyn Trait` in `schema`, `policy`, `txn`, `exec`.

## 7. Principles and invariants

**Principles**

1. The healer is not the patient. The repair core is outside the blast radius of anything it changes; no generation or proposal can modify it.
2. The model proposes; machinery disposes. Model output is a typed proposal, never a command.
3. Machinery before model. Deterministic code handles everything it can; the model is a fallback.
4. Desired, observed, and healthy are three different things. Never collapse them.
5. Every change is a transaction. Journaled before, probed after, reverted on failure, recoverable if the daemon dies.
6. Authority is derived, never supplied. The executor computes what a change touches and how risky it is from the evaluated configuration; no field of a proposal or of any other request carries authority or identity.
7. Sensor input is data, never instructions.
8. Degrade to a working machine. Without the model, the console, or the network, the system boots, runs, repairs simple faults, and reverts.
9. Don't fight the user. A deliberate stop, disable, unmount, or disconnect is an override of desired state, not a fault, provided it reaches the journal with the actor's identity before it takes effect (§11).
10. Disruption is a cost. Prefer the least disruptive repair; surface disruption before acting.
11. The oracle is protected. Nothing a proposal can do may weaken a canonical probe.
12. Grow into the hardware.
13. The executor is a reference monitor. It is always invoked, tamperproof, and small enough to verify. Everything above the verified core is a principal with an authenticated identity, a set of capabilities, and a reputation; authority is derived below that line and never held above it. The rule is species-blind: it applies the same way to users, root acting through Planarian, apps, the on-device model, and remote agents.
14. Invisible under normal use. Planarian's overhead, notifications, and effect on foreground work are measured and may not get worse; non-urgent work waits while the user is absorbed in something.
15. The response to the monitor failing cannot depend on the monitor. Failure posture is declared in the generation and enforced by systemd and the initrd.
16. Name every way around. A guarantee is stated only as widely as it holds; each route around it is a row in `docs/bypasses.md` with its phase, and no gate passes with an open High row.

**Invariants** (checked by `txn` and `policy`; each is a test in `gym` and, where marked, a proof)

| ID | Invariant | Proof |
| --- | --- | --- |
| I1 | A boot-confirmed known-good generation always exists, is bootable, and is in the boot menu; an `accepted_baseline` never replaces it there. It may lag the security floor until the floor generation is boot-confirmed (§12e); it is then a manual fallback, never an automatic one. | D |
| I2 | The installed core package's hash equals the hash recorded in its signature. In A–D the reference hash is recorded by the build and covers every Planarian binary and script (§12d); it detects a swapped file, not a rebuilt generation. | E |
| I3 | Garbage collection never removes known-good, the previous generation, the current generation, an in-flight candidate, or the boot model. | A (test), D (proof) |
| I4 | `Running` means desired-Running under the current conditions, observed-active, and every *applicable Readiness* probe passed with fresh evidence. Diagnostic probes never determine Running. | A |
| I5 | Forbidden actions are unrepresentable as transitions; `Decision::Reject` is never converted to any tier by any setting. | A (proof) |
| I6 | At most one generation-changing transaction is active (a generation transaction waiting in `Built` for an activation window, or in `AwaitingBoot`, counts as active); no transition executes while a transaction is in any mutating or checking state: `Activating`, `Checking`, `Publishing`, `Published`, `Promoted`, or `Reverting`. Unit and device repairs may execute during `Built` and `AwaitingBoot`, and during a boot-only `Promoted` (admitted at boot, awaiting its confirmation; owner decision, 31 Oct): that change is already fully in place. (This list is the one the ledger enforces; v4.5's omitted `Checking`.) | A (proof) |
| I7 | Every executed transition is logged with proposal, source, pre- and post-state, derived facts, policy version, probe evidence (per probe: id, result, time), decision, and outcome; an approved transition's log and journal records name the approver's principal and the token's `bound_to`. | A |
| I8 | A tier-3 transition executes only with an approval token bound to the concrete candidate (§12), re-validated immediately before execution. "Immediately before execution" includes the moment a transaction leaves `Built` after waiting for an activation window: facts are re-derived, `decide` re-run and the stale check repeated there too, not only at approval. | A, C (proof) |
| I9 | The model process holds exactly one write capability: submit a proposal. | B (by the sandbox, §20, and a gym case), E (proof) |
| I10 | No change that removes or alters a canonical probe executes below AskFirst, and canonical probes are evaluated from the installed core package regardless of the active generation. | A |
| I11 | A session's cumulative effect is classified at least as high as any single transition producing it. | A (proof) |
| I12 | Under the progress assumptions of §17a, every transaction in the journal reaches a terminal state (`Committed`, `Reverted`, `Rejected`, `Cancelled`, or `RecoveryFailed`); `RecoveryFailed` always alerts and sets the recovery interlock. Two states wait on events outside the system's control and are bounded separately (§12f): a transaction in `Built` waiting for an activation window is `Cancelled(Daemon)` after the parking limit; one in `AwaitingBoot` waits for the reboot it was published for and is reported as *waiting*, never as a recovery failure. | A (proof, conditional) |
| I13 | A unit under an override is never a repair target while the override holds. | A, C (proof) |
| I14 | Policy facts (sensitivity, affected units, manifest-touching, caller identity) are derived by the executor from the evaluated generation and the authenticated peer, never read from a proposal or from any other request field. | A (proof of the `decide` half; the request half by test) |
| I15 | Exactly one owner (lease) per transaction; a mutating call with a stale epoch is refused; only the lease holder advances the journal. | A (proof) |
| I16 | No automatic revert, rollback, or boot fallback selects a generation below the security floor; going below it requires administrator approval (§12e). The floor is derived from the whole system closure (§12e); a fix outside the inspected set does not move it. | A (proof of the `decide` and target-selection parts; the bootloader part by test) |
| I17 | The set of principals holding administrator capability is never empty. | A (proof, given root exists) |
| I18 | Every journal record commits to the hash of its predecessor; a broken chain is detected on read and treated as an integrity failure (§12c, §12d). This holds against damage and against anyone who cannot rewrite the whole journal and checkpoint consistently; root can, until the head is anchored off the disk (§12c). | A (proof, trusting SHA-256) |
| I19 | No principal approves its own proposal, and no principal grants itself, or a principal it controls, a capability it does not hold. | A (proof), C |
| I20 | No agent (the on-device model, a remote relay, or any agent started by `planarian agent run`) starts while `planarian-ready.target` is not reached, and every running agent is stopped when a failure posture engages, in every posture (§12d). Agents the launcher creates are inside this rule exactly as the units declared in `services.planarian.agentUnits` (the model service and any relay) are. | A |
| I21 | No transition that cannot be reversed, or that may lose a session, user data or connectivity, executes below AskFirst, unless the loss falls only on the caller's own session (and, for connectivity, the caller has a seat); a loss reaching another user's session requires administrator approval (§11 floors). Garbage collection of generations outside the protected set is Runtime by §12b, not irreversible loss in this sense (owner decision, 2026-10-30); `gc.retainAllGenerations` keeps every generation. | A (proof) |
| I22 | Changing the generation, collecting garbage, binding drivers, resolving the recovery interlock and overriding a Security-sensitive unit are administrator operations; a Security-sensitive unit is changed without approval only to restore its declared state (§11); the unattributed actor holds no authority, and an agent holds exactly its user's (§11). | A (proof) |
| I23 | A generation transaction commits only after its boot entry is written and promoted; a runtime transaction never publishes, promotes or reverts; the override file is replaced only under the daemon's exclusive lock on its directory and only when its content hash is the one recorded at `Prepared` (§9 step 4). A writer that does not take the lock is outside this guarantee (`docs/bypasses.md`, X-12). | A (proof) |
| I24 | An agent's authority is bound to the one `AgentStarted` record for the unit instance it runs in, identified by that instance (not by name); a second start under the same name neither rebinds a running agent nor is journaled before it has succeeded (§11, §16). | A |
| I25 | Post-commit bookkeeping (security-floor derivation, the committed generation's override content, session accounting) runs on every path that writes `Committed` for a generation transaction: the daemon's, the watchdog's, the boot-only confirmation's. A commit whose floor record cannot be appended does not commit (§12, §12e). | A |

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
pub enum Scope { System, User { uid: u32, session: Option<SessionId> } }
pub struct SessionId(String);               // logind session id
pub struct SeatId(String);                  // logind seat; None for SSH and other remote sessions

// ---------- Desired ----------
pub enum Condition {
    Always,
    SessionEstablished { uid: Option<u32>, seated: bool },
                                              // logind reports a new session of class `user` (authentication succeeded);
                                              // greeter and background/`manager` sessions are excluded; independent of
                                              // whether the desktop then comes up. `seated: false` matches any such
                                              // session, local or remote (user-scoped units); `seated: true` matches
                                              // only sessions with a seat (the graphical expectation, §9, §10)
    DeviceConnected(UnitId),
    OnAcPower, OnBattery,
    Foreground { session: SessionId },        // quiet mode (§12f; signals in §10): a GameMode client, a gamescope session, a fullscreen
                                              // surface holding a Wayland idle-inhibitor, or the user's Do Not Disturb
    All(Vec<Condition>), Any(Vec<Condition>),
}
pub enum DesiredStatus { Running, Stopped, Bound, Absent }
pub struct Desired { pub status: DesiredStatus, pub when: Condition }

/// A deliberate, attributed change to a unit's desired state (§11). Generalizes v4.3's `Suppression`;
/// "suppression" in older prose means an `Override` with `desired: LeaveAlone`. The `StopAndSuppress`
/// transition keeps its v4.3 name: it journals `Override { desired: Stopped, attribution: Attested }`, then stops.
pub struct Override {
    pub unit: UnitId,
    pub desired: OverrideDesired,
    pub until: Until,                        // time, next boot, or explicit lift
    pub reason: String,
    pub by: Actor,                           // derived from the socket peer (§11); never from the proposal;
                                             // `Actor::Unattributed` exactly when `attribution == Inferred`
    pub attribution: Attribution,
}
pub enum OverrideDesired {
    LeaveAlone,                              // do not repair; take no action
    Stopped,                                 // stop / kill a service
    Absent,                                  // disable / mask
    Detected,                                // unmount, eject, or unbind a device
}
pub enum Attribution {
    Attested,                                // the action reached Planarian with the actor's identity before it took effect
    Inferred,                                // the unattributed residue (§11): recorded as an inference, never as fact
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
pub enum ProbeKind { SystemdActive, Tcp { addr: String }, Http { url: String, status: u16 }, DBus { service: String, path: String, method: String }, FilePresent { path: String },
                     Exec { argv: Vec<String>, sandbox: ProbeSandbox } }   // Exec: administrator-authored manifest entries only;
                                                                          // flagged in the console and journal (§9)
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
pub enum UnitStatus { Running, Degraded(Vec<ProbeId>), Stopped, Overridden(OverrideDesired), Unknown, Failed(Reason), Absent, Detected, Bound, Transitioning }

pub struct SystemState {
    pub generation: GenerationId,
    pub known_good: GenerationId,            // boot-confirmed
    pub live_tested: Option<GenerationId>,   // passed probes live, not yet rebooted
    pub security_floor: Option<GenerationId>,  // §12e; derived, never set by a proposal
    pub units: BTreeMap<UnitId, (Observed, Vec<Evidence>)>,
    pub overrides: Vec<Override>,
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
    SetOverride(Override),                   // journals the override; for LeaveAlone, does nothing else
    LiftOverride(UnitId),
    StopAndSuppress { unit: UnitId, until: Until, reason: String },   // the user's "stop X": Override { desired: Stopped } journaled, then stop
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
/// Who may approve an AskFirst decision. The class is the maximum over every floor and table row that
/// raised the decision; it is ignored below AskFirst. `Administrator` requires the approver to hold
/// `Capability::Administrator` as well as `Capability::Approve`.
pub enum ApproverClass { AnyApprover, Administrator }
pub enum Decision { Allow { tier: Tier, approver: ApproverClass }, Reject(RejectReason) }
pub enum RejectReason { Forbidden, CoreTarget, ProbeTamper, NotInCatalog, LockedOption, Stale, Unauthorized, Interrupted, NoSpace, Precondition, ActivationUnknown, Other(String) }
// ActivationUnknown: the dry activation failed, timed out or was truncated, so the change's consequences cannot be derived (§9 step 3)

/// Derived by the executor from the evaluated generation — never from the proposal (I14).
pub struct DerivedFacts {
    pub affected_units: BTreeSet<UnitId>,
    pub sensitivity: Sensitivities,
    pub disruption: Disruption,
    pub recovery: Recovery,
    pub touches_manifest: bool,
    pub touches_canonical_probe: bool,
    pub touches_core: bool,
    pub below_security_floor: bool,         // target generation (revert, rollback, switch) is below `security_floor`
    pub other_sessions_affected: bool,       // a system-scope effect reaches another uid's online or active session (§11)
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
pub enum Actor {
    Daemon, Watchdog,
    User { uid: u32, session: Option<SessionId>, seat: Option<SeatId>, active: bool },  // filled from SO_PEERCRED → pid → logind
    Model(ModelId),
    Agent(PrincipalId),                      // an agent peer the journal has no live `AgentStarted` for (holds nothing), and
                                             // from later phases remote principals via a relay (future-work §3). A *started*
                                             // agent is authorized as `Actor::User { uid: by, session: None, seat: None, .. }`
                                             // (§11); its agent name and instance travel in `LogRecord.agent`, not in `Actor`,
                                             // so the proved `Actor` shape is unchanged
    Unattributed,                            // the actor of an `Inferred` override (§11); never a caller, never authorized
}
// `session` is None only for callers outside any logind session (e.g. a root timer); such callers never
// satisfy an "own session" floor.

// ---------- Principals and authorization (§11) ----------
pub struct PrincipalId(pub u64);             // stable; a human principal maps to a uid, an agent to a registered key
pub enum Capability {
    OwnScope,                                // act on units in one's own Scope::User
    UserControllable,                        // act on units in services.planarian.userControllable
    Administrator,
    Approve,                                 // approve others' AskFirst proposals within one's other capabilities (I19)
    Catalog, ModelCatalog,                   // propose catalog / model-catalog entries (the only non-human grants in B)
    Manifest, Merge,                         // human-only through B; Merge needs two distinct approvers
}
pub struct Grant { pub to: PrincipalId, pub capability: Capability, pub approved_by: PrincipalId, pub txn: TxnId }
/// Computed by the daemon for each call from SO_PEERCRED, logind, group membership, and journaled grants.
/// Never read from a proposal (I14).
pub struct Authorization { pub principal: PrincipalId, pub actor: Actor, pub capabilities: BTreeSet<Capability> }

/// Journaled by `planarian agent run` (§11, §16) once the agent's unit has started. `instance` is the
/// unit's InvocationID (or an equivalent per-start identity the backend can read back from the peer's
/// cgroup); a request from an agent peer is authorized as `by` only if the peer's instance equals this
/// record's and no later record names the same instance (I24). The name alone never identifies an agent.
pub struct AgentStarted { pub name: String, pub instance: InstanceId, pub by: u32 /* uid */, pub at: SystemTime }
pub struct InstanceId([u8; 16]);

// ---------- Failure posture (§12d) ----------
pub enum Posture { Relaxed, Standard, Guarded, Sealed }
pub enum FailureClass { Absent, Crashed, Integrity }

// ---------- Incidents ----------
pub enum IncidentState { Open, Cooldown { until: SystemTime }, Escalated(EscalationReason), Closed, Regressed { count: u8 } }
pub enum EscalationReason { Regressed, BudgetExhausted, DiagnoserExhausted, RevertBlockedByFloor, RecoveryFailed }
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
    Publishing,                              // boot-only path (§12 step 7): journaled before the first boot mutation
                                             // (`publish_boot_once`); recovery from here reads the op's OpBegin/OpEnd
    Published,                               // boot entry written
    AwaitingBoot,                            // boot-only candidate published as a one-shot next-boot entry (§12f); active for I6
    Promoted,                                // live path: override source promoted; boot-only path: candidate admitted as the
                                             // boot default at the boot it was published for, confirmation pending (§10)
    Committed, Reverting, Reverted, RecoveryFailed,
    Rejected(RejectReason),                  // terminal: refused after Prepared (precondition, expired/invalidated approval, policy)
    Cancelled(Actor),                        // terminal: withdrawn before any mutation
}
impl TxnState {
    /// The one list I6 and §12 "Concurrency" both mean: no transition executes while any transaction is in one of these.
    pub fn exclusive(&self) -> bool { matches!(self, Activating | Checking | Publishing | Published | Promoted | Reverting) }
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
    pub approver: PrincipalId,               // must differ from the proposer and hold the decision's ApproverClass (I19)
    pub class: ApproverClass,
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

**Status derivation** (`SystemState::status`), in order: Overridden if an override holds (reported with its `OverrideDesired`); else if the desired condition does not hold, *not expected* (observed status reported, no incident); else **Failed** if `Observed::Failed` (a definite supervisor failure is never masked by stale probes); else Unknown if any *Readiness* probe's evidence is stale or timed out; else Running if observed Active and all Readiness probes passed fresh; Degraded if Active with a failed Readiness probe; else from `Observed`. Diagnostic probes never affect status; their evidence is shown in the console and used by the diagnoser only.

**systemd mapping:** `active` → Active; `failed` → Failed(ExitCode); `inactive`/`dead` → Bound (Stopped once desired is considered); `activating`/`deactivating`/`reloading` → Transitioning; not found → Absent; D-Bus error → Unknown. Devices via udev: present without driver → Detected; bound → Bound/Active.

## 9. Manifest, change catalog, and configuration editing

**Manifest** (`services.planarian.units.<name>`): `desired` (status + condition), `edges` (kind + target), `sensitivity` (set), `restartDisruption`, `probes`, `synonyms`. Defaults derived at build time: `Requires=`/`BindsTo=`/`Requisite=` → `Requires` edges; `Wants=` → `Wants` edges (weak, never a root cause); `After=` → `Ordering` edges only; functional prerequisites systemd cannot express come only from the manifest; `predicted` from `enable`; sensitivity from a shipped table; `restart_disruption` from a shipped table (display-manager → SessionLoss; network → ConnectivityLoss; databases → DataInterruption). `Diagnostic` edges come only from the manifest or, later, from learned data, and carry a confidence; a learned edge is never admitted without a passing gym case. The manifest and the override file have `Sensitivity::{Security}`.

**Probe kinds.** Canonical and user probes are built from the typed kinds (`SystemdActive`, `Tcp`, `Http`, `DBus`, `FilePresent`). `Exec` probes, which run arbitrary commands, are permitted only in manifest entries authored by a principal with administrator authority; they are flagged in the console and the journal, and their definition changes are Security-sensitive like the rest of the manifest.

**Canonical probes** ship in the `planarian` package for networking, sshd, pipewire, display-manager, graphical-session, storage, and the user services the reference config enables. A generation may add `User` probes; it may not remove or alter canonical ones (I10). The reference-config `graphical-session` unit has desired condition `SessionEstablished { seated: true }` (logind reports a new seated session, i.e. authentication succeeded at a seat; an SSH login expects no desktop) and a Readiness probe "the compositor process in that session's cgroup (`session-<id>.scope`) reaches its ready state within 60 s of the session's creation," with `graphical-session.target` as corroboration only. (The target lives in the per-user manager, so for a second graphical session of the same uid it is already reached and cannot serve as evidence.) The condition comes from logind, the result from systemd, so a desktop that fails after a successful login opens an incident, and an idle greeter opens none. The greeter's probe is `SystemdActive`. Canonical probes are tagged `role: Readiness` where their side effects are `None` or a bounded `Measurement` (TCP connects, GETs to health endpoints); the audio tone and any `Audible`/`Visible`/`RemoteStateChange`/`Disk` probe are `Diagnostic` and OnDemand.

**Applicability of probes to authorized desired-state changes.** A probe applies only while its unit is desired-present under the *candidate's* desired state. A transaction that disables a service (authorized by policy) makes that service's probes inapplicable in the candidate; it is not probe tampering, which means changing a probe's *definition*. Both are derived facts: `touches_canonical_probe` (definition changed) versus `changes_desired` (applicability changed). Only the former is protected by I10.

**Change catalog** (`crates/changes`, wired by `nix/reference.nix`): every `ApplyChange` names a catalog entry. An entry has: `id`, `args` with types and permitted values, a `handler` that produces option assignments for the override file, `affected_modules`, `description`, and `locked_if` (user `mkForce` detected). The executor evaluates the handler's output (`GenerationBackend::evaluate`) and **derives** affected units, sensitivity, disruption, and manifest/probe-touching from the evaluated generation's option set and activation plan, not from the entry's own metadata (I14); the entry's `affected_modules` is a hint for the matcher and a test assertion, not a policy input. Phase A ships entries for: enable/disable a service from an allowlist; set font scale; set keyboard layout; select Wi-Fi network; set a service's listen address from a permitted set; re-enable a manifest-predicted option observed disabled. The model (B) may propose *new catalog entries* for human review; it never writes raw Nix.

**Override source and staged evaluation.** Planarian never edits the user's own Nix. The owner's flake imports `./planarian/overrides.nix` *relative to the flake root* (the module template does this), containing flat option assignments wrapped in `lib.mkOverride 90`. A candidate is never evaluated from mutable host files:

1. **Stage.** `GenerationBackend::stage` copies the owner's configuration as Nix will see it (for a Git flake: the tracked files from the working tree, *including uncommitted modifications to tracked files*, which is what a local Git flake input exposes; untracked files are excluded and reported; for a non-Git directory: the whole directory) plus `flake.lock` into an immutable directory `/var/lib/planarian/stage/<txn>/`, computes and records **`base_source`** (the NAR hash of that copy *before* any override replacement, i.e. the owner's source with the base override), then replaces `planarian/overrides.nix` with the candidate override set and records **`staged_source`** (the NAR hash of the tree actually evaluated and built). Both identities, plus `base_override` and `candidate_override`, are bound to the transaction and the approval token. The pre-activation stale check (step 6) recomputes the NAR hash of the same Nix-visible set of bytes from the owner's working tree and compares it to **`base_source` only**; `staged_source` is what the candidate must match at `verify_candidate`. So a change that alters only the override reaches activation without `Stale`, and an uncommitted owner edit after staging produces `Stale`. Nothing is "pinned by hash and read later": the bytes evaluated are the staged bytes.
2. **Evaluate** the staged source with `pure-eval` on (it is a path input with no external state) and record the evaluated option set, `UnitDefs`, and activation plan.
3. **Build** before approval. The candidate store path is determined by the build; approval binds to it. The build also records the candidate's **realized identity**: the store path's NAR hash (`nix path-info --json`), kept in the transaction as `candidate_nar`. Before `activate_live`, `verify_candidate(path, candidate_nar)` confirms the path exists *and* its NAR hash equals the recorded one; an existence check alone does not satisfy this step. The dry activation that produces the activation plan (`switch-to-configuration dry-activate`) MUST exit successfully within its timeout with untruncated output; otherwise the build fails. A plan is never derived from partial output.
4. **Base and candidate identities.** At `Prepared` the executor copies the live `overrides.nix` to the transaction-specific, immutable `/var/lib/planarian/txn/<txn>/base.nix` and records its content hash as `base_override`; the staged candidate's content hash is `candidate_override`. No shared `.prev` file exists. **Promote** (on the commit path, after `publish_boot`): under an exclusive `flock` on the override file's directory, read the live file's hash; if it equals `candidate_override`, the step is already done; if it equals `base_override`, write the candidate to a temp file, fsync, atomic rename over the live path, fsync the directory, release the lock; anything else → `RecoveryFailed` (a third party changed the file). **Restore** (revert path): the same procedure with base and candidate swapped. Both are therefore idempotent by construction and cannot save the candidate over the base. The lock closes the window between comparison and rename for writers that take it (Planarian's own paths, and PlanarianOS's wrapped editors from C); a root editor that does not is X-12 in the register. The `txn/<txn>/` directory is created with an exclusive `mkdir` (§12 step 4) and is deleted after `Committed`/`Reverted`/`Rejected`/`Cancelled` and a successful checkpoint (§12c); the content-addressed override store (`overrides/<hash>.nix`) is pruned of entries no live or protected generation references at the same time.
5. **GC root.** `build` is store-only bookkeeping and roots its own output: on success it creates `/nix/var/nix/gcroots/planarian/builds/<staged_source hex>` pointing at the candidate store path, before any transaction exists and without a lease (this is the one root operation that does not require `Prepared`; `protect` is the lease-gated form used for generations). When the transaction is created in §12 step 4, it *adopts* the root (recorded as `gc_root`); the root is removed when the transaction reaches a terminal state (kept if `Committed`, since the generation's own profile link then roots it). On startup, and before every `CollectGarbage`, the daemon removes any `builds/*` root not adopted by a live transaction and older than 24 h: this covers builds whose daemon died before `Prepared` as well as committed candidates. A policy record is never a root; only the symlink is. Gym cases: run GC while approval is pending (the candidate survives); crash during `build`, restart, wait past the age limit (the orphan root is gone).
6. **Stale check.** If the owner's Nix-visible source no longer hashes to `base_source` at any check between `Staged` and `Activating`, the transaction is `Rejected(Stale)` and re-prepared; the staged copy is unaffected, but the policy facts were derived against a source that no longer matches what the owner will build next. The check runs at `Prepared`, at approval, and **immediately before `Activating` on every path**, including when a transaction leaves `Built` after waiting for an activation window (§12f) — together with re-derivation and a fresh `decide` (I8). Gym cases: an override-only change with no owner edit activates without `Stale`; an uncommitted edit to a tracked owner file after staging produces `Stale`; an owner edit while a change waits for the session to idle produces `Stale` when the window opens.

Options the user set with `mkForce` are `locked`. Gym cases: an override-only candidate changes the evaluated output; the owner edits the source during a build; a crash at each commit boundary (§12).

**External desired-state source (hook).** Desired state may additionally be sourced from a signed external document, alongside the manifest, verified against a key declared in the generation. The key option and the source's location are Security-sensitive (changing either is AskFirst with administrator authority). A stale or unreachable source leaves the last valid document in force; an invalid signature is an integrity failure (§12d). Phase A implements the verification and cache path with no producer; fleet desired state, membership, and pushed defaults use it later (future-work §5) without reopening `state` or `policy`.

**Catalog coverage.** The gym computes coverage: of the options a profile's user plausibly changes (inferred from the NixOS option tree filtered to user-facing, bounded-domain, non-Security options, the desktop settings surface, and option frequency in public configurations), the fraction with a catalog entry. Coverage is a gym metric, never measured on users. Sensitivity is derived from the evaluated change (I14), so catalog growth does not grow the policy review.

**`NotInCatalog` by phase.** A: reject and say so; an authorized user may still edit the override file directly, through the transaction path. B: the model may propose a new catalog entry for review; on approval the original request runs through it. C: Flatpak is the user-scope valve for installing applications, which needs no system change and no catalog entry.

**Executor-owned requirements.** Beyond the proposer's `expected`, the executor always requires: no unit outside `may_change` that is desired-present *under the candidate* leaves Running; no Readiness probe that is applicable under the candidate and passed before fails after; the generation equals the verified candidate. The second requirement is checked **per probe against the set recorded before the change**, not by comparing aggregate unit status: a unit that was Degraded before (probe A failing, B passing) still fails the check if B fails after. The first requirement is checked over every observed unit, not only those the proposer named. A proposer can only *add* claims.

### 9a. PlanarianOS (Phase C)

PlanarianOS is a NixOS distribution in which Planarian governs the machine from first boot. It exists for the guarantees a module installed on an existing machine cannot make: no older, unmonitored generations in the boot menu; a boot chain locked from install (Secure Boot with a signed unified kernel image via Lanzaboote, bootloader editing disabled, TPM measured boot where available); failure posture and the first administrator set before anyone logs in; a known starting configuration against which catalog coverage is measured; and Planarian-native defaults (hash-chained journal from the first boot, sandbox tier where KVM exists, no out-of-band rebuild path in the default configuration). Planarian also remains installable as a module on any NixOS.

| Profile | For | Default posture | Includes | Leaves out by default |
| --- | --- | --- | --- | --- |
| Agent host | Machines that agents operate | Guarded | Sandbox tier, journal export, capability-scoped agent principals | Desktop, local model |
| Server / fleet node | Unattended servers and edge devices | Sealed | Signed external desired state, signed health reports | Desktop, local model |
| Personal | Desktops and laptops, including remotely administered ones | Standard | COSMIC reference desktop, optional console, quiet mode, model residency, Flatpak, remote administration | — |

**Gates (GC), per profile.** Agent host: an agent holding a user account completes a scripted set of real administration tasks; zero unsafe changes reach the real machine; every change attributed; every Tested change carries a passing sandbox run. Server: unattended under the full fault catalog for a set period; every fault repaired or escalated; every posture response verified by injection. Personal: a person new to Linux installs it and completes common tasks (connect to Wi-Fi, change display scaling, install an app) through whichever frontend the profile ships; catalog coverage above the owner-set threshold (set after the first catalog survey); invisibility budget met.

**Accounts.** The everyday login is a `user` account with no administrator authority, never shown an AskFirst prompt it cannot answer. Administrator authority is a capability, grantable to a local account, to a remote principal, or both (I17: the set is never empty). The installer creates the first administrator, then an everyday account, and says plainly that the everyday account is the one to use daily. An administrator may drop the capability only while another remains. Lost-administrator recovery requires physical presence: a local session (in E, the secure attention key).

**Live mode.** A live image has no generations: `planariad` runs with `max_tier = Runtime` and reports "no baseline," and every frontend says so. The live image is also the gym's VM image.

## 10. State (crate `state`)

- **Tick:** 5 s and on systemd/udev/login events. Warn if a tick exceeds 500 ms.
- **Conditions** evaluated each tick from logind (sessions), udev (devices), upower (power), and the foreground signals (a registered Feral GameMode client, an active gamescope session, a fullscreen surface holding a Wayland idle-inhibitor, the user's Do Not Disturb) for `Foreground { session }`. Two session conditions are distinguished (owner decision, 30 Oct): `SessionEstablished` counts every session of class `user`, seated or remote (greeter, `manager`, and background sessions are ignored), and is what user-scoped units are desired under; the **graphical expectation** — the `graphical-session` unit's desired condition — holds only for a *seated* `user` session (`seat` set), so an SSH-only login never expects a compositor and never opens a desktop incident. The readiness deadline is bound to that specific session id, so a second user logging in does not reset or satisfy the first session's deadline. Gym cases: SSH-only session (no graphical incident); two graphical sessions for one uid; greeter only; a locked session (no divergence).
- **Probe contract.** Every probe runs in a sandbox (`ProbeSandbox`: dedicated uid, dropped capabilities, bounded CPU and output, network only if declared), is killed at timeout with its process group, and its output is logged as data. A probe's `timeout` is a **deadline for the whole probe**: name resolution, connection, writing, and every read count against the one budget, and a probe past its deadline yields `Timeout` whatever it was doing. The probe runner bounds concurrency and never waits past the batch deadline for a straggler: a probe still running when the tick's deadline passes is recorded `Unknown` and abandoned, so one wedged service cannot stall observation, repair, approvals or the socket. Typed probes (`Tcp`, `Http`, `DBus`, `FilePresent`) run in the daemon's process in A, with `bytes_max` enforced for every kind that reads and `per` enforced by the cadence scheduler; running them in the probe sandbox is C. Probes with `side_effects` of `Audible`, `Visible`, `RemoteStateChange`, or `Disk` are `Diagnostic`, run `OnDemand` only, and `Audible`/`Visible` require a user-initiated diagnostic. `Measurement` side effects (a bounded, read-only network or local I/O such as a TCP connect or an HTTP GET to a declared health endpoint) are permitted for Readiness probes at the declared rate. A Readiness probe whose `establishes` names an external dependency (an upstream endpoint, a gateway) MUST declare a **traversable** edge to a unit representing that dependency (`service:external:<name>`): `Requires`, or `Diagnostic` with confidence ≥ 0.7, the diagnoser's threshold (§13). The module rejects a manifest that declares a weaker edge for an external dependency, so an unavailable dependency is diagnosed as such and never produces a local restart (owner decision, 30 Oct). Gym cases: a process stays active while its HTTP health endpoint returns 503 (Degraded, incident opens); the external dependency is down (incident targets the external unit; no local restart); a manifest declares a 0.5-confidence edge to an external dependency (rejected at evaluation); a stalled resolver and a server that sends one byte just before each read would time out (the batch returns within the deadline plus a small allowance and the repair loop ticks meanwhile). `WakesHardware` probes default `Every(60 s)`, `Every(300 s)` on battery. A `Timeout` or `Error` yields `Unknown`, never `Failed`. A tick that exceeds 500 ms is logged as a warning with the probes that ran in it.
- **Evidence** carries `stale_after`; the status derivation treats stale *Readiness* evidence as Unknown; stale Diagnostic evidence is displayed, never counted. An incident is not opened on Unknown; the probe is re-run with backoff and, after three consecutive Unknowns, a *diagnostic* incident is opened whose first candidate is "re-observe via a different Readiness probe," not a restart. Gym cases: Diagnostic evidence expires on a healthy machine (status stays Running); a definite `Observed::Failed` while another probe is stale (status is Failed, not Unknown).
- **Storage** is modeled per filesystem: `device:fs-root`, `device:fs-nix` (if separate), `device:fs-boot`, `device:fs-journal` (the filesystem holding the journal), each with a canonical Readiness probe (free ≥ max(2 GB, 5%) for root and nix; ≥ 64 MB for boot; journal headroom per §12c). Divergence on root/nix → `CollectGarbage` first.
- **User-scoped units** are keyed by uid and session; a user service is desired while *any* session of that uid exists, so logging out of one of two sessions does not stop the user's services.
- **Actors and sessions.** For every request on the daemon socket, the daemon obtains a pidfd for the peer (`SO_PEERPIDFD`, Linux 6.5+), resolves the logind session from that pidfd, never from a bare pid, and fills `Actor::User { uid, session, seat, active }`. A peer whose pidfd cannot be obtained, or whose process has exited, is treated as having no session. A request with no seat (SSH, other remote logins) is never treated as local. Greeter and lock-screen sessions remain excluded from `SessionEstablished`; locking a session is not a divergence.
- **Boot report.** On its first tick after boot, `planariad` writes a boot report: every unit that started before `planarian-ready.target` and is outside the generation's declared closure (from C also every such process whose executable is outside the closure, including udev `RUN+=` helpers and generators' children; user binaries started later are never early-boot findings); whether the installed Planarian package is a test build (§15); core hash against its signature (I2); journal hash-chain integrity (I18). Any finding is an `Integrity` failure (§12d) and opens an incident per undeclared item.
- **Signed health report (hook).** The core emits a signed outbound health report (status per unit, incident summary, generation identities) on a declared cadence, with contents selected by a disclosure profile that the core computes, never the requester. Phase A emits it locally only; the default profile is minimal (unit statuses and incident kinds; no versions, paths, or log content). Expanding the profile is Security-sensitive.
- **Boot confirmation** has two milestones (owner decision, 30 Oct; v4.5 conflated them). **Admission**, before `planarian-ready.target`, within the boot-ready timeout (§12d): the daemon reconciles the journal (§12: activation recoveries run just after ready) and, for a boot-only candidate in `AwaitingBoot`, runs the candidate's applicable Readiness probes once; pass → the candidate is made the default and the transaction advances to `Promoted` (the boot proceeds; principals are admitted); fail, or the target not reached → the next boot falls back (§12 step 7) and the transaction is `Reverted`. **Confirmation**, at the 10-minute checkpoint on the same boot: `GenerationBackend::last_booted()` is compared to the generation that was `live_tested` or admitted; if they match, the canonical probes pass, and, for an admitted boot-only transaction, no canonical unit needed a repair since admission (repairs run in that window, I6; a repair is evidence against the candidate even when it worked), that generation becomes `known_good` and the admitted transaction is `Committed`. A generation whose diff touches kernel, initrd, bootloader, or filesystem options can become `live_tested` but not `known_good` until confirmed by a reboot; the console says so. A boot-only candidate (§12f) is never `live_tested`. Between admission and confirmation the candidate is the default and the booted generation; a crash of the daemon in that window leaves `Promoted`, which the crash table completes.

## 11. Policy (crate `policy`)

- `decide(transition, facts: &DerivedFacts, state, defs, session, authz: &Authorization) -> Decision`. Pure. Reads nothing from `Proposal`.
- **Principals.** Every caller is a principal: an authenticated identity, a capability set, and a reputation (how much its claims about the world are credited). Defaults: a user has wide capabilities and high reputation; the diagnoser moderate and high; the model narrow and zero (I14); an app tiny and zero. These are defaults, not ceilings. Capabilities come from grants, never from what kind of thing the principal is: from B, an agent granted a capability holds it exactly as a human would, within the same floors. **In A an agent acts with its user's permissions, no more and no fewer** (owner decision, 2026-10-30): there are no grants to agents in A, so an agent's capability set is its user's. An agent (on-device model, coding agent, or any automated actor on the user's behalf) is started through `planarian agent run` (§16), which journals who started it and creates a transient unit with `DynamicUser=` for it. Its requests are authorized exactly as that user's would be, as the user with no login session, no seat and no terminal — so the own-session and seat exemptions never clear for it and it cannot approve, which is also how that user is treated over SSH — and the executor log attributes each one to the agent (`LogRecord.agent`), acting for the user. An agent is not treated differently from its user in what it may do; it is told apart so that what it did can be seen. An agent the journal has no start for holds nothing. **Identity is per instance, not per name** (I24; B-20): `agent run` refuses a name whose unit is loaded or whose last `AgentStarted` record names a live instance started by a different uid; the record is journaled only after the unit has started, carrying the instance identity the daemon reads back from the peer's cgroup, and authorization matches the peer's instance to that record. Re-running `agent run <name>` can therefore never change what an already-running agent may do. An agent run by hand under a human's uid, outside `agent run`, is that human, unattributed (`docs/bypasses.md`, X-10). The model service (B) is an agent in this sense too: `Actor::Model` holds nothing until B defines its grants, and `authorized_spec` treats it as it treats `Actor::Agent`, never as the daemon. In Phase B, non-human principals may hold catalog and model-catalog authority only; manifest and merge authority stay with humans. Capability grants are AskFirst changes approved by a *different* principal with administrator authority; the root of every grant chain is a local human session (I19).
- **Caller identity and authorization** are established by the daemon, not the proposal: the Unix socket peer is authenticated with `SO_PEERCRED` and a pidfd (§10); `Actor::User { uid, session, seat, active }` is set from it (§10), and any actor field inside a proposal (e.g. `Override.by`) is overwritten. Authorization is a separate rule evaluated before risk: a user may act on units in their own `Scope::User` and on system units listed in `services.planarian.userControllable` (default: audio, display scaling, their own Wi-Fi selection); every other system action requires administrator authority (in A, root or membership in the `planarian-admin` group; I17 holds over that group plus root). Authorized to start a unit means authorized to override it, with one exception: an override on a unit whose derived sensitivity includes `Security` (firewall, audit, sshd hardening, Planarian's own units, the sandbox) needs administrator authority. A non-administrator's override on a Security-sensitive unit is not rejected: it is held as AskFirst with `ApproverClass::Administrator`, the unit stays up meanwhile, and an administrator may approve it. Any other action outside the caller's authority → `Reject(Unauthorized)`, regardless of tier. The model and the daemon are never "authorized users"; their proposals follow the daemon rules. No request field decides authority: a property of the caller that matters (a controlling terminal, a session, a seat) is established by the daemon from the peer's pidfd, never from the request.
- **Equivalent effects, equivalent facts.** Derived facts describe what a transition *does*, not how it is spelled. `SetOverride { desired: Stopped }` stops the unit and carries the unit's `restart_disruption`, its dependents and `other_sessions_affected` exactly as `StopAndSuppress` on the same unit does; `desired: Absent` and `Detected` likewise carry the effects of the disable or unbind they cause. Only `LeaveAlone` has no effect and no disruption. `SwitchGeneration`, `Revert` and `Rollback` derive their facts from a dry activation of the target generation and the override content recorded for it, like `ApplyChange` does from its build: affected units, disruption, the option diff (for the Rollback row and I11) and `below_security_floor` all come from the target, never from the assumption that a vetted generation is harmless. Gym cases: both stop spellings on `display-manager` from a remote administrator session get SessionLoss and ask; a rollback between two vetted generations whose manifests agree but whose `NetworkManager` unit differs is scheduled as ConnectivityLoss.
- **Preconditions are the executor's.** `TransitionSpec::precondition` is checked by the executor at §12 step 5 for every proposal, whatever its source; a failed precondition is `Rejected(Precondition)`. The diagnoser's use of it to filter candidates is in addition, not instead. The preconditions the spec fixes: `SetOverride` on a unit that already holds an *Attested* override by another principal fails (only an *Inferred* override may be replaced, and only by an authorized principal; the holder lifts their own); `LiftOverride` on a unit with no override fails; `Revert { to }` with `to` the current generation and `Rollback` with `known_good` the current generation fail; `RestartUnit`/`StopUnit` on an `external:` unit or on a unit under an override fail (I13).
- **Global floors**, applied before the per-transition table, to every transition kind: `recovery == NonReversible` → at least AskFirst; `disruption ∈ {SessionLoss, DataInterruption}` → at least AskFirst unless the caller is an authorized user whose own session it is; `disruption == ConnectivityLoss` → at least AskFirst unless the caller is a user with a local (non-remote) session, i.e. `seat` is set. "Own session" is per session, not per uid: a user dropping another of their own sessions gets the floor. `other_sessions_affected` with disruption ∈ {`SessionLoss`, `ConnectivityLoss`}, on a system-scope transition → AskFirst unless the caller holds administrator authority, and the affected sessions are notified either way. `below_security_floor` → AskFirst with `ApproverClass::Administrator`, for every transition kind. So a daemon-proposed `BindDriver` that would drop a session, a `SetRuntimeOption` Wi-Fi change proposed by the diagnoser, and a non-administrator stopping the network while another user is logged in all ask.
- Reject when: `touches_core`, forbidden transition, `touches_canonical_probe` (definition) outside AskFirst, change not in catalog, locked option, unauthorized caller.
- Tier otherwise, by table; escalations compose with the floors:

| Transition | Base | → AskFirst when |
| --- | --- | --- |
| RestartUnit / StopUnit | Runtime | sensitivity ∋ Security or External (floors cover disruption) |
| SetOverride / LiftOverride / StopAndSuppress | Runtime | caller is not an authorized user; or the unit's sensitivity ∋ External; sensitivity ∋ Security and the caller is not an administrator (approver: Administrator) |
| BindDriver | Tested | sensitivity ∋ Security |
| ApplyChange | Tested | sensitivity ∌ only Routine; touches_manifest; touches_canonical_probe; cumulative diff non-Routine (I11) |
| SwitchGeneration / Revert | Tested | target not live-tested or known-good; revert target differs from the transaction's recorded `revert_to`; target below the security floor (administrator) |
| Rollback | Runtime | known_good would restore Security- or External-sensitive options that changed since (policy computes the diff); known_good below the security floor (administrator) |
| LoadModel | Tested | not in hash-pinned catalog → Reject |
| RestoreSnapshot | AskFirst | always |
| CollectGarbage | Runtime | never (I3) |
| SetRuntimeOption | Runtime | not in the core allowlist → Reject |

- **Autonomy setting:** `max_tier ∈ {Observe, Runtime, Tested}`. Any `Allow { tier: t, .. }` with `t > max_tier` becomes AskFirst with `ApproverClass::AnyApprover` (or the class already set, if higher). `Reject` is never affected (I5).
- **Approval.** Approval is a capability held by principals, granted only from a local human session. Whoever holds it, human or agent, may approve within its scope, but never a proposal it made itself (I19). Remote principals hold no approval capability by default. In Phase A approval requires root at an interactive terminal, and the daemon establishes the terminal itself (the controlling terminal of the peer's process, from its pidfd). A change to merge authority, and any proposal to grant `Merge`, requires two distinct approvers, neither of them the proposer.
- **Deliberate actions carry identity.** Every user-facing path by which an authorized principal can put a unit into a state that diverges from desired state (stop, disable, unmount, disconnect, unbind) is routed so the action is journaled as an attested `Override` before it takes effect: the CLI and console in A; in C, PlanarianOS also wraps the commands people type (`systemctl`, `nmcli`, `udisksctl`) and routes the desktop's own switches through the same path. Logging out and suspending are not divergences (conditions stop holding) and need no override. A root `nixos-rebuild` outside Planarian is observed as a new, unconfirmed base: not fought, not trusted.
- **The unattributed residue.** A raw signal or direct sysfs write has no principal. OOM kills (`Result=oom-kill`) are always faults. A stop of a Security-sensitive unit is always a fault: it is restarted and alarmed, never inferred as intended. So is a stop of a unit whose manifest sets `inferStops = false` (default true; the reference configuration sets it false for backup, sync, and the desktop's own units). `inferStops` is provisional (§19): if unit importance comes to matter beyond residue inference, replace it with a declared `importance` property separate from sensitivity. Otherwise, by posture: Relaxed and Standard accept the stop until next boot as an `Override { by: Actor::Unattributed, attribution: Inferred, until: NextBoot }`, with a notice and an undo; Guarded and Sealed open the 10 s ask window and restart if nobody answers. An inferred override is an observation the daemon records, not a proposal: it does not pass through `decide`, holds no authority, and cannot be extended or converted to `Attested` except by an authorized principal setting a new override. The journal records the inference as an inference, and the console lists inferred overrides until a user acknowledges or undoes each one.
- **Sensitivity completeness.** Overrides, the residue rule, and I22 key on `Security`, so an untagged security unit is unprotected. Units declared through the `security.*`, `networking.firewall.*`, `services.openssh.*`, `services.fail2ban.*`, `services.usbguard.*`, and VPN option trees are `Security` by default; a unit with no sensitivity entry is treated as non-Routine (fail closed). A gym entry checks a named list of security units against the shipped tables.
- **Disruption surfacing:** any Allow with disruption ≥ SessionLoss is logged and, if a console is attached, shown before execution with a 10 s cancel window for daemon-initiated actions.
- `PolicyVersion` is the hash of the policy crate build plus the shipped sensitivity tables; it is recorded in every transaction and token.

## 12. Executor and transaction kernel (crates `exec`, `txn`, `watchdog`)

**Journal:** append-only, write-ahead, fsync'd, in a preallocated file at `/var/lib/planarian/journal/` (§12c). **Read-only backend calls** (`current`, `boot_entries`, `last_booted`, `observe`, `stage`, `evaluate`, `build` — build writes only to the Nix store and activates nothing, so it is treated as read-only with respect to system state, but its output is recorded) may precede `Prepared`. **Every mutating call** (`activate_live`, `publish_boot`, `protect`, `restart`, `stop`, `snapshot`, `restore`, file promotion) requires a durably written `Prepared` record and a current lease epoch. `Prepared` is written on the Allow path as well as the AskFirst path.

**Ownership and fencing.** Each transaction has exactly one owner at a time (`Lease`). Mutating backend calls carry the lease epoch; the backend layer reads the journal's current epoch for that transaction and refuses the call if it differs (`Outcome::Failed("fenced")`). Mutations that take time (activation, revert) run in a **worker** (a thread in A, a subprocess recorded in the lease from D; see "Worker processes" below) that inherits the epoch. Taking over a transaction means: write a new lease with `epoch + 1` (durably), stop the previous worker where one can be addressed (SIGTERM then SIGKILL to its process group via pidfd, from D), then establish **confirmed quiescence**. Every mutation attempt first journals a durable **operation id** (`OpId`, an `OpBegin { txn, epoch, seq }` record written and fsynced *before* the backend call, matched by an `OpEnd` with the outcome after it; "acknowledged" below means the `OpEnd` exists), and the backend call is tagged with it (for systemd: the job's unit is started with a transient property `X-Planarian-Op=<OpId>` via `SetUnitProperties` in the same D-Bus transaction, or, where the call cannot carry a tag, the daemon records the pre-call snapshot of `pending_jobs()` as the op's baseline). Quiescence then covers both the jobs in the old lease's `jobs` list *and* every job discovered by `jobs_tagged(op)` for each journaled `OpId` whose acknowledgment was never recorded. Every such job must be cancelled (`systemctl cancel <job>` where the supervisor supports it) and confirmed gone from `pending_jobs()`, and any activation worker's own child processes reaped; the new owner waits up to the job-drain limit (60 s) for that confirmation, and if quiescence cannot be confirmed, or `jobs_tagged` returns `None` for an unacknowledged `OpId` (the backend cannot say whether undiscovered work remains), it writes `RecoveryFailed` and blocks all further mutation rather than proceeding. A drain timeout is never permission to proceed, and neither is an empty list of *known* jobs. Gym case: accept an activation job, withhold its reply, kill the owner before the job id is journaled, start recovery; recovery must discover or fence the accepted work before any conflicting mutation. Only after confirmed quiescence may the new owner advance the journal. **Lease transfer is atomic:** the lease is a file `/var/lib/planarian/txn/<txn>/lease` replaced by atomic rename of a temp file whose name embeds the candidate epoch, after `flock` on the transaction directory; two processes attempting takeover serialize on the lock and the second sees the first's epoch and backs off. An old owner that wakes up finds its epoch stale on its next call and exits. **Only the current lease holder may advance the journal or commit.** Gym case: kill and immediately restart the daemon while a deliberately slow activation worker survives; assert activation and revert never overlap and the old owner cannot commit afterward.

**Protocol** for a `Proposal`:

1. Observe S0. If `proposal.observed != S0.digest()` → Reject `Stale`, return the current digest.
2. **Admission before work.** Before any staging, evaluation or build, check what can be checked cheaply: the caller's identity and capabilities against the transition's authorization rule (§11), the catalog membership of an `ApplyChange`, and the recovery interlock (§12c). A caller who cannot be authorized for the transition causes zero `stage`/`evaluate`/`build` calls (`Reject(Unauthorized)` here). Then, for `ApplyChange`: run the handler, `stage`, `evaluate`, and `build` (read-only path); for `SwitchGeneration`/`Revert`/`Rollback`: dry-activate the target (§11). Derive facts from the evaluated candidate. Work in this step is charged to the caller and bounded (one build slot per caller class; §16a).
3. **Refinement check:** `proposal.expected` MUST agree with `spec.predict()` on every unit the spec predicts, MUST NOT broaden `may_change`, MUST NOT set `others_unchanged = false` where the spec sets true. Violation → Reject. Executor-owned requirements (§9) are appended. The transition's `RecoveryStrategy` and `revert_to` are fixed here by the spec, not the proposer.
4. `policy.decide` (with authorization). `Reject` → log, alert if the source was the model. Otherwise create the transaction atomically: `mkdir /var/lib/planarian/txn/<txn>/` (fails if it exists), write `base.nix` and the initial lease (epoch 1, this daemon) into it, then journal **`Prepared`** (durable) with facts, expected, revert_to, recovery strategy, handler, staged_source, base/candidate override hashes, gc_root, candidate path, policy version, and the lease. The transaction does not exist until the `Prepared` record is durable; the directory alone is garbage the next startup removes. `AskFirst` → request a token bound as in §8, park. On token: **re-derive facts, re-run `decide`, recompute cumulative hash and candidate verification**; any difference in `bound_to` invalidates the token and re-requests. Tokens expire in 24 h (`CLOCK_BOOTTIME`, §12h), are single-use, and **do not survive a daemon restart** (owner decision, 30 Oct): a restart invalidates every unused token, the parked change re-requests approval, and the checkpoint carries consumed nonces only, for replay protection. The approval is recorded: the token-use journal record and the transaction carry the approver's `PrincipalId`, `bound_to` and the transaction id, and the approved execution writes its own log record (I7).
5. Check precondition against the current state (`TransitionSpec::precondition`; §11). A failed precondition writes `Rejected(Precondition)`; an expired or invalidated approval that is not re-granted within its window, or a policy decision that changes to `Reject` on re-evaluation, writes the terminal `Rejected(reason)`; all release the GC root. A user withdrawing a parked proposal writes `Cancelled`. All are terminal and reopen the incident if one was waiting.
6. (The lease was created with the transaction in step 4.) Snapshot if facts.sensitivity ∋ UserData and supported; record. If unsupported in Phase A, log `NoSnapshot` and continue; from C, AskFirst.
7. Execute, by recovery strategy, which is fixed per transition and independent of tier:

   | Transition | Handler | Recovery | Notes |
   | --- | --- | --- | --- |
   | RestartUnit, StopUnit, StopAndSuppress, SetOverride, LiftOverride | UnitOp / IntentOp | ReobserveOnly | `candidate = None`; never a generation operation |
   | SetRuntimeOption, CollectGarbage | UnitOp / GcOp | ReobserveOnly | same |
   | ApplyChange, SwitchGeneration, Revert, LoadModel | GenerationOp | RevertGeneration | full journal path below |
   | **Rollback** | GenerationOp | RevertGeneration | tier may be Runtime, but it is a generation operation: serialized (I6), owned, with `candidate = known_good` (or `accepted_baseline`), `publish_boot`, and override restoration to the override content recorded for that generation; its own `revert_to` is the generation it left |
   | BindDriver | DeviceOp | UnbindDevice | a device operation via the inventory backend (`bind`/`unbind` on the sysfs driver interface); no generation is built or activated; on failure or mismatch, unbind and rebind the previously bound driver (recorded at Prepared) |
   | RestoreSnapshot | SnapshotOp | RestoreSnapshotThenRevert | C |

   - **UnitOp / IntentOp / GcOp (`ReobserveOnly`):** journal `Activating` → backend call in-process → `Checking` → settle → observe → compare → journal `Committed` with the outcome recorded, whether or not the expectation held; a mismatch informs the incident and never triggers generation reversion. A `Partial`/`Unknown` outcome means re-observe and record, nothing more. `StopAndSuppress` journals the suppression *before* calling `stop`.
   - **GenerationOp (`RevertGeneration`), boot-only candidates** (§12f: the change takes effect only at boot): `verify_candidate` → journal **`Publishing`** (durable, before any boot mutation) → `publish_boot_once(candidate)` as a one-shot next-boot entry, with the **running generation** (the one publishing the candidate; always at or above the security floor) kept as the default and fallback (owner decision, 30 Oct; `known_good` is a manual fallback per I1, never the automatic one) → journal **`AwaitingBoot`**. At the next boot, the candidate boots once; the admission check and the confirmation checkpoint of §10 apply: admitted → the candidate is made the default and the override promoted (§9 step 4) → `Promoted`; confirmed at 10 min → post-commit bookkeeping → `Committed` (boot-confirmed, `known_good`); not admitted, or the boot does not reach ready: the following boot falls back to the publishing generation → `Reverted`; admitted but **not confirmed** (canonical probes fail at the checkpoint) → `Reverting`: `publish_boot(publishing generation)` as default, restore the base override, the notice says a restart will complete it → `Reverted` (the machine runs the candidate until that restart; the daemon treats the window as a live-tested-but-unconfirmed generation). A daemon restart without a reboot leaves `AwaitingBoot` untouched and never re-prepares it.
   - **GenerationOp (`RevertGeneration`), live:** wait for an activation window if §12f requires one (the transaction stays in `Built`, bounded per §12f) → when the window opens: stale check, re-derive, re-`decide` (I8) → from B, confirm a passing sandbox run for this `staged_source` where §12g requires one → `verify_candidate` → journal `Activating` → worker: `activate_live(candidate)` → journal `Checking` → run applicable Readiness probes from both the candidate's `UnitDefs` and the installed core, plus the expectation (per probe, §9) → **pass:** `publish_boot(candidate)` → journal `Published` → promote (§9 step 4) → journal `Promoted` → **post-commit bookkeeping** (§12e floor derivation, the committed generation's override content, session accounting; part of the commit, I25) → journal `Committed` (same record marks `live_tested`). **Fail:** journal `Reverting` → worker: `activate_live(revert_to)` → `publish_boot(revert_to)` → restore base override (§9 step 4) → re-probe → `Reverted`, or `RecoveryFailed` if revert probes fail (alerts; stops all autonomous action until a human acts).
   - **DeviceOp (`UnbindDevice`):** journal `Activating` with the previously bound driver recorded → `bind` → `Checking` → probes → pass: `Committed`; fail: `Reverting` → `unbind`, rebind previous → `Reverted`/`RecoveryFailed`. Gym case: a failed driver bind restores the previous driver and attempts no generation rollback.
   - **`RestoreSnapshotThenRevert`** (RestoreSnapshot): restore, then as above.
8. **Outcomes.** `Partial`/`Unknown` are never success. In `Activating` with `RevertGeneration`: re-observe; candidate active → `Checking`; else → `Reverting`. In `Checking`: probes decide. In `Published`/`Promoted` on the live path: the candidate is already live and tested; recovery *completes the commit* (re-run `publish_boot`, re-run the promotion rename — both idempotent) rather than reverting, unless probes now fail, in which case revert. In `Promoted` on the boot-only path the candidate is admitted, not confirmed: recovery waits for the confirmation checkpoint of this boot and then commits or reverts as above; it never writes `Committed` before it. The watchdog may complete these steps because they are idempotent and were authorized by the transaction; it still cannot write `Committed` from any state before `Checking`.
9. Log (I7) with `DerivedFacts`, `PolicyVersion`, probe evidence, decision, outcome, lease epoch.

**Crash-recovery table** (what the lease holder does on finding a transaction in each state):

| Found in | Action |
| --- | --- |
| Prepared, Staged, Built (any strategy) | Nothing was mutated; mark `Rejected(Interrupted)`, release the GC root, reopen the incident if any. A transaction that was waiting for an activation window is re-prepared from the same proposal, **with its original caller and source** (not as the daemon's maintenance), once the daemon is ready; any unused approval token is invalidated by the restart and re-requested (§12 step 4) |
| Publishing (boot-only) | Read the `publish_boot_once` op's records: `OpEnd` succeeded → journal `AwaitingBoot`; no `OpEnd` → ask the backend whether the one-shot is armed (`boot_entries`); armed → `AwaitingBoot`, not armed → `Rejected(Interrupted)`. Never re-prepare a transaction that reached `Publishing` |
| AwaitingBoot | No reboot since publish: leave as is. After a reboot: `last_booted()` is the candidate → the admission check of §10; any other generation has booted since the publish → `Reverted` |
| Activating, `ReobserveOnly` | Fence; confirm quiescence; re-observe; write `Committed` with the observed outcome; inform the incident. Never a generation operation. |
| Activating, `RevertGeneration` | Fence; confirm quiescence; re-observe; candidate active → Checking, else Reverting |
| Activating, `UnbindDevice` | Fence; confirm quiescence; re-observe; bound to candidate driver → Checking, else restore previous driver → Reverted |
| Checking (generation / device) | Fence; confirm quiescence; re-run probes; pass → the complete commit path, fail → Reverting |
| Published | Promote by hash comparison (§9) → Promoted → post-commit bookkeeping → Committed, unless probes fail → Reverting |
| Promoted (live) | Post-commit bookkeeping (I25) → write Committed. Whoever holds the lease — daemon or watchdog — runs the bookkeeping; a `Committed` without it is not written |
| Promoted (boot-only, this boot) | Admitted, not confirmed: wait for the confirmation checkpoint (§10); pass → bookkeeping → Committed; fail → Reverting as in step 7. The watchdog does not advance this row; only the daemon's checkpoint does, and if the daemon is absent at the checkpoint the next boot runs the AwaitingBoot row |
| Reverting | Fence; confirm quiescence; re-run the strategy's revert steps (all idempotent) → Reverted or RecoveryFailed |
| Checking, `ReobserveOnly` | Fence; confirm quiescence; re-observe; write `Committed` with the observed outcome. Never the generation commit path. |
| RecoveryFailed | Alert; set the **recovery interlock** (§12c); refuse all autonomous transactions until an administrator records `planarian resolve <txn>` |

Gym cases: kill the daemon during a Runtime-tier `Rollback` (recovers as a generation operation) and during `StopAndSuppress` (recovers as a unit operation; no generation rollback attempted); an old backend job that outlives the 60 s drain (takeover ends in `RecoveryFailed`, never overlapping mutation); daemon and watchdog attempt takeover simultaneously (exactly one wins); daemon stays down after `Published` and after `Promoted` (watchdog completes the commit).

**Recovery watchdog.** `planarian-recovery.service`: separate unit, `Restart=always`, started before `planariad`, no dependency on it. Every 10 s it reads the journal; for a transaction in `Activating`/`Checking`/`Publishing`/`Published`/`Promoted` (live)/`Reverting` whose lease is unrenewed past `deadline` or whose owner pid is dead, it takes over the lease (fencing and confirmed quiescence as above) and runs the crash-recovery table. From `Checking` it does one of two complete things: if the authorized Readiness probes pass, it runs the **entire** authorized commit path (`publish_boot` → promote → `Committed`), because that path was authorized by the transaction and every step is idempotent; otherwise it reverts. It never stops partway. The earlier restriction is restated precisely: the watchdog may not write `Committed` from any state before `Checking`; from `Checking`, `Published` or `Promoted` (live) it completes the authorized path, bookkeeping included (I25). For a daemon that is alive and renewing its lease, the watchdog does nothing. Its binary and config are `Sensitivity::Core`.

**Daemon restart reconciliation.** On start, `planariad` reads the journal. If the watchdog holds a lease on a non-terminal transaction, the daemon **waits** until that transaction is terminal (it does not compete). Otherwise it takes over the lease (fencing) and runs the crash-recovery table. Either way it writes a reconciliation record (what it found, what it did, why) shown in the console on next open. Recovery steps that may activate a generation (a transaction found in `Activating`, `Checking`, `Publishing`, `Published` or `Reverting`) run just after `planarian-ready.target` is reached: the takeover and the reconciliation record come before it (owner decision, Nov 1). Activation reloads and restarts units ordered after the target, which would otherwise wait on `planariad`'s own start (#9).

**Self-protection during activation.** The NixOS units for `planariad` and `planarian-recovery` are declared with `restartIfChanged = false` and `stopIfChanged = false`, which NixOS's switch honors by emitting `X-RestartIfChanged=false`/`X-StopIfChanged=false`, so no activation restarts or stops them. Independently, a candidate whose evaluated unit files for these two services differ from the running generation's is `touches_core` → Reject; upgrading Planarian itself is the core update path (Phase E), and in A–D a manual `nixos-rebuild` by root outside Planarian. Networking changes set `deadline` to 90 s because loss of the daemon's control path is likely. Boot ordering, readiness, and the response to the daemon failing are in §12d.

**Concurrency:** I6. Runtime transitions may run during `build` but not during `Activating`/`Checking`/`Publishing`/`Published`/`Promoted`/`Reverting`, except a boot-only `Promoted`, during which unit and device repairs run (owner decision, 31 Oct). This list and I6's are the same list; `schema` carries it once.

**Worker processes.** v4.1–v4.5 described a worker *subprocess* whose pid the lease records. In A the activation runs in a worker *thread* and quiescence is established through `jobs_tagged` and the transient-unit tag alone, which is sufficient; the `Lease.worker_pid` and `Lease.jobs` fields are reserved for D's supervisor and are empty in A (recorded in `docs/deviations.md`).

### 12a. Runtime-settable options

A core-owned allowlist (`Sensitivity::Core`; not extensible by manifest or model) of options whose effect can be applied immediately: font scale, volume, brightness, keyboard layout, Wi-Fi network selection. `SetRuntimeOption` applies the effect as a Runtime transition (subject to the global floors: Wi-Fi selection has `ConnectivityLoss`), then enqueues an `ApplyChange` write-back whose expectation is "no unit changes." If the write-back's build or probes fail, the runtime change stays in effect, the write-back is `Reverted` (override source untouched), the console shows "this setting will not survive reboot," and the incident manager does not retry it; the user may re-issue it. The write-back is never attempted while a generation transaction is active: it is **queued** behind the active transaction and submitted when that transaction is terminal, with the same caller. A write-back refused as busy is not a failure and produces no notice.

### 12b. Garbage collection and space budgets

Protected set per I3, including in-flight candidates (via their GC-root symlinks) and every `txn/<txn>/base.nix` of a non-terminal transaction. `services.planarian.gc.retainAllGenerations` (default false) protects every generation: a full history kept for export or to go back to any of them; other store garbage is still collected, and the budgets below are reported, not enforced. Policy: keep last 10 generations and 10 snapshots **and** space budgets (default: generations ≤ 20% of the Nix store's filesystem, snapshots ≤ 10% of their volume); whichever bound is hit first collects oldest-first down to the other. If the protected set alone exceeds a budget, `CollectGarbage` collects everything unprotected, reports `BudgetUnsatisfiable` with the shortfall, and never touches the protected set; the budget is then a target, not a guarantee, and the console says so. `CollectGarbage` is Runtime. Budgets are user settings, not manifest options.

### 12c. Journal headroom and ENOSPC

- **Format.** Records are length-prefixed and CRC-32C-checked; a torn or mismatched tail record is ignored and truncated on open, never interpreted as a transition. Anything worse — a checkpoint that fails its CRC, does not parse, or violates an invariant on load, or a retained record that does — is an `Integrity` failure (§12d), reported as such by both processes; it is never reported as the journal being merely absent. Every record also carries the hash of its predecessor (I18), and the checkpoint carries the chain head, so an edit to any retained record is detected on the next read and raised as an `Integrity` failure (§12d). The chain is tamper-evident, not tamper-proof, until E signs the chain head with a key outside the running system. The journal is a preallocated file (default 64 MB) in `/var/lib/planarian/journal/`.
- **Chain head.** The chain is unkeyed in A: it detects damage and partial edits, not a consistent rewrite by root (I18). The current head is included in every signed health report (§10), so an off-machine receiver that keeps the heads it has seen can detect a rewrite of anything it has already witnessed (C, with the mesh); measured boot anchors it on the machine in E.
- **Checkpoint.** Compaction is not deletion of history; it is checkpoint-then-truncate. A checkpoint captures all live state the journal establishes: the external desired-state source's last accepted sequence number (§9), active overrides (including `Until::Explicit` ones from long-committed `StopAndSuppress`), the security floor, open and cooling incidents with their budgets and regression counts, the nonces of consumed approval tokens within their validity window (outstanding tokens are not carried: a restart invalidates them, §12 step 4), the `AgentStarted` records of live agent instances (I24), `known_good`/`accepted_baseline`/`live_tested`, every non-terminal transaction with its lease, the lease epochs of recently terminal ones, and the **recovery interlock**: the set of unresolved `RecoveryFailed` transactions with the facts needed to resolve them (what was being changed, which step failed, the observed state, the base and candidate override hashes, the revert target). The interlock is live control state, not history: while it is non-empty, autonomous mutation is blocked (only `Observe`-tier reads, user-authorized `SetOverride`/`LiftOverride`, and administrator operations run), and it survives compaction and restart of both processes. It is cleared only by `planarian resolve <txn> --as-committed | --as-reverted | --manual-repaired`, an administrator-authorized operation journaled as a transition of its own; no other request clears it. Gym case: inject a failed revert, force compaction, restart daemon and watchdog; autonomous mutation stays blocked until the resolution is durably recorded. It is written to a temp file, fsynced, renamed over `checkpoint`, directory fsynced; only then is the journal truncated to records after the checkpoint's sequence number. Recovery from (checkpoint + retained journal) MUST reconstruct the same state as recovery from full history; the gym asserts this by comparing both reconstructions after forced compaction. Compaction triggers at 75% full.
- **Filesystem contract.** The preallocation guarantee holds only where in-place rewrite does not allocate: on ext4 and XFS a `fallocate`d file; on btrfs only with the journal directory marked `nodatacow` (`chattr +C` before creation) and the file preallocated; on ZFS it does not hold, and the daemon instead reserves space with a dedicated dataset `reservation`. The installer applies the layout-specific setup and the gym validates it per supported layout (ext4, btrfs, ZFS). If a recovery-path write to the preallocation fails with ENOSPC despite the contract, the daemon writes a fixed-size `RecoveryFailed` sentinel into a separate 4 KB file reserved at install and blocks all mutation. The reservation is counted in `device:fs-journal`'s Readiness probe.
- `CollectGarbage { emergency: true }` is the only transition allowed to start while `device:fs-journal` or `device:fs-nix` is below threshold; it is Runtime and its record fits the preallocation.
- ENOSPC behavior by state: in `Prepared`/`Staged`/`Built` (write to stage or store fails) → reject with `NoSpace`, open the storage incident, do not retry the original until it closes. In `Activating`/`Checking` → treat as probe failure → `Reverting`; the revert record is in the preallocation. In `Reverting` → if a revert step fails for space, mark `RecoveryFailed` via a fixed-size sentinel record and alert. Promotion (temp-write of the override file) failing for space → treat as Checking failure → revert; the live override file is untouched because the rename never happened.
- `/boot` is tracked separately: `publish_boot` failing for space → `Checking` failure → revert; the candidate is never left as the only boot entry.

Gym cases: fill the journal filesystem to the reserved-block boundary as the daemon's uid; verify that emergency collection is recorded and executed, or that mutation stops with an explicit `RecoveryFailed`/`NoSpace` status; repeat after a snapshot and after repeated journal reuse on btrfs; force compaction with a live Explicit suppression and an exhausted incident budget, then crash and restart (both survive); interrupt a record write and a checkpoint write (neither is misread).

### 12d. Boot ordering and failure posture

**Admit no principal before the monitor.** `planariad` is ordered before every unit that admits a principal: the display manager (whichever unit NixOS uses for it — `display-manager.service`, or `greetd.service` where `services.greetd` is enabled without the display-manager alias), `getty`, `sshd`, the model service, any remote relay, `user@.service`, and **every agent unit**, declared or launched. Agents started by `planarian agent run` are created in a `planarian-agents.slice` with `After=`/`Requires=planarian-ready.target` and a start condition that fails while any `planarian-failed@*.target` is active; the posture's *disable agents* response stops that slice as a whole, not a configured list, so an agent the launcher created cannot outlive a failure posture (I20). Each launch carries `TasksMax=`, `MemoryMax=` and a per-uid count from `services.planarian.agents.limits`. When it is ready it reaches `planarian-ready.target`. Whether principal-admitting units merely follow that target or require it is the failure posture. With this ordering, the window before the monitor is ready contains only firmware, bootloader, kernel, initrd, and the generation's own early units, all already in the trusted base; and the change path fails closed while `planariad` is down, since `Proposal` is the only write path.

**Enforced outside the daemon.** The NixOS module generates `planarian-ready.target` and one `planarian-failed@<class>.target` per failure class, wired with ordering and `OnFailure=` in systemd and the initrd. `planariad` never implements its own failure response. The posture is declared in the generation, so it is immutable at boot.

| Class | Meaning | Detected by |
| --- | --- | --- |
| `Absent` | `planariad` did not reach ready within the boot-ready timeout, or was masked or stopped | ordering timeout on `planarian-ready.target` |
| `Crashed` | reached ready, then died and exhausted its restart budget; or `planarian-recovery` exhausted its own start limit | `OnFailure=` on both units, each with a `StartLimitBurst` so a crash loop ends in the class rather than running forever |
| `Integrity` | core hash ≠ signature (I2); journal chain broken (I18); boot report found undeclared early units or processes; invalid signature on the external desired-state source (§9); in E, a measured-boot mismatch | boot report, `planarian-recovery`'s independent check, initrd measurement |

`Integrity` is always treated at least as seriously as `Absent`.

**Responses** (composable): *alarm* (a non-dismissable banner on the login screen and in every session until an administrator acknowledges it: for `Absent`/`Crashed`, "Planarian, which protects this computer from unsafe changes, is not running. Assistants and system changes are turned off until it is fixed. [Administrator] has been notified."; for `Integrity`, "This computer may have been tampered with. Do not enter passwords or open sensitive files. [Administrator] has been notified."); *notify administrators*, local and remote, with the boot report; *disable agents* (the model service, any relay, every agent principal are not started); *restrict remote access* to administrators; *restrict login* to local administrators in a recovery session; *restrict network* (none, mesh-to-administrators, or full); *halt to recovery* (boot stops at a recovery target); in E, *seal* (the disk-encryption key is sealed to measurements that include the core, so an `Integrity` failure leaves the disk locked).

| Posture | For | `Absent` / `Crashed` | `Integrity` |
| --- | --- | --- | --- |
| Relaxed | Developing Planarian; throwaway VMs | Alarm (dismissable), disable agents | Alarm, notify, disable agents |
| Standard (default) | Personal machines | Alarm, notify, disable agents, restrict remote access; local login proceeds | Alarm, notify, disable agents, restrict remote access, network to mesh-to-administrators (in A, before any mesh exists: remote access off, network otherwise unrestricted); local login proceeds with the warning |
| Guarded | Work machines; agent hosts | Alarm, notify, disable agents, restrict remote access, restrict login | Halt to recovery, network to mesh-to-administrators |
| Sealed | Servers, fleet nodes | Halt to recovery, network to mesh-to-administrators | Halt to recovery, no network, seal (E) |

Every posture disables agents on any failure (I20). *Restrict remote access to administrators* means Planarian's administrators (root and `planarian-admin`), not `wheel`. In A, alarms and notification are local (the login screen, every session, `wall`, the system journal): root can clear them, and a machine whose `planariad` is stopped can go unnoticed by anyone not at it. From C, the signed health report doubles as a dead-man signal: an off-machine receiver alerts administrators when reports stop arriving within twice the declared cadence. Custom postures combine the options per class, with two constraints: agents are always disabled, and the `Integrity` response is never weaker than the `Absent` response. The installer selects the posture (C; A ships Standard). The boot-ready timeout is configurable per machine, default 60 s, bounded 15–600 s. Raising the posture or shortening the timeout is a Tested change; lowering the posture or lengthening the timeout is Security-sensitive (AskFirst with administrator authority) and takes effect at the next boot, never in the current one: the posture units read the declared posture from the *booted* generation's files, and a switch that would weaken either leaves the booted values in force until reboot (the module implements this by having `planarian-ready.target`'s configuration come from `/run/booted-system`, not `/run/current-system`). Recovery exits: an administrator acknowledges the alarm (journaled with identity), or `planariad` reaches ready and the boot report is clean, after which restrictions lift. Only an administrator clears an `Integrity` failure.

**Core hash in A–D.** The reference hash for I2 covers every Planarian binary and script the generation installs (`planariad`, `planarian-recovery`, the CLI, the posture units' scripts), recorded at build. Signatures replace it in E. A test build (the `gym-hooks` package, §15) installed outside the gym VM tests is an `Integrity` failure, and the module asserts against it.

**Lock the boot chain** where the machine allows it: bootloader editing disabled (`boot.loader.systemd-boot.editor = false`); Secure Boot with a signed unified kernel image (Lanzaboote) from C; TPM measured boot later. In C, pre-Planarian boot entries are garbage-collected after enrollment. Entries below the security floor (§12e) stay in the boot menu (I1) but are labeled, are never the automatic fallback, and, where the bootloader supports it, require administrator confirmation.

### 12e. Security floor

The security floor is the newest committed generation whose closure contains a security fix absent from **every** earlier generation (in A: absent from the current floor generation and from every generation between it and the candidate; a `Revert` to an older generation that merely *lacks* a newer package is therefore never a fix). It is a derived fact, computed as part of every generation commit on every commit path (I25) and journaled before `Committed`; a commit whose floor record cannot be written does not commit. It is never set by a proposal. The inspected set is the whole system closure: every package reachable from the generation's toplevel, including service packages, the kernel, and firmware, not only `environment.systemPackages`. In A the sources are nixpkgs vulnerability metadata, evaluated for every package in the closure (a package whose previous version carried `knownVulnerabilities` that the new one lacks), and an administrator mark (`planarian mark-security-floor`); from B, a CVE feed matched against the closure (e.g. vulnix) is added. A fix the inspected set does not show does not move the floor; the administrator mark is the remedy. Generations below the floor are not eligible as automatic revert targets, as automatic boot fallbacks, or as `Rollback` targets; going below the floor is AskFirst with `ApproverClass::Administrator` (I16). Until the floor generation is boot-confirmed, `known_good` may be below the floor: it stays bootable and in the menu (I1) as a manual, administrator-confirmed fallback, while the floor generation is the boot default. The floor never advances to a generation that has not at least committed live. If no eligible known-good generation exists above the floor when a revert or rollback is needed, the daemon escalates the incident with `EscalationReason::RevertBlockedByFloor` instead of reverting. Gym cases: a security update is applied; a probe failure is induced afterward; the revert does not cross the floor and the incident escalates. The same, with the fix in a service package (openssh) that is not in `environment.systemPackages`. The fixing generation commits via the daemon, via the watchdog after a crash at `Committed`-minus-one, and via the boot-only path; all three move the floor, and a `Rollback` to the vulnerable generation then asks. A `Revert` to an older generation sets no floor.

### 12f. Activation scheduling

A verified candidate whose activation would restart or reload any unit in an active user session (audio, compositor, input, network, the session itself) waits in `Built` until an activation window: the session is idle, the user asks, or the next boot. It never activates while `Foreground` holds in any session, except a repair rollback as below. Changes that only take effect at boot (kernel, initrd, drivers) take the boot-only path (§12, step 7): published as a one-shot next-boot entry in `AwaitingBoot`, with a non-urgent "restart to finish" notice, and confirmed or reverted at that boot. Repairs are exempt: restoring a failed unit is not an activation. A transaction waiting in `Built` holds no lease-gated mutation and counts as active for I6, so §12a write-backs queue behind it; if the daemon restarts, it is `Rejected(Interrupted)` per the crash table and re-prepared with its original caller. "The next boot" as a window therefore means: re-prepared after boot and activated before any user session starts. **Parking is bounded** (owner decision, 30 Oct): a transaction may wait in `Built` for at most the parking limit (24 h, `CLOCK_BOOTTIME`); when it expires the transaction is `Cancelled(Daemon)` with a notice naming the change and how to re-issue it, and the incident, if any, reopens. `AwaitingBoot` has no limit — it waits for the reboot it was published for — but the console and `planarian status` report it as *waiting for a restart*, distinct from any failure, and the "restart to finish" notice is repeated daily. I12 is qualified accordingly.

**Rollbacks** (owner decision, Oct 31). A `Rollback` with `Source::User` or `Source::Intent` (`planarian undo`, "roll back") runs at once: the request is the activation window. A `Rollback` with `Source::Diagnoser`, proposed after in-place repair of an incident has failed (§13 orders it last), is a repair: it does not wait for an activation window, and is not parked in `Built`. Being a repair exempts it from waiting, never from asking: the §11 disruption floors apply to it as to any transition, so a repair rollback that would end a session is AskFirst. While `Foreground` holds, a repair rollback runs only if its incident's target is one the foreground work plausibly depends on (the list under *Quiet mode*); otherwise the diagnoser does not submit it — it is deferred with the incident, as quiet mode defers any repair, with no transaction opened, and runs when quiet mode ends. The revert of a candidate that fails its own checks (`Reverting`, §12 step 7) is that transaction's recovery, not an activation, and is never deferred. I6 still holds: a repair rollback is a generation operation and waits for any active generation transaction like any other. Gym cases: `rollback-repair-foreground-dependency` (a committed update breaks Wi-Fi during a `Foreground` workload; the rollback runs at once, with one notice); `rollback-repair-foreground-unrelated` (the same update breaks the printer service; the rollback waits for the workload to end, then runs, and the incident's budget does not advance meanwhile); `rollback-repair-session-loss-asks` (a repair rollback that would restart the compositor of an active session is AskFirst and does not run without approval).

**Quiet mode.** While `Foreground` holds for a session: Diagnostic probes and the gym's trend work are deferred and Readiness probes drop to their slowest interval; activation of staged generations, garbage collection, store optimization, catalog and model updates, and sandbox snapshot creation are deferred; non-urgent notifications are queued and delivered as one batch when quiet mode ends; the model is not loaded (§20). Not deferred: repairs of units the foreground work plausibly depends on (audio, compositor, input devices, network, Bluetooth), including a repair rollback whose incident targets one of them (see *Rollbacks*), failure-posture responses, and repairs the user requests. Deferred repairs are deferred in fact: their incidents' budgets and backoff do not advance while quiet mode holds (§13), and the repair loop skips them rather than running them. Gym case: a reference game workload runs while a garbage collection, a staged update, and a non-urgent fault are queued; frame-time p99 matches a baseline with Planarian stopped, and each deferred item runs within its window afterward; a PipeWire kill during the workload is repaired immediately and produces exactly one notice.

### 12g. Sandbox tier (Phase B)

Agent-speed iteration happens beside the real machine, not on it. Three tiers, cheapest first: *dry-run* (`verify_candidate`, risk derivation, and closure diff, with no activation: seconds); *sandbox* (the candidate generation booted in a Firecracker microVM restored from a snapshot of the settled reference generation, probes run inside, VM discarded; snapshots keyed by generation hash; built with `microvm.nix`); *real* (this section's transaction path). From B, a proposal at tier Tested or above reaches the real path only with a passing sandbox run against the same `staged_source`, recorded in the journal as evidence. The sandbox pass does not shorten the real settle window. Where KVM is unavailable, the daemon reports `sandbox: unavailable` and Tested is floored to AskFirst: the machine degrades to a person looking first, never to skipping the check. The sandbox's verdict is evidence, like a probe; it never promotes anything, and it runs untrusted candidates under Firecracker's jailer. Firecracker cannot host device-family faults (GPU, Wi-Fi hardware, USB, suspend/resume); those stay on the QEMU or bare-metal gym target.

### 12h. Time

Everything that does not survive a reboot is timed on `CLOCK_BOOTTIME`, never wall-clock time: approval-token expiry (tokens are not carried across daemon restarts at all, §12 step 4; the checkpoint keeps consumed nonces only), lease deadlines, cooldowns, settle windows, activation windows, and the parking limit (§12f). Wall-clock time is used only for what is shown to people and for records that must be compared across boots. The posture options recommend authenticated time (NTS) and report unauthenticated NTP as a notice. Gym case: the wall clock is moved back 48 h after an approval is issued; the token still expires 24 h after issue.

## 13. Incidents and the diagnoser (crates `incident`, `diagnose`)

**Incident lifecycle**

- **Open** when a unit is expected (desired condition holds, no override) and its derived status is Failed, Degraded, Stopped-but-desired-Running, Detected-but-desired-Bound, or Absent-but-desired-present, with fresh evidence for two consecutive ticks.
- **Defer to systemd first.** If the unit has `Restart=` and systemd is within its own `StartLimitBurst`, the incident waits for systemd's attempt (up to the unit's `RestartSec` plus settle) before Planarian acts, so two controllers don't restart the same service.
- **Attempts** are transactions; each outcome is appended. Budget 3 per incident, persisted in the journal (survives daemon restart). Backoff between attempts: 10 s, 60 s, 300 s.
- **Closed** when the target satisfies its *desired* predicate (Running, Bound, Stopped, or Absent as desired) with fresh evidence for a stabilization window (5 min).
- **Regressed:** if the same target diverges again within 30 min of Close, the incident reopens with `count+1` and a longer backoff; at `count = 3` it goes straight to **Escalated** (report to user; cooldown 1 h; no autonomous action on that target until a human acts or the cooldown ends).
- **Cooldown** after budget exhaustion: 1 h, then one more attempt, then 6 h.
- An override on the target closes the incident (I13).
- **A person acting on the target** (`release`, `override`, `stop`, a manual repair) reopens the incident with a fresh attempt and no cooldown — but only when the action was **authorized and succeeded**. A request that is refused, parked, or fails leaves the incident record exactly as it was: budget, cooldown, escalation and next attempt unchanged. Rejection grants no indirect control over the repair loop. Gym case: an unauthorized `planarian release sshd` during sshd's cooldown changes nothing about the incident.
- **Quiet mode.** While `Foreground` holds, incidents on units the foreground work does not depend on wait (§12f); their budgets and backoff do not advance while they wait.

**Diagnoser**

1. From the open incidents, walk `Requires` edges (and `Diagnostic` edges with confidence ≥ 0.7) to the deepest divergent unit; that is the target. `Ordering` and `Wants` edges are never followed: a failed wanted unit is its own incident and is never assumed to be the cause of the wanting unit's failure. **Cycles:** the walked subgraph is first collapsed into strongly connected components; "deepest" is defined on the resulting DAG; within a component, the target is the unit with the earliest definite `Observed::Failed` timestamp, else the one with the most failed Readiness probes, else lexical order. Gym case: an optional wanted service fails while its wanting service stays healthy (two incidents at most, no false root cause).
2. Enumerate candidate transitions, depth ≤ 2, whose precondition holds and whose prediction closes the divergence. Exclude exhausted and cooling targets.
3. Order by: tier ascending, then disruption ascending, then recovery (Idempotent < Revertible), then cost. `Rollback` last.
4. Submit one at a time as `Proposal { source: Diagnoser }`. Stop at the first `Committed` whose expectation held.
5. Exhausted → `DiagnoserExhausted` → model (B) or user report (A).

Phase A `ApplyChange` candidates are limited to catalog entries tagged `repair:` (re-enable a predicted option; reapply a previously-committed change for the same target — the latter is in the catalog from v4.6; it was specified and not shipped in v4.5).

## 14. Intent matcher (crate `intent`)

Deterministic; no language model; identical behavior in degraded mode. Not in the Verus subset.

- **Index:** every `UnitDef.synonyms`, every transition verb with a phrasing list, every change-catalog entry's description tokens, every runtime-settable option.
- **Match:** normalized token overlap plus a fixed pattern set ("restart X", "reconnect X", "turn X on/off", "make X bigger/smaller", "stop/pause X [for N minutes|until I say]", "start X again"/"done with X"). Output `(Transition, confidence)`.
- **Thresholds:** ≥ 0.8 propose with `Source::Intent`; 0.5–0.8 ask the user to confirm one of the top two; < 0.5 unmatched (A: say so; B: summon the model).
- **Stopping:** "stop X" and its variants map to `StopAndSuppress { until: parsed or Explicit }`, never to a bare `StopUnit` or a bare `SetOverride`; the override is journaled before the stop (§12), so there is no window in which the repair loop restarts the unit. "Turn wifi off" and similar map to an override on the network unit. "Start X again"/"done with X" → `LiftOverride`, after which the unit is desired-Running again and is repaired if needed. A `StopUnit` issued through the CLI by an authorized user is rewritten to `StopAndSuppress { until: NextBoot }` with a notice. The first time a user's raw stop is caught as the unattributed residue (§11), the notice teaches the attributed form.
- **Authorization** applies as in §11; an unauthorized match is reported as such, not silently dropped.

## 15. Gym (crate `gym`)

- Catalog entry: `Fault { id, family, inject: Transition | RawAction, required_post: Expectation, intent: Option<Intent>, tags }`. `intent` marks cases where the correct behavior is *no* intervention (user stopped the service; login screen idle; probe timed out but the service is fine).
- Phase A catalog, minimum families: service killed; service misconfigured; required dependency stopped; ordering-only predecessor stopped (must NOT be treated as cause); driver unbound; bad generation activated; **daemon killed during Activating, Checking, and Reverting**; revert fails (RecoveryFailed path); probe delayed past timeout with the service healthy; external config edit during a build; intentional service stop; suspend/resume; network unavailable at the gateway with the driver fine; flapping service (fails 30 s after each restart); storage full; manifest edited to weaken a probe; login screen idle with autologin off; boot-to-desktop failure.
- **v4-review acceptance cases (all required in Phase A):** kill and immediately restart the daemon while a deliberately slow activation worker survives (activation and revert never overlap; the old owner cannot commit); an override-only candidate changes the evaluated output; the owner edits the source during a build (transaction rejected `Stale`); a crash injected at each of `Activating`, `Checking`, `Published`, `Promoted`, `Reverting` (running state, boot selection, override source, and journal agree after recovery); disable then re-enable a service with a canonical Readiness probe (no revert of the authorized change); Diagnostic evidence expires on a healthy machine (status stays Running); a definite failed service while another unit's probe is stale (status Failed, not Unknown); authentication succeeds but the compositor never reaches its target (incident opens); idle greeter with autologin off (no intervention); a user stops a running service (stays stopped, no repair race); an unprivileged user tries to override a system Security unit (held for administrator approval; the unit stays up); an unprivileged user tries to stop a system unit that is neither Security-sensitive nor user-controllable (rejected `Unauthorized`); the daemon proposes a session-dropping driver rebind and a runtime Wi-Fi change (both AskFirst); an optional `Wants=` unit fails while its wanting unit stays healthy (no false root cause); the journal filesystem is filled to the reserved-block boundary as the daemon's uid (emergency collection recorded and executed, or explicit `NoSpace`/`RecoveryFailed`).
- **v4.4 acceptance cases (all required in Phase A):** for each failure class under the Standard posture, inject the failure (mask the unit; kill it past its budget; corrupt the core hash; break the journal chain; plant an undeclared early unit) and verify exactly the declared responses, that no agent principal started, and that the recovery exit works (the other postures from C); a security update followed by an induced probe failure (revert does not cross the floor; the incident escalates with `RevertBlockedByFloor`); a kernel update (takes the boot-only path; confirmed at the next boot, and reverted when the injected boot fails); a user-session principal overrides the firewall (held for administrator approval; firewall stays up); a non-administrator stops the network while another uid's session is online (AskFirst; the other session is notified); two graphical sessions for one uid where the second compositor fails (an incident opens for the second session only); logging out of one of two sessions (user services keep running); an unattributed `kill -9` of a service under Standard (accepted until next boot with `attribution: Inferred` and an undo), of the firewall (restarted and alarmed), and an OOM kill (repaired as a fault); a retained journal record edited on disk (detected on read as an `Integrity` failure); a staged update while `Foreground` holds (not activated until the window); the fake backend run against every `docs/assumptions.md` entry under injected `Partial`, `Unknown`, and fenced outcomes.
- **v4.6 acceptance cases (all required in Phase A; each closes a finding §28 names):** `agent-name-collision` (alice's running agent stays unauthorized for a system unit after an administrator re-runs `agent run` with the same name; the second start is refused naming the owner); agents launched through the API, then `Absent`, `Crashed` and `Integrity` injected (every launched agent stops; new starts fail; a per-uid launch over the limit is refused); a denied `release` during a cooldown (the incident record is unchanged); `SetOverride(Stopped)` and `StopAndSuppress` on `display-manager` from a remote administrator (identical disruption and floor); a rollback between vetted generations with equal manifests and a changed network unit (ConnectivityLoss scheduling); a fixing generation committed via daemon, via watchdog and via boot-only (the floor moves in all three); a crash between `OpBegin(publish_boot_once)` and `OpEnd` (after restart and reboot, boot selection, roots, overrides and journal agree); a boot-only candidate admitted but failing the 10-minute confirmation (`Reverted`, default restored, notice); `verify_candidate` on a store path whose NAR hash differs from the recorded one (refused); an approval issued, the daemon restarted, the change re-requests approval; a transaction re-prepared after restart keeps its original caller (own-session exemption still applies); an unauthorized caller's `ApplyChange` (zero `stage`/`evaluate`/`build` calls); a checkpoint with a bad CRC (`Integrity`, not `Absent`); `planarian-recovery` crash-looping (`Crashed` raised); a generation that lowers the posture switched live (the booted posture stays in force until reboot); a unit Degraded before a change that loses a second probe (Checking fails); a dry activation that exits nonzero, times out, and emits truncated output (no autonomous activation in any case); a stalled resolver and a trickling HTTP endpoint (the batch returns by the deadline; the repair loop ticks during it); an owner edit while a change waits for an idle session (`Stale` when the window opens); `SetOverride` over another principal's attested override (`Rejected(Precondition)`); an approval, then `planarian log` names the approver; a transaction parked past the limit (`Cancelled(Daemon)` with a notice); an SSH-only login (no graphical incident); a manifest with a 0.5-confidence edge to an external dependency (rejected at evaluation); a user's first raw `kill` caught as the residue (the notice names `planarian stop <unit>`); a `Revert` to an older generation (no floor set); a §12a write-back issued while a generation transaction is active (queued, then committed, no notice); a crash during `build` (the orphan root is gone after the age limit); `rollback-repair-foreground-dependency`, `rollback-repair-foreground-unrelated`, `rollback-repair-session-loss-asks` (§12f *Rollbacks*).
- **Harness contract.** The runners report what the catalog asked, never what they managed to run: a runner (fake, VM, by-hand `run-vm.sh`) exits nonzero on any `FAIL`, `PARTIAL` or `ERROR` and on an `UNSUPPORTED` verdict for a `must-pass` or `acceptance` entry that has no waiver in `docs/deviations.md` naming that entry and harness. CI runs the fake catalog with `--strict`. A waiver is a reviewed row, not a default.
- **Fault families also include** a *malicious declaration*: a declared unit with a known-bad payload; Planarian cannot tell it from a legitimate service, so the case scores whether the incident report surfaces the declaration's origin (who declared it, when, through which path).
- Scoring per fault: pass iff `required_post` holds (or, for intent cases, iff no *autonomous* transaction was opened after the user's own setup action; the user's authorized `StopAndSuppress` or similar is the setup, not a failure). Gamed success (probe tampering, `StopUnit(target)`, an override whose `by` is the daemon, the watchdog or the model, or whose log record is attributed to an agent) fails the run. An `Unattributed` inferred override is legitimate only in the catalog cases that declare it as the expected outcome.
- **Test builds.** Fault injection in the real binaries lives behind the `gym-hooks` feature, in a separately named package; it is never installed outside the gym's VM tests (§12d).
- Metrics reported: repair rate; **unnecessary interventions** (transactions on intent cases); disruption incurred (sum of `Disruption` of executed transitions); time-to-repair; restart count per target; `RecoveryFailed` count (must be 0 unless injected); the **invisibility budget** (§21: idle CPU and memory are measured over the service cgroups of `planariad` and `planarian-recovery`, so spawned helpers count; the frame-time figure is a real p99 over frame samples, and a stand-in metric is reported as a stand-in, never as the budget); AskFirst prompts per user-week; catalog coverage per profile (§9); the verification ratio, the trust count, and the internal-unproven count (§17a); open bypasses by severity (§17b). The invisibility budget and the verification numbers are ratchets: every gate requires that they not degrade. Every gate requires zero open High bypasses.
- Phase B: fault families are split into train/held-out; GB is measured on held-out families.
- Targets: NixOS 26.05 VM gates. Non-gating from Phase A: an Asterinas NixOS VM and a Firecracker microVM (from a snapshot of the settled reference generation; service, configuration, transaction, and intent families only), failures classed `Driver`/`Backend`/`Core`; only `Core` failures are bugs. The Firecracker target becomes gating for the families it can host in B.

## 16. CLI and console

**CLI:** `planarian status | log | incidents | approve <hash> | resolve <txn> --as-committed|--as-reverted|--manual-repaired | undo | mark-good | mark-security-floor | override <unit> [--leave-alone|--stopped|--absent|--detached] [--until] | release <unit> | stop <unit> [--until] | ack | report boot | posture | agent run <name> -- <command> | gc`, and `ask "<phrase>"`. `agent run` starts an agent with the caller's permissions, attributed to the agent (§11); it refuses a name already in use (I24). `override`/`stop`/`release` create and lift `Override`s with the caller's identity. `ack` acknowledges a failure-posture alarm (administrator for `Integrity`) and, with a unit, an inferred override (§11). `report boot` prints the last boot report; `posture` prints the declared posture and timeout and whether a weaker declaration is waiting for the next boot (§12d). Every verb §16 names exists in A; changing the posture or timeout is a configuration change (§12d). `approve` and `mark-good` require root and an interactive TTY in Phase A, the TTY established by the daemon from the peer for both verbs (§11; known weakness: any root process with a terminal qualifies; broker in C). `mark-good` changes the recovery baseline and requires administrator authority. `known_good` is always boot-confirmed (I1); `mark-good` on a boot-confirmed generation moves `known_good` to it. `mark-good --accept-unconfirmed` instead sets a separate `accepted_baseline`, which the revert path may use as `revert_to` when it is newer than `known_good`, but which never replaces `known_good` in the boot menu until a reboot confirms it. Both are refused if any Readiness probe is failing. **Initial enrollment:** the first generation booted after install becomes `known_good` once its Readiness probes pass at the 10-minute checkpoint on that boot; until then Planarian runs with `max_tier = Runtime` and reports "no baseline yet."

**Operational limits (normative):** attempt budget 3 per incident; backoff 10 s / 60 s / 300 s; stabilization 5 min; regression window 30 min; escalation at 3 regressions; cooldowns 1 h then 6 h; token expiry 24 h; tick 5 s; probe timeouts as declared, default 10 s; settle default 15 s; generation deadline 15 min (networking 90 s); watchdog period 10 s; job-drain wait 60 s; journal preallocation 64 MB, compaction at 75%.

### 16a. Visual console (read-only in A)

**Socket limits.** Connections are bounded per uid and in total; a share of the total is reserved for administrators and for callers in a logind session, so services with dynamic uids cannot exhaust it. Work the socket can cause before a proposal is authorized (§12 step 2) is bounded the same way: one build slot per caller class, charged to the caller.

**Frontends.** Planarian exposes one interface, its socket API. The CLI is always present. The console is one optional frontend, shipped in the personal profile; any other frontend (a web dashboard, a TUI, an agent harness, a fleet console) uses the same API and gets the same identity derivation and policy checks. No frontend is privileged.

iced; COSMIC reference desktop; autostart as a user service on `graphical-session.target`, minimized unless there is an open incident, a pending approval, a reconciliation record, or the last boot reverted. Views: **Graph** (desired vs observed vs health per node: three small indicators, not one color; edge style by kind; overridden nodes hatched; Unknown nodes grey with a stale-clock mark), **Timeline** (transactions with journal states and outcomes), **Generations** (current, previous, known_good, live_tested, candidate; boot-confirmed marker), **Incidents** (state, attempts, cooldown). Buttons in A: `undo`, `override`/`release` (Runtime, user-actor). No approval in A. Reads only the daemon socket.

## 17. Pinned versions and conventions

NixOS **26.05** (`nixos-26.05` channel pinned to a commit in `flake.lock`; recorded in `docs/pins.md`; moves only by PR; 26.11 waits for Phase C). COSMIC from the channel module. Rust stable pinned. `zbus`, `serde`+JSON. No `unsafe` outside `backends/` and `watchdog/`. License **MPL-2.0**. CI: tests, gym Phase A catalog, dependency-boundary check, Verus proofs, Kani harnesses.

### 17a. Verification plan and trusted assumptions

Proof targets, in order: Phase A — `schema::digest`; `policy::decide` (purity; I5; I11; I14 in the sense that `decide` has no `Proposal` input; probe-tamper → AskFirst or Reject; I16 in `decide` and revert-target selection; I19: no token whose approver is the proposer, no self-grant); `txn` kernel (I6, including `Built`-waiting and `AwaitingBoot`; I12: every journaled transaction reaches a terminal state under the modeled outcomes; write-ahead ordering). Added 2026-10-29: the journal's hash chain (I18: every record written commits to its predecessor's hash, and the check on read reports the first break), in `txn` under Verus in A, trusting only SHA-256; the residue classifier (§11: which unit endings are a person's stop and which are faults) extracted as a pure function with Kani harnesses in A, Verus with `exec` in C; I17 (`user_authorization` gives root the administrator capability, so the set is never empty while root exists) in `policy` in A. `exec` orchestration gets Kani harnesses and proptest in A, Verus in C, together with I13 (the incident planner never targets an overridden unit). Diagnoser soundness and scorer in B. Broker in C. Switch/rollback and supervisor in D (store integrity proven only for content-addressed paths; input-addressed paths are verified by signature and NAR hash, not by content). OSTD, model channel, core update path in E.

`docs/assumptions.md` lists every externally specified behavior the proofs rely on, maintained as Verus `external_body`/`assume` sites are added. Phase A entries: backend `Outcome` is honest (`Succeeded` means applied; `Unknown` means the backend cannot say); `activate_live(revert_to)` restores the activation state of `revert_to`; `publish_boot` and the promotion rename are idempotent; the journal's fsync is durable and the preallocation is writable; systemd reports unit state truthfully over D-Bus and honors `X-RestartIfChanged`/`X-StopIfChanged`; fencing is effective (a stale-epoch call is refused before it mutates); the kernel and systemd are correct. Re-observation after a backend call *detects* divergence from the assumed postcondition; it does not undo an irreversible effect, which is why the `NonReversible` floor exists.

**Progress assumptions for I12** (liveness is conditional on these, stated in the proof): some lease holder (daemon or watchdog) eventually runs; a fenced worker eventually stops issuing calls or its calls are refused; journal writes eventually succeed (guaranteed by the preallocation for recovery records); backend calls terminate. Under those, every transaction reaches a terminal state; with them violated the proof says nothing, and `RecoveryFailed` plus alerting is the designed fallback.

**Verification ratio.** The trusted computing base is 𝒱 ∪ 𝒯: 𝒱, the **proven base**, is what is verified (`schema`, `policy`, `txn`, and later crates as they enter the Verus subset); 𝒯, the **trusted base**, is what is trusted but unproven (backends, Nix, systemd, the kernel, firmware), with every trust recorded in `docs/assumptions.md`. 𝒯 is accounted in three parts. **Platform trust** (P, G): what the machine underneath does. **Proof-validity trust** (V, plus the specifications the proofs prove against, Verus, Z3, and rustc): what makes a proof mean what it says. **Internal unproven code** (I-ids: `exec::derive`, `user_authorization` and the admin lookup, the residue classifier, journal I/O, the identity resolution of §10): Planarian's own code that the proven gates take input from. Internal unproven code is not an assumption about the world; it is work not yet proved, so it is reported as its own number, the **internal-unproven count**, never folded into the trust count, and it must not grow and is expected to fall from C. Every proved invariant also has at least one gym entry written from the spec's English rather than from its formal specification, since a proof certifies a wrong specification as readily as a right one. Every gate reports three numbers: the **trust count** (the count of platform and proof-validity entries in `assumptions.md`, including `external_body` and `assume` sites), the **internal-unproven count**, and the **ratio d:a**, discharged (d) to assumed (a) obligations, per invariant ("I12 rests on 3 discharged lemmas and 5 assumptions") and summed globally. GA reports both as the baseline. Every later gate requires that neither the global ratio nor any per-invariant ratio degrades and that the trust count does not grow. The v4.5 re-accounting (proof-validity entries added, internal code moved out of the trust count) sets a new baseline once, recorded with its reason; it is not a regression. D and E are expected to raise the ratio substantially; the gate requires only that it not fall, so that no one improves it with proofs that discharge nothing load-bearing.

**The accounting is itself checked.** `planarian-gym verification` rejects a duplicate obligation id; requires every invariant in the baseline to be present in the current accounting (a removed invariant is a failure, not an absence); and ties each discharged obligation to a proof artifact the verifier actually produced (the Verus check's output, or a reviewed manifest naming the proof function), not to the textual presence of a function name. Gym mutations: delete an invariant, duplicate an obligation, rename a proof function; each fails the gate.

**Status of the Phase A proof targets at v4.6.** Proved: `policy::decide` (I5, I11, I14-decide, I16-decide, I19, I21, I22), the `txn` kernel (I6, I12 conditional, I15, I23, write-ahead ordering), the hash chain (I18). Property-tested, not proved (deviations): `schema::digest`. **Not yet done, still required in A:** the residue classifier's Kani harnesses and the I17 `policy` proof. The gate is not called while either is a unit test.

### 17b. Bypass register

`docs/bypasses.md` lists every known route by which the machine can reach a state this spec says cannot happen, or by which a stated guarantee stops describing the real machine, whether or not a proof is involved. One row per route: id (B for open, X for accepted; never reused), route, what it breaks (always invoked, tamperproof, or correct), severity (High: defeats a stated guarantee in the shipped configuration without root; Medium: needs root, a network position, or a likely deployment, or the spec overstates the mechanism; Low: narrow, availability-only, or process; Accepted: outside the claim by design), status, mitigation, phase, and the invariants it limits (`all`, or `—` for none; §17c). Any change that adds a path to the machine (a request type, backend call, hook, or posture option) adds a row or states in its PR that it opens none. `planarian-gym verification --gate` checks the file's format and fails a gate with an open High row. The file has three tables — **Open**, **Closed** (status `Closed (<sha>)`, kept forever), and **Accepted** — and a row moves between them when its status changes; the format check rejects a Closed row in the Open table. **Rows added at v4.6:** B-20 (High, Open: agent-name collision rebinds a running agent's authority; closed by I24); X-12 (Accepted: an override-file writer that does not take the daemon's lock).

Verus subset applies to `schema`, `policy`, `txn` only. `exec`, `diagnose`, `incident`, `state` keep the no-`dyn` and no-`unsafe` rules so they can be brought in later; `intent`, `console`, `daemon`, `cli`, `gym` are unconstrained.

### 17c. Guarantees site

Planarian publishes a generated documentation site organized around its guarantees, as docs.rs is organized around a crate's API: every page is computed from the repository at one commit, never written by hand, and every claim links down to the code, proofs, tests and limits that carry it. It exists so an auditor can start from "what does this system promise?" and reach the exact lines that keep the promise, at the exact commit under audit.

**Sources.** The site is built only from files the repository already maintains: the invariant table (§7), `docs/verification-ratio.toml` (obligations and assumptions per invariant), `docs/assumptions.md`, `docs/bypasses.md`, the gym catalog (each entry's `spec` and `invariants` fields) and its latest run results, `docs/spec-history.md`, and the source tree (to locate each obligation by name). Nothing on the site is entered anywhere else.

**Pages.**

- **One page per invariant:** the statement verbatim from §7; proof phase, status and d:a against the baseline; each discharged obligation with its kind (verified fn, proof fn, Kani harness), what it guarantees, and a permalink to its line at the commit; the assumptions it rests on, each with its text, its kind (platform, proof-validity, internal unproven) and the other invariants that rest on it; the global proof-validity assumptions that apply to every proof; the gym entries that exercise it, with harness, expectation and the verdict from the run at that commit; the bypass rows that limit it; and its history across spec versions.
- **Reverse indexes:** per assumption (which invariants fall if it is false); per bypass (which guarantees it narrows); per source file (which invariants and obligations live there); per gym entry (what it exercises).
- **The spec itself**, one page per section, with cross-references as links.
- **API docs:** `cargo doc` output for the workspace, linked from invariant pages for the types they concern. Proof obligations link to source lines, not rustdoc, because rustdoc renders `verus!` blocks poorly.

**Versions.** A snapshot is built for every tagged release and for the head of `main`. Tagged snapshots are immutable and kept; `main` is rebuilt on every push. Every page names its commit and spec version in its first line and links to the same page in other snapshots.

**The build is the check.** The generator fails the build on any reference it cannot resolve: an obligation name with no matching function, an assumption or bypass id with no entry, an invariant with no page, a gym entry naming an invariant that does not exist, a bypass row with no invariants column. CI runs it on every push, so a docs failure is a build failure; a gate claim (§18 rule 19) may cite the site's snapshot at the gate commit.

**Where it lives.** The generator is a subcommand of `planarian-gym` (`planarian-gym site`), beside `verification`, which already parses these files and checks the same names. The site is an mdBook published to GitHub Pages from CI. It is generated output and is never committed to the repository.

## 18. Instructions to the coding agent (AGENTS.md)

0. **First deliverable, before any other code:** the Phase A fault catalog (`crates/gym/catalog/phase-a.toml`), one entry per §15 family at minimum, each with `inject`, `required_post`, `intent`, `family`; stop for owner review.
1. **Second deliverable:** the GA demonstration script (`gym/demo.sh`): fault → repair; bad config → revert; kill `planariad` during `Activating`; watchdog reverts; restart daemon; reconciliation record printed. Build toward making it pass; everything else is in service of it.
2. Implement Phase A only; traits for B–E with one implementation.
3. Build order (historical; every crate exists at v4.6): `schema` → `txn` (with the journal and the `fake` backends) → `policy` → `state` + `backends/linux` (systemd, logind, sysfs) → `exec` + `backends/linux` (nixos-rebuild) → `watchdog` → `changes` → `incident` → `diagnose` → `gym` → `intent` → `cli` → `daemon` → `console`. The console Graph view may be built as soon as `state` works.
4. Preserve however the schema evolves: I5, I6, I10–I25; `digest()` excludes resources and timestamps; `Proposal` is the only write path; policy facts derived by the executor; gym scores on `required_post` and intent cases, never on absence of errors; diagnoser before any model; probes with side effects other than `None` or a bounded `Measurement` never on a cadence.
5. Do not resolve §19 items; `TODO(owner)` with the stated default.
6. No language model, LLM API, or prompt anywhere in Phase A.
7. Where NixOS and this spec disagree on mechanism, follow NixOS and record in `docs/deviations.md`.
8. Every executor outcome must be reproducible from the log: proposal, pre/post state, `DerivedFacts`, `PolicyVersion`, probe evidence, decision, outcome.
9. `schema`, `policy`, `txn` in the Verus subset; land `policy` proofs before starting `exec`.
10. The Asterinas and Firecracker gym targets may stay red in A. Classify failures; fix only `Core`.
11. Every new `assume`/`external_body` adds a line to `docs/assumptions.md` in the same PR.
12. The fake backend used by the transaction kernel MUST satisfy every entry in `docs/assumptions.md`, not only the trait signatures: it is a second real implementation, not a mock. The gym runs the kernel against it under injected `Partial`, `Unknown`, and fenced outcomes.
13. The journal is hash-chained from the first commit that writes it (I18).
14. Never implement Planarian's response to its own failure inside `planariad`; it lives in `nix/posture.nix` as systemd and initrd units (§12d).
15. Report the invisibility budget (§21) and the verification ratio (§17a) from the first gym run; treat any degradation as a failing test.
16. `docs/future-work.md` is non-normative. Cite it; do not implement from it. If anything there seems to block Phase A, stop and ask.
17. Phase A was held open for v4.4: the schema-affecting changes (`Override`, the `Actor` shape, the security floor, the hash-chained journal) land before the Phase A proofs are written, not as migrations after them.
18. Keep `docs/bypasses.md` current (§17b): a PR that adds a path to the machine adds a row or says it opens none.
19. **v4.6 handoff, in this order.** (a) Reconcile: the close-out review in the project ("Phase A close-out review, head 805cd1c") lists every finding with its status at that head; before touching anything, confirm each item you take on is still open at *your* head and record which commit closed the ones that aren't. (b) B-20 first (I24; §11, §16): register the row, fix, add `agent-name-collision` to both harnesses. (c) The documentation sweep: every doc agrees with head and with this spec before any further status is cited (`ga-status.md`'s summary; `guarantees.md`'s accounting; `bypasses.md`'s three tables; `AGENTS.md` mirroring §18 rules 0–21; `catalog-review.md`'s counts and a v4.6 section; `phase-a.toml`'s header; the deviations rows §28 names). (d) The §28 required changes, one PR each, each with its §15 acceptance case landing in the same PR. (e) §15's harness contract and §17a's accounting checks. (f) Then, and only then, run the whole VM catalog on one commit and update `ga-status.md` from that run; a gate claim cites one commit and one run, never a union of runs.
20. **Equivalent effects, equivalent treatment.** When two spellings of a request, two paths to a commit, or two sources of a proposal produce the same effect on the machine, they get the same derived facts, the same floors, and the same bookkeeping (§11, I25). A PR that adds a spelling, a path or a source states which existing one it is equivalent to and shows the gym case that holds them equal.
21. **Nothing is derived from a failed tool.** A backend or helper that exits nonzero, times out, or returns truncated output never contributes a smaller plan, a `None` disruption, or a passing verdict; the step fails or the change parks (§9 step 3, §15 harness contract).
22. The guarantees site (§17c) builds on every push. A change that renames an obligation, adds an invariant or assumption, or adds a bypass row makes the site resolve in the same PR.

## 19. Open questions (owner decides)

- [x] GA threshold 60%; NixOS 26.05; MPL-2.0.
- [x] All of Future Work v0.2 §1 accepted into v4.4; schema-affecting items land in Phase A (Oct 28).
- [x] Invisibility budget targets: idle CPU < 0.5% of one core; resident memory < 50 MB excluding any model; no statistically significant frame-time or input-latency difference with Planarian running vs. stopped. Reference workload: one GPU-heavy game under Proton; the agent proposes the title and a scripted benchmark for owner sign-off.
- [x] Probe kinds: typed kinds by default; administrator-authored `Exec` probes allowed, flagged.
- [x] Hash-chained journal is a Phase A requirement.
- [x] Unattributed-stop residue: accepted with an undo under Relaxed/Standard; ask window under Guarded/Sealed.
- [x] Multi-user system-scope overrides: AskFirst for non-administrators when another uid's session is online.
- [x] Sandbox pass required for Tested where KVM exists, floored to AskFirst where not; Firecracker gym target non-gating from A.
- [x] Installer selects the posture; boot-ready timeout configurable (60 s default, 15–600 s).
- [x] Phase B grants to non-human principals: catalog and model-catalog authority only; merge authority requires two distinct approvers.
- [x] Learned `Diagnostic` edges are never admitted without a passing gym case.
- [x] Spec vulnerability review (Oct 29) merged as v4.5: a launcher for agents; the floor from the whole closure; no request field decides authority; trust accounting in three parts; I2, I14, I16, I18 qualified; the bypass register as a gate.
- [x] Repairs run while an admitted boot-only change awaits its confirmation; a canonical repair in that window means it is not confirmed (Oct 31; I6, §10).
- [x] Guarantees site: generated per commit and per tag, organized around invariants, published to GitHub Pages; never hand-edited (Oct 31; §17c).
- [x] Rollbacks in activation scheduling: user-requested runs at once; diagnoser rollback after failed repair is a repair, floors and quiet mode still apply (Oct 31; §12f).
- [x] Agents act with their user's permissions, attributed per instance (Oct 30; §11, I24). GC stays Runtime with `retainAllGenerations` (Oct 30; I21, §12b).
- [x] Close-out review (Oct 30) merged as v4.6. Decided: boot-only fallback is the publishing (running) generation, never `known_good` automatically (§12 step 7); parking in `Built` is bounded at 24 h, `AwaitingBoot` is unbounded and reported as waiting (§12f, I12); an external dependency needs a traversable edge, and the module rejects weaker ones (§10); approval tokens die with the daemon (§12 step 4, §12h). Taken as defaults, overturnable here: boot confirmation has two milestones, admission and the 10-minute confirmation (§10); only seated sessions carry a graphical expectation (§10); §6 describes the repository as it is.
- [ ] `assets/identity/source/prompts.md` records that the raster master was generated with an image model. Keep the provenance note in the public repository, or remove it? And is the identity kit under the repository's MPL-2.0 or reserved? (Not a spec matter; recorded here so it is decided.)
- [ ] Rule 5 (`TODO(owner)` markers) has never been used: no marker exists in the tree. Either every default below was resolved (then say so in AGENTS.md and retire the rule) or the convention should start being followed.
- [ ] **Provisional, revisit at each review:** `inferStops` (§11) stands in for a unit-importance property. Revisit if importance should also affect daemon-proposed stops, quiet-mode deferral, diagnoser ordering, or the console. If it should, add `importance` as its own field, not a `Sensitivity`: sensitivity is the risk of changing a unit, importance the harm of its absence.
- [ ] Catalog coverage threshold for the personal-profile gate: set after the first catalog survey.
- [ ] Choice of the reference game and benchmark sequence for the invisibility budget.
- [ ] Phase B threshold Y.
- [ ] Six observed states plus Unknown/Transitioning — revisit after the A catalog.
- [ ] Phase C snapshot backend: btrfs only, or btrfs + ZFS?
- [ ] Nix vs Nickel for the Phase D evaluator.
- [ ] Boot model family/size (default ~4B, 4-bit, CPU, 8 GB floor).
- [ ] Reference laptop (E). Fork Asterinas NixOS or parallel distribution (E).
- [ ] Should `Diagnostic` edges be learnable from incident history in C, or stay manifest-only?

## 20. Later phases — design notes carried forward

Not Phase A work; kept so the design is not lost.

**Model service (B).** The model is treated as an adversary: its judgement is never trusted and is not a vector, because any proposal it can make is one an attacker with the same socket could make, and every proposal passes the same checks. What must hold is **containment** (I9). Until I9 is proved in E, it is held by the unit's sandbox, which is normative: `DynamicUser=`; no capabilities; `ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp=yes`, read-only access to the model files and the report socket; `RestrictAddressFamilies=AF_UNIX`, widened only for a declared remote endpoint (future-work §3); a `SystemCallFilter=` allowlist; device access limited to the GPU's render node when GPU inference is enabled; the proposal socket as its only write path. Gym case (B): from inside the service, attempt every other write path (the journal, the override file, the store, another unit's socket, a capability-changing syscall); each fails and none leaves a trace outside the service. Unprivileged systemd service; reads reports over a Unix socket; emits `Proposal`s. Boot model ~4B at 4-bit on CPU via mistral.rs or candle; RAM floor 8 GB. **Residency** is declared like any other unit: `unit:model-service` desired Resident when `All[Not(Foreground), memory free ≥ model size + headroom]`, otherwise Unloaded. Loads lazily when an incident escalates to it (zero steady-state memory; 5–15 s cold start); unloads after a declared idle period (default 10 min) and immediately on GPU or memory pressure from any foreground principal: the user's session always outranks agent inference. If an escalation arrives while loading is not allowed, it falls back in order to the deterministic path, CPU inference where available outside quiet mode, a configured remote endpoint (future-work §3) within its disclosure profile, or deferral until the condition clears. It never loads over a foreground app. `keep_warm` offered at ≥ 16 GB outside quiet mode. Summoned only on `DiagnoserExhausted` or intent < 0.5. Tools: inventory, health report (including attempts and the incident), dependency graph, config read, local manual search, ask-user, propose (cataloged changes or new catalog entries for human review; never raw Nix). All text inputs tagged untrusted. Training: distillation in the gym, scored on diagnoser-failed and held-out faults. Model planner: largest catalog model that fits measured resources; installed as a Tested generation; switched only if it beats the **currently active** model on repair accuracy; falls back to the boot model on resource loss. Catalog models hash-pinned with training manifest and eval results.

**Approval broker and secure attention (C, E).** Separate process minting `ApprovalToken`s for any principal holding approval capability (§11), never for its own proposals. C: its own socket and a confirmation surface the compositor cannot draw over. E: a kernel-intercepted secure attention key hands the display to the broker.

**Remote principals, apps, fleets (future).** The endpoint catalog and relay for remote agents, app capability manifests, fleet membership (Raft and BFT behind one interface, BFT the intended default), attestation, and gossip of shared knowledge are directions in `docs/future-work.md` §3–§5. The hooks in §9 (signed external desired state) and §10 (signed health report), and the reserved `Actor::Agent`, exist so they can arrive without reopening the proven crates.

**Rust system layer (D).** Snix (git.snix.dev/snix/snix; crates GPL-3.0, protobuf definitions MIT) as the `GenerationBackend`, spoken to over its MIT protocols from a separate process. Rust PID 1 plus supervisor as `UnitBackend`, driven by `Requires` edges with `Wants` preserved as weak. Rust CoW filesystem as `SnapshotBackend`. relibc for Rust `std` (vendors openlibm, C; a named exception). Store integrity is proven for content-addressed paths and signature-and-NAR-hash-checked for input-addressed ones. Backend contracts are revised at the start of D from `docs/assumptions.md` and `docs/deviations.md`.

**Asterinas (E).** Fork at a pinned release (0.19.0 at writing). Driver priority for a reference laptop: NVMe, input, display → Wi-Fi, Ethernet, USB → audio, power, suspend → GPU modesetting → GPU 3D/compute (port Nova or Tyr) → Bluetooth, webcam, fingerprint. Firmware blobs allowed. Desktop: Smithay compositor with Rust software renderer; iced UI; COSMIC later. Verification: OSTD (vostd), executor, policy, diagnoser, broker, switch/rollback, store integrity, model channel, core update path. Core image: signed bundle installed only with project signature plus secure attention; previous core stays bootable.

**Trust base accepted as unproven at every phase:** firmware, bootloader, Rust compiler, CPU; plus the Linux kernel and systemd in A–D.

## 21. Expected resource profile

| Situation | Cost |
| --- | --- |
| Idle | Single-digit MB resident, < 0.5% of one core (the invisibility budget below); watchdog sleeps on a 10 s timer |
| **Invisibility budget (normative, ratchet)** | Idle CPU < 0.5% of one core; resident memory < 50 MB excluding any model; wakeups per second at idle reported; input-to-display latency and p99 frame time on the reference game workload with no statistically significant difference vs. Planarian stopped; notifications per user-week reported, and zero for self-resolved faults the user could not perceive |
| Fault → detection | One tick plus probe timeout (5–30 s); up to one cadence period for hardware probes |
| Fault → deterministic fix | 10–60 s per attempt plus settle; defer-to-systemd adds up to `RestartSec` + settle |
| Fault → model-assisted fix (B) | 1–3 min, plus cold start if not warm |
| Config change (Tested) | 30 s to several minutes, dominated by Nix evaluation and builds; plus the stage copy (seconds) |
| Runtime-settable option | Immediate; write-back follows in the background |
| Journal | One fsync per state change, roughly ten per generation transaction; 64 MB preallocated |
| Disk | Bounded by keep-N and space budgets; `BudgetUnsatisfiable` reported if the protected set alone exceeds them |
| Executor log | Tens of KB/day in steady state; rotated at 50 MB, kept 30 days |

## 22–27. Earlier changes

The changes from v3 through v4.4 (§22–§27) are in `docs/spec-history.md`, with their section numbers unchanged. Only the latest revision's changes stay in this file.

## 28. Changes from v4.5

Incorporates the Phase A close-out review of Oct 30 against commit `805cd1c`: four read-only code audits of Oct 29 (ids C/P/D/K/H in the review document), the third-party handoff of Oct 30 (R01–R16, S01–S07), and the owner decisions of Oct 30. Ids in brackets name the finding each change closes; the review document in the project carries the file:line evidence for each.

**New invariants and schema**

- I24: agent authority bound per instance; `AgentStarted { name, instance, by }`; `agent run` refuses a name in use; B-20 (High) registered and closed by this [new finding; R05 context].
- I25: post-commit bookkeeping on every commit path; a commit whose floor record cannot be written does not commit [R02, C8].
- I6 and §12 Concurrency carry the same exclusive-state list, now including `Checking` and `Publishing`; `TxnState::exclusive` is that list and the ledger reads it [S07, D11, C20].
- I7: probe evidence per probe and the approver's identity in the record [C1, C17]. I8: re-validation also when leaving `Built` [C2, P1]. I12: parked states bounded or reported [S03]. I20: launched agents inside the rule [R05]. I23: the override CAS is under the daemon's lock; X-12 for writers outside it [R11].
- `TxnState::Publishing` for the boot-only path [R01]. `RejectReason::{Precondition, ActivationUnknown}` [C3, R10].

**§9 and §10**

- `verify_candidate` checks the recorded NAR hash of the store path, not existence; the dry activation must succeed, in time, untruncated [C6/P2, R10].
- Promote/restore under `flock`; `txn/<id>/` by exclusive `mkdir` and deleted after terminal + checkpoint; the content-addressed override store pruned [C5, R11].
- Orphan build roots aged out at startup and before every GC, including crashed builds [C4/P5].
- Stale check, re-derive and re-`decide` on every path into `Activating`, including from `Built` [C2].
- Executor-owned post-check per probe against the pre-change set, and over every observed unit [R07, C22].
- Probe `timeout` is a whole-probe deadline; the batch never waits past it; typed probes' sandboxing deferred to C with `bytes_max` enforced for every reading kind [R06, P10]. Slow ticks warned [P9].
- Graphical expectation for seated sessions only; `SessionEstablished` unchanged [S05].
- External dependencies need a traversable edge (Requires or Diagnostic ≥ 0.7); the module rejects weaker ones [S06, P12].
- Boot confirmation as two milestones, admission and confirmation [S02].

**§11**

- Equivalent effects, equivalent facts: `SetOverride{Stopped|Absent|Detected}` carries the effects it causes; existing-generation operations derive from a dry activation of the target and its recorded override content [R03/C11, R04/C7].
- Preconditions checked by the executor for every proposal [C3].
- Agent identity per instance; `Actor::Model` authorized as an agent, never as the daemon [new finding, C14].

**§12, §12a–§12h**

- Admission before work: authorization, catalog membership and the interlock checked before `stage`/`evaluate`/`build`; prebuild work bounded and charged [R09].
- Tokens die with the daemon; consumed nonces in the checkpoint; approvals recorded with approver and `bound_to`; the approved execution logged [S07, C1].
- Boot-only path: `Publishing` journaled before `publish_boot_once`; the publishing generation is the fallback, never `known_good` automatically; crash-table row for `Publishing`; `AwaitingBoot` never re-prepared [R01, S01].
- Re-prepared transactions keep their original caller and source [C21].
- Post-commit bookkeeping in the kernel's commit on every path [R02, C8]. Floor derived relative to every earlier generation, so a `Revert` sets no floor [C9/H17].
- Worker subprocess wording replaced: a worker thread in A; `Lease.worker_pid`/`jobs` reserved for D (deviations row) [C13/P3].
- §12a write-backs queue behind an active generation transaction [P7]. §12f: parking in `Built` bounded at 24 h; `AwaitingBoot` reported as waiting; deferred repairs are deferred in fact [S03, P8]. §12c: a damaged checkpoint or record is `Integrity`, never `Absent` [C16].
- §12d: launched agents in `planarian-agents.slice`, ordered and conditioned on readiness, stopped wholesale by the posture, with per-launch and per-uid limits [R05]; `greetd` ordered when it is the display manager [P13]; "administrators" means Planarian's, not `wheel` [P14]; `planarian-recovery` has a start limit and raises `Crashed` [P15]; weakening posture/timeout takes effect at the next boot because the posture units read the booted generation [P16].

**§13–§16**

- Incident control state changes only on an authorized, successful human action [R08].
- The `repair:reapply` catalog entry ships [P22].
- Residue notice teaches the attributed form [P23] (unchanged text in §14; the requirement is restated as a §15 case).
- §15: the v4.6 acceptance cases; the harness contract (runners exit nonzero on `ERROR`/`FAIL`/`PARTIAL` and on unwaived `UNSUPPORTED`; CI strict) [R12, R15]; invisibility measured over service cgroups with a real p99 [R13].
- §16: `report boot`, `posture` exist; `ack <unit>`; `mark-good`'s TTY from the daemon; `agent run` refuses names in use [P17, P18, K10].

**§17a, §17b, §18, §19, §6**

- §17a: the accounting is checked (no duplicate ids, baseline invariants required, obligations tied to verifier output) [R14, D1]; the Phase A proof status stated, with the residue Kani harnesses and the I17 proof named as still required [D4].
- §17b: three tables, Closed rows kept; B-20 and X-12 [D13].
- §17c (new, Oct 31): the guarantees site; bypass rows name the invariants they limit; rule 22.
- I6, §10, §12 Concurrency (owner decision, Oct 31): unit and device repairs run during a boot-only `Promoted`, and a canonical unit that needed a repair since admission means the change is not confirmed.
- §12f *Rollbacks* (owner decision, Oct 31): a user- or intent-requested rollback runs at once; a diagnoser rollback after failed in-place repair is a repair, exempt from activation windows but not from the disruption floors, and deferred with its incident under quiet mode unless its target is a foreground dependency; the revert of a failing candidate is never deferred. Three §15 cases.
- §18: rules 19–21 (the handoff order; equivalent effects; nothing from a failed tool); rule 4's preserve list to I25 [D5].
- §19: the Oct 30 decisions recorded; two owner items added [Q7, Q8].
- §6: the layout describes the repository as it is [D14, H14].

**Documentation, to be corrected in the sweep (not spec changes):** `ga-status.md` describes the pre-805cd1c agent model and two of three verification numbers; `guarantees.md` carries the v4.4 trust count and P9; `AGENTS.md` lacks rules 12–21 and says the console is unbuilt; `catalog-review.md` counts a 71-entry catalog; `phase-a.toml` says v4.4; `vm.yml` and `AGENTS.md` count 7/62 jobs and 70 runner minutes; `assumptions.md` P5 names `txn::journal::chain`; `verification.md` cites §8 for §7 [D6–D10, D12, H2–H4, R16]. `docs/why.md` is still to be written; the review's §5 has notes on the draft.

## Sources

- [NixOS manual: what happens during a system switch](https://nixos.org/manual/nixos/stable/) · [systemd.unit: dependencies](https://www.freedesktop.org/software/systemd/man/latest/systemd.unit.html) · [Verus: trusted components](https://verus-lang.github.io/verus/guide/tcb.html) · [Nix glossary: content vs input addressing](https://nix.dev/manual/nix/2.30/glossary.html)
- [NixOS 26.05 release](https://phoronix.com/news/nixos-26.05-released) · [COSMIC on NixOS](https://smithery.ai/skills/olafkfreund/cosmic-de)
- [Firecracker](https://firecracker-microvm.github.io/) · [microvm.nix](https://github.com/astro/microvm.nix) · [Lanzaboote](https://github.com/nix-community/lanzaboote) · [Feral GameMode](https://github.com/FeralInteractive/gamemode) · Anderson, *Computer Security Technology Planning Study*, ESD-TR-73-51 (1972) · [Burgess, "Computer Immunology" (1998)](https://www.usenix.org/legacy/publications/library/proceedings/lisa98/full_papers/burgess/burgess_html/burgess.html)
- [Asterinas](https://github.com/asterinas/asterinas) · [paper](https://arxiv.org/html/2506.03876v1) · [0.19](https://phoronix.com/news/Asterinas-0.19-Released) · [vostd](https://github.com/asterinas/vostd) · [Verus](https://www.microsoft.com/en-us/research/?p=1083954) · [Snix](https://git.snix.dev/snix/snix) · [relibc](https://github.com/redox-os/relibc) · [mistral.rs](https://www.sourcepulse.org/projects/1770767) · [Nova](https://www.phoronix.com/news/Nova-Driver-LPC-2026) · [Tyr](https://lwn.net/Articles/1055590) · [Smithay](https://smithay.github.io/smithay/smithay/backend/renderer/index.html) · [niri](https://lwn.net/Articles/1025866) · [COSMIC 1.10](https://phoronix.com/news/COSMIC-Epoch-1.10)
