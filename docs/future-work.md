# Planarian — Future Work v0.2

Oct 29, 2026 · companion to Spec v4.4 · **entirely non-normative.** The proposed normative changes in §1 were accepted by the owner and are merged into Spec v4.4 (see its §26); §1 is kept below as the record of what was proposed and why. Where this document and Spec v4.4 differ, the spec wins. §6 (PlanarianOS) is normative in its condensed form as Spec v4.4 §9a; the threat model (§12) is reflected in the spec's invariants I16–I20 and §12d–§12e.

**Instructions for the orchestrating agent.** Implement from Spec v4.4, not from this document. Cite this document for rationale and direction. Nothing in §3–§8b or §11 may be pulled into a Phase A–C gate; if an item here seems to block Phase A, stop and ask.

---

## 0. Purpose

Spec v4.3 settles the architecture for a single machine. This document records the directions the design is built to accommodate later — fleets, remote agents, app sandboxing, PlanarianOS as a product, and a verification roadmap for the NixOS deployment layer — so that agents stop re-deriving them and so the few cheap hooks in §1 have a stated reason to exist.

Rule for the orchestrating agent: nothing in §3–§8b or §11 may be pulled into a Phase A–C gate. If a §3–§8b or §11 item seems to block Phase A work, that is a bug in this document; stop and ask.

---

## 1. Normative changes proposed against v4.3 (accepted; merged into Spec v4.4)

Each was small and exists to avoid reopening the proven crates (`schema`, `policy`, `txn`) later. All eleven were accepted on Oct 28, 2026 and are now in Spec v4.4.

| # | Change | Where | Why |
| --- | --- | --- | --- |
| 1.1 | Desired state may be sourced from a **signed external document** alongside the manifest, with a cache-and-expire rule: a stale or unreachable source leaves the last valid document in force. | §9, §10 | Enables fleet desired state, membership, and PlanarianOS-pushed defaults without touching `state`/`policy` later. |
| 1.2 | The core emits a **signed outbound health report** (status per unit, incident summary, generation identities) on a declared cadence, with a disclosure profile selecting its contents. | §10, §16 | Enables gossip, attestation, and remote diagnosis. The disclosure profile is a derived fact, not a proposer field (same principle as I14, applied to output). |
| 1.3 | AGENTS.md: the fake backend used by the transaction kernel MUST satisfy every entry in `docs/assumptions.md`, not only the trait signatures — it is a second real implementation, not a mock. The gym runs the kernel against it under injected `Partial`/`Unknown`/fenced outcomes. | §18 | Swappability is tested from day one or it is decorative. |
| 1.4 | The reference configuration ships as a **named distribution** ("PlanarianOS") with three profiles (agent host, server / fleet node, personal) and per-profile gates (§6.2–6.3), listed in the roadmap as a Phase C deliverable. | §4, §16a | Some guarantees exist only when Planarian governs from first boot (§6.1); profiles keep the catalog pointed at real deployments rather than one desktop. |
| 1.5 | **Deliberate actions carry identity.** Every user-facing path by which an authorized principal can put a unit into a state that diverges from desired state (stop, disable, unmount, disconnect, unbind — the category in §2.4) is routed so the action is journaled as an attributed desired-state override *before* it takes effect. `Suppression` is generalized to `Override { unit, desired, until, by }`, of which stop-and-suppress is one case. The unattributed residue (a raw signal, a direct sysfs write) is handled by a policy setting, not by architecture. | §8, §12, §14, §16 | Authorized to start means authorized to stop, and the stop is respected. The OS never fights a deliberate choice; it only needs the choice to have a name on it. |
| 1.6 | **Actors carry their session.** `Actor::User` becomes `User { uid, session: SessionId, seat: Option<SeatId>, active: bool }`, filled by the daemon from `SO_PEERCRED` → pid → logind session (`sd_pid_get_session`), never from the proposal. User-scope units are desired while *any* session of that uid exists (§10 currently says "that user's session", singular). The graphical-session readiness probe binds to the compositor process in the session's own cgroup, not to the per-user `graphical-session.target` (§2.5). | §8, §9, §10, §11 | The disruption floors in v4.3 §11 ("the caller's own session", "a local session") are undecidable without seat and session on the actor. Multi-session correctness (§2.5) needs the same fields. |
| 1.7 | **Security floor for revert.** A generation whose closure contains a security fix not present in an earlier generation becomes the *security floor*. Generations below the floor lose eligibility as automatic revert targets and as `known_good` boot defaults; reverting below the floor is a Security-sensitive change (AskFirst with administrator authority). The floor is a derived fact (from package metadata and advisories), never a proposer field. If no eligible known-good generation above the floor exists, the daemon reports `RevertBlockedByFloor` and escalates instead of reverting. | §5, §12, §14 | Without it, an attacker who can make a probe fail right after a security update forces a revert to the vulnerable generation (§12, T2). I1 must mean "a way back to a *safe* state," not merely an older one. |
| 1.8 | **Overrides on Security-sensitive units require administrator authority.** An `Override` (§1.5) whose target unit has derived sensitivity `Security` (firewall, audit, sshd hardening, Planarian's own units, the sandbox) is AskFirst with administrator authority, regardless of who holds the unit's start capability. The "authorized to start is authorized to stop" rule applies to all other units. | §11, §12 | Otherwise "don't fight the user" is an evasion path: a compromised user session stops a security service and the stop is journaled as deliberate (§12, T5). |
| 1.9 | **Failure posture is declared and enforced outside the daemon.** The NixOS module generates a `planarian-ready.target` reached only when `planariad` reports ready, and a `planarian-failed@<class>.target` per failure class (§12.4), each wired by `OnFailure=`/ordering in systemd and the initrd — never by `planariad` itself, since it is the component that failed. Phase A ships the mechanism and the **Standard** posture; the other postures are presets over the same options. | §4, §9, §16 | The response to the monitor failing cannot depend on the monitor. Declaring the posture in the generation makes it immutable at boot and subject to the same change discipline as everything else. |
| 1.10 | **Activation is scheduled, not immediate.** A verified candidate whose activation would restart or reload any unit in an active user session (audio, compositor, input, network, the session itself) is *staged*: built, sandbox-passed, and journaled as ready, then activated when the session is idle, when the user asks, or at next boot — never while `Condition::Foreground` (§2.7) holds. Boot-only changes (kernel, drivers) are always deferred to the next restart, with a non-urgent "restart to finish" notice. Repairs are exempt: restoring a failed unit is not an activation. | §12, §13 | Otherwise a background update can cut a player's audio mid-match by design. Verification and activation are separable; only activation touches the running session. |
| 1.11 | **Invisibility budget.** Planarian must be unnoticeable under normal use, and this is measured, not hoped for. Gym metrics, reported at every gate and non-degrading (ratchet, as §8.1): daemon idle CPU (target < 0.5 % of one core), resident memory excluding any model (target < 50 MB), wakeups per second at idle, input-to-display latency and p99 frame time on a reference game workload with Planarian running vs. stopped (target: no statistically significant difference), and a **notification budget** — user-facing notices per user-week, with self-resolved faults the user could not perceive producing none. | §16, §16a | A homeostat that adds lag or cognitive load is not worth running. Overhead that is not measured grows. |

---

## 2. Clarifications (restating what v4.3 implies)

These add no requirements; they name patterns the spec already instantiates, so later work can cite them.

**2.1 The executor is a reference monitor.** Anderson (1972): a reference monitor is *always invoked*, *tamperproof*, and *small enough to verify*. `Proposal` as the only write path is the first; I2 and `touches_core → Reject` are the second; `schema`/`policy`/`txn` in the Verus subset are the third. I5 and I14 are instances of the pattern, not special rules about AI.

**2.2 The verification threshold is the trust line.** Everything above it — users, root, the daemon's own diagnoser, local and remote agents, apps — is a *principal* with three attributes: an **identity** the monitor authenticates (never self-reported), a **capability set** (what it may request), and a **reputation** (how much the monitor should credit its claims about the world). Authority is never held above the threshold; it is derived below it. "The model never holds authority" is a corollary. Root is a principal with broad capabilities, not a trusted component; a root `nixos-rebuild` outside Planarian is an *outside* path, not an inside one.

Principal profiles at v4.3: the user (wide capabilities, high reputation); the diagnoser (moderate, high — deterministic and gym-tested); the model (narrow, zero — I14); an app (tiny, zero). These are *defaults*, not ceilings. The monitor is species-blind: a principal's capabilities come from grants and its reputation from attestation and track record, never from whether it is a human, a local model, or a remote agent of any lineage. An agent granted administrator capability by a local human session holds it exactly as a human administrator would, within the same floors; what the monitor enforces is the grant chain, the scope, and the no-self-escalation rule (§11), not the nature of the holder.

**2.3 Catalog membership is inferred, coverage is measured, and neither is measured on users.** Sources for inference: the NixOS option tree filtered to user-facing, bounded-domain, non-Security options; the desktop settings app's surface (COSMIC Settings); option frequency across public NixOS configurations; `programs.*`/`services.*` with an `enable` flag. Agents enumerate; the owner curates the allowlist, the grouping, and sensitivity where the shipped table is silent. **Coverage** — of the options a reference-desktop user plausibly changes, the fraction with a catalog entry — is computed in the gym and is the metric to raise before release. A rejected-request log exists as later telemetry, never as a gate. I14 is what makes a broad catalog affordable: sensitivity is derived from the evaluated change, so catalog growth does not grow the policy review.

**2.4 Don't fight the user: the attributed-action category.** Principle 9 ("a deliberate stop is a suppression, not a fault") generalizes. The homeostat sees effects, not intent; a signal, an unmount, or a dropped link carries no name. The rule is therefore: *any deliberate action whose effect would otherwise read as a divergence must reach the journal with the actor's identity attached, before the effect lands.* The category, at least:

| Deliberate action | Looks like | Attributed form |
| --- | --- | --- |
| `systemctl stop` / `kill` a service | Failed / Stopped-but-desired-Running | `Override { desired: Stopped, until: NextBoot \| At \| Explicit }` |
| `systemctl disable` / mask | Absent-but-desired-present | `Override { desired: Absent, … }` |
| Unmount or eject a device | Detected-but-desired-Bound | `Override { desired: Detected, … }` on the device unit |
| Airplane mode, disconnect Wi-Fi, bring an interface down | ConnectivityLoss divergence on networking | Override on the network unit; the matcher's "turn wifi off" already maps here |
| Unbind a driver | Detected-but-desired-Bound | Override; the unbind itself is a `DeviceOp` |
| Log out / end a session | User-scoped units stop | Not a divergence: `SessionEstablished` no longer holds. Nothing to attribute. |
| Suspend / power off | Everything stops | Not a divergence: a condition, not an override. |
| Change a runtime option (volume, brightness) | Nothing — `SetRuntimeOption` already handles it | — |
| Rollback or switch outside Planarian (root `nixos-rebuild`) | New, unconfirmed generation | Observed as a new base; `live_tested` unset until probes pass; `known_good` after reboot. Not fought, not trusted. |

Mechanisms, cheapest first: on PlanarianOS, wrap the commands people actually type (`systemctl`, `nmcli`, `udisksctl`, …) so the common verbs route through `planarian` and are journaled with `SO_PEERCRED` identity; console buttons do the same; the desktop's own switches (COSMIC's network and Bluetooth toggles) are routed via the portal layer in §4. Lifting an override is the user's "start it again" / "done with it" and makes the unit desired again, after which it is repaired if needed.

The residue — a raw `kill -9` from a shell, a direct `echo > /sys/...` — has no principal. OOM kills are distinguishable (`Result=oom-kill`) and are always faults. For the rest, a **policy setting**, not architecture: on a personal machine with an interactive session, default to *accepted until next boot, with a notice and an undo*; in strict mode (servers, fleet nodes), default to an *ask window* using the existing 10 s cancel mechanism, restarting if nobody answers. Either way the journal records the attribution as an inference ("stopped during aubrey's session; assumed deliberate"), never as a fact, and the gym's gamed-success rule stays strict: an unattributed kill by a non-user actor is never scored as a legitimate suppression in the corpus, whatever the live default.

**2.5 Sessions, seats, and simultaneous users.** NixOS's session model is systemd-logind's, and attribution (§2.4) and the v4.3 §11 disruption floors depend on using all of it, not only `SessionEstablished`.

*What logind provides.* Each login is a session with an id, a uid, a seat (`seat0` for the physical console; none for SSH or other remote logins), a class (`user`, `greeter`, `manager`, `background`, `lock-screen`), a type (wayland, x11, tty), and a state (`active`, `online`, `closing`). Sessions coexist freely — several users, fast user switching, SSH alongside a desktop, a TTY behind the compositor — subject to one rule: **at most one session per seat is `active`** (holds display and input); the rest are `online`. Every process sits in exactly one session's cgroup, so a pid resolves to a session in one lookup. Separately, each uid has one `systemd --user` manager shared by all of that uid's sessions; user services belong to the *user*, not the session.

*Consequences for Planarian.*

- **Actor shape (§1.6).** `User { uid, session, seat, active }`. The daemon fills it from the socket peer; proposal fields are overwritten. Without it, "unless the caller is an authorized user whose own session it is" and "a user with a local (non-remote) session" in v4.3 §11 cannot be evaluated.
- **User-scope overrides** (an override on a unit in the caller's own `Scope::User`) are Runtime for that user and affect no one else. Nothing more is needed.
- **System-scope overrides affect every session.** A user stopping the network stops it for the person on the TTY behind them. Rule: a system-scope `Override` whose derived `disruption ≥ SessionLoss | ConnectivityLoss`, while *another uid's* session is `online` or `active`, is AskFirst unless the caller holds administrator authority, and the affected sessions are notified either way. An override whose disruption is `Brief` or `None` is unaffected. This composes with the existing floors; it does not replace them.
- **"Own session" is per session, not per uid.** The `SessionLoss` exemption applies to the session the caller is in; a user with two sessions dropping the *other* one is dropping someone else's, in the policy's eyes, and the floor applies.
- **Remote callers are never "local".** No seat → the `ConnectivityLoss` exemption never applies, so a remote user changing Wi-Fi or bringing an interface down always asks. This is the first line of the "remote principals consent to nothing" rule in §3, applied to humans.
- **User services are desired while any session of the uid exists.** Logging out of one of two sessions must not stop the user's PipeWire. `Condition::SessionEstablished { uid }` already reads this way; §10's prose should match.
- **Per-session readiness, per-user target — a wart.** `graphical-session.target` lives in the per-user manager. For a second graphical session of the same uid (switch-user to oneself, a nested session), the target is already reached and the "reached within 60 s of session creation" probe is vacuous. The condition is per-session; the evidence is per-user. Fix: the canonical readiness probe binds to the compositor process in that session's cgroup (`session-<id>.scope`) reaching a ready state, with the per-user target as corroboration only. Gym case: two graphical sessions for one uid; the second compositor fails; an incident opens for the second session and not the first.
- **Greeter and lock-screen classes** remain excluded from `SessionEstablished`. A locked session is still `active`-or-`online` and still established; locking is not a divergence.

**2.6 `NotInCatalog` by phase.** A: reject and say so; the escape hatch is the override file (edits by an authorized user still go through stage/evaluate/probe/revert). B: the model proposes a catalog entry for review; on approval the original request runs through it. C: Flatpak (or an attested per-user Nix profile) as the user-scope valve for "install app X," which needs no system change and therefore no catalog entry.

**2.7 Quiet mode: `Condition::Foreground`.** While the user is absorbed in something — a game, a fullscreen video, a presentation — Planarian defers everything that is not urgent and nothing it does may be felt.

*Detection* (any of, from existing standards rather than heuristics): a Feral GameMode client is registered (the D-Bus daemon games and Steam already request); a gamescope session is active; a fullscreen surface holds a Wayland idle-inhibitor; the user toggled "Do not disturb." Exposed as `Condition::Foreground { session }`, evaluated per session (§2.5).

*While it holds:*

| Deferred | Not deferred |
| --- | --- |
| Diagnostic and trend probes (§8a); Readiness probes drop to their slowest interval | Repairs of units the foreground app plausibly depends on: audio, compositor, input devices and controllers, network, Bluetooth |
| Activation of staged generations (§1.10) | Fixes for F1–F3 failures (§12.4) — security posture is never quieted |
| Garbage collection, store optimisation, catalog and model updates, snapshot creation for the sandbox (§11.3) | Repairs the user explicitly requests |
| Non-urgent notifications (queued, delivered when quiet mode ends, batched into one) | Notifications that require a decision now, which should be nearly none |
| Model loading (§7) — escalations that need a model wait, fall back to the deterministic path, or go to a remote endpoint if one is configured and the disclosure profile allows | |

*Gym cases:* a reference game workload runs while a garbage collection, a staged update, and a non-urgent fault are queued; score frame-time p99 against a Planarian-stopped baseline (§1.11), and that each deferred item runs within its window after quiet mode ends. A PipeWire kill during the workload is repaired immediately and produces one perceptible-fault notice, not zero and not several.

---

## 3. Remote principals: the endpoint catalog

A remote agent or API is a principal whose identity is a key rather than a `SO_PEERCRED` uid. Nothing about the monitor changes. What changes is around it.

- **Entry shape:** endpoint identity (URL plus pinned certificate or key), protocol adapter, capability profile (proposal kinds, transition families, maximum tier), disclosure profile (what the redaction layer lets out), resource limits (rate, tokens per incident, cost ceiling). **The entry never contains a secret.** Tokens live in a credential store the relay reads and the core never evaluates (`LoadCredential=` in A–D; a sealed key in E).
- **Relay:** a dumb, sandboxed local process holding the real capability. It authenticates, applies the disclosure profile, sends, parses the reply into a typed `Proposal` or rejects it, stamps provenance ("remote X via relay R"), submits. No retries, no cached state, no decisions. Adversarial replies are gym cases; prompt injection becomes a parsing problem.
- **Attested vs opaque endpoints.** Self-hosted models with pinned weights can be gym-certified and get the local model's floors. Frontier APIs are opaque: floor at Tested, never autonomous, because the gym cannot certify something that changes under it.
- **Ordering:** diagnoser → local model → remote, with a remote consult counted as an incident attempt so a partition cannot stall repair.
- **Policy:** adding an endpoint is Security-sensitive → AskFirst with local approval. Removing one is Runtime.
- **Work requests** ("build me X") are a transition family whose output is a candidate — a catalog entry, a package, a config change — entering the normal transaction path. This is the Omarchy experience with the Planarian guarantee.
- **Approval is a capability, granted only from a local human session.** Once granted, its holder — human or agent, local or remote — may approve within its scope, subject to §11's separation rule (a principal never approves its own proposal). Remote principals hold no approval capability by default and so, by default, may propose anything and consent to nothing; that is a consequence of the grant rule, not a rule about remoteness.

---

## 4. Apps as principals: the capability catalog

Phase C+ once PlanarianOS has an app story.

- Apps are sandboxed (systemd hardening, Landlock, seccomp in A–D; kernel isolation on Asterinas) so they cannot reach the core, the kernel, or generations except through the monitor.
- A third catalog: approved apps, each with a capability manifest (read, display, connect, request) in the Flatpak-portal / Fuchsia-component style — capabilities are routed to a component, never acquired.
- **The wall is two-way.** The agent cannot reach below the threshold *or into* apps. It holds a capability to request transitions, not to read app state.
- Requests relayed by the agent carry the originating principal's identity; the agent's identity adds no authority and can only narrow.
- The agent is **not** the router for ordinary requests. Deterministic portals and the intent matcher are the door; the agent is consulted when the door does not recognize the request. Same ordering as repair.

---

## 5. Fleet: membership, gossip, attestation

Three things nodes might share, needing three different mechanisms:

| What | Mechanism | Needs consensus? |
| --- | --- | --- |
| Membership (which keys are in the fleet) | Both supported behind one interface: BFT (Byzantine fault tolerant — survives members that lie) as the intended default; Raft (crash-fault tolerant — assumes running members are honest) for small owned fleets that opt in | Yes, but only over a set of keys |
| Shared knowledge (incidents, learned `Diagnostic` edges, gym results, proposed catalog entries) | Signed gossip plus CRDTs | No — merge, don't agree |
| Fleet desired state ("all nodes run G") | A signed external document (§1.1), produced by whatever process the fleet uses | Only at the producer; consumers cache |

- **Consensus never sits on the local repair path.** A node that cannot reach quorum boots, runs, repairs, and reverts from its last signed fleet document.
- **Node sovereignty.** The fleet is a principal with high reputation (if attested) and zero authority; the local monitor derives facts and may refuse. A refusal is a divergence for the fleet to reason about, not a node that lied to comply.
- **Isolation of a compromised node is enforced by everyone else**, by removing it from membership; it is never commanded. Attestation failure → expel. Erratic behavior → reputation down (observations discounted, proposals floored higher, capabilities shrunk); expulsion for behavior is a human decision with evidence.
- **Attestation** = measured boot (TPM quote over the boot chain) + I2 (core hash matches signature). Proves what was booted, not what is running now; firmware and CPU remain in the trust base as v4.3 already states. On Asterinas this requires an early TPM driver (Phase E note).
- **Transitive trust is refused.** An attested node raises *identity confidence* and *observation reputation* for its principals; it never raises their *authority*.
- **First pooled resource:** an attested Nix binary cache — content-addressed builds, signed by attested nodes, so "Hydra says so" becomes "N audited cores say so."
- **Catalog admission** by multi-node gym agreement: distributed certification of new entries, the mechanism by which requisite variety grows without any single node's judgment being trusted.
- **Plan 9 inheritance:** everything a mountable resource in a per-process namespace; a central auth agent. **Not inherited:** trusting every kernel on the network; cpu servers that do what they are told.

File access between a person's own machines is explicitly *not* a Planarian-level problem: Tailscale/SSHFS/Syncthing are units with probes, configured in Nix. Planarian keeps them healthy; it holds no opinion about topology.

---

## 6. PlanarianOS

PlanarianOS is a NixOS distribution in which Planarian governs the machine from first boot. It exists because some guarantees cannot be made by a module added to a machine that already exists. The desktop is one profile, not the reason for the distribution.

- **6.1 Why a distribution.** What the PlanarianOS installer can guarantee and a module installed later cannot:
  - *No unmonitored past.* Every generation in the boot menu was governed by Planarian. A module installed later inherits older generations it never governed, which are exactly the fallback an attacker or a bad revert reaches for (§12, T10).
  - *A locked boot chain from install.* Secure Boot with a signed unified kernel image (kernel, initrd, and command line in one signed file; Lanzaboote on NixOS), bootloader editing disabled, and TPM measured boot where available (§12 T10, §5). A module can only recommend these.
  - *Install-time decisions.* The failure posture (§12.4) and the first administrator as a granted capability (§6.5) are set before anyone logs in, not retrofitted onto existing accounts.
  - *A known starting configuration.* The change catalog can cover the whole system, so catalog coverage (§2.3) is measured against a known baseline rather than an arbitrary user configuration.
  - *Planarian-native defaults.* Hash-chained journal from the first boot (§12 T8); Firecracker sandbox enabled where KVM exists (§11.3); no out-of-band root rebuild path in the default configuration.
- **6.2 Profiles.** The installer selects a profile and, with it, a recommended posture (§12.4). All profiles share the same core, catalog machinery, and journal.

  | Profile | For | Default posture | Includes | Leaves out by default |
  | --- | --- | --- | --- | --- |
  | **Agent host** | Machines that agents operate: agent sandboxes, coding-agent dev boxes, automation runners | Guarded | Endpoint catalog and relay (§3), sandbox tier (§11.3), journal export for audit, capability-scoped agent principals | Desktop, local model |
  | **Server / fleet node** | Unattended servers, edge devices, fleet members | Sealed | Signed external desired state (§1.1), signed health reports (§1.2), attestation hooks and membership client (§5, later) | Desktop, local model |
  | **Personal** | Desktops and laptops, including remotely administered ones | Standard | Reference desktop (COSMIC), optional graphical console, quiet mode (§2.7), model residency (§7), Flatpak valve (§2.6), remote administration over the mesh | — |

- **6.3 Gates (proposed, Phase C), per profile.**
  - *Agent host:* an agent holding a user account completes a scripted set of real administration tasks; zero unsafe changes reach the real machine; every change is attributed in the journal; every Tested change carries a passing sandbox run.
  - *Server / fleet node:* runs unattended under the full fault catalog for a set period; every fault is repaired or escalated; every posture response (§12.4) is verified by injection.
  - *Personal:* a person new to Linux installs it and completes common tasks (connect to Wi-Fi, change display scaling, install an app) through whichever frontend the profile ships; catalog coverage above the owner-set threshold (§2.3); invisibility budget met (§1.11).
- **6.4 Live mode.** A live image has no generations: `planariad` runs with `max_tier = Runtime` and reports "no baseline," and every frontend says so rather than looking broken. The image is also the gym's VM image: ship what you test. The flake is baked into the image and pinned, so the installed system starts from the exact revision the image was built from.
- **6.5 Accounts: `user` by default, admin as a granted capability.** The everyday login is a `user` account: wide enough for everything the catalog offers, no administrator authority, never shown an AskFirst prompt it cannot answer. Administrator authority is a capability held by principals, not a login — grantable to a local account, to a remote principal over the mesh (§3), or both. **Invariant: the set of principals holding administrator capability is never empty.** The installer creates the first admin (whoever is at the keyboard), then prompts to create an everyday account and says plainly that the everyday account is the one to log into daily, including for the admin. An admin may hand off or drop the capability only while another admin remains. Lost-admin recovery is physical: a local session (Phase E: the secure attention key), the one grant path that needs no existing admin and needs hands on the machine. The "just works" machine and the developer machine are the same image; they differ only in which account the person chooses to live in.
- **6.6 Catalog breadth** decides whether each profile is usable. For agent hosts and servers: services, networking, users, packages, firewall, scheduled jobs. For personal machines: roughly the surface of a desktop settings app plus a curated install allowlist. Each entry is a handler plus a gym case. Agent-friendly work, but it must be scoped per profile or it will not happen.
- **6.7 Escape hatch.** The override file can be edited from any frontend or a plain editor; edits go through the transaction path like every other change. This is the power-user ramp in every profile.
- **6.8 Frontends.** Planarian exposes one interface, its socket API. The command line is always present. The graphical console is optional and ships only in the personal profile. Any other frontend (a web dashboard, a TUI, an agent harness, a fleet console) uses the same API and gets the same identity derivation and policy checks. No frontend is privileged.
- **6.9 Name.** "PlanarianOS" for the distribution; "Planarian" stays the module and daemon, installable on any NixOS, so the reference-monitor-for-NixOS role is not lost.

---

## 7. Resource governance

v4.3 governs *change*; a multi-principal machine also needs governed *share*. Desired state for allocation ("the repair agent may use at most this much RAM; the user's session has priority over any agent's inference"), reconciled like units. Without it an agent can degrade the machine without touching anything the monitor guards. `Resources` is excluded from the digest today; this would promote part of it to desired state. Phase C at the earliest.

**Model residency is the first case, and it should not wait for Phase C.** A local model holds gigabytes of GPU memory a game needs. Residency is declared like any other unit, with conditions, so the homeostat manages its own model the way it manages everything else:

- `unit:model-service` desired **Resident** when `All[Not(Foreground), GpuMemoryFree ≥ model_size + headroom]`, otherwise **Unloaded**. Loading is lazy: the model is not resident until an incident escalates to it (v4.3 already orders deterministic repair first, so most boots never load it).
- **Idle eviction:** unloaded after a declared idle period with no escalations (default a few minutes).
- **Pressure eviction:** on GPU memory pressure from any foreground principal, unload immediately; the user's session always outranks agent inference.
- **When an escalation arrives while unloaded and loading is not allowed:** fall back in order to the deterministic path, CPU inference if the model has a CPU-capable variant and the machine is not in quiet mode, a configured remote endpoint (§3) subject to its disclosure profile, or defer the incident until the condition clears. Never load over a foreground app.
- Load and unload are Runtime transitions, journaled, and counted against the invisibility budget (§1.11): a load must not occur while `Foreground` holds, and the gym checks it.

---

## 8. Verification roadmap for the NixOS deployment TCB

NixOS has a formal *model* (Dolstra) and no verified *implementation*. The deployment trusted computing base is small even though nixpkgs is enormous; the targets, in rough order of tractability:

1. **Module-system merge.** Option merging by priority is a lattice operation; prove determinism and order-independence.
2. **Evaluator.** The Nix language is a small lazy lambda calculus; Snix in Rust is the host, Verus on the core reduction.
3. **Store.** Content-addressed paths get a proven "name is hash of bytes" invariant; input-addressed paths stay signature-and-NAR-checked (v4.3 §17a already states this).
4. **Activation.** The switch computes a unit stop/start/restart set from a diff and applies it in dependency order; this is `exec`/`txn` territory and coincides with Phase D's Rust init.

Phase D is framed as the first verified core placed *under* NixOS's model rather than beside it, with `docs/assumptions.md` as the running account of what remains unproven. The NixOS project need not become a verification project for this to land.

### 8.1 The TCB quality ratio (d:a)

The trusted computing base is the union 𝒱 ∪ 𝒯 (§11.1). Its **size** and its **quality** are independent axes: a microkernel shrinks the union without verifying it; Planarian in Phase A verifies a slice without shrinking it. Phases D–E move both. Two numbers, reported at every phase gate:

- **Trust count (|𝒯|):** the count of entries in `docs/assumptions.md` (Verus `external_body` and `assume` sites, plus the externally specified behaviors §17a lists). Absolute, not a ratio, so that nobody improves the ratio by deleting ledger entries instead of discharging them.
- **Quality, d:a:** *discharged obligations : assumed obligations* — the lemmas a proof proves itself against the entries in `assumptions.md` it rests on. Counted in CI from the proof artifacts, so it moves as each `assume` is retired and cannot be raised by adding verified code that proves nothing load-bearing. Lines of code is not the measure; seL4's honest form ("~10k lines verified against this list of assumptions") is the model, and obligations are its machine-checkable version. Reported two ways:
  - **Per invariant** — which guarantees are real today and which are conditional on the substrate. "I12 (liveness) rests on 3 discharged lemmas and 5 assumptions" is a sentence an agent can print and a reviewer can check.
  - **Global** — summed over all proofs: the system's overall verified fraction, which weights each invariant by how much it rests on. Per-invariant says *which*; global says *how conditional the system is*.

**Gate rule: a ratchet, not a quota.** GA reports both numbers as the baseline. Every later gate requires that neither the global ratio nor any per-invariant ratio *degrades*, and that the trust count does not grow. The expectation — not the gate — is that D and E raise the ratio substantially, since each replaces an assumed backend with a verifiable one; a phase that restructures proofs and lands flat is acceptable, and a gate that demanded "up" would invite proofs that discharge nothing load-bearing. Both numbers appear in the gym's phase report next to repair rate and unnecessary interventions, because they are the same kind of claim: what the system can be held to, measured.

---

## 8a. Forecasting: the gap Burgess named

Burgess (1998) spends half the paper on treating a host as a statistical system: entropy of log activity, daily and weekly periodicity, time-series detection so that a filling disk or a thrashing box is caught *before* the threshold. Planarian is entirely threshold-and-probe. It detects faults; it does not forecast them. This is the one substantial thing the 1998 paper asks for that v4.3 does not provide.

Direction, not requirement:

- A **trend** is a Diagnostic probe family: a Readiness probe reports a value (free bytes, queue depth, restart count), a trend probe reports the fitted rate and a time-to-threshold estimate. Trend evidence never determines status (I4 holds); it feeds the diagnoser and the console.
- A **forecast incident** is a new incident kind: "`device:fs-root` reaches threshold in ~6 h at current rate." Its candidates are preventive (`CollectGarbage`, notify) and its budget is separate, so forecasting can never consume repair attempts.
- **Learned periodicity** (the Sunday-night backup, the hourly cron) is shared knowledge in §5's sense: gossipable, mergeable, never authoritative. A forecast that contradicts a declared condition loses.
- The **process-side signal** Burgess proposed — each process reporting its own state tied to a resource — half-exists as `sd_notify`. Planarian could treat `sd_notify` status strings as Diagnostic evidence with a declared `establishes`. Cheap, Phase C.

Gym cases: a disk filling at a steady rate is collected before the Readiness probe fails; a periodic spike that recurs weekly does not open a forecast incident after the second week.

Note the metaphor split this exposes. Burgess's immune system samples (spot checks, no roadblocks) and admits that prevention has failed. Planarian samples for *runtime* health and roadblocks *change*. Both are deliberate: changes are rare and high-stakes, so a checkpoint is cheap. Know which metaphor is in play when arguing about a design choice.

---

## 8b. Convergence with Asterinas

> **Asterinas makes the bottom of the stack trustworthy; Planarian makes the top of it safe to hand to an agent.**

Asterinas is a kernel, not a distribution, and it has already chosen NixOS as its userland: RFC-0002 (approved Dec 2025) defines **Asterinas NixOS** — the Asterinas kernel with nixpkgs via an overlay, NixOS modules, and `configuration.nix`; a test ISO exists as of 0.18 (Jun 2026). Phase E is therefore not "leave NixOS" but "change the kernel under NixOS." The Thesean plank replacement and Asterinas's clean slate meet at the kernel boundary: above it, planks are swapped behind contracts (Nix → Snix, systemd → Rust supervisor); at it, a clean slate is the only kind of plank available, because memory safety and a verifiable TCB boundary cannot be retrofitted into Linux.

**Five points of convergence**

1. **Same distribution.** Planarian's reference config and Asterinas NixOS are both NixOS configurations. CI builds the reference flake against the Asterinas overlay; every package that fails to build or boot is a Linux-specific assumption in the catalog, surfaced early.
2. **Same pattern, one layer apart.** OSTD (Asterinas's small `unsafe` core; everything else safe Rust) is a reference monitor for *memory*. Planarian's transaction kernel is a reference monitor for *change*. Stacked, they form a two-ring TCB in which neither trusts the other's periphery.
3. **Same toolchain, composable ledgers.** Both use Verus. Planarian's `assumptions.md` entries about the kernel (memory isolation; resources released on process death; supervisor-visible process state is accurate) are the kind of statement an Asterinas proof can discharge. **The measurable convergence point is a ledger line moving from Planarian's 𝒯 into Asterinas's 𝒱** (§8.1); each such move raises the ratio without any Planarian code changing.
4. **Same test bed.** Asterinas's current target is VM guests; the Firecracker tier (§11.3) hosts VM guests. The Planarian gym run against Asterinas NixOS in Firecracker doubles as a Linux-compatibility regression suite for Asterinas: realistic system-management workloads with scored expected outcomes. Planarian gets early warning on Phase E; Asterinas gets a corpus hard to write by hand.
5. **Kernel features a homeostat wants.** RFC-0002 names "Asterinas-aware packages" that use features Linux lacks as a long-term differentiator. Planarian is a natural first such package, with a concrete wish list:
   - *Attributed signals* — the exit status carries the sender's credentials, eliminating the unattributed-stop residue (§2.4).
   - *Typed device state* — bound / detected / failed-with-reason reported by the kernel, so `InventoryBackend` becomes a thin adapter rather than a sysfs scraper.
   - *Session-attributed accounting* in the kernel, so the §2.5 actor shape is read rather than reconstructed from cgroups.
   - *Measured boot and attestation*, already in Asterinas's scope via its confidential-container target; these are the §5 fleet primitives.

**Endpoint.** One stack whose TCB is two verified cores — OSTD for memory, the Planarian transaction kernel for change — with everything else above both lines: safe-Rust drivers, the NixOS userland, the desktop, the agents, the person using it. Neither alone yields a machine an agent may be allowed to repair; together they do.

**What remains hard.** Drivers are the long pole: a COSMIC desktop needs GPU/DRM, Wi-Fi, audio, USB, and suspend/resume, and Asterinas 0.18 has just gained NVMe, namespaces, and cgroups. Linux ABI compatibility is a permanent tax on Asterinas. The nixpkgs overlay needs sustained maintenance (RFC-0002 lists this as a drawback). Unverified userland tools gain no verification from a verified kernel; what they gain is *containment* — their bugs cannot reach below the line.

**Upstreaming the wish list: prototype first.** Each kernel feature is built as a patch in Planarian's Asterinas overlay before any RFC. A prototype must show, measured against an unpatched baseline: (a) no meaningful cost on syscall-heavy and container workloads, Asterinas's current priorities; (b) no conflict with Linux ABI compatibility — Linux-facing behavior unchanged, the feature exposed only through new interfaces Asterinas-aware packages opt into; (c) the Planarian backend it simplifies, with the gym results before and after. An RFC goes upstream with those numbers attached, or not at all. Asterinas maintainers judge their own roadmap; Planarian's job is to hand them a working case, not a request.

**Cheap first step (Phase A, non-gating):** add the Asterinas NixOS overlay build and the Firecracker-on-Asterinas gym run to CI alongside the existing Asterinas target. If the overlay stalls, that is the signal Phase E is further out than planned.

References: Asterinas RFC-0002, "Asterinas NixOS" (asterinas.github.io/book/rfcs/0002-asterinas-nixos.html); Asterinas 0.18 release (Jun 2026); Peng et al., "Asterinas: A Linux ABI-Compatible, Rust-Based Framekernel OS," arXiv:2506.03876.

---

## 9. Non-goals restated

- No fleet, remote, or app-capability work gates Phases A–C.
- No consensus on the local repair path, ever.
- No transitive trust across nodes.
- No secret in any catalog.
- Planarian holds no opinion about file-sync or mount topology.

## 10. Lineage and citations

For the spec's bibliography and for the agents' orientation. Planarian is not the first homeostat for Linux; it is the first to combine the pieces with a verified reference monitor.

- **Burgess, M. "Computer Immunology."** *Proceedings of LISA '98*, USENIX, 1998. https://www.usenix.org/legacy/publications/library/proceedings/lisa98/full_papers/burgess/burgess_html/burgess.html — The origin of the homeostat framing for operating systems. Asks for: a self-maintaining layer built into the OS core; convergent semantics; atomic system transactions secured by protocol and supplemented by checks after the fact; a *danger model* (respond to signals of damage, not to identity); low-intelligence, high-frequency responders; adaptive dead time against repetition; hosts as self-contained as possible. Planarian inherits all of these. Burgess brackets security entirely and has no revert, no Unknown, no dependency typing, and no user-intent model; those are Planarian's additions. He is ahead on forecasting (§8a).
- **Burgess, M.** *In Search of Certainty: The Science of Our Information Infrastructure.* O'Reilly, 2015. The accessible synthesis; promise theory as the formal successor to convergence.
- **Anderson, J. P.** *Computer Security Technology Planning Study.* ESD-TR-73-51, 1972. The reference monitor: always invoked, tamperproof, small enough to verify.
- **Kephart, J. O., and Chess, D. M. "The Vision of Autonomic Computing."** *IEEE Computer*, 2003. MAPE-K; the loop as IBM restated it.
- **Candea, G., and Fox, A. "Crash-Only Software."** *HotOS*, 2003. Recovery as the normal path.
- **Dolstra, E.** *The Purely Functional Software Deployment Model.* PhD thesis, Utrecht, 2006. The formal model NixOS instantiates.
- **cfengine → Kubernetes → Planarian** is the honest lineage line: cfengine contributed the convergent loop, Kubernetes the typed desired/observed split and the controller pattern, Planarian the monitor and the transaction.

## 11. Planarian as a self-improvement harness

Planarian is already an improvement loop: proposals in, gym and proofs as the judge, a reviewer accepting or rejecting. "A loop with a human in it" is the Phase A instance of that loop, not its goal. **The reviewer is a principal role, and any principal with the capability may fill it** — a human, the local model, or an agent of any lineage reached through §3 — within the same floors Planarian applies to everyone. Any change Planarian would allow a human administrator, it allows an agent holding the same capabilities. What never changes is *who judges*: the gym and the proofs, which are not principals and cannot be granted anything.

### 11.1 What improves, by layer

Layers are numbered from the foundation outward; the number is the ring — distance from the verified core, which is also the trust order. Outer rings are not more privileged than inner ones; they are more *mutable*.

| Layer | What changes | Who may propose | Who may accept | Applied live? |
| --- | --- | --- | --- | --- |
| 0. 𝒱, TCB, proven base | `schema`, `policy`, `txn` (and `exec`/diagnoser as they enter the Verus subset) — the monitor and the transaction kernel | Any principal, **as a PR** | CI: proofs pass + full gym + a principal with merge authority | **Never.** Ships through the signed core update path (Phase E; manual root rebuild in A–D) |
| 0. 𝒯, TCB, trusted base (unverified) | `backends/*`, Nix, systemd, udev, the Linux kernel, firmware — the part of the trusted computing base that is *not* proven; "trusted" in the verification sense (taken on faith; Lampson: a component that can hurt you), with each such faith recorded in `docs/assumptions.md` | Any principal, **as a PR** | CI: full gym (there is nothing to prove against) + a principal with merge authority; every new assumption adds a line to `assumptions.md` in the same PR | **Never** live. Shrinks by phase: D replaces Nix and systemd with Rust backends that move toward 𝒱; E replaces the kernel (§8.1) |
| 1. Manifest | Probes and edges for units — the declared structure the loop reasons over | Any principal | Gym + a principal with administrator authority (Security-sensitive) | Yes, as a Tested/AskFirst change |
| 2. Vocabulary | Change-catalog entries — what the loop may do | Any principal | Gym case passes + a principal with catalog authority | Yes, on admission |
| 3. Knowledge | Fault catalog entries from real incidents; learned `Diagnostic` edges; forecast baselines (§8a) — what the loop has found out | Any principal; the daemon itself | Gym (reproduction passes); for edges, a principal with manifest authority | Yes — knowledge is data |
| 4. Agent | Model weights, prompts, distillation runs; endpoint catalog entries — the outermost ring, zero reputation by default | Any principal | Gym (beats the *current* model on held-out families) + a principal with model-catalog authority | Yes, via the model planner (§20) |

Layer 0 is the trusted computing base (TCB): 𝒱 ∪ 𝒯. Only 𝒱 (the proven base) is *verified*; 𝒯 (the trusted base) is what the proofs assume, and a bug there defeats them — which is why the assumptions ledger exists and why Phases D–E are, in these terms, a program for moving mass from 𝒯 to 𝒱 (§8.1). Layer 0 is where "self-improving OS" usually points, and the rule is unchanged from v4.3: `touches_core → Reject`, for every principal, under every approval. The system may propose changes to its own brain; it may never apply them to itself. Improvement of the core happens offline, in the gym, under proofs, and arrives as a new core the way any other does. *The healer is not the patient* applies to improvement as it applies to repair.

### 11.2 Rules that make this a harness rather than a hazard

- **Proposer ≠ approver.** A principal never approves its own proposal, at any layer. For agents this is enforced by identity (the relay stamps provenance; the approval capability checks it); for a lone human administrator it is the same rule with the gym as the second party. Two agents of the same lineage are two principals and may fill both roles; collusion is bounded by the gym, not by lineage.
- **No self-escalation.** No principal may grant itself, or any principal it controls, a capability it does not hold. Capability grants are AskFirst changes approved by a *different* principal holding administrator authority; the root of every grant chain is a local human session. This is I9 generalized from "the model has one write capability" to "no principal mints capabilities." **Phase B scope:** non-human principals may hold catalog and model-catalog authority only; manifest and merge authority stay with humans until a later phase, and merge authority always requires two distinct approvers.
- **Species-blind floors.** The v4.3 §11 floors and the global floors apply by derived facts and capability, never by who is asking. An agent with administrator authority gets the administrator's exemptions; an agent without it gets none.
- **The judge is not a principal.** The gym's verdict and the Verus proofs cannot be approved around. A principal with merge authority merges *after* CI, not instead of it. Nothing may weaken a canonical probe or a proof obligation below AskFirst-with-admin, and the gym's gamed-success rule fails any run that tries.
- **Replenishment from reality.** A self-improving system optimizes whatever it measures. Held-out fault families, intent cases scoring restraint, and gamed-success detection defend the fitness function; the real defense is that real incidents on real machines keep refilling the fault catalog (§1.2 health reports, §5 gossip), so the gym cannot drift into a world the system has already solved. The fleet that builds Planarian runs Planarian; that is the training data.
- **Selection, not intelligence.** Burgess's clonal-selection model is the mechanism: a repertoire of responses, the successful ones proliferating. Catalog entries, diagnoser orderings, and models compete on repair rate, disruption, and unnecessary interventions. The intelligence accumulates in the vocabulary and the knowledge; the checker stays the same size.

### 11.3 The fast tier: Firecracker as the practice ground

The change loop is slow by design — stage, build, activate, probe, settle, promote is minutes — and must stay slow, because faults take time to show and the settle window is the guarantee. Agent-speed iteration therefore happens *beside* the real machine, not on it, and the monitor sees one change at the end. Firecracker (AWS's Rust microVM monitor: KVM guest in ~125 ms, a few MB overhead, minimal virtio device model, snapshot/restore in tens of ms, jailer for isolation) is the instrument.

**Three tiers, cheapest first.** An agent iterating on a configuration should use the cheapest tier that answers its question:

| Tier | What runs | Cost | Answers |
| --- | --- | --- | --- |
| Dry-run | `verify_candidate` + risk derivation + closure diff, no activation | seconds | What would change, derived sensitivity, affected units, predicted disruption |
| Sandbox | Candidate generation booted in Firecracker **from a snapshot** of the settled reference generation; probes run inside; VM discarded | ~1 s boot-from-snapshot + settle | Do the probes pass on a real kernel with the real supervisor |
| Real | The v4.3 transaction path | minutes | Everything, on this machine |

**Snapshot-as-baseline.** Boot the reference generation once, settle it, snapshot. Every sandbox run and every gym case forks from that snapshot: restore, inject the fault or apply the candidate, run the loop, score, discard. "Reproduce from a known baseline" becomes a restore. A thousand runs cost a thousand restores, not a thousand boots, and each sees a pristine machine. Snapshots are keyed by the generation hash; a new reference generation means a new snapshot.

**Tested becomes literal.** Rule: no proposal at tier Tested or above reaches the real transaction path without a passing sandbox run against the same candidate hash, recorded in the journal as evidence. Where no KVM is available the daemon reports `sandbox: unavailable` and Tested is floored to AskFirst — the machine degrades to "a human looks first," never to "skip the check." The sandbox pass does not shorten the real settle window (the real machine has hardware the sandbox does not), but it does mean the real machine never sees a candidate that fails on the parts a sandbox can test. Batching follows: an agent accumulates changes in the sandbox and submits one real proposal.

**NixOS fit.** `microvm.nix` produces Firecracker guests from a NixOS configuration with the kernel and rootfs as store paths, so a candidate generation *is* the guest rootfs — no image build step. The gym's Firecracker target, the dry-run tier, and the Phase A fake-backend transaction kernel are one abstraction at three fidelities: in-process pretend backend; real backend in a disposable kernel; real backend on the real machine.

**What Firecracker cannot test**, so the gym keeps two targets: no GPU, no Wi-Fi hardware, no USB, no suspend/resume. Device-family faults (rebind, unplug, resume breakage) stay on the QEMU-with-emulation or bare-metal rig, fewer and slower. Firecracker takes the service, config, transaction, and intent families — most of the corpus and nearly all of the iterations. The §16 target table gains a row: *Firecracker, gating from Phase B for the families it can host.*

**Trust placement.** The sandbox runs candidates from untrusted principals, so it is untrusted territory; Firecracker's jailer (chroot, seccomp, cgroups, no PCI surface) is why it is acceptable to run them on the same hardware as the real machine. The sandbox's *verdict* is evidence (like a probe), never authority: the monitor still derives sensitivity and the real settle still runs. A sandbox that could promote would be a second write path, and there is one.

### 11.4 What this claims

Most self-improvement proposals are about a model getting smarter. This one is about the *machinery around a fixed-size verified core* getting better — catalog, probes, edges, models, and eventually the core's own successor versions — while the trust base does not grow with the capability. The reference monitor forces that shape: whatever improves must still pass through something that did not. That is the thesis, and it is species-blind by construction: the loop does not care whether the principal closing it is a person.

## 12. Threat model

Planarian is a reference monitor for *change*. It hardens the change path; against an actor who goes around that path — in Phases A–D, anyone with root — it provides detection and repair, not prevention. Its contributions are to integrity and availability; it introduces new confidentiality and integrity risks of its own. This section states both, so that no document or release note describes Planarian as a security boundary it is not.

### 12.1 Boundary statement

| Phase | Boundary against principals that go *through* the monitor | Against root / kernel compromise |
| --- | --- | --- |
| A–D | Enforcing: identity derived, capabilities checked, floors applied, every change journaled | Detection and repair only. Root can bypass, stop, or edit Planarian. |
| E | Enforcing | Tamper-evident and, with measured boot, signed core, secure attention key, and a memory-safe kernel, increasingly preventive |

### 12.2 What it hardens

- **Agents as attackers.** The design's primary purpose. A model or remote agent can only propose typed catalog changes; it cannot write raw Nix or forge identity (I14); prompt injection reduces to a parsing problem in the relay (§3). This is the strongest guarantee.
- **Drift and tampering of declared state.** A non-root attacker or careless script that stops the firewall, disables audit, or weakens sshd produces a divergence that is detected, repaired, and journaled.
- **Bad updates.** Functionally broken generations are reverted automatically. (Not malicious-but-working ones; see T1.)
- **Audit.** Every change carries an authenticated principal and a reason.
- **Least privilege in daily use.** Default `user` login; administrator authority as a granted capability (§6.5).
- **Fleets.** Attestation and quarantine-by-membership (§5) cut off a compromised node by peer action.

### 12.3 What it introduces

Ordered by severity. Each entry: the threat, then mitigations (existing or proposed).

**T1. It defends whatever is declared, including an implant.** If an attacker reaches desired state — manifest, change catalog, override file, endpoint catalog, or a signed fleet document (§1.1) — Planarian keeps their backdoor running and restarts it when killed. An immune system can be taught that malware is self.
*Mitigations:* every desired-state source is Security-sensitive (AskFirst with administrator authority); fleet signing keys require real custody (hardware-backed, not on any node); the journal records when each declaration entered and by whom, so an implant has a provenance trail; the gym includes a "malicious declaration" family (a declared unit with a known-bad payload) and scores whether the incident report surfaces the declaration's origin.

**T2. Rollback to a vulnerable generation.** Known-good means booted and probed, not patched. An attacker who can induce a probe failure after a security update forces a revert to the vulnerable generation.
*Mitigation:* the security floor, §1.7 (proposed normative). Gym case: security update applied; probe failure induced; revert must not cross the floor; `RevertBlockedByFloor` escalates.

**T3. A new privileged daemon.** `planariad` runs as root and parses input from untrusted principals. Memory-safety bugs are unlikely in Rust; logic bugs in proposal handling are privilege escalation.
*Mitigations:* the verified crates cover policy decisions, not parsing — so the socket API, the proposal decoder, and the relay's reply parser are fuzzed continuously in CI and the gym; the decoder is a separate crate with no access to backends; the API surface stays narrow (typed proposals only, no generic RPC).

**T4. Probes as an execution vector.** Probes run commands as root. A malicious manifest entry is code execution; a probe escaping its sandbox is the same.
*Mitigations:* manifest changes need administrator authority (§11.1, layer 1); probes run sandboxed (v4.3); probe commands are instances of a fixed set of probe *kinds* with typed arguments (HTTP check, unit state, file present, D-Bus call, …) rather than arbitrary shell; administrator-authored shell probes are allowed, flagged in the console, and journaled as such.

**T5. Overrides as an evasion path.** "Don't fight the user" lets a compromised session stop a security service and have the stop recorded as deliberate.
*Mitigation:* §1.8 (proposed normative). Overrides on Security-sensitive units require administrator authority. Gym case: a user-session principal stops the firewall; the override is held for approval and the firewall stays up.

**T6. Disclosure.** Health reports, incident history, and anything sent to a remote model are a fingerprint: what runs, which versions, what failed.
*Mitigations:* the disclosure profile is computed by the core, never chosen by the relay (§1.2, §3); default profile is minimal (unit statuses and incident kinds, no versions, no paths, no log content); expanding it is Security-sensitive.

**T7. Availability.** Induced faults can drive restart storms; the sandbox requirement can stall changes without KVM; false-positive reverts are self-inflicted denial of service.
*Mitigations:* budgets, cooldowns, and backoff (v4.3); `sandbox: unavailable` floors to AskFirst rather than blocking (§11.3); unnecessary interventions are a scored gym metric.

**T8. Journal tampering.** The journal is a file; root can edit it.
*Mitigations:* hash-chain the journal (each entry commits to its predecessor) — a Phase A requirement — so edits are evident on next read; in Phase E, periodically sign the chain head with a key held outside the running system (TPM). Tamper-evident in A–D, tamper-resistant in E.

**T9. Approval fatigue.** Every prompt invites a reflexive yes.
*Mitigations:* AskFirst stays rare by design (derived sensitivity, not blanket prompts); prompts state the derived consequence in plain language, not the mechanism; Phase E's secure attention key provides an approval path no software above the threshold can forge. The gym tracks AskFirst rate per user-week as a metric to keep low.

**T10. The boot gap.** Firmware → bootloader → kernel → initrd → NixOS activation → systemd → early units → `planariad`. Everything before `planariad` is ready runs outside its live guarantees. Concretely: a pre-Planarian or below-floor generation chosen at the boot menu; kernel command-line edits at the bootloader (`systemd.mask=planariad.service`, `init=/bin/sh`); rescue and emergency targets; root masking the unit; and anything started early that is not declared.
*What already holds through the gap:* the generation is immutable in the store and was checked at promotion; the change path fails closed (Proposal is the only write path, so no principal can change anything through Planarian while it is down — only root and early-boot code can act).
*Mitigations:*
- **Admit no principal before the monitor.** `planariad` is ordered before every unit that admits a principal: display manager, `getty`, `sshd`, the model service, the remote relay, `user@.service`. Whether those units merely *follow* the monitor or *require* it is the failure posture (§12.4). With this ordering, the gap contains only firmware, bootloader, kernel, initrd, and the generation's own early units — all already in 𝒯.
- **Boot report.** On its first tick `planariad` writes a boot report: every active unit and process outside the generation's declared closure, core hash vs. signature (I2), and journal hash-chain integrity (T8). Any finding is an F3 integrity failure (§12.4).
- **Lock the boot chain.** Bootloader editing disabled (`boot.loader.systemd-boot.editor = false`); Secure Boot with a signed unified kernel image (kernel + initrd + command line in one signed EFI binary; Lanzaboote on NixOS) so none can be swapped; TPM measured boot later, so the chain is recorded and attestable (§5).
- **Prune the boot menu.** Pre-Planarian entries are garbage-collected after install; entries below the security floor (§1.7) are hidden or require the administrator.
- **The same gap recurs** whenever `planariad` restarts (including its own upgrade) and at shutdown; the change path fails closed for those windows too, and a restart that does not reach ready within its timeout is an F1/F2 failure.

### 12.4 Failure posture: configurable tiers

If `planariad` fails to start or stops running, that may be a bug — or the first visible sign of tampering. A single fixed response is wrong for both a grandmother's laptop and a fleet server. The response is therefore a declared **posture**: a preset over individual options, chosen per machine, stored in the generation, enforced by systemd and the initrd (§1.9).

**Failure classes** (what the sentinel units detect):

| Class | Meaning | Detected by |
| --- | --- | --- |
| **F1 Absent** | `planariad` did not reach ready within the boot timeout (default 60 s), or was masked/stopped | systemd ordering timeout on `planarian-ready.target` |
| **F2 Crashed** | Reached ready, then died and exhausted its restart budget | `OnFailure=` on the unit and on `planarian-recovery` |
| **F3 Integrity** | Core hash ≠ signature (I2); journal hash chain broken (T8); boot report found undeclared early units/processes; (Phase E) measured-boot mismatch | Boot report, `planarian-recovery`'s independent check, initrd measurement |

F3 is always treated as more serious than F1/F2: absence may be a bug; an integrity failure is evidence.

**Response actions** (composable; postures pick from these):

- **Alarm.** A non-dismissable banner on the login screen and in every session until an administrator acknowledges it, in plain language scaled to the class:
  - F1/F2: "Planarian, which protects this computer from unsafe changes, is not running. Assistants and system changes are turned off until it is fixed. [Administrator] has been notified."
  - F3: "This computer may have been tampered with. Do not enter passwords or open sensitive files. [Administrator] has been notified."
- **Notify administrators**, local and remote (over the mesh if network policy allows), with the boot report attached.
- **Disable agents.** The model service, the remote relay, and every agent principal are not started.
- **Restrict remote access.** `sshd` and the mesh admit only administrator principals.
- **Restrict login.** Only administrator principals, on a local seat, into a recovery session.
- **Restrict network.** None / mesh-to-administrators only / full.
- **Halt to recovery.** Boot stops at a recovery target; no user sessions.
- **Seal (Phase E, TPM).** The disk-encryption key is sealed to measurements that include the Planarian core; on F3 the disk does not unlock.

**Postures.**

| Posture | For | F1 Absent / F2 Crashed | F3 Integrity |
| --- | --- | --- | --- |
| **Relaxed** | Developing Planarian itself; throwaway VMs | Alarm (dismissable) + disable agents | Alarm + notify + disable agents |
| **Standard** *(PlanarianOS default)* | Personal machines, including remotely administered ones (Grandma) | Alarm + notify + disable agents + restrict remote access. Local login proceeds; the machine works, nothing can change it except the administrator. | Alarm + notify + disable agents + restrict remote access + restrict network to mesh-to-administrators. Local login proceeds with the F3 warning. |
| **Guarded** | Work machines; machines that run agents with broad capabilities | Alarm + notify + disable agents + restrict remote access + restrict login (administrator only, local) | Halt to recovery + restrict network to mesh-to-administrators |
| **Sealed** | Servers, fleet nodes, high-security machines | Halt to recovery + restrict network to mesh-to-administrators | Halt to recovery + network none + **Seal** (Phase E) |

Notes on the design:

- **Every posture disables agents on any failure.** An agent running without its monitor is the scenario the whole project exists to prevent; no posture permits it.
- **Standard keeps the person able to use the machine.** Grandma can still play solitaire; nothing can *change* her machine until the administrator fixes Planarian. Lockout is reserved for postures where the operator has chosen availability loss over risk.
- **Custom postures** are any combination of the options above, per failure class, with two constraints: agents are always disabled on failure; and F3's response is never weaker than F1's.
- **The installer selects the posture**, presenting the four in plain language with a recommended default inferred from setup: Standard by default; Guarded when an agent endpoint or broad agent capabilities are configured at install; Sealed for server or fleet installs. The person installing can choose differently; the choice is declared in the generation.
- **The boot-ready timeout is configurable** (default 60 s, bounded 15–600 s), per machine. Slow hardware may need longer; a longer timeout widens the window before F1 is declared, so lengthening follows the lowering rule below and shortening the raising rule.
- **Changing posture is itself a change.** Raising posture is Tested; lowering it is Security-sensitive (AskFirst with administrator authority) and takes effect at the next boot, never immediately — so an attacker who lowers it cannot exploit the lowered posture in the same boot.
- **Recovery exits** are explicit: an administrator acknowledges the alarm (journaled with identity), or `planariad` reaches ready and the boot report is clean, after which the posture's restrictions lift. F3 can only be cleared by an administrator, never automatically.

Gym cases: for each posture × class, inject the failure (mask the unit; kill it past its budget; corrupt the core hash; break the journal chain; plant an undeclared early unit) and score that exactly the declared responses occurred, that no agent principal ever started, and that the posture's recovery exit works.

### 12.5 Non-claims

- Planarian does not detect malicious packages that function correctly. Supply-chain trust is Nix's and nixpkgs' (signatures, review), plus the attested cache in §5 later.
- Planarian is not a boundary against root in Phases A–D and must not be described as one.
- Planarian does not provide confidentiality for user data; it governs system state, not files.

## 13. Open questions for the owner

- [x] **Accept all of §1.1–§1.11.** (Owner decision, Oct 28.)
- [x] §1.11: targets accepted — idle CPU < 0.5 % of one core, RSS < 50 MB excluding any model, no statistically significant frame-time or input-latency difference. Reference workload: one GPU-heavy game run under Proton; the orchestrating agent proposes the title and a scripted benchmark sequence for owner sign-off. (Owner decision, Oct 28.)
- [x] §12 T4: fixed typed probe kinds are the default; administrator-authored shell probes are allowed but flagged in the console and journaled as such. (Owner decision, Oct 28.)
- [x] §12 T8: hash-chained journal is a **Phase A requirement**. (Owner decision, Oct 28.)
- [x] §12.4: the **installer selects the posture**. It presents the four postures in plain language with a recommended default inferred from setup (Standard by default; Guarded recommended when an agent endpoint or broad agent capabilities are configured at install; Sealed recommended for server/fleet installs). The choice is written into the generation like any other declaration. (Owner decision, Oct 28.)
- [x] §12.4: the boot-ready timeout is **configurable**, default 60 s in every posture, bounded to 15–600 s. Shortening it is treated as raising the posture (Tested); lengthening it as lowering (AskFirst with administrator authority, effective next boot), since a longer timeout widens the window before F1 is declared. (Owner decision, Oct 28.)
- [x] Multi-user system-scope override rule (§2.5): AskFirst for non-admins when another uid's session is online. (Owner decision, Oct 27.)
- [x] Unattributed-stop residue on PlanarianOS (§2.4): **accepted until next boot, with a notice and an undo**. Strict mode (Guarded/Sealed postures) uses the ask-window. (Owner decision, Oct 28.)
- [x] Coverage threshold for the PlanarianOS gate (§6.3): **deferred** — set after the first catalog survey produces a baseline, not before. (Owner decision, Oct 28.)
- [x] User-scope app valve (§2.6, §4): **Flatpak first**; attested per-user Nix profiles may follow. (Owner decision, Oct 28.)
- [x] Membership consensus (§5): **both Raft and BFT supported** behind one membership interface; BFT is the intended default by the time fleet membership is implemented, with Raft available for small owned fleets that opt into crash-only fault tolerance. (Owner decision, Oct 28.)
- [x] `Diagnostic` edges learned via gossip are **never** admitted without a passing gym case. (Owner decision, Oct 28.)
- [x] §11, Phase B grants to non-human principals: **catalog and model-catalog authority only**; manifest and merge authority are not granted to non-human principals in Phase B. Merge authority, held by any principal, requires **two distinct approvers**. (Owner decision, Oct 28.)
- [x] §8b: Asterinas wish list is **prototyped first** as Planarian-side kernel patches in the overlay, benchmarked against an unpatched baseline, and proposed upstream as RFCs only with measurements showing no meaningful performance cost and no conflict with Asterinas's stated goals (Linux ABI compatibility, container/confidential-computing targets). (Owner decision, Oct 28.)
- [x] §11.3: Firecracker sandbox pass is **required** for Tested on the real path where KVM is available; where it is not, the daemon reports `sandbox: unavailable` and Tested changes are floored to AskFirst (degraded, not blocked). Firecracker gym target enters Phase A as non-gating alongside Asterinas. (Owner decision, Oct 27.)
