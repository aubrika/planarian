# Proposed performance experiment (R13)

This is a measurement plan for owner review, not completed hardware evidence or
an adopted change to SPEC §21. The idle targets remain CPU <0.5% of one core and
resident memory <50 MB (50,000,000 bytes), excluding a model. Historical MainPID measurements and
one-second minimum-FPS proxies do not establish this candidate's whole-cgroup,
per-frame, or personal-profile results.

## Headless scope

`nix build -L .#legacyPackages.x86_64-linux.bench.invisibility` measures the
complete persistent `planarian-monitor.slice`, including daemon, independent
watchdog, posture services and their descendants. Both owned transient launch
paths (`probe::sandbox_argv` and `Nixos::activate_live_inner`) explicitly select
that same slice, so Exec probes and activation services do not escape accounting
when systemd launches them outside the daemon's own service cgroup. Ordinary
fork/exec children inherit their parent's cgroup. Agents stay in the sibling
`planarian-agents.slice` and cannot consume the monitor's measured budget.
The slice carries no new resource restriction or authority; failure posture
remains enforced by systemd outside the failed daemon.

The headless scope excludes desktop/console/tray processes, any model,
interactive client/acknowledgment processes and indirect work in shared
`nix-daemon`/systemd-manager or application cgroups. It does not claim to attribute
all machine work caused by a requested action. Those indirect effects still
affect the frame-interference comparison and require the broader personal
experiment. It reads hierarchical `cpu.stat usage_usec` once at the slice root,
so exited helpers remain counted and descendant counters are not counted twice.
Replaced cgroups, missing counters, and counter resets invalidate the run.

After 120 seconds of settling, it samples for 300 seconds at one-second
intervals. It records all unique TGIDs' sampled RSS, and separately reports a
conservative sum of cgroup lifetime `memory.peak` charges (including cache,
kernel memory and startup). Both sampled RSS and this stronger charged-memory
bound must be below 50,000,000 bytes for the headless guard to pass. The latter is not
relabeled RSS; a failure needs investigation rather than silently substituting
the old MainPID metric. RSS samples alone can miss between-sample peaks.

Sampled live-task context switches are reported with their limitations. They
are not scheduler wakeups and omit threads exiting between samples. Actual
wakeup tracing remains outstanding; it needs a declared system-wide/cgroup
tracepoint experiment with instrument overhead measured in the stopped control.

The VM also runs an actual short-lived CPU helper whose MainPID waits, then
checks that service-cgroup CPU retains the helper's work after exit. This is an
authored VM control, not an executed result in this workspace.

The frame experiment runs Xonotic's installed keybench demo (or records its
explicit fallback demo), llvmpipe, 320x240, `effects-low.cfg`, no sound, five
interleaved repetitions each of stopped/idle/busy. Busy crashes the watched
fixture every 30 seconds. All rendered frames of the identical game process,
including initialization, are in this scoped stream. The output records
guest-visible hardware, kernel/tools, unit and merged canonical/user probe
counts, workload settings, each run and its raw CSV hash; `raw.tar.gz` retains
the raw logs.

MangoHud 0.8.3 `log_interval=0` records each frame; `frametime` is milliseconds
and `elapsed` is nanoseconds. The parser requires a complete, monotonic stream
with at least 100 samples and elapsed-span/frame-duration consistency within
`max(50 ms, 1%)` for endpoint/logging overhead. The timedemo completion summary
must exist and the stream must cover at least its completed frame count; engine
FPS is used only as a workload-completion marker. Missing, periodic, malformed
or truncated data fails the measurement. No minimum-FPS or engine-average
fallback exists. Nearest-rank
p99, p50, maximum and >=50 ms stall counts retain all samples. A single isolated
long frame may properly leave p99 unchanged but remains visible in max/stalls.

The proposed headless practical guard is a per-pair p99 increase no greater
than `max(0.5 ms, 2% of stopped p99)` in each of five matched repetitions. This
is an interference smoke guard, not a statistical-equivalence claim. The report
always says `statistical_equivalence: NOT_ESTABLISHED` and
`personal_profile_acceptance: NOT_RUN`. A headless pass cannot become a PASS for
the full `quiet-reference-workload` catalog contract.

## Reference personal-profile plan for review

Proposed workload: the Windows version of **Shadow of the Tomb Raider**, using
**Proton 9.0-4**, its built-in benchmark, High preset, 1920x1080, fullscreen,
uncapped frame rate, VSync and VRR disabled. The exact game depot/build hashes,
Proton closure/hash, launch/menu sequence and reference machine must be recorded
and reviewed before measurement. Availability, the title and machine selection
remain owner decisions; this plan acquires no software or changes accounts.
Use the installed personal profile and real GPU/compositor, including its
console/tray. Record machine/firmware, CPU/GPU, RAM, kernel, driver, compositor,
display/input devices, refresh rate, thermal/power mode, active unit/probe
counts, background workload and every instrument/tool version.

Run at least 20 independent repetitions per stopped/idle/busy condition after
five minutes of warmup, interleaving conditions in a predeclared seeded random
order. Capture real per-frame samples for the scripted benchmark, with fixed
capture boundaries and no outlier removal. Predeclare a one-sided 99% confidence
analysis of paired mean changes across independent repetition summaries; do not
treat a nonsignificant difference as equivalence. Proposed practical margins:
p99 frame time +`max(0.5 ms, 2%)`, input-to-display median +1 ms and p99 +2 ms.
These margins and the analysis need review before data collection.

Input-to-display must use a single calibrated external acquisition clock:
electrical HID actuation to an optical display response, not application event,
queue, presentation or compositor timestamps. Proposed capture is a programmable
HID mouse moving a fixed high-contrast scene edge across a photodiode region,
with a declared luminance threshold, reverse motion/reset and randomized
inter-trial intervals. Validate the scene/reset, threshold and response before
the experiment. Take at least 100 paired trials per condition/repetition.
Preserve every attempted trial, including failures/timeouts, which invalidate a
complete-paired claim instead of being dropped. Calibrate before and after;
require maximum timing uncertainty <=0.5 ms and record raw acquisition files.

`python3 nix/gym/performance.py input-summary input.json` validates an imported
format-1 `external_hid_optical` record and computes p50/p99/max/stalls plus a
reproducible 10,000-resample paired bootstrap 99% upper bound. The document
requires one source revision/workload/clock across all runs, exact complete
condition/repetition/trial sets, reviewed-plan identity, calibration/capture
SHA256 references, hardware settings and the seeded interleaved order. The
code's input schema and `fixture_input` in `test_performance.py` give a complete
synthetic shape; those fixtures are accounting controls and are never hardware
measurements. The importer always leaves `acceptance_complete` false: raw-file
hashes and declared provenance do not attest physical instruments, truthful
capture or owner adoption of a plan. Hardware/provenance review and all other
personal-profile gates remain required.

## Available evidence and remaining acceptance

Local Python regressions exercise missing/proxy frame streams, isolated long
frames, exited-helper cgroup accounting, missing/reset counters, incomplete or
mixed input trials/captures and practical guards. Two tests also invoke the
actual old benchmark functions on controlled fixtures: the old MainPID sampler
misses helper CPU and the old fallback invents p99 from one-second minimum FPS.
That is before/after measurement-code evidence, not a VM or hardware run.

No current-candidate Nix benchmark, cgroup VM control, actual wakeup trace,
reference-game experiment or optical input capture has run here. Full
personal-profile performance acceptance remains open.

Source contract references: pinned [MangoHud package](https://github.com/NixOS/nixpkgs/blob/1f607aa79b6356ed45d3cd3c8079c196e79efa2c/pkgs/by-name/ma/mangohud/package.nix),
[per-frame update](https://github.com/flightlessmango/MangoHud/blob/v0.8.3/src/overlay.cpp#L302),
and [CSV logging](https://github.com/flightlessmango/MangoHud/blob/v0.8.3/src/logging.cpp#L200).
