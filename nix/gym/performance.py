#!/usr/bin/env python3
"""Collect scoped performance evidence; never substitute proxies for measurements.

The VM benchmark is a headless interference check. Imported input-to-display
records describe external HID/optical measurements; this module cannot attest
that an instrument or its declared provenance is truthful.
"""

import argparse
import csv
import hashlib
import io
import json
import math
from pathlib import Path
import random
import re
import statistics
import subprocess
import time


CONDITIONS = ("stopped", "idle", "busy")
MB = 1_000_000  # Preserve the <50 MB target conservatively in decimal bytes.
# Proposed practical guards for the scoped headless experiment, not an
# assertion of statistical equivalence or owner adoption of a personal gate.
FRAME_MARGIN = {"absolute_ms": 0.5, "relative": 0.02}
INPUT_MARGINS_MS = {"p50_ms": 1.0, "p99_ms": 2.0}


class EvidenceError(ValueError):
    pass


def positive_number(value, label):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value <= 0:
        raise EvidenceError(f"{label}: expected finite positive number")
    return value


def integer(value, label):
    if isinstance(value, bool) or not isinstance(value, int):
        raise EvidenceError(f"{label}: expected integer")
    return value


def percentile(values, fraction):
    """Nearest-rank quantile of the complete sample set (no outlier removal)."""
    if not values or not 0 < fraction <= 1:
        raise EvidenceError("invalid percentile sample/fraction")
    values = sorted(positive_number(v, "sample") for v in values)
    return values[math.ceil(len(values) * fraction) - 1]


def latency_summary(values, stall_ms):
    return {
        "samples": len(values),
        "p50_ms": percentile(values, 0.50),
        "p99_ms": percentile(values, 0.99),
        "max_ms": max(values),
        "stall_threshold_ms": stall_ms,
        "stalls": sum(v >= stall_ms for v in values),
        "quantile": "nearest-rank; all samples retained",
    }


def mangohud_frames(text, *, log_interval_ms, minimum_samples=100):
    """MangoHud 0.8.3 per-frame CSV: frametime ms, elapsed nanoseconds.

    Version 0.8.3 logs per frame only when log_interval=0. Header/row/time
    errors invalidate the stream; aggregated engine FPS is never accepted.
    """
    if isinstance(log_interval_ms, bool) or log_interval_ms != 0:
        raise EvidenceError("periodic MangoHud samples are not a per-frame stream")
    rows = list(csv.reader(io.StringIO(text)))
    headers = [i for i, row in enumerate(rows) if "frametime" in row and "elapsed" in row]
    if len(headers) != 1:
        raise EvidenceError("expected exactly one MangoHud frame header")
    header = rows[headers[0]]
    if len(header) != len(set(header)):
        raise EvidenceError("duplicate MangoHud columns")
    frame_index, elapsed_index = header.index("frametime"), header.index("elapsed")
    times, elapsed_values, last_elapsed = [], [], -1
    for row in rows[headers[0] + 1:]:
        if not row or all(not field.strip() for field in row):
            continue
        if len(row) != len(header):
            raise EvidenceError("incomplete MangoHud frame row")
        try:
            frame_ms = float(row[frame_index])
            elapsed = int(row[elapsed_index])
        except ValueError as error:
            raise EvidenceError("malformed MangoHud frame row") from error
        positive_number(frame_ms, "frametime")
        if elapsed < 0 or elapsed <= last_elapsed:
            raise EvidenceError("MangoHud elapsed must strictly increase")
        times.append(frame_ms)
        elapsed_values.append(elapsed)
        last_elapsed = elapsed
    if len(times) < minimum_samples:
        raise EvidenceError(f"only {len(times)} actual frame samples, need {minimum_samples}")
    # The first sample's clock offset is arbitrary. Thereafter per-frame
    # durations must describe the elapsed span, allowing 50ms or 1% for
    # endpoint/logging overhead. Wrong units or periodic sparse samples fail.
    span_ns = elapsed_values[-1] - elapsed_values[0]
    frame_span_ns = sum(times[1:]) * 1_000_000
    tolerance_ns = max(50_000_000, frame_span_ns * 0.01)
    if abs(span_ns - frame_span_ns) > tolerance_ns:
        raise EvidenceError("elapsed units/span do not match a complete per-frame stream")
    return {
        **latency_summary(times, 50.0),
        "source": "MangoHud 0.8.3 per-frame CSV",
        "log_interval_ms": 0,
        "elapsed_unit": "nanoseconds",
        "raw_sha256": hashlib.sha256(text.encode()).hexdigest(),
        "sampled_elapsed_ns": last_elapsed,
        "elapsed_frame_consistency_tolerance_ns": tolerance_ns,
    }


def completed_game_frames(text, engine_log, *, exit_status, log_interval_ms):
    if exit_status != 0:
        raise EvidenceError("game command failed/timed out")
    completed = re.findall(r"(\d+) frames ([\d.]+) seconds ([\d.]+) fps, one-second fps min/avg/max:", engine_log)
    if len(completed) != 1:
        raise EvidenceError("missing/ambiguous completed Xonotic timedemo summary")
    count, seconds, _ = completed[0]
    count, seconds = int(count), positive_number(float(seconds), "engine duration")
    if count < 100:
        raise EvidenceError("completed timedemo has fewer than 100 frames")
    result = mangohud_frames(text, log_interval_ms=log_interval_ms)
    if result["samples"] < count:
        raise EvidenceError("frame stream does not cover the completed timedemo")
    return {**result, "engine_completed_frames": count, "engine_completed_seconds": seconds,
            "engine_summary_role": "workload completion only; FPS is not frame-time evidence"}


def paired_frame_guards(runs, repetitions=5):
    """A predeclared per-run guard, deliberately not a non-significance test."""
    if set(runs) != set(CONDITIONS) or any(len(runs[c]) != repetitions for c in CONDITIONS):
        raise EvidenceError("missing condition or independent repetition")
    results = {}
    for condition in ("idle", "busy"):
        comparisons = []
        for baseline, changed in zip(runs["stopped"], runs[condition], strict=True):
            delta = changed["p99_ms"] - baseline["p99_ms"]
            margin = max(FRAME_MARGIN["absolute_ms"], FRAME_MARGIN["relative"] * baseline["p99_ms"])
            comparisons.append({"delta_ms": delta, "margin_ms": margin, "within_guard": delta <= margin})
        results[condition] = {"pairs": comparisons, "within_guard": all(p["within_guard"] for p in comparisons)}
    return {"proposed_margin": FRAME_MARGIN, "conditions": results, "statistical_equivalence": "NOT_ESTABLISHED"}


def key_values(path):
    try:
        rows = [line.split() for line in path.read_text().splitlines()]
        fields = dict(rows)
        if len(rows) != len(fields):
            raise EvidenceError(f"duplicate cgroup counters: {path}")
        return {key: int(value) for key, value in fields.items()}
    except (OSError, ValueError) as error:
        raise EvidenceError(f"cannot read complete cgroup counters: {path}") from error


def cgroup_counters(path):
    """One hierarchical read per root: child/exited-helper CPU is included."""
    try:
        identity = path.stat()
        cpu = key_values(path / "cpu.stat")["usage_usec"]
        current = int((path / "memory.current").read_text())
        peak = int((path / "memory.peak").read_text())
        final_identity = path.stat()
    except (OSError, ValueError, KeyError) as error:
        raise EvidenceError(f"missing CPU/memory cgroup evidence: {path}") from error
    if min(cpu, current, peak) < 0 or peak < current:
        raise EvidenceError("invalid cgroup counter values")
    if (identity.st_dev, identity.st_ino) != (final_identity.st_dev, final_identity.st_ino):
        raise EvidenceError("cgroup replaced while reading counters")
    return {"identity": [identity.st_dev, identity.st_ino], "cpu_usec": cpu,
            "memory_current_bytes": current, "memory_lifetime_peak_bytes": peak}


def cpu_percent(before, after, elapsed_seconds):
    positive_number(elapsed_seconds, "measurement duration")
    if set(before) != set(after):
        raise EvidenceError("service set changed during measurement")
    usage = 0
    for unit in before:
        a, b = before[unit], after[unit]
        if a["identity"] != b["identity"] or b["cpu_usec"] < a["cpu_usec"]:
            raise EvidenceError(f"cgroup replaced/reset during measurement: {unit}")
        usage += b["cpu_usec"] - a["cpu_usec"]
    return usage / 1_000_000 / elapsed_seconds * 100


def cgroup_pids(paths):
    # cgroup.procs lists TGIDs, not threads. Descendants are traversed for RSS
    # only; summing hierarchical CPU/memory counters would double count them.
    pids = set()
    for root in paths:
        try:
            for procs in [root / "cgroup.procs", *root.rglob("cgroup.procs")]:
                try:
                    pids.update(int(pid) for pid in procs.read_text().split())
                except FileNotFoundError:
                    continue  # A short-lived descendant was reaped.
        except (OSError, ValueError) as error:
            raise EvidenceError(f"cannot enumerate service cgroup tasks: {root}") from error
    return pids


def resident_and_switches(pids, proc=Path("/proc")):
    rss, switches = 0, {}
    for pid in pids:
        directory = proc / str(pid)
        try:
            # Field 22 (index 19 after comm) distinguishes reused process IDs.
            start = int((directory / "stat").read_text().rsplit(")", 1)[1].split()[19])
            status = (directory / "status").read_text()
            match = re.search(r"^VmRSS:\s+(\d+) kB$", status, re.MULTILINE)
            if not match and not re.search(r"^(?:State:\s+Z|Kthread:\s+1)", status, re.MULTILINE):
                raise EvidenceError("missing resident-memory evidence for a live service process")
            rss += int(match.group(1)) * 1024 if match else 0
            for task in (directory / "task").iterdir():
                try:
                    counts = re.findall(r"^(?:non)?voluntary_ctxt_switches:\s+(\d+)$",
                                        (task / "status").read_text(), re.MULTILINE)
                    if len(counts) != 2:
                        raise EvidenceError("missing task context-switch counters")
                    switches[f"{pid}:{start}:{task.name}"] = sum(int(count) for count in counts)
                except FileNotFoundError:
                    continue
        except (FileNotFoundError, ProcessLookupError):
            continue
        except (OSError, ValueError, IndexError) as error:
            raise EvidenceError(f"cannot sample service process {pid}") from error
    return rss, switches


def service_paths(units, cgroup_root=Path("/sys/fs/cgroup")):
    paths = {}
    for unit in units:
        result = subprocess.run(["systemctl", "show", "--property=ControlGroup", "--value", unit],
                                check=True, capture_output=True, text=True, timeout=5)
        value = result.stdout.strip()
        if not value.startswith("/") or value == "/" or ".." in Path(value).parts:
            raise EvidenceError(f"inactive/invalid service cgroup: {unit}")
        path = cgroup_root / value.lstrip("/")
        if any(path == other or path in other.parents or other in path.parents for other in paths.values()):
            raise EvidenceError("overlapping service roots would double count")
        paths[unit] = path
    if not paths:
        raise EvidenceError("no service roots selected")
    return paths


def cgroup_window(units, duration, interval):
    positive_number(duration, "duration")
    positive_number(interval, "sample interval")
    paths = service_paths(units)
    start = time.monotonic()
    before = {unit: cgroup_counters(path) for unit, path in paths.items()}
    previous_counters = before
    charged_peak = sum(item["memory_lifetime_peak_bytes"] for item in before.values())
    rss_peak, last_switches = resident_and_switches(cgroup_pids(paths.values()))
    switch_delta, samples, seen_pids = 0, 1, set()
    deadline = start + duration
    while True:
        remaining = deadline - time.monotonic()
        if remaining > 0:
            time.sleep(min(interval, remaining))
        after = {unit: cgroup_counters(path) for unit, path in paths.items()}
        # Detect resets in every sample, not only at the endpoints.
        cpu_percent(previous_counters, after, max(time.monotonic() - start, 1e-9))
        previous_counters = after
        charged_peak = max(charged_peak, sum(item["memory_lifetime_peak_bytes"] for item in after.values()))
        pids = cgroup_pids(paths.values())
        seen_pids.update(pids)
        rss, switches = resident_and_switches(pids)
        rss_peak = max(rss_peak, rss)
        switch_delta += sum(max(0, count - last_switches.get(key, count)) for key, count in switches.items())
        last_switches = switches
        samples += 1
        if time.monotonic() >= deadline:
            break
    elapsed = time.monotonic() - start
    return {
        "format": 1, "scope": "complete selected service cgroups including descendants and exited-helper CPU",
        "units": units, "cgroups": {unit: str(path) for unit, path in paths.items()},
        "cpu_percent_of_one_core": cpu_percent(before, after, elapsed),
        "cpu_source": "hierarchical cpu.stat usage_usec; no child counter summation",
        "resident_sampled_peak_mb": rss_peak / MB,
        "resident_semantics": "sum of unique live TGID VmRSS; shared mappings may be counted more than once",
        "charged_lifetime_peak_upper_bound_mb": charged_peak / MB,
        "charged_memory_semantics": "sum of cgroup memory.peak; includes cache/kernel/startup and is not labeled RSS",
        "sampled_live_task_context_switches_per_second": switch_delta / elapsed,
        "wakeups": {"status": "NOT_MEASURED", "reason": "sampled context switches are not scheduler wakeups; exited tasks may be missed"},
        "duration_seconds": elapsed, "requested_duration_seconds": duration,
        "sample_interval_seconds": interval, "samples": samples, "processes_seen": sorted(seen_pids),
        "before": before, "after": after,
        "targets": {"cpu_percent_of_one_core": 0.5, "resident_mb": 50},
        "memory_budget_guard": "both sampled RSS and conservative lifetime charged peak < 50000000 bytes (50 decimal MB)",
    }


def checked_hash_file(base, reference, label):
    if not isinstance(reference, dict) or set(reference) != {"path", "sha256"}:
        raise EvidenceError(f"{label}: missing raw file reference")
    filename, expected = reference["path"], reference["sha256"]
    if not isinstance(filename, str) or not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{64}", expected):
        raise EvidenceError(f"{label}: invalid path/hash")
    path = (base / filename).resolve()
    if not path.is_relative_to(base.resolve()) or path == base.resolve():
        raise EvidenceError(f"{label}: capture must be inside the evidence directory")
    try:
        digest = hashlib.sha256()
        with path.open("rb") as source:
            size = 0
            while chunk := source.read(1024 * 1024):
                size += len(chunk)
                digest.update(chunk)
        if size == 0:
            raise EvidenceError(f"{label}: empty capture")
        actual = digest.hexdigest()
    except OSError as error:
        raise EvidenceError(f"{label}: missing capture") from error
    if actual != expected:
        raise EvidenceError(f"{label}: capture hash mismatch")
    return actual


def external_input_evidence(path):
    """Summarize calibrated external HID/optical input-to-display trials.

    This validates declared evidence shape and hashes; imported captures still
    need reviewed provenance, workload/plan approval and hardware acceptance.
    Application delivery/presentation timestamps are deliberately unsupported.
    """
    raw_document = path.read_bytes()
    document = json.loads(raw_document)
    if not isinstance(document, dict):
        raise EvidenceError("input evidence must be an object")
    if integer(document.get("format"), "input format") != 1 or document.get("method") != "external_hid_optical":
        raise EvidenceError("input latency requires format 1 external HID/optical measurements")
    for key in ("source_revision", "plan_review", "workload", "input_trigger", "display_threshold",
                "instrument", "input_device", "display", "gpu", "driver", "compositor", "proton"):
        value = document.get(key)
        if not isinstance(value, str) or not value.strip():
            raise EvidenceError(f"missing hardware/workload provenance: {key}")
    if not re.fullmatch(r"[0-9a-f]{40}", document["source_revision"]) or not document["plan_review"].startswith("https://"):
        raise EvidenceError("invalid immutable revision or reviewed plan reference")
    if document.get("clock") != "single_external_acquisition_clock":
        raise EvidenceError("input and optical edges require one calibrated external clock")
    if not isinstance(document.get("vrr"), bool):
        raise EvidenceError("display VRR setting must be declared")
    positive_number(document.get("refresh_hz"), "refresh_hz")
    positive_number(document.get("sample_rate_hz"), "sample_rate_hz")
    checked_hash_file(path.parent, document.get("plan"), "reviewed plan")
    for phase in ("calibration_before", "calibration_after"):
        calibration = document.get(phase, {})
        if not isinstance(calibration, dict):
            raise EvidenceError("calibration evidence must be an object")
        error = calibration.get("maximum_error_ns")
        positive_number(error, f"{phase} uncertainty")
        if error > 500_000:
            raise EvidenceError("calibration uncertainty exceeds proposed 0.5 ms bound")
        checked_hash_file(path.parent, calibration.get("capture"), phase)
    repetitions = integer(document.get("repetitions"), "repetitions")
    if repetitions < 20:
        raise EvidenceError("reference plan requires at least 20 independent repetitions")
    integer(document.get("order_seed"), "order_seed")
    if document.get("order") != "randomized_interleaved":
        raise EvidenceError("measurement order and reproducible randomization seed are required")
    if positive_number(document.get("warmup_seconds"), "warmup_seconds") < 300:
        raise EvidenceError("reference plan requires at least 300 seconds of warmup")
    expected = {(condition, repetition) for condition in CONDITIONS for repetition in range(repetitions)}
    seen, sequence, summaries, trial_ids, previous_edge = set(), [], {}, set(), -1
    runs = document.get("runs")
    if not isinstance(runs, list):
        raise EvidenceError("input runs must be an array")
    for run in runs:
        if not isinstance(run, dict) or not isinstance(run.get("condition"), str):
            raise EvidenceError("input runs must have a named condition")
        integer(run.get("repetition"), "run repetition")
        if any(run.get(field) != document[field] for field in ("source_revision", "workload", "clock")):
            raise EvidenceError("mixed revision/workload/clock in input runs")
        key = (run.get("condition"), run.get("repetition"))
        if key not in expected or key in seen:
            raise EvidenceError("unknown/duplicate condition/repetition")
        seen.add(key)
        sequence.append(key)
        checked_hash_file(path.parent, run.get("capture"), "raw input/optical capture")
        trials = run.get("trials")
        if not isinstance(trials, list):
            raise EvidenceError("input trials must be an array")
        attempted = integer(run.get("attempted_trials"), "attempted_trials")
        if attempted != len(trials) or len(trials) < 100:
            raise EvidenceError("every attempted input trial must have a paired optical result (>=100)")
        latencies = []
        for trial in trials:
            if not isinstance(trial, dict):
                raise EvidenceError("input trial must be an object")
            trial_id = trial.get("id")
            start, end = trial.get("input_edge_ns"), trial.get("photon_edge_ns")
            if not isinstance(trial_id, str) or not trial_id or trial_id in trial_ids:
                raise EvidenceError("missing/duplicate input trial id")
            if any(not isinstance(value, int) or isinstance(value, bool) for value in (start, end)):
                raise EvidenceError("edge timestamps must be integer nanoseconds")
            if start <= previous_edge or start < 0 or end <= start or end - start > 10_000_000_000:
                raise EvidenceError("invalid, unordered or unpaired input/display edges")
            trial_ids.add(trial_id)
            previous_edge = end
            latencies.append((end - start) / 1_000_000)
        summaries[key] = latency_summary(latencies, 50.0)
    if seen != expected:
        raise EvidenceError("incomplete input condition/repetition set")
    order = []
    rng = random.Random(document["order_seed"])
    for repetition in range(repetitions):
        conditions = list(CONDITIONS)
        rng.shuffle(conditions)
        order.extend((condition, repetition) for condition in conditions)
    if sequence != order:
        raise EvidenceError("run order does not match predeclared interleaved randomization")
    comparisons = {}
    for condition in ("idle", "busy"):
        comparisons[condition] = {}
        for metric, margin in INPUT_MARGINS_MS.items():
            deltas = [summaries[(condition, r)][metric] - summaries[("stopped", r)][metric] for r in range(repetitions)]
            rng = random.Random(0)
            bootstrap = sorted(statistics.mean(rng.choices(deltas, k=len(deltas))) for _ in range(10_000))
            upper = bootstrap[math.ceil(0.99 * len(bootstrap)) - 1]
            comparisons[condition][metric] = {"paired_mean_delta_ms": statistics.mean(deltas),
                                              "bootstrap_upper_99_ms": upper, "proposed_margin_ms": margin,
                                              "within_proposed_margin": upper <= margin}
    return {
        "format": 1, "scope": "imported reference-hardware external input-to-display evidence",
        "source_revision": document["source_revision"], "plan_review": document["plan_review"],
        "provenance": {key: value for key, value in document.items() if key != "runs"},
        "input_record_sha256": hashlib.sha256(raw_document).hexdigest(),
        "run_captures": [{"condition": run["condition"], "repetition": run["repetition"],
                          "capture": run["capture"]} for run in runs],
        "runs": [{"condition": c, "repetition": r, **summaries[(c, r)]} for c, r in sequence],
        "comparisons": comparisons,
        "statistical_method": "paired percentile bootstrap mean delta; one-sided 99% upper bound; 10000 resamples; seed 0",
        "acceptance_complete": False,
        "limitation": "Importer validates declared provenance/shape and raw hashes; it does not attest physical hardware, plan adoption or the full personal profile",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    cgroups = commands.add_parser("cgroup-window")
    cgroups.add_argument("--unit", action="append", required=True)
    cgroups.add_argument("--duration", type=float, default=300)
    cgroups.add_argument("--interval", type=float, default=1)
    inputs = commands.add_parser("input-summary")
    inputs.add_argument("path", type=Path)
    args = parser.parse_args()
    try:
        result = cgroup_window(args.unit, args.duration, args.interval) if args.command == "cgroup-window" else external_input_evidence(args.path)
    except (EvidenceError, OSError, ValueError, subprocess.SubprocessError) as error:
        parser.exit(1, f"performance evidence rejected: {error}\n")
    print(json.dumps(result, indent=2, allow_nan=False))


if __name__ == "__main__":
    main()
