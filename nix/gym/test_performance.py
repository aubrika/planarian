#!/usr/bin/env python3
"""Contract regressions for R13 measurement integrity; no hardware PASS claims."""

import copy
import hashlib
import json
import os
from pathlib import Path
import random
import re
import tempfile
import textwrap
import unittest
from unittest.mock import patch

import performance


def frames(values):
    rows = ["os,cpu,gpu,ram,kernel,driver", "fixture,fixture,fixture,1,fixture,fixture", "fps,frametime,elapsed"]
    elapsed = 0
    for value in values:
        elapsed += round(value * 1_000_000)
        rows.append(f"{1000 / value},{value},{elapsed}")
    return "\n".join(rows) + "\n"


def legacy_functions():
    """Optional actual old benchmark adapter for the before/after experiment."""
    filename = os.environ.get("PLANARIAN_PERFORMANCE_BASELINE")
    if not filename:
        return None
    source = Path(filename).read_text()
    code = textwrap.dedent(source.split("  testScript = ''\n", 1)[1].rsplit("  '';", 1)[0])
    namespace = {"re": re, "json": json}
    start, end = code.index("def sample(pid):"), code.index('with subtest("idle")')
    exec(code[start:end], namespace)
    start, end = code.index("def run(cond, i, limit=900):"), code.index("def mann_whitney_p")
    exec(code[start:end], namespace)
    return namespace


def fixture_input(directory):
    capture = directory / "capture.bin"
    capture.write_bytes(b"synthetic optical/HID accounting fixture; not measured hardware")
    reference = {"path": capture.name, "sha256": hashlib.sha256(capture.read_bytes()).hexdigest()}
    document = {
        "format": 1, "method": "external_hid_optical", "source_revision": "a" * 40,
        "plan_review": "https://example.invalid/review/fixture", "plan": reference,
        "workload": "synthetic importer control; not a game benchmark",
        "input_trigger": "electrical HID button edge", "display_threshold": "photodiode ROI crosses 50% luminance",
        "instrument": "synthetic", "input_device": "synthetic", "display": "synthetic",
        "gpu": "synthetic", "driver": "synthetic", "compositor": "synthetic", "proton": "synthetic",
        "clock": "single_external_acquisition_clock", "vrr": False, "refresh_hz": 120,
        "sample_rate_hz": 100_000, "order": "randomized_interleaved", "order_seed": 317,
        "repetitions": 20, "warmup_seconds": 300, "runs": [],
        "calibration_before": {"maximum_error_ns": 1000, "capture": reference},
        "calibration_after": {"maximum_error_ns": 1000, "capture": reference},
    }
    rng = random.Random(document["order_seed"])
    clock = 1
    for repetition in range(document["repetitions"]):
        conditions = list(performance.CONDITIONS)
        rng.shuffle(conditions)
        for condition in conditions:
            trials = []
            for trial in range(100):
                trials.append({"id": f"{condition}-{repetition}-{trial}", "input_edge_ns": clock,
                               "photon_edge_ns": clock + 20_000_000})
                clock += 1_000_000_000
            document["runs"].append({"condition": condition, "repetition": repetition,
                                     "source_revision": document["source_revision"], "workload": document["workload"],
                                     "clock": document["clock"], "capture": reference,
                                     "attempted_trials": 100, "trials": trials})
    return document


class PerformanceContract(unittest.TestCase):
    def test_complete_service_cpu_includes_an_exited_helper(self):
        old = legacy_functions()
        if old:
            class LegacyMachine:
                def succeed(self, command):
                    if command.endswith("/stat"):
                        # The sleeping MainPID used no CPU. Its helper spent
                        # two seconds of CPU before exiting inside the window.
                        return "1 (sleep) " + " ".join(["0"] * 30)
                    if command.endswith("/status"):
                        return "VmRSS: 1 kB\n"
                    return "0\n0\n"
            old["machine"] = LegacyMachine()
            before, after = old["sample"](1), old["sample"](1)
            actual = (after[0] - before[0]) / 100 / 10 * 100
        else:
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                (root / "memory.current").write_text("1024")
                (root / "memory.peak").write_text("4096")
                (root / "cgroup.procs").write_text("1\n")
                (root / "cpu.stat").write_text("usage_usec 100000\nuser_usec 100000\nsystem_usec 0\n")
                before = {"service": performance.cgroup_counters(root)}
                # Child is gone from cgroup.procs; root accounting retains its
                # CPU and includes descendant cgroups without a second sum.
                child = root / "departed-child"
                child.mkdir()
                (child / "cpu.stat").write_text("usage_usec 2000000\n")
                (root / "cpu.stat").write_text("usage_usec 2100000\nuser_usec 2100000\nsystem_usec 0\n")
                after = {"service": performance.cgroup_counters(root)}
                actual = performance.cpu_percent(before, after, 10)
        self.assertEqual(actual, 20.0, "the service's exited helper CPU must remain measured")

    def test_no_real_frame_stream_cannot_claim_p99(self):
        old = legacy_functions()
        if old:
            class LegacyMachine:
                def succeed(self, command):
                    return ""  # No MangoHud CSV exists.

                def execute(self, command):
                    return 0, "1000 frames 10 seconds 100 fps, one-second fps min/avg/max: 20 100 120"
            old.update({"machine": LegacyMachine(), "demo": "demos/fixture.dem", "game": "/fixture/game"})
            result = old["run"]("probe", 0)
            self.assertIsNone(result["p99_ms"], "an engine's one-second min FPS is not a frame sample")
        else:
            with self.assertRaises(performance.EvidenceError):
                performance.mangohud_frames("1000 frames 10 seconds 100 fps", log_interval_ms=0)

    def test_true_tail_and_isolated_long_frames_are_visible(self):
        # More than one percent isolated stalls must change p99.
        result = performance.mangohud_frames(frames([10.0, 200.0] * 20 + [10.0] * 960), log_interval_ms=0)
        self.assertEqual(result["p99_ms"], 200.0)
        self.assertEqual(result["stalls"], 20)
        # One isolated frame need not alter nearest-rank p99. It must remain
        # visible in the max and stall count, rather than being averaged away.
        result = performance.mangohud_frames(frames([10.0] * 999 + [200.0]), log_interval_ms=0)
        self.assertEqual(result["p99_ms"], 10.0)
        self.assertEqual((result["max_ms"], result["stalls"]), (200.0, 1))

    def test_frame_stream_rejects_periodic_missing_duplicate_and_bad_values(self):
        invalid = [
            (frames([10] * 100), 100),
            (frames([10] * 99), 0),
            (frames([10] * 100) + frames([10] * 100), 0),
            (frames([10] * 100) + "60,nan,2000000000\n", 0),
            (frames([10] * 100) + "60,10\n", 0),
            (frames([10] * 100) + "60,10,1\n", 0),
            (frames([10] * 100) + "60,-1,2000000000\n", 0),
            (frames([10] * 100).replace("1000000000", "1000000"), 0),
            ("fps,frametime,elapsed\n" + "\n".join(f"100,10,{i * 100_000_000}" for i in range(100)), 0),
        ]
        for text, interval in invalid:
            with self.subTest(interval=interval, tail=text[-40:]), self.assertRaises(performance.EvidenceError):
                performance.mangohud_frames(text, log_interval_ms=interval)

    def test_complete_workload_is_required_in_addition_to_real_frames(self):
        summary = "100 frames 1 seconds 100 fps, one-second fps min/avg/max: 100 100 100"
        actual = performance.completed_game_frames(frames([10] * 100), summary, exit_status=0, log_interval_ms=0)
        self.assertEqual(actual["engine_completed_frames"], 100)
        for log, status in (("", 0), (summary, 124), (summary + summary, 0), (summary.replace("100 frames", "1000 frames"), 0)):
            with self.subTest(log=log, status=status), self.assertRaises(performance.EvidenceError):
                performance.completed_game_frames(frames([10] * 100), log, exit_status=status, log_interval_ms=0)

    def test_counter_reset_missing_memory_and_overlapping_roots_do_not_read_as_zero(self):
        before = {"service": {"identity": [1, 2], "cpu_usec": 100}}
        for after in ({"service": {"identity": [1, 3], "cpu_usec": 200}},
                      {"service": {"identity": [1, 2], "cpu_usec": 99}}, {}):
            with self.subTest(after=after), self.assertRaises(performance.EvidenceError):
                performance.cpu_percent(before, after, 10)
        with tempfile.TemporaryDirectory() as temporary, self.assertRaises(performance.EvidenceError):
            performance.cgroup_counters(Path(temporary))
        class Result:
            stdout = "/system.slice/fixture.service\n"
        with patch("performance.subprocess.run", return_value=Result()), self.assertRaises(performance.EvidenceError):
            performance.service_paths(["a", "b"])

    def test_resident_enumeration_deduplicates_tgids_and_includes_descendants(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "cgroup.procs").write_text("1\n2\n")
            (root / "nested").mkdir()
            (root / "nested/cgroup.procs").write_text("2\n3\n")
            self.assertEqual(performance.cgroup_pids([root]), {1, 2, 3})

    def test_guard_detects_practically_large_delta_without_p_value_claim(self):
        good = {condition: [{"p99_ms": 10.0}] * 5 for condition in performance.CONDITIONS}
        result = performance.paired_frame_guards(good)
        self.assertEqual(result["statistical_equivalence"], "NOT_ESTABLISHED")
        good["busy"] = [{"p99_ms": 13.0}] * 5
        self.assertFalse(performance.paired_frame_guards(good)["conditions"]["busy"]["within_guard"])

    def test_external_input_control_remains_imported_evidence_not_hardware_certification(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            document = fixture_input(directory)
            path = directory / "input.json"
            path.write_text(json.dumps(document))
            result = performance.external_input_evidence(path)
            self.assertFalse(result["acceptance_complete"])
            self.assertEqual(len(result["runs"]), 60)
            self.assertEqual(result["comparisons"]["busy"]["p99_ms"]["paired_mean_delta_ms"], 0)
            self.assertEqual(result["provenance"]["instrument"], "synthetic")
            self.assertEqual(result["input_record_sha256"], hashlib.sha256(path.read_bytes()).hexdigest())

    def test_input_app_timestamps_incomplete_sets_unbound_captures_and_mixed_runs_reject(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            original = fixture_input(directory)
            path = directory / "input.json"
            changes = {
                "application timestamps": lambda d: d.update(method="application_event_to_present"),
                "mixed clocks": lambda d: d["runs"][0].update(clock="another_clock"),
                "mixed revision": lambda d: d["runs"][0].update(source_revision="b" * 40),
                "mixed workload": lambda d: d["runs"][0].update(workload="a different game"),
                "missing run": lambda d: d["runs"].pop(),
                "duplicate run": lambda d: d["runs"].append(copy.deepcopy(d["runs"][0])),
                "missing trial": lambda d: d["runs"][0]["trials"].pop(),
                "duplicate trial": lambda d: d["runs"][0]["trials"][1].update(id=d["runs"][0]["trials"][0]["id"]),
                "unpaired optical": lambda d: d["runs"][0]["trials"][0].pop("photon_edge_ns"),
                "calibration uncertainty": lambda d: d["calibration_after"].update(maximum_error_ns=1_000_000),
                "wrong capture hash": lambda d: d["runs"][0]["capture"].update(sha256="0" * 64),
                "no review": lambda d: d.pop("plan_review"),
                "incomplete randomization": lambda d: d["runs"].reverse(),
                "boolean format": lambda d: d.update(format=True),
                "boolean seed": lambda d: d.update(order_seed=True),
                "boolean repetition": lambda d: d["runs"][0].update(repetition=False),
                "noninteger attempts": lambda d: d["runs"][0].update(attempted_trials=100.0),
                "wrong run container": lambda d: d.update(runs=None),
                "wrong trial container": lambda d: d["runs"][0].update(trials=None),
                "wrong calibration container": lambda d: d.update(calibration_before=[]),
                "overlapping run timestamps": lambda d: d["runs"][1]["trials"][0].update(input_edge_ns=1, photon_edge_ns=20_000_001),
            }
            for name, change in changes.items():
                with self.subTest(case=name):
                    document = copy.deepcopy(original)
                    change(document)
                    path.write_text(json.dumps(document))
                    with self.assertRaises(performance.EvidenceError):
                        performance.external_input_evidence(path)


if __name__ == "__main__":
    unittest.main()
