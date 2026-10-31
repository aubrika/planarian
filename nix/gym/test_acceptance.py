#!/usr/bin/env python3
"""Contract regressions for build errors, coverage, roles and waivers."""
import datetime
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
RUNNER = Path(os.environ.get("PLANARIAN_VM_RUNNER", HERE / "run-vm.sh"))
spec = importlib.util.spec_from_file_location("acceptance", HERE / "acceptance.py")
acceptance = importlib.util.module_from_spec(spec)
spec.loader.exec_module(acceptance)

CATALOG = '''[[fault]]
id = "required"
scoring = "must-pass"
harness = ["fake", "vm"]
[[fault]]
id = "intent"
scoring = "intent"
harness = ["vm"]
'''


class AcceptanceContract(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.catalog = self.root / "catalog.toml"
        self.catalog.write_text(CATALOG)
        self.entries = acceptance.catalog_entries(self.catalog)
        self.expected = acceptance.expected_entries(self.entries, "vm", [])
        self.waivers = self.root / "waivers.toml"
        self.waivers.write_text("format_version = 1\n")

    def verdict(self, name, fault_id="required", result="PASS"):
        path = self.root / name
        path.write_text(json.dumps({"id": fault_id, "result": result}))
        return path

    def check(self, paths, waivers=None):
        return acceptance.validate(self.entries, self.expected, "vm", paths, waivers or {})

    def test_complete_pass_is_the_control(self):
        report = self.check([self.verdict("a"), self.verdict("b", "intent")])
        self.assertTrue(report["acceptance_complete"])
        self.assertTrue(report["full_harness_acceptance_complete"])
        self.assertEqual([r["role"] for r in report["cases"]], ["must-pass", "intent"])
        selected = acceptance.expected_entries(self.entries, "vm", ["required"])
        partial = acceptance.validate(self.entries, selected, "vm", [self.verdict("a")], {})
        self.assertTrue(partial["acceptance_complete"])
        self.assertFalse(partial["full_harness_acceptance_complete"])
        self.assertEqual(partial["scope"], "selected-cases")

    def test_cli_accepts_verdict_paths_after_and_between_options(self):
        a, b = self.verdict("a"), self.verdict("b", "intent")
        options = ["--catalog", str(self.catalog), "--harness", "vm", "--waivers", str(self.waivers)]
        layouts = [
            ["check", *options, str(a), str(b)],
            ["check", str(a), *options, str(b)],
            [*options, "check", str(a), str(b)],
        ]
        for arguments in layouts:
            with self.subTest(arguments=arguments):
                run = subprocess.run([sys.executable, str(HERE / "acceptance.py"), *arguments],
                                     capture_output=True, text=True, timeout=10)
                self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
                self.assertEqual(run.stdout.count("PASS"), 2)

    def test_required_pass_cannot_become_unsupported_or_vanish(self):
        other = self.verdict("intent", "intent")
        for result in ("FAIL", "PARTIAL", "ERROR", "UNSUPPORTED", "unrecognized"):
            with self.subTest(result=result):
                self.assertFalse(self.check([self.verdict("a", result=result), other])["acceptance_complete"])
        self.assertFalse(self.check([other])["acceptance_complete"])
        self.assertFalse(self.check([])["acceptance_complete"])

    def test_duplicate_unknown_and_malformed_verdicts_fail(self):
        a, b = self.verdict("a"), self.verdict("b", "intent")
        for paths in ([a, b, a], [a, b, self.verdict("extra", "not-in-catalog")], [a, self.root / "missing"]):
            self.assertFalse(self.check(paths)["acceptance_complete"])
        b.write_text("{")
        self.assertFalse(self.check([a, b])["acceptance_complete"])

    def test_selection_and_catalog_ids_are_exact(self):
        for selected in (["required", "required"], ["required", "missing"]):
            with self.assertRaises(ValueError):
                acceptance.expected_entries(self.entries, "vm", selected)
        with self.assertRaises(ValueError):
            acceptance.expected_entries(self.entries, "fake", ["intent"])
        self.catalog.write_text(CATALOG + CATALOG)
        with self.assertRaises(ValueError):
            acceptance.catalog_entries(self.catalog)

    def test_waiver_is_reviewed_role_qualified_expiring_and_only_for_unsupported(self):
        waiver = '''format_version = 1
[[waiver]]
id = "required"
harness = "vm"
role = "must-pass"
result = "UNSUPPORTED"
reason = "Installed-entry boot target tracked separately"
reviewed_by = "owner"
review_url = "https://github.com/aubrika/planarian/pull/1#pullrequestreview-2"
expires = "2099-01-01"
'''
        self.waivers.write_text(waiver)
        waivers = acceptance.reviewed_waivers(self.waivers, self.entries)
        other = self.verdict("b", "intent")
        self.assertTrue(self.check([self.verdict("a", result="UNSUPPORTED"), other], waivers)["acceptance_complete"])
        for result in ("FAIL", "PARTIAL", "ERROR"):
            self.assertFalse(self.check([self.verdict("a", result=result), other], waivers)["acceptance_complete"])
        for bad in (waiver.replace('role = "must-pass"', 'role = "intent"'), waiver.replace('expires = "2099-01-01"', 'expires = "2000-01-01"'), waiver.replace('reviewed_by = "owner"', 'reviewed_by = ""'), waiver.replace('result = "UNSUPPORTED"', 'result = "FAIL"')):
            self.waivers.write_text(bad)
            with self.assertRaises(ValueError):
                acceptance.reviewed_waivers(self.waivers, self.entries)

    def run_vm_stub(self, mode):
        binary = self.root / "nix"
        binary.write_text('''#!/usr/bin/env bash
if [ "$STUB_MODE" = eval-error ]; then exit 7; fi
if [ "$1" = eval ]; then
  if [[ " $* " == *" --json "* ]]; then echo '["required","intent"]'; else echo x86_64-linux; fi
  exit 0
fi
if [ "$STUB_MODE" = build-error ]; then exit 19; fi
if [[ " $* " == *" --print-out-paths "* ]]; then
  id=${!#}; id=${id##*.}
  printf '%s/%s\\n' "$STUB_ROOT" "$id"
fi
exit 0
''')
        binary.chmod(0o755)
        for fault_id in self.expected:
            output = self.root / fault_id
            output.mkdir(exist_ok=True)
            result = mode if mode in ("FAIL", "PARTIAL", "ERROR", "UNSUPPORTED") else "PASS"
            (output / "verdict.json").write_text(json.dumps({"id": fault_id, "result": result}))
        if mode == "missing":
            (self.root / "intent" / "verdict.json").unlink()
        if mode == "duplicate":
            (self.root / "intent" / "verdict.json").write_text(json.dumps({"id": "required", "result": "PASS"}))
        env = dict(os.environ, PATH=str(self.root) + os.pathsep + os.environ["PATH"], GYM_CATALOG=str(self.catalog), GYM_ACCEPTANCE=str(HERE / "acceptance.py"), GYM_WAIVERS=str(self.waivers), GYM_RESULTS_DIR=str(self.root / "results"), STUB_ROOT=str(self.root), STUB_MODE=mode)
        return subprocess.run(["bash", str(RUNNER)], env=env, capture_output=True, text=True, timeout=10)

    def test_actual_runner_propagates_build_and_verdict_failures(self):
        for mode in ("build-error", "FAIL", "PARTIAL", "ERROR", "UNSUPPORTED", "missing", "duplicate"):
            with self.subTest(mode=mode):
                run = self.run_vm_stub(mode)
                self.assertNotEqual(run.returncode, 0, run.stdout + run.stderr)
        control = self.run_vm_stub("PASS")
        self.assertEqual(control.returncode, 0, control.stdout + control.stderr)

    def test_failed_new_run_cannot_leave_a_prior_success_report(self):
        results = self.root / "results"
        results.mkdir()
        old_report = results / "acceptance.json"
        old_report.write_text('{"acceptance_complete":true}')
        run = self.run_vm_stub("eval-error")
        self.assertNotEqual(run.returncode, 0)
        self.assertFalse(old_report.exists())

    def test_fake_wrapper_preserves_execution_failure_and_only_waives_coverage(self):
        binary = self.root / "cargo"
        binary.write_text('''#!/usr/bin/env bash
out=${!#}
python3 - "$out" "$STUB_RESULT" <<'PY'
import json,sys,pathlib
(pathlib.Path(sys.argv[1]) / "required.json").write_text(json.dumps({"id":"required", "result":sys.argv[2]}))
PY
exit "$STUB_STATUS"
''')
        binary.chmod(0o755)
        def run(result, status):
            env = dict(os.environ, PATH=str(self.root) + os.pathsep + os.environ["PATH"], TMPDIR=str(self.root), GYM_CATALOG=str(self.catalog), GYM_ACCEPTANCE=str(HERE / "acceptance.py"), GYM_WAIVERS=str(self.waivers), STUB_RESULT=result, STUB_STATUS=str(status))
            return subprocess.run(["bash", str(HERE / "run-fake.sh")], env=env, capture_output=True, text=True, timeout=10)
        self.assertEqual(run("PASS", 0).returncode, 0)
        for status in (1, 2, 101):
            self.assertNotEqual(run("PASS", status).returncode, 0)
        self.assertNotEqual(run("UNSUPPORTED", 3).returncode, 0)
        self.waivers.write_text('''format_version = 1
[[waiver]]
id = "required"
harness = "fake"
role = "must-pass"
result = "UNSUPPORTED"
reason = "Reviewed fixture limitation"
reviewed_by = "owner"
review_url = "https://github.com/aubrika/planarian/pull/1#pullrequestreview-2"
expires = "2099-01-01"
''')
        accepted = run("UNSUPPORTED", 3)
        self.assertEqual(accepted.returncode, 0, accepted.stdout + accepted.stderr)
        self.assertNotEqual(run("UNSUPPORTED", 1).returncode, 0)

    def test_fake_wrapper_reused_directory_does_not_reuse_old_passes(self):
        binary = self.root / "cargo"
        binary.write_text('''#!/usr/bin/env bash
if [ "$STUB_WRITE" = yes ]; then
  printf '{"id":"required","result":"PASS"}\\n' > "${!#}/required.json"
fi
exit 0
''')
        binary.chmod(0o755)
        results = self.root / "results"
        env = dict(os.environ, PATH=str(self.root) + os.pathsep + os.environ["PATH"], GYM_RESULTS_DIR=str(results), GYM_CATALOG=str(self.catalog), GYM_ACCEPTANCE=str(HERE / "acceptance.py"), GYM_WAIVERS=str(self.waivers), STUB_WRITE="yes")
        command = ["bash", str(HERE / "run-fake.sh")]
        control = subprocess.run(command, env=env, capture_output=True, text=True, timeout=10)
        self.assertEqual(control.returncode, 0, control.stdout + control.stderr)
        self.assertTrue(json.loads((results / "acceptance.json").read_text())["acceptance_complete"])
        env["STUB_WRITE"] = "no"
        missing = subprocess.run(command, env=env, capture_output=True, text=True, timeout=10)
        self.assertNotEqual(missing.returncode, 0)
        self.assertFalse(json.loads((results / "acceptance.json").read_text())["acceptance_complete"])


if __name__ == "__main__":
    unittest.main()
