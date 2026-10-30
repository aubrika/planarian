#!/usr/bin/env python3
"""Manifest-accounting tests; synthetic receipts below are not harness passes."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
spec = importlib.util.spec_from_file_location("manifest", HERE / "manifest.py")
manifest = importlib.util.module_from_spec(spec)
spec.loader.exec_module(manifest)

CATALOG = '''[[fault]]
id = "required"
scoring = "must-pass"
harness = ["fake", "vm"]
[[fault]]
id = "intent"
scoring = "intent"
harness = ["vm"]
'''


class ManifestContract(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        previous = Path.cwd()
        os.chdir(self.root)
        self.addCleanup(os.chdir, previous)
        manifest.CATALOG.parent.mkdir(parents=True)
        manifest.CATALOG.write_text(CATALOG)
        manifest.WAIVERS.parent.mkdir(parents=True)
        manifest.WAIVERS.write_text("format_version = 1\n")
        Path("nix").mkdir()
        Path("nix/fixture.sh").write_text("#!/bin/sh\nexit 0\n")
        self.git("init", "-q")
        self.git("add", ".")
        self.git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-qm", "synthetic source fixture")
        self.revision = self.git("rev-parse", "HEAD").strip()

    def git(self, *args):
        return subprocess.run(["git", *args], check=True, capture_output=True, text=True).stdout

    def receipt(self, harness="fake", suffix="one"):
        # Accounting control only: these hand-authored receipts do not claim
        # the catalog's service/runtime postconditions were executed.
        directory = self.root / "docs" / "evidence" / suffix
        directory.mkdir(parents=True, exist_ok=True)
        entries = manifest.acceptance.catalog_entries(manifest.CATALOG)
        rows = [{"id": key, "result": "PASS", "role": row["scoring"], "harness": harness, "accepted": True, "waiver": None}
                for key, row in entries.items() if harness in row["harness"]]
        report = directory / "acceptance.json"
        report.write_text(json.dumps({"catalog_sha256": manifest.sha256(manifest.CATALOG), "waivers_sha256": manifest.sha256(manifest.WAIVERS), "harness": harness, "errors": [], "cases": rows}))
        log = directory / "run.log"
        log.write_text("synthetic receipt accounting fixture, no real harness run\n")
        receipt = directory / "receipt.json"
        receipt.write_text(json.dumps({"format_version": 1, "source": manifest.source_identity(self.revision), "source_unchanged": True,
            "harness": harness, "selected": [], "command": ["bash", f"nix/gym/run-{harness}.sh"], "exit_status": 0,
            "tool_versions": {"mock": "synthetic test data only"}, "report": report.name, "report_sha256": manifest.sha256(report),
            "log": log.name, "log_sha256": manifest.sha256(log)}))
        return receipt

    def test_default_inventory_never_invents_a_pass(self):
        report = manifest.collect(self.revision, [])
        self.assertTrue(report["source"]["revision_verified"])
        self.assertEqual(report["catalog_id_count"], 2)
        self.assertEqual(len(report["cases"]), 3)
        self.assertTrue(all(row["result"] == "NOT_RUN" and not row["accepted"] for row in report["cases"]))
        self.assertFalse(report["catalog_acceptance_complete"])
        self.assertFalse(report["acceptance_complete"])

    def test_current_bound_receipt_only_fills_its_actual_harness(self):
        report = manifest.collect(self.revision, [self.receipt()])
        self.assertTrue(report["harness_acceptance_complete"]["fake"])
        self.assertFalse(report["harness_acceptance_complete"]["vm"])
        self.assertFalse(report["acceptance_complete"])
        self.assertTrue(all(row["status"] == "NOT_RUN" for row in report["required_non_catalog_evidence"]))

    def test_wrong_revision_dirty_source_and_mode_changes_cannot_reuse_results(self):
        receipt = self.receipt()
        original = receipt.read_text()
        data = json.loads(original)
        data["source"]["revision"] = "0" * 40
        receipt.write_text(json.dumps(data))
        self.assertTrue(manifest.collect(self.revision, [receipt])["errors"])
        receipt.write_text(original)
        Path("nix/fixture.sh").write_text("#!/bin/sh\nexit 1\n")
        self.assertTrue(manifest.collect(self.revision, [receipt])["errors"])
        Path("nix/fixture.sh").write_text("#!/bin/sh\nexit 0\n")
        Path("nix/fixture.sh").chmod(0o755)
        self.assertTrue(manifest.collect(self.revision, [receipt])["errors"])

    def test_missing_modified_failed_duplicate_and_incomplete_run_evidence_fails(self):
        receipt = self.receipt()
        original = receipt.read_text()
        for field, value in (("exit_status", 1), ("source_unchanged", False), ("report_sha256", "0" * 64)):
            data = json.loads(original)
            data[field] = value
            receipt.write_text(json.dumps(data))
            with self.subTest(field=field):
                self.assertTrue(manifest.collect(self.revision, [receipt])["errors"])
        receipt.write_text(original)
        report = manifest.collect(self.revision, [receipt, receipt])
        self.assertTrue(report["errors"])
        self.assertTrue(any(row["result"] == "DUPLICATE" for row in report["cases"]))
        evidence = receipt.parent / "acceptance.json"
        data = json.loads(evidence.read_text())
        data["cases"] = []
        evidence.write_text(json.dumps(data))
        data = json.loads(original)
        data["report_sha256"] = manifest.sha256(evidence)
        receipt.write_text(json.dumps(data))
        self.assertTrue(manifest.collect(self.revision, [receipt])["errors"])
        self.assertTrue(manifest.collect(self.revision, ["missing.json"])["errors"])

    def test_evidence_only_commit_preserves_source_fingerprint(self):
        receipt = self.receipt()
        before = manifest.source_identity(self.revision)
        Path("docs/shared-core-review.md").write_text("Evidence-only explanatory report.\n")
        self.git("add", ".")
        self.git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-qm", "synthetic evidence-only followup")
        after = manifest.source_identity(self.revision)
        self.assertNotEqual(before["checkout_head"], after["checkout_head"])
        self.assertEqual(before["fingerprint"], after["fingerprint"])
        self.assertTrue(after["revision_verified"])
        self.assertTrue(manifest.collect(self.revision, [receipt])["harness_acceptance_complete"]["fake"])
        Path("docs/SPEC.md").write_text("A new governing contract.\n")
        self.assertFalse(manifest.source_identity(self.revision)["revision_verified"])

    def test_immutable_revision_is_required(self):
        for revision in ("main", "HEAD", "805cd1c"):
            with self.subTest(revision=revision), self.assertRaises(ValueError):
                manifest.source_identity(revision)
        unavailable = manifest.collect("0" * 40, [])
        self.assertFalse(unavailable["source"]["revision_available"])
        self.assertFalse(unavailable["source"]["revision_verified"])
        self.assertTrue(unavailable["errors"])


if __name__ == "__main__":
    unittest.main()
