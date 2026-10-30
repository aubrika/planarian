#!/usr/bin/env python3
"""Proof-accounting negative regressions; these do not run any verifier."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
spec = importlib.util.spec_from_file_location("proofs", HERE / "proofs.py")
proofs = importlib.util.module_from_spec(spec)
spec.loader.exec_module(proofs)


class ProofAccountingContract(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        for name in ("docs/assumptions.md", "docs/proof-obligations.toml", "docs/verification-ratio.toml", "Cargo.toml", "Cargo.lock", "rust-toolchain.toml", "nix/gym/proofs.py", "nix/template/planarian/overrides.nix", "assets/identity/animations/keyframes.json", "assets/identity/marks/planarian-mark-micro-currentcolor.svg"):
            target = self.root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, target)
        for directory in ("crates", "share"):
            shutil.copytree(ROOT / directory, self.root / directory)
        previous = Path.cwd()
        os.chdir(self.root)
        self.addCleanup(os.chdir, previous)

    def mock_output(self, engine, status=0, crate=None):
        obligations = proofs.mapped_obligations()
        if engine == "verus":
            log = "verification results:: 52 verified, 0 errors\n" * 2
        else:
            groups = [[proof_id.split("::")[1] for proof_id, item in obligations.items() if item["engine"] == "kani" and proof_id.startswith(group_crate + "::")] for group_crate in ((crate,) if crate else ("txn", "exec"))]
            log = "".join("".join(f"Checking harness kani::{symbol}...\nVERIFICATION:- SUCCESSFUL\n" for symbol in group)
                          + f"Complete - {len(group)} successfully verified harnesses, 0 failures, {len(group)} total.\n" for group in groups)
        return subprocess.CompletedProcess([], status, stdout=log)

    def receipts(self):
        for engine in proofs.COMMANDS:
            def mocked(command, **_kwargs):
                crate = command[-1].removeprefix("planarian-") if command[:2] == ["cargo", "kani"] and "-p" in command else None
                return self.mock_output(engine, crate=crate)
            with patch.object(subprocess, "run", side_effect=mocked), contextlib.redirect_stdout(io.StringIO()):
                proofs.run(engine, f"artifacts/{engine}.json")

    def test_control_preserves_unique_obligations_and_artifacts(self):
        obligations = proofs.mapped_obligations()
        self.assertEqual(len(obligations), 45)
        self.assertEqual(sum(len(item["invariants"]) for item in obligations.values()), 47)
        self.receipts()
        with contextlib.redirect_stdout(io.StringIO()):
            proofs.check("artifacts")

    def test_removing_an_invariant_and_duplicate_obligations_fail(self):
        ratio = Path("docs/verification-ratio.toml")
        original = ratio.read_text()
        ratio.write_text(re.sub(r'\[\[invariant\]\]\nid = "I1".*?(?=\[\[invariant\]\])', '', original, flags=re.S))
        with self.assertRaises(ValueError):
            proofs.mapped_obligations()
        ratio.write_text(original)
        manifest = Path("docs/proof-obligations.toml")
        text = manifest.read_text()
        manifest.write_text(text + text[text.index("[[obligation]]"):text.index("[[obligation]]", text.index("[[obligation]]") + 1)])
        with self.assertRaises(ValueError):
            proofs.mapped_obligations()

    def test_an_existing_unverified_function_cannot_replace_an_obligation(self):
        ratio = Path("docs/verification-ratio.toml")
        ratio.write_text(ratio.read_text().replace("policy::decide", "policy::own_session_is_per_session", 1))
        with self.assertRaises(ValueError):
            proofs.mapped_obligations()

        # Even changing both declarations and the map cannot turn ordinary code into a proof.
        ratio.write_text(ratio.read_text().replace("policy::own_session_is_per_session", "policy::just_a_function", 1))
        source = Path("crates/policy/src/ordinary.rs")
        source.write_text("pub fn just_a_function() {}\n")
        root = Path("crates/policy/src/lib.rs")
        root.write_text(root.read_text().replace("pub mod proofs;", "pub mod proofs;\npub mod ordinary;"))
        manifest = Path("docs/proof-obligations.toml")
        manifest.write_text(manifest.read_text().replace('id = "policy::decide"\nengine = "verus"\nsource = "crates/policy/src/lib.rs"', 'id = "policy::just_a_function"\nengine = "verus"\nsource = "crates/policy/src/ordinary.rs"'))
        with self.assertRaises(ValueError):
            proofs.mapped_obligations()
        for payload in ('/* outer /* nested */ pub proof fn just_a_function() {} */', 'const HIDDEN: &str = r###"words " pub proof fn just_a_function() {} "###;'):
            source.write_text("use vstd::prelude::*;\nverus! {}\n" + payload)
            with self.subTest(hidden_name=payload), self.assertRaises(ValueError):
                proofs.mapped_obligations()

    def test_excluded_external_or_redirected_proofs_cannot_count_as_discharged(self):
        source = Path("crates/policy/src/proofs.rs")
        original = source.read_text()
        for annotation in ("#[cfg(any())]", "#[ cfg(any()) ]", "#[r#cfg(any())]", "# [ cfg ( any() ) ]", "#[cfg_attr(all(), verifier::external_body)]", "#[verifier::external_body]", "#[verifier :: external_body]"):
            source.write_text(original.replace("pub proof fn i5_autonomy_never_touches_reject", annotation + "\npub proof fn i5_autonomy_never_touches_reject"))
            with self.subTest(annotation=annotation), self.assertRaises(ValueError):
                proofs.mapped_obligations()
        source.write_text(original)
        root = Path("crates/policy/src/lib.rs")
        original_root = root.read_text()
        for annotation in ("#[cfg(any())]", "#[ r#cfg ( any() ) ]", '#[path = "ordinary.rs"]'):
            root.write_text(original_root.replace("pub mod proofs;", annotation + "\npub mod proofs;"))
            with self.subTest(module_annotation=annotation), self.assertRaises(ValueError):
                proofs.mapped_obligations()

    def test_dependency_sources_are_bound_by_receipts(self):
        self.receipts()
        dependency = Path("crates/changes/src/lib.rs")
        dependency.write_text(dependency.read_text() + "\n// dependency changed after proof\n")
        with self.assertRaises(ValueError), contextlib.redirect_stdout(io.StringIO()):
            proofs.check("artifacts")

    def test_unused_macro_tokens_cannot_become_mapped_proofs(self):
        source = Path("crates/txn/src/kani.rs")
        text = source.read_text()
        start = text.index("#[kani::proof]")
        source.write_text(text[:start] + "macro_rules! unused_proofs { () => {" + text[start:] + "}; }\n")
        with self.assertRaises(ValueError):
            proofs.mapped_obligations()

    def test_each_kani_harness_needs_its_own_success_and_complete_summary(self):
        obligations = proofs.mapped_obligations()
        output = self.mock_output("kani").stdout
        self.assertTrue(proofs.log_success("kani", output, obligations))
        symbols_only = "\n".join(item.split("::")[-1] for item, row in obligations.items() if row["engine"] == "kani") + "\nVERIFICATION:- SUCCESSFUL\n"
        self.assertFalse(proofs.log_success("kani", symbols_only, obligations))
        self.assertFalse(proofs.log_success("kani", output.replace("VERIFICATION:- SUCCESSFUL", "VERIFICATION:- FAILED", 1), obligations))
        self.assertFalse(proofs.log_success("kani", output.replace("Complete -", "Incomplete -", 1), obligations))

    def test_spaced_trust_sites_cannot_disappear_from_the_ratchet(self):
        before = proofs.trust_sites()
        source = Path("crates/txn/src/accounting_fixture.rs")
        source.write_text('''// assume(false); #[verifier::external_body]
const COMMENT: &str = "assume(false); #[verifier::external_body]";
#[ verifier :: external_body ]
fn trusted_fixture() { assume (false); kani :: assume (true); }
''')
        self.assertEqual(proofs.trust_sites(), before + 2)

    def test_missing_stale_edited_or_failed_artifacts_fail(self):
        with self.assertRaises(OSError), contextlib.redirect_stdout(io.StringIO()):
            proofs.check("artifacts")
        self.receipts()
        source = Path("crates/txn/src/kernel.rs")
        source.write_text(source.read_text() + "\n// changed after proof\n")
        with self.assertRaises(ValueError), contextlib.redirect_stdout(io.StringIO()):
            proofs.check("artifacts")
        self.receipts()
        log = Path("artifacts/verus.log")
        log.write_text(log.read_text() + "edited\n")
        with self.assertRaises(ValueError), contextlib.redirect_stdout(io.StringIO()):
            proofs.check("artifacts")
        result = self.mock_output("verus", status=7)
        with patch.object(subprocess, "run", return_value=result), self.assertRaises(ValueError), contextlib.redirect_stdout(io.StringIO()):
            proofs.run("verus", "artifacts/verus.json")
        self.assertFalse(Path("artifacts/verus.json").exists())


if __name__ == "__main__":
    unittest.main()
