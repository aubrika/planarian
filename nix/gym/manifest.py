#!/usr/bin/env python3
"""Record catalog runs and collect one candidate's acceptance evidence.

Absent, unbound and failed evidence is never a pass. Run this in a clean
checkout of the immutable candidate; evidence-only files belong in docs/evidence.
Receipts are reproducibility records, not protection from a malicious root.
"""
import argparse
import collections
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tomllib

import acceptance

CATALOG = Path("crates/gym/catalog/phase-a.toml")
WAIVERS = Path("docs/acceptance-waivers.toml")
BUILD_FILES = ("Cargo.toml", "Cargo.lock", "rust-toolchain.toml", "flake.nix", "flake.lock", ".gitignore")
EVIDENCE_DOCS = {"shared-core-review.md", "shared-core-acceptance.json", "shared-core-acceptance-report.md"}
REQUIRED_COMMANDS = [
    "cargo fmt --check",
    "cargo clippy --workspace --all-targets -- -D warnings",
    "cargo clippy -p planarian-daemon -p planarian-backend-linux --features planarian-daemon/gym-hooks -- -D warnings",
    "cargo test --workspace", "bash nix/gym/run-fake.sh", "crates/gym/demo.sh --harness fake",
    "bash nix/tests/boundaries.sh .", "cargo run -p planarian-gym -- verification --gate",
    "cargo kani -p planarian-txn", "cargo kani -p planarian-exec",
    "nix build .#checks.x86_64-linux.package .#checks.x86_64-linux.module-eval .#checks.x86_64-linux.boundaries .#checks.x86_64-linux.verus",
    "nix build .#checks.x86_64-linux.vm-runtime .#checks.x86_64-linux.vm-generations .#checks.x86_64-linux.vm-posture",
    "nix run .#gym-vm",
    "nix build .#checks.x86_64-linux.vm-installed-boot .#checks.x86_64-linux.vm-installed-boot-watchdog .#checks.x86_64-linux.vm-boot-confirmation",
    "installed-entry publication crash matrix: legacyPackages.x86_64-linux.boot-entry-tests",
    "real-filesystem ext4 and nodatacow-btrfs durability/ENOSPC acceptance", "reference-hardware personal-profile performance",
]


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def source_files():
    paths = {Path(name) for name in BUILD_FILES if Path(name).is_file()}
    for directory in (".github", "crates", "nix", "share", "assets", "docs"):
        for path in Path(directory).rglob("*"):
            if not path.is_file() or "__pycache__" in path.parts:
                continue
            if directory == "docs" and ("evidence" in path.parts or path.name in EVIDENCE_DOCS):
                continue
            paths.add(path)
    return {str(path): {"sha256": hashlib.sha256(os.readlink(path).encode() if path.is_symlink() else path.read_bytes()).hexdigest(),
                        "mode": "120000" if path.is_symlink() else ("100755" if path.stat().st_mode & 0o111 else "100644")}
            for path in sorted(paths)}


def fingerprint(files):
    return hashlib.sha256(json.dumps(files, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def git_output(*args):
    result = subprocess.run(["git", *args], capture_output=True, text=True)
    if result.returncode:
        raise ValueError("cannot inspect checkout: " + result.stderr.strip())
    return result.stdout.strip()


def source_identity(revision):
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise ValueError("source revision must be a full immutable Git SHA")
    files = source_files()
    head = git_output("rev-parse", "HEAD")
    available = subprocess.run(["git", "cat-file", "-e", revision + "^{commit}"], capture_output=True).returncode == 0
    if not available:
        return {"revision": revision, "checkout_head": head, "revision_available": False, "revision_verified": False,
                "fingerprint": fingerprint(files), "files": files,
                "scope": "unbound local inventory; candidate Git objects are unavailable"}
    # Only fingerprints of implementation, fixtures and governing contracts are
    # compared. Evidence-only commits may change the explicitly excluded files.
    # A clean index alone is insufficient: new/untracked source is included too.
    tree = git_output("ls-tree", "-r", revision).splitlines()
    tree_modes = {line.split("\t", 1)[1]: line.split()[0] for line in tree}
    committed = {}
    for name in files:
        result = subprocess.run(["git", "show", f"{revision}:{name}"], capture_output=True)
        if result.returncode:
            break
        committed[name] = {"sha256": hashlib.sha256(result.stdout).hexdigest(), "mode": tree_modes.get(name)}
    revision_files = list(tree_modes)
    claimed = set(files)
    expected = set()
    for name in revision_files:
        path = Path(name)
        if name in BUILD_FILES or (path.parts and path.parts[0] in {".github", "crates", "nix", "share", "assets", "docs"}):
            if path.parts[0] == "docs" and ("evidence" in path.parts or path.name in EVIDENCE_DOCS):
                continue
            expected.add(name)
    verified = claimed == expected and committed == files
    return {"revision": revision, "checkout_head": head, "revision_available": True, "revision_verified": verified,
            "fingerprint": fingerprint(files), "files": files,
            "scope": "implementation, fixtures, assets, build/CI inputs and governing docs; explicitly named evidence docs excluded"}


def tool_versions(harness):
    commands = [["python3", "--version"], ["git", "--version"], ["cargo", "--version"] if harness == "fake" else ["nix", "--version"]]
    versions = {}
    for command in commands:
        try:
            run = subprocess.run(command, capture_output=True, text=True)
            versions[" ".join(command)] = {"exit_status": run.returncode, "output": (run.stdout + run.stderr).strip()}
        except OSError as error:
            versions[" ".join(command)] = {"unavailable": str(error)}
    return versions


def record(revision, harness, selected, output):
    entries = acceptance.catalog_entries(CATALOG)
    acceptance.expected_entries(entries, harness, selected)
    if harness == "fake" and selected:
        raise ValueError("the fake wrapper records complete coverage; selections are unsupported")
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    # Never attest a run whose own output changes the tested source snapshot.
    relative = output.relative_to(Path.cwd().resolve()) if output.is_relative_to(Path.cwd().resolve()) else None
    if relative is not None and not relative.is_relative_to("docs/evidence"):
        raise ValueError("in-repository run output must be under docs/evidence")
    receipt_path = output / "receipt.json"
    receipt_path.unlink(missing_ok=True)
    before = source_identity(revision)
    command = ["bash", f"nix/gym/run-{harness}.sh", *selected]
    versions = tool_versions(harness)
    env = dict(os.environ, GYM_FLAKE=".", GYM_RESULTS_DIR=str(output), GYM_CATALOG=str(CATALOG), GYM_ACCEPTANCE="nix/gym/acceptance.py", GYM_WAIVERS=str(WAIVERS))
    with open(output / "run.log", "w") as log:
        run = subprocess.run(command, env=env, stdout=log, stderr=subprocess.STDOUT)
    after = source_identity(revision)
    report = output / "acceptance.json"
    receipt = {"format_version": 1, "source": before, "source_unchanged": before == after,
               "harness": harness, "selected": selected, "command": command,
               "exit_status": run.returncode, "tool_versions": versions,
               "recorded_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
               "report": report.name if report.is_file() else None,
               "report_sha256": sha256(report) if report.is_file() else None,
               "log": "run.log", "log_sha256": sha256(output / "run.log")}
    receipt_path.write_text(json.dumps(receipt, indent=2) + "\n")
    return run.returncode if run.returncode else (0 if before["revision_verified"] and before == after else 1)


def load_run(path, current, entries, waivers):
    path = Path(path)
    receipt = json.loads(path.read_text())
    if receipt.get("format_version") != 1:
        raise ValueError(f"{path}: unsupported receipt format")
    source = receipt.get("source", {})
    if source.get("revision") != current["revision"] or source.get("fingerprint") != current["fingerprint"] or source.get("files") != current["files"]:
        raise ValueError(f"{path}: evidence belongs to a different source revision/snapshot")
    if source.get("revision_verified") is not True or not current["revision_verified"] or receipt.get("source_unchanged") is not True:
        raise ValueError(f"{path}: run is not bound to unchanged committed source")
    harness, selected = receipt.get("harness"), receipt.get("selected")
    if harness not in {"fake", "vm"} or not isinstance(selected, list):
        raise ValueError(f"{path}: invalid run scope")
    expected = acceptance.expected_entries(entries, harness, selected)
    if receipt.get("command") != ["bash", f"nix/gym/run-{harness}.sh", *selected]:
        raise ValueError(f"{path}: command does not match catalog runner")
    if receipt.get("exit_status") != 0 or not receipt.get("tool_versions"):
        raise ValueError(f"{path}: run failed or has no tool version evidence")
    for key in ("report", "log"):
        name = receipt.get(key)
        if not isinstance(name, str) or Path(name).name != name or sha256(path.parent / name) != receipt.get(key + "_sha256"):
            raise ValueError(f"{path}: missing or edited {key}")
    report = json.loads((path.parent / receipt["report"]).read_text())
    if report.get("catalog_sha256") != sha256(CATALOG) or report.get("waivers_sha256") != sha256(WAIVERS) or report.get("harness") != harness or report.get("errors") != []:
        raise ValueError(f"{path}: catalog, waivers or reported errors do not match")
    cases = report.get("cases", [])
    if len(cases) != len(expected) or {row.get("id") for row in cases} != set(expected):
        raise ValueError(f"{path}: incomplete or duplicate reported coverage")
    rows = []
    for case in cases:
        fault_id = case["id"]
        entry = expected[fault_id]
        if case.get("harness") != harness or case.get("role") != entry["scoring"] or case.get("result") not in acceptance.RESULTS:
            raise ValueError(f"{path}: invalid result role or harness")
        waiver = waivers.get((fault_id, harness, entry["scoring"])) if case["result"] == "UNSUPPORTED" else None
        accepted = case["result"] == "PASS" or waiver is not None
        if case.get("accepted") is not accepted or not accepted:
            raise ValueError(f"{path}: failed/unwaived result cannot establish acceptance")
        rows.append({"id": fault_id, "harness": harness, "role": entry["scoring"], "result": case["result"], "accepted": accepted, "waiver": waiver, "receipt": str(path)})
    return rows


def collect(revision, receipts):
    current = source_identity(revision)
    entries = acceptance.catalog_entries(CATALOG)
    waivers = acceptance.reviewed_waivers(WAIVERS, entries)
    rows = {(fault_id, harness): {"id": fault_id, "role": entry["scoring"], "harness": harness,
             "result": "NOT_RUN", "accepted": False, "waiver": None, "receipt": None}
            for fault_id, entry in entries.items() for harness in entry["harness"]}
    errors, seen = [], set()
    for path in receipts:
        try:
            evidence = load_run(path, current, entries, waivers)
            for row in evidence:
                key = row["id"], row["harness"]
                if key in seen:
                    rows[key]["result"], rows[key]["accepted"] = "DUPLICATE", False
                    errors.append(f"duplicate run evidence for {key}")
                else:
                    rows[key] = row
                    seen.add(key)
        except (OSError, ValueError, KeyError, TypeError) as error:
            errors.append(str(error))
    if not current["revision_verified"]:
        errors.append("working source does not match the declared immutable revision; this is an unbound draft inventory")
    by_harness = {harness: all(row["accepted"] for row in rows.values() if row["harness"] == harness)
                  for harness in sorted({row["harness"] for row in rows.values()})}
    ratio_path, map_path = Path("docs/verification-ratio.toml"), Path("docs/proof-obligations.toml")
    ratio = tomllib.loads(ratio_path.read_text()) if ratio_path.is_file() else {}
    obligations = tomllib.loads(map_path.read_text()).get("obligation", []) if map_path.is_file() else []
    return {"format_version": 1, "source": current,
            "catalog_sha256": sha256(CATALOG), "waivers_sha256": sha256(WAIVERS),
            "catalog_id_count": len(entries), "roles": dict(collections.Counter(entry["scoring"] for entry in entries.values())),
            "harness_acceptance_complete": by_harness, "catalog_acceptance_complete": all(by_harness.values()) and not errors,
            "acceptance_complete": False,
            "findings": [{"id": finding, "status": "open", "fixing_revision": None, "before_after_evidence": [],
                          "remaining": "See docs/shared-core-review.md; implementation/source analysis is not acceptance evidence."}
                         for finding in [*(f"R{i:02}" for i in range(1, 17)), *(f"S{i:02}" for i in range(1, 8)), "P09", "GC"]],
            "proof_accounting": {"current_successful_verification": "NOT_RUN", "artifacts": [],
                                 "declared_unique_obligation_ids": len({row.get("id") for row in obligations}),
                                 "declared_invariant_support_edges": sum(len(row.get("invariants", [])) for row in obligations),
                                 "invariant_ids": [row.get("id") for row in ratio.get("invariant", [])],
                                 "historical_baseline_only": ratio.get("baseline", {}),
                                 "note": "Declared mappings and historical ratios do not establish current successful proofs."},
            "required_non_catalog_evidence": [{"command_or_scope": command, "status": "NOT_RUN", "evidence": None} for command in REQUIRED_COMMANDS],
            "non_catalog_note": "Catalog receipts cannot establish Rust checks, successful proofs, installed-entry boot behavior, real-filesystem durability or hardware performance. Attach those independent results and finding dispositions before release certification.",
            "cases": list(rows.values()), "errors": errors}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("record", "collect"))
    parser.add_argument("--source-revision", required=True)
    parser.add_argument("--harness", choices=("fake", "vm"))
    parser.add_argument("--id", action="append", default=[])
    parser.add_argument("--output", required=True)
    parser.add_argument("--receipt", action="append", default=[])
    args = parser.parse_args(argv)
    try:
        if args.command == "record":
            if args.harness is None:
                raise ValueError("record needs --harness")
            return record(args.source_revision, args.harness, args.id, args.output)
        report = collect(args.source_revision, args.receipt)
        Path(args.output).write_text(json.dumps(report, indent=2, default=str) + "\n")
        print(f"{report['catalog_id_count']} catalog IDs; {len(report['cases'])} role/harness slots; acceptance_complete=false")
        return 0
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
