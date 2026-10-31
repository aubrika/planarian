#!/usr/bin/env python3
"""Validate catalog coverage and verdicts; missing evidence is a failure."""

import argparse
import datetime
import hashlib
import json
from pathlib import Path
import re
import sys
import tomllib

ROLES = {"must-pass", "intent", "repair"}
HARNESSES = {"fake", "vm", "bench"}
RESULTS = {"PASS", "PARTIAL", "FAIL", "ERROR", "UNSUPPORTED"}


def catalog_entries(path):
    with open(path, "rb") as source:
        entries = tomllib.load(source).get("fault", [])
    if not entries:
        raise ValueError("catalog has no fault entries")
    by_id = {}
    for entry in entries:
        fault_id = entry.get("id", "")
        if not re.fullmatch(r"[a-z0-9][a-z0-9-]*", fault_id):
            raise ValueError(f"invalid catalog id: {fault_id!r}")
        if fault_id in by_id:
            raise ValueError(f"duplicate catalog id: {fault_id}")
        if entry.get("scoring") not in ROLES:
            raise ValueError(f"{fault_id}: invalid acceptance role")
        harnesses = entry.get("harness", [])
        if not harnesses or len(harnesses) != len(set(harnesses)) or not set(harnesses) <= HARNESSES:
            raise ValueError(f"{fault_id}: invalid harness applicability")
        by_id[fault_id] = entry
    return by_id


def expected_entries(entries, harness, selected):
    if len(selected) != len(set(selected)):
        raise ValueError("duplicate requested id")
    for fault_id in selected:
        if fault_id not in entries or harness not in entries[fault_id]["harness"]:
            raise ValueError(f"{fault_id}: unknown or inapplicable to {harness}")
    expected = {key: value for key, value in entries.items() if harness in value["harness"] and (not selected or key in selected)}
    if not expected:
        raise ValueError(f"no applicable {harness} entries")
    return expected


def reviewed_waivers(path, entries, today=None):
    if path is None:
        return {}
    today = today or datetime.date.today()
    with open(path, "rb") as source:
        doc = tomllib.load(source)
    if doc.get("format_version") != 1:
        raise ValueError("unsupported waiver format")
    waivers = {}
    for waiver in doc.get("waiver", []):
        fault_id, harness, role = (waiver.get(key) for key in ("id", "harness", "role"))
        key = (fault_id, harness, role)
        if key in waivers:
            raise ValueError(f"duplicate waiver: {key}")
        entry = entries.get(fault_id)
        if entry is None or harness not in entry["harness"] or role != entry["scoring"]:
            raise ValueError(f"waiver does not match catalog role/applicability: {key}")
        if waiver.get("result") != "UNSUPPORTED":
            raise ValueError(f"{fault_id}: only UNSUPPORTED can be waived")
        if not waiver.get("reason", "").strip() or not waiver.get("reviewed_by", "").strip():
            raise ValueError(f"{fault_id}: waiver lacks reason or reviewer")
        if not re.fullmatch(r"https://github\.com/[^/]+/[^/]+/pull/[0-9]+#pullrequestreview-[0-9]+", waiver.get("review_url", "")):
            raise ValueError(f"{fault_id}: waiver needs a review permalink")
        try:
            expires = datetime.date.fromisoformat(str(waiver["expires"]))
        except (ValueError, KeyError) as error:
            raise ValueError(f"{fault_id}: waiver needs an ISO expiry date") from error
        if expires < today:
            raise ValueError(f"{fault_id}: waiver expired {expires}")
        waivers[key] = waiver
    return waivers


def validate(entries, expected, harness, paths, waivers):
    verdicts = {}
    errors = []
    for path in paths:
        try:
            with open(path) as source:
                verdict = json.load(source)
            fault_id, result = verdict["id"], verdict["result"]
            if not isinstance(fault_id, str) or result not in RESULTS:
                raise ValueError("invalid id or result")
            if fault_id in verdicts:
                errors.append(f"duplicate verdict: {fault_id}")
                continue
            if fault_id not in expected:
                errors.append(f"unexpected verdict: {fault_id}")
                continue
            verdicts[fault_id] = verdict
        except (OSError, ValueError, KeyError, TypeError) as error:
            errors.append(f"{path}: unusable verdict: {error}")
    rows = []
    for fault_id, entry in expected.items():
        verdict = verdicts.get(fault_id)
        result = verdict["result"] if verdict else "MISSING"
        waiver = waivers.get((fault_id, harness, entry["scoring"])) if result == "UNSUPPORTED" else None
        accepted = result == "PASS" or waiver is not None
        if not accepted:
            errors.append(f"{fault_id} ({entry['scoring']}, {harness}): {result}")
        rows.append({"id": fault_id, "role": entry["scoring"], "harness": harness, "result": result, "accepted": accepted, "waiver": waiver})
    all_ids = {fault_id for fault_id, entry in entries.items() if harness in entry["harness"]}
    full_harness = set(expected) == all_ids
    return {"format_version": 1, "scope": "full-harness" if full_harness else "selected-cases", "harness": harness, "catalog_expected_count": len(all_ids), "acceptance_complete": not errors, "full_harness_acceptance_complete": full_harness and not errors, "expected_count": len(expected), "verdict_count": len(verdicts), "cases": rows, "errors": errors}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("ids", "check"))
    parser.add_argument("--catalog", default="crates/gym/catalog/phase-a.toml")
    parser.add_argument("--harness", choices=sorted(HARNESSES), required=True)
    parser.add_argument("--id", action="append", default=[])
    parser.add_argument("--waivers")
    parser.add_argument("--report")
    parser.add_argument("verdicts", nargs="*")
    # Verdict paths follow the options in both runner wrappers. Explicitly
    # support interspersed options/positionals across Python minor versions.
    args = parser.parse_intermixed_args(argv)
    try:
        entries = catalog_entries(args.catalog)
        expected = expected_entries(entries, args.harness, args.id)
        if args.command == "ids":
            print("\n".join(expected))
            return 0
        waivers = reviewed_waivers(args.waivers, entries)
        report = validate(entries, expected, args.harness, args.verdicts, waivers)
        report["catalog_sha256"] = hashlib.sha256(Path(args.catalog).read_bytes()).hexdigest()
        report["waivers_sha256"] = hashlib.sha256(Path(args.waivers).read_bytes()).hexdigest() if args.waivers else None
        if args.report:
            Path(args.report).write_text(json.dumps(report, indent=2, default=str) + "\n")
        for row in report["cases"]:
            print(f"{row['result']:<12} {row['id']} ({row['role']})" + (" [reviewed waiver]" if row["waiver"] else ""))
        for error in report["errors"]:
            print(f"ERROR: {error}", file=sys.stderr)
        return 0 if report["acceptance_complete"] else 1
    except (OSError, ValueError, TypeError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
