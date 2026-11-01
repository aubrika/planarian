"""The §15 harness contract, for the VM runners (run-vm.sh, vm.yml).

    harness-contract.py HARNESS CATALOG DEVIATIONS VERDICT.json...

Exits 1 when a verdict is ERROR, FAIL or PARTIAL, or UNSUPPORTED on a
must-pass or acceptance entry that docs/deviations.md's "Harness waivers"
table does not waive for HARNESS. CATALOG is a .toml file or a directory of
them. `planarian-gym run --strict` applies the same rule on the fake.
"""
import json, os, re, sys, tomllib

harness, catalog, deviations, *verdicts = sys.argv[1:]
files = sorted(os.path.join(catalog, f) for f in os.listdir(catalog) if f.endswith(".toml")) if os.path.isdir(catalog) else [catalog]
entries = {e["id"]: e for f in files for e in tomllib.load(open(f, "rb")).get("fault", [])}

waived, table = set(), False
for line in open(deviations):
    if line.startswith("## "):
        table = line.strip().startswith("## Harness waivers")
    m = table and re.match(r"\|\s*`([^`]+)`\s*\|\s*([a-z]+)\s*\|", line)
    if m:
        waived.add((m.group(1), m.group(2)))

bad = []
for p in verdicts:
    v = json.load(open(p))
    vid, result = v.get("id", "?"), v.get("result", "ERROR")
    e = entries.get(vid, {})
    gating = e.get("scoring") == "must-pass" or "acceptance" in e.get("tags", [])
    if result == "PASS" or (result == "UNSUPPORTED" and (not gating or (vid, harness) in waived)):
        continue
    bad.append(f"{vid}: {result}")
for b in bad:
    print("not cleared:", b)
sys.exit(1 if bad else 0)
