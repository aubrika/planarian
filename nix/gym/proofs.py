#!/usr/bin/env python3
"""Run fixed verifier commands and bind proof accounting to their artifacts.

A source-level function name is only a declared obligation. It is counted as
verified only with successful artifacts for the same complete source snapshot.
The proposed obligation map is reviewable; it is not itself a verifier result.
"""
import argparse
import hashlib
from functools import lru_cache
import json
from pathlib import Path
import re
import subprocess
import sys
import tomllib

MANIFEST = Path("docs/proof-obligations.toml")
RATIO = Path("docs/verification-ratio.toml")
BASELINE_INVARIANTS = {f"I{i}" for i in range(1, 24) if i != 9}
COMMANDS = {
    "verus": [["cargo-verus", "verify", "-p", "planarian-policy", "-p", "planarian-txn", "--offline"]],
    "kani": [["cargo", "kani", "-p", "planarian-txn"], ["cargo", "kani", "-p", "planarian-exec"]],
}


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def read_toml(path):
    with open(path, "rb") as source:
        return tomllib.load(source)


@lru_cache(maxsize=64)
def without_comments(text):
    # Strip nested Rust comments and cooked/raw strings before looking for
    # declarations. Names in comments or string payloads are not obligations.
    result = []
    index = 0
    while index < len(text):
        end = None
        if text.startswith("//", index):
            newline = text.find("\n", index)
            end = len(text) if newline < 0 else newline
        elif text.startswith("/*", index):
            end, depth = index + 2, 1
            while end < len(text) and depth:
                if text.startswith("/*", end):
                    depth += 1
                    end += 2
                elif text.startswith("*/", end):
                    depth -= 1
                    end += 2
                else:
                    end += 1
        else:
            raw = re.compile(r'(?:br|rb|r)(#{0,255})"').match(text, index) if text[index] in "br" else None
            if raw:
                closing = '"' + raw.group(1)
                found = text.find(closing, raw.end())
                end = len(text) if found < 0 else found + len(closing)
            elif text[index] == '"':
                end = index + 1
                while end < len(text):
                    if text[end] == "\\":
                        end += 2
                    elif text[end] == '"':
                        end += 1
                        break
                    else:
                        end += 1
        if end is not None:
            result.append("".join("\n" if char == "\n" else " " for char in text[index:end]))
            index = end
        else:
            result.append(text[index])
            index += 1
    text = "".join(result)
    # Rust permits whitespace between attribute tokens and raw identifiers.
    return re.sub(r"#\s*(?:!\s*)?\[[^]]*\]", lambda match: re.sub(r"r#([A-Za-z_][A-Za-z0-9_]*)", r"\1", re.sub(r"\s+", "", match.group())), text)


def item_attributes(prefix):
    pattern = r"((?:#\[[^]]+\]\s*)*)(?:(?:pub(?:\([^)]*\))?|open|closed|spec|proof|unsafe|async)\s+)*$"
    match = re.search(pattern, prefix)
    return match.group(1) if match else ""


def check_module(crate, source, engine):
    root = Path("crates") / crate / "src" / "lib.rs"
    text = without_comments(root.read_text())
    # This is a deliberately conservative source map, not a cfg evaluator.
    # The existing Verus auto-derive allow annotation does not exclude code.
    allowed = "#![cfg_attr(verus_keep_ghost,verifier::allow(autoderive_clone_without_spec))]"
    for annotation in re.findall(r"#!\[(?:cfg|cfg_attr)\b[^\n]*", text):
        if re.sub(r"\s+", "", annotation) != allowed:
            raise ValueError(f"{source}: conditional crate cannot establish obligation coverage")
    if source == root:
        return
    if source.parent != root.parent:
        raise ValueError(f"{source}: nested modules need an explicit reviewed mapper extension")
    declarations = list(re.finditer(r"\bmod\s+" + re.escape(source.stem) + r"\s*;", text))
    if len(declarations) != 1:
        raise ValueError(f"{source}: source is not the unique direct crate module")
    attributes = item_attributes(text[:declarations[0].start()])
    if engine == "kani" and source.stem == "kani":
        attributes = re.sub(r"#\[cfg\(kani\)\]", "", attributes)
    if re.search(r"#\[(?:cfg|cfg_attr|path)\b", attributes):
        raise ValueError(f"{source}: conditional or redirected module is not covered")


def declaration_scopes(text, offset, engine):
    # Do not count a declaration merely mentioned in an unused macro's token
    # body. Existing mappings are deliberately narrow: top-level Kani harnesses
    # and direct Verus functions/methods in one top-level verus! block.
    scopes = []
    for match in re.finditer(r"[{}]", text[:offset]):
        if match.group() == "{":
            scopes.append(match.start())
        elif scopes:
            scopes.pop()
    if engine == "kani":
        return not scopes
    if not scopes or len(scopes) > 2 or not re.search(r"\bverus\s*!\s*$", text[:scopes[0]]):
        return False
    if len(scopes) == 2 and not re.search(r"\bimpl\b[^{};]*$", text[:scopes[1]]):
        return False
    return True


def trust_sites():
    count = 0
    for directory in ("crates/policy/src", "crates/schema/src", "crates/txn/src"):
        for path in Path(directory).rglob("*.rs"):
            text = without_comments(path.read_text())
            count += len(re.findall(r"#\[[^]]*\bexternal_body\b[^]]*\]", text))
            for match in re.finditer(r"(?<![A-Za-z0-9_])(?:r#)?assume\s*\(", text):
                if not re.search(r"\bkani\s*::\s*$", text[:match.start()]):
                    count += 1
    return count


def mapped_obligations():
    manifest, ratio = read_toml(MANIFEST), read_toml(RATIO)
    if manifest.get("format_version") != 1:
        raise ValueError("unsupported proof manifest format")
    invariants = {}
    for invariant in ratio.get("invariant", []):
        inv_id = invariant.get("id")
        if inv_id in invariants:
            raise ValueError(f"duplicate invariant: {inv_id}")
        names = invariant.get("discharged", [])
        if len(names) != len(set(names)):
            raise ValueError(f"{inv_id}: duplicate obligation id")
        assumptions = invariant.get("assumes", [])
        if len(assumptions) != len(set(assumptions)):
            raise ValueError(f"{inv_id}: duplicate assumption id")
        invariants[inv_id] = set(names)
    baseline = set(ratio.get("baseline", {}).get("per_invariant", {}))
    if not BASELINE_INVARIANTS <= baseline or not baseline <= set(invariants):
        raise ValueError("complete baseline invariant set must remain present")
    obligations = {}
    for obligation in manifest.get("obligation", []):
        proof_id = obligation.get("id", "")
        if proof_id in obligations:
            raise ValueError(f"duplicate proof obligation id: {proof_id}")
        if not re.fullmatch(r"(policy|schema|txn|exec)::[a-z][a-z0-9_]*", proof_id):
            raise ValueError(f"invalid proof obligation id: {proof_id}")
        crate, symbol = proof_id.split("::")
        source = Path(obligation["source"])
        if source.is_absolute() or ".." in source.parts or not str(source).startswith(f"crates/{crate}/src/") or source.suffix != ".rs":
            raise ValueError(f"{proof_id}: invalid mapped source")
        text = without_comments(source.read_text())
        engine = obligation.get("engine")
        check_module(crate, source, engine)
        function = re.search(r"\b(?:proof\s+)?fn\s+" + re.escape(symbol) + r"\s*[(<]", text)
        if function is None:
            raise ValueError(f"{proof_id}: function is not declared in mapped source")
        if not declaration_scopes(text, function.start(), engine):
            raise ValueError(f"{proof_id}: declaration is not in a supported verified item scope")
        if re.search(r"#\[(?:cfg|cfg_attr)\b", text[:function.start()]):
            raise ValueError(f"{proof_id}: conditional proof declarations are not coverage")
        attributes = item_attributes(text[:function.start()])
        attributes = re.sub(r"#\[verifier::loop_isolation\(false\)\]", "", attributes)
        if "verifier::" in attributes:
            raise ValueError(f"{proof_id}: external or specially attributed proof needs explicit review")
        if engine == "kani":
            declaration = r"#\[kani::proof\](?:\s*#\[[^]]+\])*\s*(?:pub\s+)?fn\s+" + re.escape(symbol) + r"\s*[(<]"
            proven = re.search(declaration, text) is not None
        elif engine == "verus":
            declaration = re.search(r"\b(?:proof\s+)?fn\s+" + re.escape(symbol) + r"\s*[(<]", text)
            proven = declaration is not None and "verus!" in text and (
                declaration.group().startswith("proof")
                or "ensures" in text[declaration.end():].split("{", 1)[0]
            )
        else:
            raise ValueError(f"{proof_id}: unknown verifier engine")
        if not proven:
            raise ValueError(f"{proof_id}: source is not a mapped {engine} proof/verified function")
        covered = obligation.get("invariants", [])
        if not covered or len(covered) != len(set(covered)) or not set(covered) <= set(invariants):
            raise ValueError(f"{proof_id}: invalid invariant coverage")
        obligations[proof_id] = obligation
    for inv_id, names in invariants.items():
        mapped = {proof_id for proof_id, obligation in obligations.items() if inv_id in obligation["invariants"]}
        if mapped != names:
            raise ValueError(f"{inv_id}: declared obligations differ from explicit proof map")
    return obligations


def snapshot(engine):
    del engine  # Both engines bind the same complete workspace source inputs.
    paths = {Path(path) for path in ("Cargo.toml", "Cargo.lock", "rust-toolchain.toml", "nix/gym/proofs.py", str(MANIFEST), str(RATIO), "docs/assumptions.md", "nix/template/planarian/overrides.nix", "assets/identity/animations/keyframes.json", "assets/identity/marks/planarian-mark-micro-currentcolor.svg")}
    for directory in ("crates", "share"):
        paths.update(path for path in Path(directory).rglob("*") if path.is_file())
    return {str(path): digest(path) for path in sorted(paths)}


def log_success(engine, log, obligations):
    if engine == "verus":
        summaries = re.findall(r"verification results::\s*([0-9]+) verified,\s*([0-9]+) errors", log)
        return len(summaries) >= 2 and all(int(verified) > 0 and int(errors) == 0 for verified, errors in summaries)
    symbols = {proof_id.split("::")[1] for proof_id, obligation in obligations.items() if obligation["engine"] == engine}
    # Pinned Kani 0.68.0 emits one named Checking harness segment followed by
    # its own status, then a complete summary per command. A successful status
    # for one harness must not discharge names merely printed elsewhere.
    segments = re.split(r"Checking harness ([A-Za-z_][A-Za-z0-9_:]*)\.\.\.", log)
    checked = {}
    for index in range(1, len(segments), 2):
        symbol, body = segments[index].split("::")[-1], segments[index + 1]
        if symbol in checked or body.count("VERIFICATION:- SUCCESSFUL") != 1 or "VERIFICATION:- FAILED" in body:
            return False
        checked[symbol] = True
    summaries = re.findall(r"Complete - ([0-9]+) successfully verified harnesses, ([0-9]+) failures, ([0-9]+) total\.", log)
    return (symbols <= set(checked) and len(summaries) == len(COMMANDS[engine])
            and all(int(success) > 0 and int(failed) == 0 and success == total for success, failed, total in summaries)
            and sum(int(total) for _, _, total in summaries) == len(checked))


def run(engine, output):
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.unlink(missing_ok=True)
    obligations = mapped_obligations()
    before = snapshot(engine)
    version_commands = [["cargo", "--version"], ["rustc", "--version"],
                        ["verus", "--version"] if engine == "verus" else ["cargo", "kani", "--version"]]
    tool_versions = {}
    for command in version_commands:
        version = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        if version.returncode:
            raise ValueError("cannot record tool version: " + " ".join(command))
        tool_versions[" ".join(command)] = version.stdout.strip()
    logs = []
    for command in COMMANDS[engine]:
        print("Running " + " ".join(command), flush=True)
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        print(result.stdout, end="", flush=True)
        logs.append(result.stdout)
        if result.returncode:
            output.with_suffix(".log").write_text("\n".join(logs))
            raise ValueError(f"{engine} failed with exit {result.returncode}; no success receipt written")
    log = "\n".join(logs)
    if snapshot(engine) != before:
        raise ValueError("proof sources changed while verification ran")
    if not log_success(engine, log, obligations):
        raise ValueError(f"{engine}: missing successful complete verifier output")
    log_path = output.with_suffix(".log")
    log_path.write_text(log)
    receipt = {"format_version": 1, "engine": engine, "commands": COMMANDS[engine], "success": True, "sources": before, "obligations": sorted(proof_id for proof_id, obligation in obligations.items() if obligation["engine"] == engine), "log": log_path.name, "log_sha256": digest(log_path), "tool_versions": tool_versions}
    output.write_text(json.dumps(receipt, indent=2) + "\n")


def check(artifacts, source_only=False):
    obligations = mapped_obligations()
    print(f"{len(obligations)} unique proof obligations; {sum(len(o['invariants']) for o in obligations.values())} historical invariant-support edges")
    if source_only:
        print("Source accounting only: no successful verification claimed.")
        return
    for engine in COMMANDS:
        path = Path(artifacts) / f"{engine}.json"
        receipt = json.loads(path.read_text())
        expected = sorted(proof_id for proof_id, obligation in obligations.items() if obligation["engine"] == engine)
        if receipt.get("format_version") != 1 or receipt.get("engine") != engine or receipt.get("commands") != COMMANDS[engine] or receipt.get("success") is not True:
            raise ValueError(f"{path}: not a successful supported verifier artifact")
        if not receipt.get("tool_versions"):
            raise ValueError(f"{path}: tool versions not recorded")
        if receipt.get("sources") != snapshot(engine) or receipt.get("obligations") != expected:
            raise ValueError(f"{path}: artifacts do not cover the current complete proof snapshot")
        log_name = receipt.get("log", "")
        if Path(log_name).name != log_name:
            raise ValueError(f"{path}: invalid log path")
        log_path = path.parent / log_name
        if digest(log_path) != receipt.get("log_sha256") or not log_success(engine, log_path.read_text(), obligations):
            raise ValueError(f"{path}: missing, edited, or unsuccessful verifier log")
        print(f"{engine}: successful artifacts match current sources and mapped obligations")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("run", "check", "trust-sites"))
    parser.add_argument("--engine", choices=sorted(COMMANDS))
    parser.add_argument("--output")
    parser.add_argument("--artifacts", default="proof-results")
    parser.add_argument("--source-only", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.command == "trust-sites":
            print(trust_sites())
        elif args.command == "run":
            if args.engine is None or args.output is None:
                raise ValueError("run needs --engine and --output")
            run(args.engine, args.output)
        else:
            check(args.artifacts, args.source_only)
        return 0
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
