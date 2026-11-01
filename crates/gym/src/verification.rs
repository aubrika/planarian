//! `planarian-gym verification`: the verification ratio d:a (discharged to
//! assumed obligations), the trust count |𝒯| and the internal-unproven count
//! (SPEC §17a), from docs/verification-ratio.toml, checked against the source
//! and docs/assumptions.md, and held to the recorded baseline; and the bypass
//! register, docs/bypasses.md (§17b): its format, and its open rows by
//! severity. `--gate` also fails on an open High row (every gate does).
//!
//! The trust count is the number of platform and proof-validity ids in
//! assumptions.md (P, G, V) plus every `external_body` and `assume` site in
//! the verified crates. The internal-unproven count is the number of U ids:
//! Planarian's own unproven code that the proven gates take input from. A
//! discharged obligation is a Verus lemma or verified function, or a Kani
//! harness, named in the file and present in the source.

use std::collections::BTreeMap;
use std::path::Path;
use toml::Value as T;

const RATIO: &str = "docs/verification-ratio.toml";
const ASSUMPTIONS: &str = "docs/assumptions.md";
const BYPASSES: &str = "docs/bypasses.md";
const CATALOG: &str = "crates/gym/catalog/phase-a.toml";
const VERIFIED: &[&str] = &["crates/policy/src", "crates/schema/src", "crates/txn/src"];

fn rust_files(dir: &Path, out: &mut Vec<String>) {
    for e in std::fs::read_dir(dir).into_iter().flatten().flatten() {
        let p = e.path();
        if p.is_dir() {
            rust_files(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(std::fs::read_to_string(&p).unwrap_or_default());
        }
    }
}

fn source(krate: &str) -> Vec<String> {
    let mut v = vec![];
    rust_files(&Path::new("crates").join(krate).join("src"), &mut v);
    v
}

/// What discharges an obligation (§17a, R14): a Verus `proof fn` or a
/// function verified against its `ensures`, inside `verus!`; or a Kani
/// harness (`#[kani::proof]`). A name that is only present (a plain
/// function, a test, a comment) discharges nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Discharge {
    Verus,
    Kani,
}

pub fn discharge_in(files: &[String], name: &str) -> Option<Discharge> {
    let pat = format!("fn {name}");
    for f in files {
        for (i, _) in f.match_indices(&pat) {
            let after = &f[i + pat.len()..];
            if !after.chars().next().is_some_and(|c| c == '(' || c == '<') {
                continue;
            }
            let line_start = f[..i].rfind('\n').map_or(0, |n| n + 1);
            // The attributes directly above the function, and only those.
            let attrs: Vec<&str> =
                f[..line_start].lines().rev().map(str::trim_start).take_while(|l| l.starts_with("#[")).collect();
            if attrs.iter().any(|l| l.starts_with("#[kani::proof")) {
                return Some(Discharge::Kani);
            }
            if !f[..i].contains("verus!") {
                continue;
            }
            let head = &after[..after.find('{').unwrap_or(after.len())];
            if f[line_start..i].contains("proof ") || head.contains("ensures") {
                return Some(Discharge::Verus);
            }
        }
    }
    None
}

fn discharge(krate: &str, name: &str) -> Option<Discharge> {
    discharge_in(&source(krate), name)
}

/// R14's structural checks on the accounting, apart from the source: no
/// invariant listed twice, no obligation listed twice under one invariant,
/// and every invariant of the baseline still accounted.
pub fn structure_errors(doc: &T) -> Vec<String> {
    let mut errors = vec![];
    let mut seen = std::collections::BTreeSet::new();
    for inv in doc.get("invariant").and_then(T::as_array).into_iter().flatten() {
        let id = inv.get("id").and_then(T::as_str).unwrap_or("?");
        if !seen.insert(id.to_string()) {
            errors.push(format!("{id} is accounted twice"));
        }
        let mut names = std::collections::BTreeSet::new();
        for n in inv.get("discharged").and_then(T::as_array).into_iter().flatten().filter_map(T::as_str) {
            if !names.insert(n) {
                errors.push(format!("{id}: {n} is listed twice"));
            }
        }
    }
    if let Some(bp) = doc.get("baseline").and_then(|b| b.get("per_invariant")).and_then(T::as_table) {
        for id in bp.keys() {
            if !seen.contains(id) {
                errors.push(format!("{id} is in the baseline but no longer accounted (a removed invariant fails)"));
            }
        }
    }
    errors
}

/// `external_body` attributes and `assume(` calls in the verified crates
/// (Kani's input bounds, `kani::assume`, are not trust).
fn trust_sites() -> usize {
    let mut files = vec![];
    for d in VERIFIED {
        rust_files(Path::new(d), &mut files);
    }
    files
        .iter()
        .map(|f| {
            f.matches("#[verifier::external_body]").count()
                + f.lines().filter(|l| l.contains("assume(") && !l.contains("kani::assume")).count()
        })
        .sum()
}

pub struct Report {
    pub text: String,
    pub ok: bool,
}

/// The bypass register's open rows by severity, and its format errors.
fn bypasses() -> (BTreeMap<String, Vec<String>>, Vec<String>) {
    match std::fs::read_to_string(BYPASSES) {
        Ok(text) => parse_bypasses(&text),
        Err(_) => (BTreeMap::new(), vec![format!("{BYPASSES} is missing")]),
    }
}

pub fn parse_bypasses(text: &str) -> (BTreeMap<String, Vec<String>>, Vec<String>) {
    let mut open: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut errors = vec![];
    let mut seen = std::collections::BTreeSet::new();
    for line in text.lines() {
        let cells: Vec<&str> = line.trim().trim_matches('|').split('|').map(str::trim).collect();
        let id = cells.first().copied().unwrap_or("");
        let (kind, width) = match id.split_once('-') {
            Some(("B", n)) if n.parse::<u32>().is_ok() => ('B', 8),
            Some(("X", n)) if n.parse::<u32>().is_ok() => ('X', 6),
            _ => continue,
        };
        if !seen.insert(id.to_string()) {
            errors.push(format!("{BYPASSES}: {id} appears twice (ids are never reused)"));
        }
        if cells.len() != width {
            errors.push(format!("{BYPASSES}: {id} has {} cells, want {width}", cells.len()));
            continue;
        }
        // §17c: every row names the invariants it limits, or `all`, or `—`.
        let invariants = cells[width - 1];
        let named = invariants == "all"
            || invariants == "—"
            || invariants
                .split(',')
                .map(str::trim)
                .all(|i| i.strip_prefix('I').is_some_and(|n| n.parse::<u32>().is_ok()));
        if invariants.is_empty() || !named {
            errors.push(format!("{BYPASSES}: {id}: invariants {invariants:?} is not a list of ids, `all` or `—`"));
        }
        if kind == 'X' {
            continue;
        }
        let (severity, status) = (cells[3], cells[4]);
        if !matches!(severity, "High" | "Medium" | "Low") {
            errors.push(format!("{BYPASSES}: {id}: severity {severity:?} is not High, Medium or Low"));
        }
        if status.starts_with("Open") {
            open.entry(severity.to_string()).or_default().push(id.to_string());
        } else if !(status.starts_with("Closed (") && status.ends_with(')')) {
            errors.push(format!("{BYPASSES}: {id}: status {status:?} is neither Open… nor Closed (<commit>)"));
        }
    }
    (open, errors)
}

pub fn run(write_baseline: bool, gate: bool) -> Report {
    let mut errors: Vec<String> = vec![];
    let doc: T = match std::fs::read_to_string(RATIO)
        .map_err(|e| e.to_string())
        .and_then(|t| toml::from_str(&t).map_err(|e| e.to_string()))
    {
        Ok(d) => d,
        Err(e) => return Report { text: format!("{RATIO}: {e}"), ok: false },
    };
    let assumptions = std::fs::read_to_string(ASSUMPTIONS).unwrap_or_default();
    let ids: Vec<String> = ["V", "P", "G", "U"]
        .iter()
        .flat_map(|p| (1..=40).map(move |n| format!("{p}{n}")))
        .filter(|id| assumptions.contains(&format!("**{id}**")))
        .collect();
    let internal = ids.iter().filter(|i| i.starts_with('U')).count();
    let trust_ids = ids.len() - internal;
    let trust_count = trust_ids + trust_sites();

    errors.extend(structure_errors(&doc));
    let mut used: BTreeMap<(String, Discharge), std::collections::BTreeSet<String>> = BTreeMap::new();
    let mut lines = vec![];
    let mut per: BTreeMap<String, (usize, usize)> = BTreeMap::new();
    let (mut d_sum, mut a_sum) = (0usize, 0usize);
    for inv in doc.get("invariant").and_then(T::as_array).into_iter().flatten() {
        let id = inv.get("id").and_then(T::as_str).unwrap_or("?").to_string();
        let names: Vec<&str> =
            inv.get("discharged").and_then(T::as_array).into_iter().flatten().filter_map(T::as_str).collect();
        let assumes: Vec<&str> =
            inv.get("assumes").and_then(T::as_array).into_iter().flatten().filter_map(T::as_str).collect();
        for n in &names {
            match n.split_once("::").map(|(k, f)| (k, discharge(k, f))) {
                Some((k, Some(d))) => {
                    used.entry((k.to_string(), d)).or_default().insert(n.to_string());
                }
                _ => errors.push(format!(
                    "{id}: {n} is not a proof fn, a verified fn with ensures, or a Kani harness in the source"
                )),
            }
        }
        for a in &assumes {
            if !ids.iter().any(|x| x == a) {
                errors.push(format!("{id}: assumption {a} is not in {ASSUMPTIONS}"));
            }
        }
        let (d, a) = (names.len(), assumes.len());
        d_sum += d;
        a_sum += a;
        per.insert(id.clone(), (d, a));
        let phase = inv.get("phase").and_then(T::as_str).unwrap_or("");
        lines.push(format!(
            "  {id:<4} rests on {d} discharged and {a} assumed ({}){}",
            if a == 0 { "-".into() } else { format!("{:.2}", d as f64 / a as f64) },
            if d == 0 { format!("; {phase}: tested, not proved") } else { String::new() }
        ));
    }

    // R14: tied to the verifier's output. `[verifier]` records what the
    // Verus run reports per crate ("N verified"); the Verus flake check
    // fails when its log disagrees. No crate can be credited with more
    // distinct Verus obligations than its run verifies.
    let verifier = doc.get("verifier").and_then(T::as_table);
    if verifier.is_none() {
        errors.push("no [verifier] counts: obligations are not tied to the verifier's output".into());
    }
    for ((k, d), names) in &used {
        if *d != Discharge::Verus {
            continue;
        }
        let verified = verifier.and_then(|v| v.get(k.as_str())).and_then(T::as_integer).unwrap_or(0) as usize;
        if names.len() > verified {
            errors.push(format!(
                "{k}: {} distinct Verus obligations credited, but its Verus run verifies {verified}",
                names.len()
            ));
        }
    }

    // §17a: every proved invariant has a catalog entry written from its
    // English (tag `english`), so a wrong specification shows up as a failure.
    let english: Vec<String> = std::fs::read_to_string(CATALOG)
        .ok()
        .and_then(|t| toml::from_str::<T>(&t).ok())
        .and_then(|d| d.get("fault").and_then(T::as_array).cloned())
        .unwrap_or_default()
        .iter()
        .filter(|e| {
            e.get("tags").and_then(T::as_array).is_some_and(|t| t.iter().any(|x| x.as_str() == Some("english")))
        })
        .flat_map(|e| e.get("spec").and_then(T::as_array).cloned().unwrap_or_default())
        .filter_map(|x| x.as_str().map(String::from))
        .collect();
    let unwritten: Vec<&String> =
        per.iter().filter(|(id, (d, _))| *d > 0 && !english.contains(id)).map(|(id, _)| id).collect();
    if !unwritten.is_empty() {
        errors.push(format!(
            "proved without an entry written from the English (§17a): {}",
            unwritten.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
        ));
    }

    // The ratchet: neither the global nor any per-invariant ratio falls, and
    // the trust count does not grow.
    let base = doc.get("baseline");
    let b = |k: &str| base.and_then(|b| b.get(k)).and_then(T::as_integer).unwrap_or(0) as usize;
    if !write_baseline && base.is_some() {
        if trust_count > b("trust_count") {
            errors.push(format!("the trust count grew: {trust_count} > {}", b("trust_count")));
        }
        if internal > b("internal_unproven") {
            errors.push(format!("the internal-unproven count grew: {internal} > {}", b("internal_unproven")));
        }
        let (bd, ba) = (b("discharged"), b("assumed"));
        if ba > 0 && a_sum > 0 && (d_sum as f64 / a_sum as f64) < (bd as f64 / ba as f64) - 1e-9 {
            errors.push(format!("the global ratio fell: {d_sum}:{a_sum} < {bd}:{ba}"));
        }
        if let Some(bp) = base.and_then(|b| b.get("per_invariant")).and_then(T::as_table) {
            for (id, (d, a)) in &per {
                let Some([pd, pa]) = bp.get(id).and_then(T::as_array).map(|v| {
                    [v.first().and_then(T::as_integer).unwrap_or(0), v.get(1).and_then(T::as_integer).unwrap_or(0)]
                }) else {
                    continue;
                };
                let (pd, pa) = (pd as f64, pa as f64);
                if pa > 0.0 && *a > 0 && (*d as f64 / *a as f64) < pd / pa - 1e-9 {
                    errors.push(format!("{id}'s ratio fell: {d}:{a} < {pd}:{pa}"));
                }
            }
        }
    }

    let (open, format_errors) = bypasses();
    errors.extend(format_errors);
    let high = open.get("High").cloned().unwrap_or_default();
    if gate && !high.is_empty() {
        errors.push(format!("open High bypasses block every gate (§17b): {}", high.join(", ")));
    }
    let mut text = format!(
        "verification ratio (SPEC §17a)\n  trust count: {trust_count} ({} platform and proof-validity entries + {} external_body/assume sites)\n  internal-unproven count: {internal}\n  global d:a: {d_sum}:{a_sum} ({:.2})\n",
        trust_ids,
        trust_count - trust_ids,
        if a_sum == 0 { 0.0 } else { d_sum as f64 / a_sum as f64 }
    );
    text.push_str(&lines.join("\n"));
    text.push_str("\nbypass register (SPEC §17b)\n");
    for sev in ["High", "Medium", "Low"] {
        let ids = open.get(sev).cloned().unwrap_or_default();
        text.push_str(&format!("  open {sev}: {} {}\n", ids.len(), ids.join(" ")));
    }
    if write_baseline {
        let per_s: Vec<String> = per.iter().map(|(k, (d, a))| format!("{k} = [{d}, {a}]")).collect();
        text.push_str(&format!(
            "\n[baseline]\ntrust_count = {trust_count}\ninternal_unproven = {internal}\ndischarged = {d_sum}\nassumed = {a_sum}\n\n[baseline.per_invariant]\n{}\n",
            per_s.join("\n")
        ));
    }
    for e in &errors {
        text.push_str(&format!("  ERROR: {e}\n"));
    }
    Report { text, ok: errors.is_empty() }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// R14's gym mutations: a removed invariant, a duplicated obligation and
    /// a renamed proof function each fail; a plain function or a test of the
    /// same name discharges nothing.
    #[test]
    fn the_accounting_checks_bite() {
        let doc = |t: &str| toml::from_str::<T>(t).unwrap();
        let ok = doc("[[invariant]]\nid = \"I1\"\ndischarged = [\"txn::a\"]\n[baseline.per_invariant]\nI1 = [1, 0]\n");
        assert!(structure_errors(&ok).is_empty());
        let removed = doc("[[invariant]]\nid = \"I2\"\n[baseline.per_invariant]\nI1 = [1, 0]\n");
        assert!(!structure_errors(&removed).is_empty(), "a removed invariant");
        let dup = doc("[[invariant]]\nid = \"I1\"\ndischarged = [\"txn::a\", \"txn::a\"]\n");
        assert!(!structure_errors(&dup).is_empty(), "a duplicated obligation");
        let twice = doc("[[invariant]]\nid = \"I1\"\n[[invariant]]\nid = \"I1\"\n");
        assert!(!structure_errors(&twice).is_empty(), "an invariant twice");

        let src = vec![
            "verus! {\n    pub proof fn lemma_a(x: u8)\n        ensures x == x,\n    {}\n    pub fn decide(x: u8) -> (r: u8)\n        ensures r == x,\n    { x }\n    fn helper(x: u8) -> u8 { x }\n}\n#[kani::proof]\nfn harness_b() {}\n#[test]\nfn lemma_c() {}\n// fn lemma_d()\n".to_string(),
        ];
        assert_eq!(discharge_in(&src, "lemma_a"), Some(Discharge::Verus));
        assert_eq!(discharge_in(&src, "decide"), Some(Discharge::Verus), "verified against its ensures");
        assert_eq!(discharge_in(&src, "harness_b"), Some(Discharge::Kani));
        assert_eq!(discharge_in(&src, "helper"), None, "a plain function");
        assert_eq!(discharge_in(&src, "lemma_c"), None, "a test");
        assert_eq!(discharge_in(&src, "lemma_d"), None, "a comment");
        assert_eq!(discharge_in(&src, "lemma_renamed"), None, "a renamed proof function");
    }

    #[test]
    fn the_register_parses_and_its_checks_bite() {
        // The shipped register, where the source tree has it (the Nix
        // package build copies only the crates; CI's cargo test has docs/).
        if let Ok(shipped) = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../docs/bypasses.md")) {
            let (open, errors) = parse_bypasses(&shipped);
            assert!(errors.is_empty(), "{errors:?}");
            assert!(open.values().flatten().count() > 0);
        }
        let row = |id: &str, sev: &str, status: &str| format!("| {id} | r | b | {sev} | {status} | m | A | I1, I2 |\n");
        let bad = [
            row("B-1", "High", "Open") + &row("B-1", "Low", "Open"),
            row("B-2", "Severe", "Open"),
            row("B-3", "Low", "Done"),
            "| B-4 | r | b | Low | Open |\n".to_string(),
            "| X-1 | r | b | n |\n".to_string(),
            "| B-7 | r | b | Low | Open | m | A | |\n".to_string(),
            "| B-8 | r | b | Low | Open | m | A | everything |\n".to_string(),
        ];
        for text in bad {
            assert!(!parse_bypasses(&text).1.is_empty(), "accepted: {text}");
        }
        let (open, errors) =
            parse_bypasses(&(row("B-5", "High", "Open (v4.5)") + &row("B-6", "Low", "Closed (abc123)")));
        assert!(errors.is_empty());
        assert_eq!(open.get("High").map(Vec::len), Some(1));
        assert_eq!(open.get("Low"), None);
    }
}
