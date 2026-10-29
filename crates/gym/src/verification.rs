//! `planarian-gym verification`: the verification ratio d:a (discharged to
//! assumed obligations) and the trust count |𝒯| (SPEC §17a), from docs/verification-ratio.toml, checked against the
//! source and docs/assumptions.md, and held to the recorded baseline.
//!
//! The trust count is the number of assumptions.md ids (V, P, G) plus every
//! `external_body` and `assume` site in the verified crates. A discharged
//! obligation is a Verus lemma or verified function, or a Kani harness,
//! named in the file and present in the source.

use std::collections::BTreeMap;
use std::path::Path;
use toml::Value as T;

const RATIO: &str = "docs/verification-ratio.toml";
const ASSUMPTIONS: &str = "docs/assumptions.md";
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

/// `fn name` appears in the crate (a proof fn, a verified fn, a Kani harness).
fn defined(krate: &str, name: &str) -> bool {
    let pat = format!("fn {name}");
    source(krate).iter().any(|f| {
        f.match_indices(&pat)
            .any(|(i, _)| f[i + pat.len()..].chars().next().is_some_and(|c| c == '(' || c == '<' || c.is_whitespace()))
    })
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

pub fn run(write_baseline: bool) -> Report {
    let mut errors: Vec<String> = vec![];
    let doc: T = match std::fs::read_to_string(RATIO)
        .map_err(|e| e.to_string())
        .and_then(|t| toml::from_str(&t).map_err(|e| e.to_string()))
    {
        Ok(d) => d,
        Err(e) => return Report { text: format!("{RATIO}: {e}"), ok: false },
    };
    let assumptions = std::fs::read_to_string(ASSUMPTIONS).unwrap_or_default();
    let ids: Vec<String> = ["V", "P", "G"]
        .iter()
        .flat_map(|p| (1..=40).map(move |n| format!("{p}{n}")))
        .filter(|id| assumptions.contains(&format!("**{id}**")))
        .collect();
    let trust_count = ids.len() + trust_sites();

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
            match n.split_once("::") {
                Some((k, f)) if defined(k, f) => {}
                _ => errors.push(format!("{id}: {n} is not defined in the source")),
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

    // The ratchet: neither the global nor any per-invariant ratio falls, and
    // the trust count does not grow.
    let base = doc.get("baseline");
    let b = |k: &str| base.and_then(|b| b.get(k)).and_then(T::as_integer).unwrap_or(0) as usize;
    if !write_baseline && base.is_some() {
        if trust_count > b("trust_count") {
            errors.push(format!("the trust count grew: {trust_count} > {}", b("trust_count")));
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

    let mut text = format!(
        "verification ratio (SPEC §17a)\n  trust count: {trust_count} ({} assumptions.md entries + {} external_body/assume sites)\n  global d:a: {d_sum}:{a_sum} ({:.2})\n",
        ids.len(),
        trust_count - ids.len(),
        if a_sum == 0 { 0.0 } else { d_sum as f64 / a_sum as f64 }
    );
    text.push_str(&lines.join("\n"));
    text.push('\n');
    if write_baseline {
        let per_s: Vec<String> = per.iter().map(|(k, (d, a))| format!("{k} = [{d}, {a}]")).collect();
        text.push_str(&format!(
            "\n[baseline]\ntrust_count = {trust_count}\ndischarged = {d_sum}\nassumed = {a_sum}\n\n[baseline.per_invariant]\n{}\n",
            per_s.join("\n")
        ));
    }
    for e in &errors {
        text.push_str(&format!("  ERROR: {e}\n"));
    }
    Report { text, ok: errors.is_empty() }
}
