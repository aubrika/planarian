//! planarian-gym: runs catalog entries (SPEC §15).
//!
//!   planarian-gym list    [--catalog FILE]
//!   planarian-gym run     [--catalog FILE] --harness fake [--id ID ...] [--all]
//!   planarian-gym show-reconciliation --harness fake --id ID
//!   planarian-gym verification [--write-baseline] [--gate]   d:a, trust and bypass report (§17a, §17b)
//!
//! The fake harness runs the real daemon core, executor, kernel and watchdog
//! logic against the in-memory machine (`planarian-fake`). The VM harness is
//! the flake's NixOS tests (`nix flake check`, `checks.vm-runtime`).

mod check;
mod conformance;
mod evidence;
mod live;
mod metrics;
mod serve;
mod sim;
#[cfg(test)]
mod tests;
mod verification;

use sim::Sim;
use toml::Value as T;

const DEFAULT_CATALOG: &str = "crates/gym/catalog/phase-a.toml";

/// The catalog being run, for entries that run others (the conformance matrix).
static CATALOG: std::sync::OnceLock<Vec<T>> = std::sync::OnceLock::new();

#[derive(Debug, PartialEq, Eq, Clone, Copy, PartialOrd, Ord)]
enum Result_ {
    Pass,
    Partial,
    Fail,
    Unsupported,
    NotFake,
}

struct Run {
    result: Result_,
    notes: Vec<String>,
    sim: Option<Sim>,
}

fn steps(entry: &T, key: &str) -> Vec<T> {
    match entry.get(key) {
        Some(T::Array(a)) => a.clone(),
        Some(t @ T::Table(_)) => vec![t.clone()],
        _ => vec![],
    }
}

pub fn window(entry: &T) -> planarian_schema::Millis {
    let s = entry.get("window").and_then(T::as_str).unwrap_or("10m");
    let n: u64 = s.trim_end_matches(|c: char| c.is_alphabetic()).parse().unwrap_or(10);
    planarian_schema::Millis(if s.ends_with('h') {
        n * 3_600_000
    } else if s.ends_with('s') && !s.ends_with("ms") {
        n * 1000
    } else {
        n * 60_000
    })
}

fn run_entry(entry: &T) -> Run {
    let fake = entry.get("harness").and_then(T::as_array).is_some_and(|h| h.iter().any(|x| x.as_str() == Some("fake")));
    if !fake {
        return Run { result: Result_::NotFake, notes: vec!["VM-only entry".into()], sim: None };
    }
    // A matrix entry (fake-assumptions-conformance) runs the conformance suite.
    if entry.get("matrix").is_some() {
        let catalog = CATALOG.get().cloned().unwrap_or_default();
        let (ok, notes) = conformance::run(&catalog);
        return Run { result: if ok { Result_::Pass } else { Result_::Fail }, notes, sim: None };
    }
    let mut sim = Sim::new();
    let setup = steps(entry, "setup");
    let inject = steps(entry, "inject");
    let after = steps(entry, "after");
    let all: Vec<&T> = setup.iter().chain(inject.iter()).chain(after.iter()).collect();
    let (consumed, crash) = sim.arm(&all);
    // Let the machine settle into its healthy steady state first.
    for _ in 0..3 {
        sim.tick();
    }
    sim.begin();
    for (i, s) in all.iter().enumerate() {
        if consumed.contains(&i) {
            continue;
        }
        match &crash {
            Some((j, p)) if *j == i => sim.set_crash(Some(p.clone())),
            _ => sim.set_crash(None),
        }
        if let Err(u) = sim.step(s) {
            return Run { result: Result_::Unsupported, notes: vec![u.0], sim: Some(sim) };
        }
    }
    sim.set_crash(None);
    sim.run_window(window(entry));
    let post = entry.get("required_post").cloned().unwrap_or(T::Table(Default::default()));
    let v = check::judge(&sim.evidence(), &post);
    let mut notes = v.failures.clone();
    notes.extend(v.unchecked.iter().map(|u| format!("unchecked: {u}")));
    let result = if !v.failures.is_empty() {
        Result_::Fail
    } else if !v.unchecked.is_empty() {
        Result_::Partial
    } else {
        Result_::Pass
    };
    Run { result, notes, sim: Some(sim) }
}

fn load(path: &str) -> Vec<T> {
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| {
        eprintln!("{path}: {e}");
        std::process::exit(2)
    });
    let doc: T = toml::from_str(&text).unwrap_or_else(|e| {
        eprintln!("{path}: {e}");
        std::process::exit(2)
    });
    let entries = doc.get("fault").and_then(T::as_array).cloned().unwrap_or_default();
    if let Err(error) = validate_catalog(&entries) {
        eprintln!("{path}: {error}");
        std::process::exit(2);
    }
    entries
}

fn validate_catalog(entries: &[T]) -> Result<(), String> {
    let mut ids = std::collections::BTreeSet::new();
    if entries.is_empty() {
        return Err("catalog contains no faults".into());
    }
    for entry in entries {
        let id = entry.get("id").and_then(T::as_str).unwrap_or("");
        if id.is_empty() || !id.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-') {
            return Err(format!("invalid catalog id: {id:?}"));
        }
        if !ids.insert(id) {
            return Err(format!("duplicate catalog id: {id}"));
        }
        if !matches!(entry.get("scoring").and_then(T::as_str), Some("must-pass" | "intent" | "repair")) {
            return Err(format!("{id}: missing or invalid acceptance role"));
        }
        let harnesses = entry.get("harness").and_then(T::as_array).ok_or_else(|| format!("{id}: no harness"))?;
        let mut seen = std::collections::BTreeSet::new();
        if harnesses.is_empty()
            || harnesses.iter().any(|h| !matches!(h.as_str(), Some("fake" | "vm" | "bench")) || !seen.insert(h.as_str()))
        {
            return Err(format!("{id}: invalid harness applicability"));
        }
    }
    Ok(())
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("verification") {
        let r = verification::run(args.iter().any(|a| a == "--write-baseline"), args.iter().any(|a| a == "--gate"));
        print!("{}", r.text);
        std::process::exit(if r.ok { 0 } else { 1 });
    }
    if args.first().map(String::as_str) == Some("vm") {
        // The VM harness's in-VM half (live.rs).
        let catalog = args
            .iter()
            .position(|a| a == "--catalog")
            .and_then(|i| args.get(i + 1))
            .cloned()
            .or_else(|| std::env::var("PLANARIAN_GYM_CATALOG").ok())
            .unwrap_or_else(|| DEFAULT_CATALOG.to_string());
        std::process::exit(live::main(&args[1..], &load(&catalog)));
    }
    let mut catalog = DEFAULT_CATALOG.to_string();
    let mut ids: Vec<String> = vec![];
    let mut harness = "fake".to_string();
    let mut verbose = false;
    let mut show_notices = false;
    let mut verdict_dir: Option<std::path::PathBuf> = None;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--catalog" => {
                catalog = args.get(i + 1).cloned().unwrap_or_default();
                i += 1;
            }
            "--id" => {
                ids.push(args.get(i + 1).cloned().unwrap_or_default());
                i += 1;
            }
            "--harness" => {
                harness = args.get(i + 1).cloned().unwrap_or_default();
                i += 1;
            }
            "--all" => {}
            "--socket" => i += 1,
            "-v" | "--verbose" => verbose = true,
            "--notices" => show_notices = true,
            // Kept for old invocations; applicable UNSUPPORTED now always
            // fails. Reviewed scoped waivers are interpreted by acceptance.py.
            "--strict" => {}
            "--verdict-dir" => {
                verdict_dir = args.get(i + 1).map(std::path::PathBuf::from);
                i += 1;
            }
            other => {
                eprintln!("unknown argument {other}");
                std::process::exit(2);
            }
        }
        i += 1;
    }
    let entries = load(&catalog);
    let mut requested = std::collections::BTreeSet::new();
    for id in &ids {
        if !requested.insert(id) || !entries.iter().any(|entry| entry.get("id").and_then(T::as_str) == Some(id)) {
            eprintln!("duplicate or unknown requested id: {id}");
            std::process::exit(2);
        }
    }
    if let Some(dir) = &verdict_dir {
        std::fs::create_dir_all(dir).unwrap_or_else(|error| {
            eprintln!("{}: {error}", dir.display());
            std::process::exit(2);
        });
    }
    let _ = CATALOG.set(entries.clone());
    let cmd = args.first().map(String::as_str).unwrap_or("list");
    if !matches!(harness.as_str(), "fake" | "vm") {
        eprintln!("unknown harness: {harness}");
        std::process::exit(2);
    }
    if harness == "vm" && cmd != "list" {
        eprintln!("The VM harness runs as NixOS tests: `nix build .#checks.x86_64-linux.vm-runtime` (needs KVM).");
        std::process::exit(2);
    }
    let selected: Vec<&T> = entries
        .iter()
        .filter(|e| ids.is_empty() || ids.iter().any(|id| e.get("id").and_then(T::as_str) == Some(id)))
        .collect();
    if selected.is_empty() {
        eprintln!("no catalog entries matched {ids:?}");
        std::process::exit(2);
    }
    if cmd == "run" && !ids.is_empty() {
        for entry in &selected {
            if !entry
                .get("harness")
                .and_then(T::as_array)
                .is_some_and(|hs| hs.iter().any(|h| h.as_str() == Some(harness.as_str())))
            {
                eprintln!(
                    "requested entry is not applicable to {harness}: {}",
                    entry.get("id").and_then(T::as_str).unwrap_or("?")
                );
                std::process::exit(2);
            }
        }
    }
    match cmd {
        "list" => {
            for e in selected {
                println!(
                    "{:<44} {:<36} {:<10} {}",
                    e.get("id").and_then(T::as_str).unwrap_or(""),
                    e.get("family").and_then(T::as_str).unwrap_or(""),
                    e.get("scoring").and_then(T::as_str).unwrap_or(""),
                    e.get("harness").map(|h| h.to_string()).unwrap_or_default()
                );
            }
        }
        "run" => {
            let mut worst = Result_::Pass;
            let mut tally = std::collections::BTreeMap::new();
            let mut metrics = metrics::Metrics::default();
            for e in selected {
                let id = e.get("id").and_then(T::as_str).unwrap_or("?");
                if let Some(dir) = &verdict_dir {
                    let path = dir.join(format!("{id}.json"));
                    if path.exists() {
                        std::fs::remove_file(&path).unwrap_or_else(|error| {
                            eprintln!("{}: {error}", path.display());
                            std::process::exit(2);
                        });
                    }
                }
                let r = run_entry(e);
                if r.result != Result_::NotFake && let Some(dir) = &verdict_dir {
                    let verdict = serde_json::json!({
                        "id": id,
                        "result": format!("{:?}", r.result).to_uppercase(),
                        "role": e.get("scoring").and_then(T::as_str),
                        "harness": "fake",
                        "notes": r.notes,
                    });
                    let path = dir.join(format!("{id}.json"));
                    std::fs::write(&path, verdict.to_string()).unwrap_or_else(|error| {
                        eprintln!("{}: {error}", path.display());
                        std::process::exit(2);
                    });
                }
                metrics.add(e, r.result == Result_::Pass, r.result == Result_::Partial, r.sim.as_ref());
                *tally.entry(format!("{:?}", r.result)).or_insert(0) += 1;
                if r.result != Result_::NotFake {
                    worst = worst.max(r.result);
                }
                println!("{:<12} {id}", format!("{:?}", r.result).to_uppercase());
                if verbose || r.result == Result_::Fail || r.result == Result_::Unsupported {
                    for n in &r.notes {
                        println!("             {n}");
                    }
                }
                if show_notices && let Some(sim) = &r.sim {
                    for n in &sim.notices {
                        println!("             notice: {n}");
                    }
                    for r in &sim.responses {
                        println!("             response: {r:?}");
                    }
                }
            }
            println!("\n{tally:?}");
            println!("\n{metrics}");
            // Applicability comes from the catalog. An applicable required
            // case cannot disappear behind an UNSUPPORTED verdict.
            let failed = tally.contains_key("Fail") || tally.contains_key("Partial");
            // Exit 3 is exclusively unsupported coverage; the wrapper may
            // accept it only after validating reviewed scoped waivers. A
            // failing execution keeps exit 1 even if another case is waived.
            std::process::exit(if failed { 1 } else if worst == Result_::Unsupported { 3 } else { 0 });
        }
        "serve" => {
            let socket = args.iter().position(|a| a == "--socket").and_then(|i| args.get(i + 1)).cloned();
            serve::serve(&socket.unwrap_or_else(|| "/tmp/planarian-gym.sock".into()));
        }
        "show-reconciliation" => {
            let r = run_entry(selected[0]);
            let Some(sim) = r.sim else { std::process::exit(1) };
            match sim.ledger().last_reconciliation {
                Some(rec) => {
                    println!("by {:?}", rec.by);
                    for a in rec.actions {
                        println!("  {a}");
                    }
                }
                None => {
                    println!("no reconciliation record");
                    std::process::exit(1);
                }
            }
        }
        other => {
            eprintln!("unknown command {other}");
            std::process::exit(2);
        }
    }
}
