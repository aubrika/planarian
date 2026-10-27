//! planarian-gym: runs catalog entries (SPEC §15).
//!
//!   planarian-gym list    [--catalog FILE]
//!   planarian-gym run     [--catalog FILE] --harness fake [--id ID ...] [--all]
//!   planarian-gym show-reconciliation --harness fake --id ID
//!
//! The fake harness runs the real daemon core, executor, kernel and watchdog
//! logic against the in-memory machine (`planarian-fake`). The VM harness is
//! the flake's NixOS tests (`nix flake check`, `checks.vm-runtime`).

mod check;
mod serve;
mod sim;

use sim::Sim;
use toml::Value as T;

const DEFAULT_CATALOG: &str = "crates/gym/catalog/phase-a.toml";

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

fn window(entry: &T) -> planarian_schema::Millis {
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
    sim.start = sim.now();
    sim.pre_status = sim.statuses();
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
    let v = check::judge(&mut sim, &post);
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
    doc.get("fault").and_then(T::as_array).cloned().unwrap_or_default()
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut catalog = DEFAULT_CATALOG.to_string();
    let mut ids: Vec<String> = vec![];
    let mut harness = "fake".to_string();
    let mut verbose = false;
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
            other => {
                eprintln!("unknown argument {other}");
                std::process::exit(2);
            }
        }
        i += 1;
    }
    let entries = load(&catalog);
    let cmd = args.first().map(String::as_str).unwrap_or("list");
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
            for e in selected {
                let id = e.get("id").and_then(T::as_str).unwrap_or("?");
                let r = run_entry(e);
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
            }
            println!("\n{tally:?}");
            std::process::exit(match worst {
                Result_::Pass | Result_::Partial | Result_::NotFake => 0,
                _ => 1,
            });
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
