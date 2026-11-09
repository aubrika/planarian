//! `planarian-unitclass`: the build-time classifier of raw unit files and the
//! hold verifier (docs/raw-unit-classification.md).
//!
//!   classify --out DIR [--netwatch] [--cycle NAME]... [--own NAME]...
//!            [--have-hold NAME]... PKG...
//!   verify-hold --units DIR --tools FILE [--netwatch] [--cycle NAME]...
//!   check FILE
//!   show --units DIR UNIT.service   (the effective settings as JSON)
//!
//! Exit status: 0 success; 1 a hold is not in force (verify-hold) or FILE is
//! not a sorted list of unique names (check); 2 usage; 3 an I/O error. A unit
//! it cannot read exactly is a tool, not an error. A nonzero exit is never an
//! empty list of tools.

use planarian_unitclass::tree;
use std::collections::BTreeSet;
use std::path::PathBuf;
use std::process::ExitCode;

fn usage() -> ExitCode {
    eprintln!(
        "usage: planarian-unitclass classify --out DIR [--netwatch] [--cycle NAME]... [--own NAME]... [--have-hold NAME]... PKG..."
    );
    eprintln!("       planarian-unitclass verify-hold --units DIR --tools FILE [--netwatch] [--cycle NAME]...");
    eprintln!("       planarian-unitclass check FILE");
    eprintln!("       planarian-unitclass show --units DIR UNIT.service");
    ExitCode::from(2)
}

/// A JSON array of strings, as `names_json` writes it.
pub fn names_json(names: &[String]) -> String {
    let mut s = String::from("[");
    for (i, n) in names.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        s.push('"');
        for c in n.chars() {
            match c {
                '"' => s.push_str("\\\""),
                '\\' => s.push_str("\\\\"),
                c if (c as u32) < 0x20 => s.push_str(&format!("\\u{:04x}", c as u32)),
                c => s.push(c),
            }
        }
        s.push('"');
    }
    s.push_str("]\n");
    s
}

/// Parse what `names_json` writes (and only that): `[]` or `["a","b"]` with
/// the escapes `\"` and `\\`.
fn parse_names_json(text: &str) -> Option<Vec<String>> {
    let t = text.trim();
    let inner = t.strip_prefix('[')?.strip_suffix(']')?.trim();
    let mut out = Vec::new();
    if inner.is_empty() {
        return Some(out);
    }
    let mut chars = inner.chars().peekable();
    loop {
        if chars.next()? != '"' {
            return None;
        }
        let mut cur = String::new();
        loop {
            match chars.next()? {
                '"' => break,
                '\\' => match chars.next()? {
                    '"' => cur.push('"'),
                    '\\' => cur.push('\\'),
                    _ => return None,
                },
                c => cur.push(c),
            }
        }
        out.push(cur);
        match chars.next() {
            None => return Some(out),
            Some(',') => {}
            Some(_) => return None,
        }
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("classify") => classify(&args[1..]),
        Some("verify-hold") => verify(&args[1..]),
        Some("check") => check(&args[1..]),
        Some("show") => show(&args[1..]),
        _ => usage(),
    }
}

struct Opts {
    out: Option<PathBuf>,
    units: Option<PathBuf>,
    tools: Option<PathBuf>,
    netwatch: bool,
    cycle: BTreeSet<String>,
    own: BTreeSet<String>,
    have_hold: BTreeSet<String>,
    rest: Vec<String>,
}

fn opts(args: &[String]) -> Option<Opts> {
    let mut o = Opts {
        out: None,
        units: None,
        tools: None,
        netwatch: false,
        cycle: BTreeSet::new(),
        own: BTreeSet::new(),
        have_hold: BTreeSet::new(),
        rest: Vec::new(),
    };
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--out" => o.out = Some(it.next()?.into()),
            "--units" => o.units = Some(it.next()?.into()),
            "--tools" => o.tools = Some(it.next()?.into()),
            "--netwatch" => o.netwatch = true,
            "--cycle" => {
                o.cycle.insert(it.next()?.clone());
            }
            "--own" => {
                o.own.insert(it.next()?.clone());
            }
            "--have-hold" => {
                o.have_hold.insert(it.next()?.clone());
            }
            s if s.starts_with("--") => return None,
            _ => o.rest.push(a.clone()),
        }
    }
    Some(o)
}

fn classify(args: &[String]) -> ExitCode {
    let Some(o) = opts(args) else { return usage() };
    let Some(out) = o.out else { return usage() };
    let roots: Vec<PathBuf> = o.rest.iter().flat_map(|p| tree::package_roots(std::path::Path::new(p))).collect();
    let own = |n: &str| o.own.contains(n) || n.split_once('@').is_some_and(|(t, _)| o.own.contains(&format!("{t}@")));
    let tools = match tree::classify(&roots, &own) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("planarian-unitclass: {e}");
            return ExitCode::from(3);
        }
    };
    let mut names = Vec::new();
    for t in &tools {
        if let Some(why) = &t.unreadable {
            eprintln!("planarian-unitclass: {}: a network tool because it cannot be read exactly: {why}", t.name);
        }
        names.push(t.name.clone());
        if o.have_hold.contains(&t.name) {
            continue;
        }
        let dir = out.join("lib/systemd/system").join(format!("{}.service.d", t.name));
        let content = tree::hold_dropin(o.netwatch, !o.cycle.contains(&t.name));
        if let Err(e) =
            std::fs::create_dir_all(&dir).and_then(|_| std::fs::write(dir.join("50-planarian-hold.conf"), content))
        {
            eprintln!("planarian-unitclass: {}: {e}", dir.display());
            return ExitCode::from(3);
        }
    }
    let share = out.join("share/planarian");
    if let Err(e) = std::fs::create_dir_all(&share)
        .and_then(|_| std::fs::write(share.join("raw-network-tools.json"), names_json(&names)))
    {
        eprintln!("planarian-unitclass: {e}");
        return ExitCode::from(3);
    }
    ExitCode::SUCCESS
}

fn verify(args: &[String]) -> ExitCode {
    let Some(o) = opts(args) else { return usage() };
    let (Some(units), Some(tools)) = (o.units, o.tools) else { return usage() };
    let text = match std::fs::read_to_string(&tools) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("planarian-unitclass: {}: {e}", tools.display());
            return ExitCode::from(3);
        }
    };
    let mut bad = 0;
    for tool in text.lines().map(str::trim).filter(|l| !l.is_empty()) {
        if let Some(p) = tree::hold_problem(&units, tool, o.netwatch && !o.cycle.contains(tool)) {
            eprintln!("planarian-unitclass: the hold is not in force: {p}");
            eprintln!(
                "planarian-unitclass: restore the hold's drop-in for that unit (or remove the file that shadows it): a network tool's failure must hold traffic (SPEC §12d)"
            );
            bad += 1;
        }
    }
    if bad > 0 { ExitCode::from(1) } else { ExitCode::SUCCESS }
}

fn check(args: &[String]) -> ExitCode {
    let [file] = args else { return usage() };
    let Ok(text) = std::fs::read_to_string(file) else {
        eprintln!("planarian-unitclass: cannot read {file}");
        return ExitCode::from(3);
    };
    match parse_names_json(&text) {
        Some(n) if n.windows(2).all(|w| w[0] < w[1]) => ExitCode::SUCCESS,
        _ => {
            eprintln!("planarian-unitclass: {file} is not a sorted JSON array of unique names");
            ExitCode::from(1)
        }
    }
}

/// `show --units DIR UNIT.service`: the effective settings of one unit in a
/// merged tree, as JSON (an instance reads its template's file).
fn show(args: &[String]) -> ExitCode {
    let Some(o) = opts(args) else { return usage() };
    let (Some(units), [unit]) = (o.units, o.rest.as_slice()) else { return usage() };
    let mut main = units.join(unit);
    if std::fs::symlink_metadata(&main).is_err() {
        let Some((t, _)) = unit.strip_suffix(".service").and_then(|s| s.split_once('@')) else {
            eprintln!("planarian-unitclass: no {unit} in {}", units.display());
            return ExitCode::from(3);
        };
        main = units.join(format!("{t}@.service"));
    }
    match tree::effective(std::slice::from_ref(&units), unit, &main) {
        Ok(s) => {
            println!("{}", s.to_json(planarian_unitclass::rule::is_network_tool(&s)));
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("planarian-unitclass: {e}");
            ExitCode::from(1)
        }
    }
}
