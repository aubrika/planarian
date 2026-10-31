//! `planarian-gym site`: the guarantees site (SPEC §17c). Every page is
//! computed from the repository at one commit: the invariant table (§7),
//! docs/verification-ratio.toml, docs/assumptions.md, docs/bypasses.md, the
//! gym catalog and a run's results, docs/spec-history.md and the source
//! tree. It writes an mdBook (`book.toml`, `src/`); `mdbook build` turns it
//! into the site. The build is the check: any reference it cannot resolve
//! fails it.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use toml::Value as T;

pub const SPEC: &str = "docs/SPEC.md";
pub const HISTORY: &str = "docs/spec-history.md";
pub const RATIO: &str = "docs/verification-ratio.toml";
pub const ASSUMPTIONS: &str = "docs/assumptions.md";
pub const BYPASSES: &str = "docs/bypasses.md";
pub const CATALOG: &str = "crates/gym/catalog/phase-a.toml";
/// The crates Verus checks: a function there is a verified fn.
const VERIFIED: &[&str] = &["policy", "schema", "txn"];

/// What a page needs to know about where it is published.
pub struct Opts {
    /// The commit the sources are at, and the repository (`owner/name`).
    pub commit: String,
    pub repo: String,
    /// This snapshot's name (`main`, a tag) and the other published ones.
    pub snapshot: String,
    pub others: Vec<String>,
}

/// Every file the site is built from, read once.
#[derive(Default)]
pub struct Sources {
    pub spec: String,
    pub history: String,
    pub ratio: String,
    pub assumptions: String,
    pub bypasses: String,
    pub catalog: String,
    /// `PASS id`-style lines from `planarian-gym run`, if a run was given.
    pub results: Option<String>,
    /// Per crate directory under `crates/`: the name rustdoc files it under
    /// (its package, or its binary if it has no library) and its `src/`
    /// files (path relative to the repository root, text).
    pub crates: BTreeMap<String, (String, Vec<(String, String)>)>,
}

impl Sources {
    pub fn load(root: &Path, results: Option<&Path>) -> Result<Sources, String> {
        let read = |p: &str| std::fs::read_to_string(root.join(p)).map_err(|e| format!("{p}: {e}"));
        let mut crates = BTreeMap::new();
        for e in std::fs::read_dir(root.join("crates")).map_err(|e| e.to_string())?.flatten() {
            let dir = e.path();
            let Ok(manifest) = std::fs::read_to_string(dir.join("Cargo.toml")) else { continue };
            // The name rustdoc files the crate under: the package's for a
            // library, else its first binary's.
            let field = |l: &str| l.trim().strip_prefix("name = ").map(|v| v.trim_matches('"').to_string());
            let package = manifest.lines().find_map(field).unwrap_or_default();
            let bin = manifest.split("[[bin]]").nth(1).and_then(|b| b.lines().find_map(field));
            let name = if dir.join("src/lib.rs").exists() { package } else { bin.unwrap_or(package) };
            let mut files = vec![];
            rust_files(root, &dir.join("src"), &mut files);
            files.sort();
            crates.insert(e.file_name().to_string_lossy().to_string(), (name, files));
        }
        Ok(Sources {
            spec: read(SPEC)?,
            history: read(HISTORY)?,
            ratio: read(RATIO)?,
            assumptions: read(ASSUMPTIONS)?,
            bypasses: read(BYPASSES)?,
            catalog: read(CATALOG)?,
            results: match results {
                Some(p) => Some(std::fs::read_to_string(p).map_err(|e| format!("{}: {e}", p.display()))?),
                None => None,
            },
            crates,
        })
    }
}

fn rust_files(root: &Path, dir: &Path, out: &mut Vec<(String, String)>) {
    for e in std::fs::read_dir(dir).into_iter().flatten().flatten() {
        let p = e.path();
        if p.is_dir() {
            rust_files(root, &p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            let rel = p.strip_prefix(root).unwrap_or(&p).to_string_lossy().to_string();
            out.push((rel, std::fs::read_to_string(&p).unwrap_or_default()));
        }
    }
}

// ---------- References in text ----------

/// The invariant numbers a text names: `I18`, and ranges `I1–I14`.
pub fn invariant_refs(text: &str) -> Vec<u32> {
    let b = text.as_bytes();
    let mut out = vec![];
    let mut i = 0;
    while i < b.len() {
        if !text.is_char_boundary(i) {
            i += 1;
            continue;
        }
        let prev = text[..i].chars().last();
        let starts = b[i] == b'I' && !prev.is_some_and(|p| p.is_alphanumeric() || p == '_');
        if starts && i + 1 < b.len() && b[i + 1].is_ascii_digit() {
            let mut j = i + 1;
            while j < b.len() && b[j].is_ascii_digit() {
                j += 1;
            }
            if text[j..].chars().next().is_some_and(|c| c.is_alphanumeric() || c == '_') {
                i = j;
                continue;
            }
            let n: u32 = text[i + 1..j].parse().unwrap_or(0);
            out.push(n);
            // A range: "I1–I14" or "I1-I14".
            let rest = &text[j..];
            let after = rest.strip_prefix('–').or_else(|| rest.strip_prefix('-'));
            if let Some(after) = after
                && let Some(num) = after.strip_prefix('I')
            {
                let digits: String = num.chars().take_while(char::is_ascii_digit).collect();
                if let Ok(m) = digits.parse::<u32>()
                    && m > n
                    && m - n < 40
                {
                    out.extend(n + 1..=m);
                }
            }
            i = j;
        } else {
            i += 1;
        }
    }
    let mut seen = BTreeSet::new();
    out.retain(|n| seen.insert(*n));
    out
}

/// The spec sections a text names: `§12c` → "12c", `§12 step 4` → "12".
fn section_refs(text: &str) -> Vec<String> {
    let mut out = vec![];
    for (i, _) in text.match_indices('§') {
        let rest = &text[i + '§'.len_utf8()..];
        let num: String = rest.chars().take_while(char::is_ascii_digit).collect();
        if num.is_empty() {
            continue;
        }
        let letter = rest[num.len()..].chars().next().filter(|c| c.is_ascii_lowercase() && *c != 's');
        out.push(match letter {
            Some(l) if !rest[num.len() + 1..].starts_with(|c: char| c.is_alphabetic()) => format!("{num}{l}"),
            _ => num,
        });
    }
    out
}

/// Bypass ids a text names: `B-8`, `X-12`.
fn bypass_refs(text: &str) -> Vec<String> {
    let b = text.as_bytes();
    let mut out = vec![];
    for i in 0..b.len() {
        if !text.is_char_boundary(i) {
            continue;
        }
        if (b[i] == b'B' || b[i] == b'X')
            && i + 2 < b.len()
            && b[i + 1] == b'-'
            && b[i + 2].is_ascii_digit()
            && !text[..i].chars().last().is_some_and(char::is_alphanumeric)
        {
            let digits: String = text[i + 2..].chars().take_while(char::is_ascii_digit).collect();
            let end = i + 2 + digits.len();
            if !text[end..].chars().next().is_some_and(char::is_alphanumeric) {
                out.push(format!("{}-{digits}", b[i] as char));
            }
        }
    }
    out
}

/// Markdown with §, invariant and bypass references as links, outside code
/// spans. `up` leads from the page to the snapshot root.
fn linkify(text: &str, up: &str, sections: &BTreeSet<String>, bypasses: &BTreeSet<String>) -> String {
    let mut out = String::new();
    for (k, part) in text.split('`').enumerate() {
        if k % 2 == 1 {
            out.push('`');
            out.push_str(part);
            out.push('`');
            continue;
        }
        let mut s = String::new();
        let mut rest = part;
        while !rest.is_empty() {
            let c = rest.chars().next().unwrap_or(' ');
            if c == '§' {
                let r = &rest['§'.len_utf8()..];
                let num: String = r.chars().take_while(char::is_ascii_digit).collect();
                let letter = r[num.len()..].chars().next().filter(|c| c.is_ascii_lowercase());
                let with = letter.map(|l| format!("{num}{l}"));
                let slug = match &with {
                    Some(w) if sections.contains(w) && !r[num.len() + 1..].starts_with(|c: char| c.is_alphabetic()) => {
                        Some(w.clone())
                    }
                    _ if !num.is_empty() && sections.contains(&num) => Some(num.clone()),
                    _ => None,
                };
                if let Some(slug) = slug {
                    s.push_str(&format!("[§{slug}]({up}spec/{slug}.md)"));
                    rest = &r[slug.len()..];
                    continue;
                }
            }
            let prev_alnum = s.chars().last().is_some_and(|p| p.is_alphanumeric() || p == '_');
            if (c == 'I') && !prev_alnum {
                let digits: String = rest[1..].chars().take_while(char::is_ascii_digit).collect();
                let next = rest[1 + digits.len()..].chars().next();
                if !digits.is_empty() && !next.is_some_and(|n| n.is_alphanumeric() || n == '_') {
                    s.push_str(&format!("[I{digits}]({up}invariants/I{digits}.md)"));
                    rest = &rest[1 + digits.len()..];
                    continue;
                }
            }
            if (c == 'B' || c == 'X') && !prev_alnum && rest[1..].starts_with('-') {
                let digits: String = rest[2..].chars().take_while(char::is_ascii_digit).collect();
                let id = format!("{c}-{digits}");
                if !digits.is_empty() && bypasses.contains(&id) {
                    s.push_str(&format!("[{id}]({up}bypasses/{id}.md)"));
                    rest = &rest[2 + digits.len()..];
                    continue;
                }
            }
            s.push(c);
            rest = &rest[c.len_utf8()..];
        }
        out.push_str(&s);
    }
    out
}

/// A table row's cells, the outer pipes dropped.
fn cells(line: &str) -> Vec<String> {
    line.trim().trim_matches('|').split('|').map(|c| c.trim().to_string()).collect()
}

fn esc(s: &str) -> String {
    s.replace('|', "\\|").replace('\n', " ").replace('<', "&lt;").replace('>', "&gt;")
}

// ---------- The parsed repository ----------

struct Invariant {
    id: String,
    statement: String,
    phase: String,
}

#[derive(Default)]
struct Row {
    discharged: Vec<String>,
    assumes: Vec<String>,
    tested: Vec<String>,
}

struct Assumption {
    id: String,
    text: String,
    sites: String,
    kind: &'static str,
}

struct Bypass {
    id: String,
    route: String,
    severity: String,
    status: String,
    closes: String,
    mitigation: String,
    breaks: String,
    /// The Invariants column: ids, or `all`, or empty for `—`.
    limits: Vec<String>,
    all: bool,
}

struct Entry {
    id: String,
    summary: String,
    harness: Vec<String>,
    scoring: String,
    expects: String,
    invariants: BTreeSet<String>,
}

struct Obligation {
    name: String,
    kind: &'static str,
    doc: String,
    file: String,
    line: usize,
    /// The rustdoc page of its module, if rustdoc renders it.
    rustdoc: Option<String>,
}

struct Section {
    slug: String,
    title: String,
    body: String,
}

fn kind_of(id: &str) -> &'static str {
    match id.chars().next() {
        Some('P') => "Platform",
        Some('G') => "Platform (progress)",
        Some('V') => "Proof-validity",
        Some('U') => "Internal unproven",
        _ => "?",
    }
}

/// assumptions.md: each bold id with its text and the sites column.
fn parse_assumptions(text: &str) -> BTreeMap<String, Assumption> {
    let mut out = BTreeMap::new();
    for line in text.lines() {
        let mut rest = line;
        while let Some(i) = rest.find("**") {
            let after = &rest[i + 2..];
            let Some(j) = after.find("**") else { break };
            let id = &after[..j];
            let valid = id.len() >= 2
                && matches!(id.chars().next(), Some('V' | 'P' | 'G' | 'U'))
                && id[1..].chars().all(|c| c.is_ascii_digit());
            let tail = &after[j + 2..];
            if valid && !out.contains_key(id) {
                let row = cells(line);
                let (text, sites) = if line.trim_start().starts_with('|') {
                    // `| **V1** text | sites |` or `| **U1** | code | proved in |`.
                    let first = row.first().map(String::as_str).unwrap_or("");
                    let own = first.split_once("**").map(|(_, r)| r).and_then(|r| r.split_once("**")).map(|(_, t)| t);
                    match own.map(str::trim) {
                        Some(t) if !t.is_empty() => (t.to_string(), row.get(1).cloned().unwrap_or_default()),
                        _ => (row.get(1).cloned().unwrap_or_default(), row.get(2).cloned().unwrap_or_default()),
                    }
                } else {
                    // A paragraph: `**G1** text. **G2** …`.
                    let t = tail.split("**").next().unwrap_or("").trim().to_string();
                    (t, String::new())
                };
                out.insert(id.to_string(), Assumption { id: id.to_string(), text, sites, kind: kind_of(id) });
            }
            rest = tail;
        }
    }
    out
}

/// The proof-validity ids every proof rests on: "proof-validity trust (V7–V11)".
fn global_ids(text: &str) -> Vec<String> {
    let Some(i) = text.find("proof-validity trust (") else { return vec![] };
    let inner = &text[i + "proof-validity trust (".len()..];
    let inner = &inner[..inner.find(')').unwrap_or(0)];
    let nums: Vec<u32> =
        inner.split(['–', '-']).filter_map(|p| p.trim().trim_start_matches('V').parse().ok()).collect();
    match nums.as_slice() {
        [a, b] if a <= b => (*a..=*b).map(|n| format!("V{n}")).collect(),
        [a] => vec![format!("V{a}")],
        _ => vec![],
    }
}

fn parse_bypasses(text: &str) -> BTreeMap<String, Bypass> {
    let mut out = BTreeMap::new();
    for line in text.lines() {
        let c = cells(line);
        let id = c.first().cloned().unwrap_or_default();
        let open_or_closed = id.starts_with("B-") && c.len() == 8;
        let accepted = id.starts_with("X-") && c.len() == 6;
        if !open_or_closed && !accepted {
            continue;
        }
        let inv = c.last().cloned().unwrap_or_default();
        let all = inv == "all";
        let limits = if all || inv == "—" {
            vec![]
        } else {
            inv.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect()
        };
        let b = if open_or_closed {
            Bypass {
                id: id.clone(),
                route: c[1].clone(),
                breaks: c[2].clone(),
                severity: c[3].clone(),
                status: c[4].clone(),
                mitigation: c[5].clone(),
                closes: c[6].clone(),
                limits,
                all,
            }
        } else {
            Bypass {
                id: id.clone(),
                route: c[1].clone(),
                breaks: c[2].clone(),
                severity: "Accepted".into(),
                status: "Accepted".into(),
                mitigation: c[3].clone(),
                closes: c[4].clone(),
                limits,
                all,
            }
        };
        out.insert(id, b);
    }
    out
}

/// A heading's slug: "12c" for `### 12c. …`, "22-27" for `## 22–27. …`,
/// else the title in lower case with dashes.
fn slug_of(title: &str) -> String {
    let num: String = title.chars().take_while(|c| c.is_ascii_alphanumeric() || *c == '–').collect();
    if let Some(rest) = title.strip_prefix(&num)
        && rest.starts_with(". ")
        && num.starts_with(|c: char| c.is_ascii_digit())
    {
        return num.replace('–', "-");
    }
    let mut s = String::new();
    for c in title.chars() {
        if c.is_alphanumeric() {
            s.extend(c.to_lowercase());
        } else if !s.ends_with('-') {
            s.push('-');
        }
    }
    s.trim_matches('-').to_string()
}

/// `##` and `###` sections, in order, with their text.
fn split_sections(text: &str) -> Vec<Section> {
    let mut out: Vec<Section> = vec![];
    for line in text.lines() {
        let heading = line.strip_prefix("### ").or_else(|| line.strip_prefix("## "));
        match heading {
            Some(t) => out.push(Section { slug: slug_of(t), title: t.to_string(), body: String::new() }),
            None => {
                if let Some(last) = out.last_mut() {
                    last.body.push_str(line);
                    last.body.push('\n');
                }
            }
        }
    }
    out
}

/// The changes sections, each with the version it produced: "Changes from
/// v4.4" produced the next one's from-version, the last the current spec.
fn change_sections<'a>(sections: &'a [Section], current: &str) -> Vec<(String, &'a Section)> {
    let changes: Vec<&Section> = sections.iter().filter(|s| s.title.contains("Changes from v")).collect();
    let from = |s: &Section| s.title.split("Changes from ").nth(1).unwrap_or("").trim().to_string();
    changes
        .iter()
        .enumerate()
        .map(|(i, s)| (changes.get(i + 1).map(|n| from(n)).unwrap_or_else(|| current.to_string()), *s))
        .collect()
}

/// The part of a changelog bullet about invariant `n`: its clauses that
/// name it.
fn about(bullet: &str, n: u32) -> String {
    let clauses: Vec<&str> = bullet.split("; ").flat_map(|c| c.split(". ")).collect();
    let hit: Vec<&str> = clauses.iter().copied().filter(|c| invariant_refs(c).contains(&n)).collect();
    let s = if hit.is_empty() { bullet.to_string() } else { hit.join("; ") };
    s.trim().trim_end_matches('.').to_string()
}

/// Invariant ids in numeric order (I6 before I12).
fn by_number(ids: &mut [String]) {
    ids.sort_by_key(|i| i.trim_start_matches('I').parse::<u32>().unwrap_or(0));
}

fn short_title(statement: &str) -> String {
    let cut = statement.find(['.', ';']).unwrap_or(statement.len());
    let t = statement[..cut].trim().trim_end_matches(',');
    if t.chars().count() > 90 { format!("{}…", t.chars().take(88).collect::<String>()) } else { t.to_string() }
}

/// A short, computed account of what an entry requires afterwards.
fn expectation(post: Option<&T>) -> String {
    let Some(t) = post.and_then(T::as_table) else { return String::new() };
    let show = |v: &T| -> String {
        match v {
            T::String(s) => s.clone(),
            T::Array(a) => a
                .iter()
                .map(|x| match x {
                    T::String(s) => s.clone(),
                    T::Table(t) => t
                        .iter()
                        .filter(|(k, _)| matches!(k.as_str(), "target" | "terminal" | "transition" | "unit"))
                        .map(|(_, v)| v.as_str().unwrap_or("").to_string())
                        .collect::<Vec<_>>()
                        .join(" "),
                    other => other.to_string(),
                })
                .collect::<Vec<_>>()
                .join(", "),
            T::Table(t) => t
                .iter()
                .map(|(k, v)| format!("{k} {}", v.as_str().unwrap_or(&v.to_string())))
                .collect::<Vec<_>>()
                .join(", "),
            other => other.to_string(),
        }
    };
    let s = t.iter().map(|(k, v)| format!("{k}: {}", show(v))).collect::<Vec<_>>().join("; ");
    if s.chars().count() > 220 { format!("{}…", s.chars().take(218).collect::<String>()) } else { s }
}

/// `fn name` in a crate's sources: file, line, kind, doc comment, module.
fn locate(krate: &str, func: &str, src: &Sources) -> Option<Obligation> {
    let (pkg, files) = src.crates.get(krate)?;
    let pat = format!("fn {func}");
    for (path, text) in files {
        let lines: Vec<&str> = text.lines().collect();
        for (n, l) in lines.iter().enumerate() {
            let Some(i) = l.find(&pat) else { continue };
            let next = l[i + pat.len()..].chars().next();
            if !next.is_some_and(|c| c == '(' || c == '<' || c.is_whitespace()) {
                continue;
            }
            let before: Vec<&str> = lines[n.saturating_sub(8)..n].to_vec();
            let kani = before.iter().rev().take_while(|b| !b.trim().is_empty()).any(|b| b.contains("kani::proof"));
            let kind = if kani {
                "Kani harness"
            } else if l.contains("proof fn") {
                "proof fn"
            } else if VERIFIED.contains(&krate) {
                "verified fn"
            } else {
                "function"
            };
            let mut doc = vec![];
            let mut k = n;
            while k > 0 {
                k -= 1;
                let t = lines[k].trim();
                if let Some(d) = t.strip_prefix("///") {
                    doc.push(d.trim().to_string());
                } else if t.starts_with("#[") || t.starts_with("#![") {
                    continue;
                } else {
                    break;
                }
            }
            doc.reverse();
            let module = path.split("/src/").nth(1).map(|m| m.trim_end_matches(".rs").trim_end_matches("/mod"));
            let lib = pkg.replace('-', "_");
            let rustdoc = match module {
                Some("lib") => Some(format!("{lib}/index.html")),
                Some(m) if !m.contains("kani") && !m.contains("tests") => Some(format!("{lib}/{m}/index.html")),
                _ => None,
            };
            return Some(Obligation {
                name: format!("{krate}::{func}"),
                kind,
                doc: doc.join(" ").trim().to_string(),
                file: path.clone(),
                line: n + 1,
                rustdoc,
            });
        }
    }
    None
}

/// A gym reference in a `tested` list: "gym journal-record-edited", "gym
/// posture-*"; the entries it names, or None if it is not a gym reference.
fn gym_ref<'a>(t: &str, entries: &'a BTreeMap<String, Entry>) -> Option<(String, Vec<&'a str>)> {
    let rest = t.strip_prefix("gym ")?;
    let name = rest.split_whitespace().next().unwrap_or("").to_string();
    // Prose ("gym (every entry …)") names no entry.
    if !name.starts_with(|c: char| c.is_ascii_alphanumeric()) {
        return None;
    }
    let hits: Vec<&str> = match name.strip_suffix('*') {
        Some(prefix) => entries.keys().filter(|k| k.starts_with(prefix)).map(String::as_str).collect(),
        None => entries.keys().filter(|k| **k == name).map(String::as_str).collect(),
    };
    Some((name, hits))
}

// ---------- The build ----------

pub struct Site {
    /// Paths under the book directory, with their contents.
    pub files: Vec<(PathBuf, String)>,
    pub summary: String,
}

pub fn build(src: &Sources, o: &Opts) -> Result<Site, Vec<String>> {
    let mut errors: Vec<String> = vec![];
    let version = src.spec.lines().next().and_then(|l| l.rsplit("Spec ").next()).unwrap_or("?").trim().to_string();

    // §7: the invariants.
    let invariants: Vec<Invariant> = src
        .spec
        .lines()
        .filter(|l| l.starts_with("| I") && l[3..].starts_with(|c: char| c.is_ascii_digit()))
        .filter_map(|l| {
            let c = cells(l);
            (c.len() >= 3 && c[0].starts_with('I')).then(|| Invariant {
                id: c[0].clone(),
                statement: c[1].clone(),
                phase: c[2].clone(),
            })
        })
        .collect();
    let inv_ids: BTreeSet<String> = invariants.iter().map(|i| i.id.clone()).collect();
    if invariants.is_empty() {
        errors.push(format!("{SPEC}: no invariant table (§7)"));
    }

    // The ratio rows and baseline.
    let ratio: T = toml::from_str(&src.ratio).unwrap_or_else(|e| {
        errors.push(format!("{RATIO}: {e}"));
        T::Table(Default::default())
    });
    let list = |v: &T, k: &str| -> Vec<String> {
        v.get(k).and_then(T::as_array).into_iter().flatten().filter_map(T::as_str).map(String::from).collect()
    };
    let mut rows: BTreeMap<String, Row> = BTreeMap::new();
    for r in ratio.get("invariant").and_then(T::as_array).into_iter().flatten() {
        let id = r.get("id").and_then(T::as_str).unwrap_or("?").to_string();
        if !inv_ids.contains(&id) {
            errors.push(format!("{RATIO}: {id} is not an invariant in §7 (it would have no page)"));
        }
        rows.insert(
            id,
            Row { discharged: list(r, "discharged"), assumes: list(r, "assumes"), tested: list(r, "tested") },
        );
    }
    let baseline: BTreeMap<String, (i64, i64)> = ratio
        .get("baseline")
        .and_then(|b| b.get("per_invariant"))
        .and_then(T::as_table)
        .map(|t| {
            t.iter()
                .filter_map(|(k, v)| {
                    let a = v.as_array()?;
                    Some((k.clone(), (a.first()?.as_integer()?, a.get(1)?.as_integer()?)))
                })
                .collect()
        })
        .unwrap_or_default();

    let assumptions = parse_assumptions(&src.assumptions);
    let global = global_ids(&src.assumptions);
    for g in &global {
        if !assumptions.contains_key(g) {
            errors.push(format!("{ASSUMPTIONS}: proof-validity id {g} has no entry"));
        }
    }
    let bypasses = parse_bypasses(&src.bypasses);
    let bypass_ids: BTreeSet<String> = bypasses.keys().cloned().collect();
    // Bypass rows that have no Invariants column are skipped by the parser;
    // name them here.
    for line in src.bypasses.lines() {
        let c = cells(line);
        let id = c.first().cloned().unwrap_or_default();
        if (id.starts_with("B-") || id.starts_with("X-"))
            && id[2..].parse::<u32>().is_ok()
            && !bypasses.contains_key(&id)
        {
            errors.push(format!("{BYPASSES}: {id} has no Invariants column"));
        }
    }
    for b in bypasses.values() {
        for i in &b.limits {
            if !inv_ids.contains(i) {
                errors.push(format!("{BYPASSES}: {} names {i}, which is not an invariant", b.id));
            }
        }
    }

    // The catalog.
    let catalog: T = toml::from_str(&src.catalog).unwrap_or_else(|e| {
        errors.push(format!("{CATALOG}: {e}"));
        T::Table(Default::default())
    });
    let mut entries: BTreeMap<String, Entry> = BTreeMap::new();
    for e in catalog.get("fault").and_then(T::as_array).into_iter().flatten() {
        let id = e.get("id").and_then(T::as_str).unwrap_or("?").to_string();
        let post = e.get("required_post");
        let mut named: BTreeSet<String> = BTreeSet::new();
        for s in list(e, "spec") {
            named.extend(invariant_refs(&s).into_iter().map(|n| format!("I{n}")));
        }
        if let Some(p) = post {
            named.extend(list(p, "invariants"));
        }
        for n in &named {
            if !inv_ids.contains(n) {
                errors.push(format!("{CATALOG}: {id} names {n}, which is not an invariant"));
            }
        }
        entries.insert(
            id.clone(),
            Entry {
                id,
                summary: e.get("summary").and_then(T::as_str).unwrap_or("").to_string(),
                harness: list(e, "harness"),
                scoring: e.get("scoring").and_then(T::as_str).unwrap_or("").to_string(),
                expects: expectation(post),
                invariants: named,
            },
        );
    }
    let verdicts: BTreeMap<String, String> = src
        .results
        .iter()
        .flat_map(|r| r.lines())
        .filter_map(|l| {
            let mut w = l.split_whitespace();
            let v = w.next()?;
            let id = w.next()?;
            (matches!(v, "PASS" | "FAIL" | "PARTIAL" | "UNSUPPORTED" | "NOTFAKE" | "ERROR") && w.next().is_none())
                .then(|| (id.to_string(), v.to_string()))
        })
        .collect();

    // Obligations, located in the source.
    let mut obligations: BTreeMap<String, Obligation> = BTreeMap::new();
    for (id, r) in &rows {
        for a in &r.assumes {
            if !assumptions.contains_key(a) {
                errors.push(format!("{RATIO}: {id} rests on {a}, which has no entry in {ASSUMPTIONS}"));
            }
        }
        for n in &r.discharged {
            if obligations.contains_key(n) {
                continue;
            }
            match n.split_once("::").and_then(|(k, f)| locate(k, f, src)) {
                Some(ob) => {
                    obligations.insert(n.clone(), ob);
                }
                None => errors.push(format!("{RATIO}: {id}'s obligation {n} has no matching function")),
            }
        }
        for t in &r.tested {
            if let Some((name, hits)) = gym_ref(t, &entries)
                && hits.is_empty()
            {
                errors.push(format!("{RATIO}: {id} is tested by gym {name}, which matches no catalog entry"));
            }
        }
    }

    // The spec, with the history's sections, which keep their numbers.
    let mut sections = split_sections(&src.spec);
    let spec_slugs: BTreeSet<String> = sections.iter().map(|s| s.slug.clone()).collect();
    for h in split_sections(&src.history) {
        if !spec_slugs.contains(&h.slug) {
            sections.push(h);
        }
    }
    let slugs: BTreeSet<String> = sections.iter().map(|s| s.slug.clone()).collect();
    sections.sort_by_key(|s| {
        let n: u32 = s.slug.chars().take_while(char::is_ascii_digit).collect::<String>().parse().unwrap_or(999);
        (n, s.slug.clone())
    });
    // Bypass ids the invariants and bypass rows cite must have rows.
    for i in &invariants {
        for b in bypass_refs(&i.statement) {
            if !bypass_ids.contains(&b) {
                errors.push(format!("{SPEC}: {} cites {b}, which has no row in {BYPASSES}", i.id));
            }
        }
    }
    let changes = change_sections(&sections, &version);

    if !errors.is_empty() {
        errors.sort();
        errors.dedup();
        return Err(errors);
    }

    // ---------- Pages ----------
    let tree = format!("https://github.com/{}/blob/{}", o.repo, o.commit);
    let short = &o.commit[..o.commit.len().min(7)];
    let header = |path: &str| -> String {
        let up = "../".repeat(path.matches('/').count());
        let others: Vec<String> =
            o.others.iter().filter(|s| **s != o.snapshot).map(|s| format!("[{s}]({up}../{s}/{path}.html)")).collect();
        format!(
            "`planarian` @ [`{short}`](https://github.com/{}/tree/{}) · Spec {version} · snapshot `{}` · [all versions]({up}../index.html){}\n\n",
            o.repo,
            o.commit,
            o.snapshot,
            if others.is_empty() { String::new() } else { format!(" · also in {}", others.join(", ")) }
        )
    };
    let link = |text: &str, up: &str| linkify(text, up, &slugs, &bypass_ids);
    let mut files: Vec<(PathBuf, String)> = vec![];
    let entries_for = |inv: &str| -> Vec<&Entry> {
        let mut ids: BTreeSet<&str> =
            entries.values().filter(|e| e.invariants.contains(inv)).map(|e| e.id.as_str()).collect();
        if let Some(r) = rows.get(inv) {
            for t in &r.tested {
                if let Some((_, hits)) = gym_ref(t, &entries) {
                    ids.extend(hits);
                }
            }
        }
        ids.iter().filter_map(|i| entries.get(*i)).collect()
    };
    // Closed rows no longer limit anything; they stay on their own pages.
    let limits_of = |inv: &str| -> Vec<&Bypass> {
        let mut v: Vec<&Bypass> = bypasses
            .values()
            .filter(|b| !b.status.starts_with("Closed"))
            .filter(|b| b.all || b.limits.iter().any(|l| l == inv))
            .collect();
        v.sort_by_key(|b| (b.id.starts_with('X'), b.id[2..].parse::<u32>().unwrap_or(0)));
        v
    };
    let verdict = |e: &Entry| -> String {
        let fake = if e.harness.iter().any(|h| h == "fake") {
            match verdicts.get(&e.id) {
                Some(v) => format!("fake: {v}"),
                None => "fake: not run in this build".into(),
            }
        } else {
            String::new()
        };
        let vm =
            if e.harness.iter().any(|h| h == "vm") { "VM: not run in this build".to_string() } else { String::new() };
        [fake, vm].into_iter().filter(|s| !s.is_empty()).collect::<Vec<_>>().join("; ")
    };
    let n_of = |id: &str| -> u32 { id.trim_start_matches('I').parse().unwrap_or(0) };

    let mut index_rows = vec![];
    for inv in &invariants {
        let path = format!("invariants/{}", inv.id);
        let up = "../";
        let row = rows.get(&inv.id);
        let (d, a) = row.map(|r| (r.discharged.len(), r.assumes.len())).unwrap_or((0, 0));
        let gym = entries_for(&inv.id);
        let must = gym.iter().filter(|e| e.scoring == "must-pass").count();
        let status = match row {
            None => "**Not accounted** (no row in `docs/verification-ratio.toml`)".to_string(),
            Some(_) if d > 0 => "**Proved**".to_string(),
            Some(_) if !gym.is_empty() || row.is_some_and(|r| !r.tested.is_empty()) => {
                "**Tested, not proved**".to_string()
            }
            Some(_) => "**Neither proved nor tested**".to_string(),
        };
        let da = match (row, baseline.get(&inv.id)) {
            (None, _) => "—".to_string(),
            (Some(_), Some((bd, ba))) => {
                let now = if a == 0 { 0.0 } else { d as f64 / a as f64 };
                let then = if *ba == 0 { 0.0 } else { *bd as f64 / *ba as f64 };
                format!(
                    "**{d} : {a}** (baseline {bd} : {ba}, {})",
                    if now + 1e-9 < then { "degraded" } else { "not degraded" }
                )
            }
            (Some(_), None) => format!("**{d} : {a}** (no baseline yet)"),
        };
        let title = short_title(&inv.statement);
        let mut p = format!("# {} · {}\n\n", inv.id, esc(&title));
        p.push_str(&header(&path));
        p.push_str(&format!("> {}\n>\n> — [SPEC §7]({up}spec/7.md)\n\n", link(&inv.statement, up)));
        p.push_str("| Status | Proof phase | d:a | Gym |\n| --- | --- | --- | --- |\n");
        p.push_str(&format!(
            "| {status} | {} | {da} | {} {}, {must} must-pass |\n\n",
            esc(&inv.phase),
            gym.len(),
            if gym.len() == 1 { "entry" } else { "entries" }
        ));

        p.push_str("## How it is proved\n\n");
        let obs: Vec<&Obligation> =
            row.into_iter().flat_map(|r| &r.discharged).filter_map(|n| obligations.get(n)).collect();
        if obs.is_empty() {
            p.push_str("No obligation discharges it: nothing about it is proved.\n\n");
        } else {
            let modules: BTreeSet<String> = obs.iter().map(|o| o.file.clone()).collect();
            p.push_str(&format!(
                "{} {}, in {}; every one is checked on every CI run.\n\n| Obligation | Kind | What it guarantees | Source |\n| --- | --- | --- | --- |\n",
                obs.len(),
                if obs.len() == 1 { "obligation" } else { "obligations" },
                modules.iter().map(|m| format!("`{m}`")).collect::<Vec<_>>().join(", ")
            ));
            for ob in &obs {
                let file = ob.file.rsplit('/').next().unwrap_or(&ob.file);
                p.push_str(&format!(
                    "| `{}` | {} | {} | [{file}:{}]({tree}/{}#L{}) |\n",
                    ob.name.split("::").nth(1).unwrap_or(&ob.name),
                    ob.kind,
                    if ob.doc.is_empty() { "*(no doc comment)*".to_string() } else { esc(&link(&ob.doc, up)) },
                    ob.line,
                    ob.file,
                    ob.line
                ));
            }
            p.push('\n');
        }

        p.push_str(
            "## What it rests on\n\nIf any of these is false, the proof no longer describes the real machine.\n\n",
        );
        let assumed = row.map(|r| r.assumes.clone()).unwrap_or_default();
        if assumed.is_empty() {
            p.push_str("Nothing beyond the global assumptions below.\n\n");
        } else {
            p.push_str("| Id | Assumption | Kind | Also relied on by |\n| --- | --- | --- | --- |\n");
            for a in &assumed {
                let Some(asm) = assumptions.get(a) else { continue };
                let mut also: Vec<String> = rows
                    .iter()
                    .filter(|(k, r)| **k != inv.id && r.assumes.contains(a))
                    .map(|(k, _)| k.clone())
                    .collect();
                by_number(&mut also);
                let also: Vec<String> = also.iter().map(|k| format!("[{k}](./{k}.md)")).collect();
                p.push_str(&format!(
                    "| [{a}]({up}assumptions/{a}.md) | {} | {} | {} |\n",
                    esc(&link(&asm.text, up)),
                    asm.kind,
                    if also.is_empty() { "—".into() } else { also.join(", ") }
                ));
            }
            p.push('\n');
        }
        if !obs.is_empty() {
            let kani = obs.iter().any(|o| o.kind == "Kani harness");
            let g: Vec<String> = global
                .iter()
                .filter(|g| kani || !assumptions.get(*g).is_some_and(|a| a.sites.to_lowercase().contains("kani")))
                .map(|g| {
                    let t = assumptions
                        .get(g)
                        .map(|a| a.text.split(". ").next().unwrap_or("").to_string())
                        .unwrap_or_default();
                    format!("[{g}]({up}assumptions/{g}.md) ({})", esc(t.trim_end_matches('.')))
                })
                .collect();
            p.push_str(&format!("Every proof also rests on {}.\n\n", g.join(", ")));
        }

        p.push_str("## How it is tested\n\n");
        if gym.is_empty() {
            p.push_str("No gym entry exercises it.\n\n");
        } else {
            p.push_str(
                "| Entry | Harness | What it does | Expects | Latest verdict |\n| --- | --- | --- | --- | --- |\n",
            );
            for e in &gym {
                p.push_str(&format!(
                    "| [`{0}`]({up}gym/{0}.md) | {1} | {2} | {3} | {4} |\n",
                    e.id,
                    e.harness.join(", "),
                    esc(&e.summary),
                    esc(&e.expects),
                    verdict(e)
                ));
            }
            p.push('\n');
        }
        let other_tests: Vec<String> = row
            .into_iter()
            .flat_map(|r| &r.tested)
            .filter(|t| !t.starts_with("gym "))
            .map(|t| format!("`{t}`"))
            .collect();
        if !other_tests.is_empty() {
            p.push_str(&format!("Also tested by {}.\n\n", other_tests.join(", ")));
        }

        p.push_str("## Known limits\n\n");
        let lim = limits_of(&inv.id);
        if lim.is_empty() {
            p.push_str("No row of the bypass register limits it.\n\n");
        } else {
            p.push_str("| Bypass | Route | Severity | Status | Closes in |\n| --- | --- | --- | --- | --- |\n");
            for b in &lim {
                p.push_str(&format!(
                    "| [{0}]({up}bypasses/{0}.md) | {1} | {2} | {3} | {4} |\n",
                    b.id,
                    esc(&link(&b.route, up)),
                    b.severity,
                    esc(&b.status),
                    esc(&b.closes)
                ));
            }
            p.push('\n');
        }

        p.push_str("## History\n\n");
        let n = n_of(&inv.id);
        let mut hist = vec![];
        for (v, s) in &changes {
            for bullet in s.body.lines().filter(|l| l.starts_with("- ")) {
                if invariant_refs(bullet).contains(&n) {
                    hist.push(format!("| {v} | {} |", esc(&link(&about(&bullet[2..], n), up))));
                }
            }
        }
        if hist.is_empty() {
            p.push_str("No changes section names it.\n\n");
        } else {
            p.push_str(&format!("| Spec | Change |\n| --- | --- |\n{}\n\n", hist.join("\n")));
        }

        p.push_str("## See also\n\n");
        let mut see: Vec<String> = vec![];
        let mut seen = BTreeSet::new();
        for sref in section_refs(&inv.statement) {
            if slugs.contains(&sref) && seen.insert(sref.clone()) {
                see.push(format!("[§{sref}]({up}spec/{sref}.md)"));
            }
        }
        for m in invariant_refs(&inv.statement) {
            let other = format!("I{m}");
            if other != inv.id && inv_ids.contains(&other) && seen.insert(other.clone()) {
                see.push(format!("[{other}](./{other}.md)"));
            }
        }
        let docs: BTreeSet<&String> = obs.iter().filter_map(|o| o.rustdoc.as_ref()).collect();
        for d in docs {
            see.push(format!(
                "[`{}` in rustdoc]({up}rustdoc/{d})",
                d.trim_end_matches("/index.html").replace('/', "::")
            ));
        }
        p.push_str(&if see.is_empty() { "—\n".to_string() } else { format!("{}\n", see.join(" · ")) });
        files.push((PathBuf::from(format!("{path}.md")), p));
        index_rows.push(format!(
            "| [{0}](invariants/{0}.md) | {1} | {2} | {3} | {4} | {5} |",
            inv.id,
            esc(&title),
            status.replace("**", ""),
            if row.is_some() { format!("{d} : {a}") } else { "—".into() },
            gym.len(),
            limits_of(&inv.id).len()
        ));
    }

    // Reverse index: assumptions.
    for a in assumptions.values() {
        let path = format!("assumptions/{}", a.id);
        let up = "../";
        let mut on: Vec<String> =
            rows.iter().filter(|(_, r)| r.assumes.contains(&a.id)).map(|(k, _)| k.clone()).collect();
        by_number(&mut on);
        let on: Vec<String> = on.iter().map(|k| format!("[{k}]({up}invariants/{k}.md)")).collect();
        let every = global.contains(&a.id);
        let mut p = format!("# {} · {}\n\n{}", a.id, a.kind, header(&path));
        p.push_str(&format!("> {}\n\n", link(&a.text, up)));
        if !a.sites.is_empty() && a.sites != "—" {
            p.push_str(&format!("Sites: {}\n\n", link(&a.sites, up)));
        }
        p.push_str("## If it is false\n\n");
        if every {
            p.push_str("Every proof stops describing the real machine: it is proof-validity trust.\n\n");
        }
        p.push_str(&if on.is_empty() {
            "No invariant names it in `docs/verification-ratio.toml`.\n".to_string()
        } else {
            format!("These invariants fall: {}.\n", on.join(", "))
        });
        files.push((PathBuf::from(format!("{path}.md")), p));
    }

    // Reverse index: bypasses.
    for b in bypasses.values() {
        let path = format!("bypasses/{}", b.id);
        let up = "../";
        let mut p = format!("# {} · {}\n\n{}", b.id, b.severity, header(&path));
        p.push_str(&format!("> {}\n\n", link(&b.route, up)));
        p.push_str(&format!(
            "| Breaks | Status | Mitigation | Closes in |\n| --- | --- | --- | --- |\n| {} | {} | {} | {} |\n\n",
            esc(&b.breaks),
            esc(&b.status),
            esc(&link(&b.mitigation, up)),
            esc(&b.closes)
        ));
        p.push_str("## The guarantees it narrows\n\n");
        p.push_str(&if b.all {
            "Every invariant.\n".to_string()
        } else if b.limits.is_empty() {
            "None: a process or availability row.\n".to_string()
        } else {
            format!(
                "{}.\n",
                b.limits.iter().map(|i| format!("[{i}]({up}invariants/{i}.md)")).collect::<Vec<_>>().join(", ")
            )
        });
        files.push((PathBuf::from(format!("{path}.md")), p));
    }

    // Reverse index: gym entries.
    let mut gym_index = vec![];
    for e in entries.values() {
        let path = format!("gym/{}", e.id);
        let up = "../";
        let on: Vec<String> = invariants
            .iter()
            .filter(|i| entries_for(&i.id).iter().any(|x| x.id == e.id))
            .map(|i| i.id.clone())
            .collect();
        let mut p = format!("# `{}`\n\n{}", e.id, header(&path));
        p.push_str(&format!("> {}\n\n", link(&esc(&e.summary), up)));
        p.push_str(&format!(
            "| Harness | Scoring | Expects | Latest verdict |\n| --- | --- | --- | --- |\n| {} | {} | {} | {} |\n\n",
            e.harness.join(", "),
            e.scoring,
            esc(&e.expects),
            verdict(e)
        ));
        p.push_str(&format!(
            "## What it exercises\n\n{}\n",
            if on.is_empty() {
                "No invariant by name.".to_string()
            } else {
                on.iter().map(|i| format!("[{i}]({up}invariants/{i}.md)")).collect::<Vec<_>>().join(", ")
            }
        ));
        files.push((PathBuf::from(format!("{path}.md")), p));
        gym_index.push(format!(
            "| [`{0}`](gym/{0}.md) | {1} | {2} | {3} |",
            e.id,
            e.harness.join(", "),
            on.join(", "),
            verdict(e)
        ));
    }

    // Reverse index: source files.
    let mut by_file: BTreeMap<String, Vec<(&Obligation, Vec<String>)>> = BTreeMap::new();
    for ob in obligations.values() {
        let mut invs: Vec<String> =
            rows.iter().filter(|(_, r)| r.discharged.contains(&ob.name)).map(|(k, _)| k.clone()).collect();
        by_number(&mut invs);
        by_file.entry(ob.file.clone()).or_default().push((ob, invs));
    }
    let mut src_page =
        format!("# Source files\n\n{}Which invariants and obligations live in each file.\n\n", header("files"));
    for (file, obs) in &by_file {
        src_page.push_str(&format!(
            "## [`{file}`]({tree}/{file})\n\n| Obligation | Kind | Line | Invariants |\n| --- | --- | --- | --- |\n"
        ));
        let mut obs = obs.clone();
        obs.sort_by_key(|(o, _)| o.line);
        for (ob, invs) in obs {
            src_page.push_str(&format!(
                "| `{}` | {} | [{}]({tree}/{file}#L{}) | {} |\n",
                ob.name,
                ob.kind,
                ob.line,
                ob.line,
                invs.iter().map(|i| format!("[{i}](invariants/{i}.md)")).collect::<Vec<_>>().join(", ")
            ));
        }
        src_page.push('\n');
    }
    files.push((PathBuf::from("files.md"), src_page));

    // The spec, one page per section.
    for s in &sections {
        let path = format!("spec/{}", s.slug);
        let mut p = format!("# §{}\n\n{}", esc(&s.title), header(&path));
        p.push_str(&link(&s.body, "../"));
        files.push((PathBuf::from(format!("{path}.md")), p));
    }

    // API docs.
    let mut api = format!(
        "# API docs\n\n{}`cargo doc` for the workspace. Proof obligations link to source lines instead: rustdoc renders `verus!` blocks poorly.\n\n",
        header("api")
    );
    for (dir, (pkg, _)) in &src.crates {
        api.push_str(&format!("- [`{pkg}`](rustdoc/{}/index.html) (`crates/{dir}`)\n", pkg.replace('-', "_")));
    }
    files.push((PathBuf::from("api.md"), api));

    // The index and the gym index.
    let (dsum, asum): (usize, usize) =
        rows.values().fold((0, 0), |(d, a), r| (d + r.discharged.len(), a + r.assumes.len()));
    let mut index = format!(
        "# Planarian's guarantees\n\n{}What Planarian promises, and the code, proofs, tests and limits that carry each promise, computed from the repository at this commit (SPEC {}).\n\n{} invariants · {} obligations discharged against {} assumptions (d:a {dsum} : {asum}) · {} assumptions · {} bypass rows · {} gym entries\n\n| Invariant | Statement | Status | d:a | Gym | Limits |\n| --- | --- | --- | --- | --- | --- |\n{}\n",
        header("index"),
        if slugs.contains("17c") { "[§17c](spec/17c.md)" } else { "§17c" },
        invariants.len(),
        dsum,
        asum,
        assumptions.len(),
        bypasses.len(),
        entries.len(),
        index_rows.join("\n")
    );
    let unaccounted: Vec<&str> =
        invariants.iter().filter(|i| !rows.contains_key(&i.id)).map(|i| i.id.as_str()).collect();
    if !unaccounted.is_empty() {
        index
            .push_str(&format!("\nNot yet accounted in `docs/verification-ratio.toml`: {}.\n", unaccounted.join(", ")));
    }
    files.push((PathBuf::from("index.md"), index));
    files.push((
        PathBuf::from("gym.md"),
        format!(
            "# Gym entries\n\n{}| Entry | Harness | Invariants | Latest verdict |\n| --- | --- | --- | --- |\n{}\n",
            header("gym"),
            gym_index.join("\n")
        ),
    ));

    // The book's table of contents.
    let mut summary = String::from("# Summary\n\n[Guarantees](index.md)\n\n# Invariants\n\n");
    for i in &invariants {
        summary.push_str(&format!(
            "- [{} · {}](invariants/{}.md)\n",
            i.id,
            short_title(&i.statement).replace(['[', ']'], ""),
            i.id
        ));
    }
    summary.push_str("\n# Indexes\n\n- [Assumptions](assumptions/index.md)\n");
    for a in assumptions.keys() {
        summary.push_str(&format!("  - [{a}](assumptions/{a}.md)\n"));
    }
    summary.push_str("- [Bypasses](bypasses/index.md)\n");
    for b in bypasses.keys() {
        summary.push_str(&format!("  - [{b}](bypasses/{b}.md)\n"));
    }
    summary.push_str("- [Gym entries](gym.md)\n");
    for e in entries.keys() {
        summary.push_str(&format!("  - [{e}](gym/{e}.md)\n"));
    }
    summary.push_str("- [Source files](files.md)\n- [API docs](api.md)\n\n# Specification\n\n");
    for s in &sections {
        summary.push_str(&format!("- [§{}](spec/{}.md)\n", s.title.replace(['[', ']'], ""), s.slug));
    }
    let asm_index = format!(
        "# Assumptions\n\n{}| Id | Kind | Assumption | Invariants |\n| --- | --- | --- | --- |\n{}\n",
        header("assumptions/index"),
        assumptions
            .values()
            .map(|a| {
                let mut on: Vec<String> =
                    rows.iter().filter(|(_, r)| r.assumes.contains(&a.id)).map(|(k, _)| k.clone()).collect();
                by_number(&mut on);
                format!(
                    "| [{0}]({0}.md) | {1} | {2} | {3} |",
                    a.id,
                    a.kind,
                    esc(&a.text),
                    if global.contains(&a.id) { "every proof".into() } else { on.join(", ") }
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    );
    files.push((PathBuf::from("assumptions/index.md"), asm_index));
    let byp_index = format!(
        "# Bypasses\n\n{}| Id | Severity | Status | Invariants |\n| --- | --- | --- | --- |\n{}\n",
        header("bypasses/index"),
        bypasses
            .values()
            .map(|b| {
                format!(
                    "| [{0}]({0}.md) | {1} | {2} | {3} |",
                    b.id,
                    b.severity,
                    esc(&b.status),
                    if b.all {
                        "all".into()
                    } else if b.limits.is_empty() {
                        "—".into()
                    } else {
                        b.limits.join(", ")
                    }
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    );
    files.push((PathBuf::from("bypasses/index.md"), byp_index));
    files.push((PathBuf::from("SUMMARY.md"), summary));

    // The build is the check (§17c): every relative link resolves to a page.
    let pages: BTreeSet<PathBuf> = files.iter().map(|(p, _)| p.clone()).collect();
    let mut broken = vec![];
    for (page, text) in &files {
        let dir = page.parent().map(Path::to_path_buf).unwrap_or_default();
        for (i, _) in text.match_indices("](") {
            let target = text[i + 2..].split(')').next().unwrap_or("");
            let path = target.split('#').next().unwrap_or("");
            if path.is_empty() || path.contains("://") || !path.ends_with(".md") {
                continue;
            }
            let mut resolved = dir.clone();
            for part in path.split('/') {
                match part {
                    "." => {}
                    ".." => {
                        resolved.pop();
                    }
                    p => resolved.push(p),
                }
            }
            if !pages.contains(&resolved) {
                broken.push(format!("{}: links to {path}, which is not a page", page.display()));
            }
        }
    }
    if !broken.is_empty() {
        broken.sort();
        broken.dedup();
        return Err(broken);
    }

    let summary = format!(
        "{} pages: {} invariants, {} assumptions, {} bypass rows, {} gym entries, {} spec sections, {} obligations located",
        files.len(),
        invariants.len(),
        assumptions.len(),
        bypasses.len(),
        entries.len(),
        sections.len(),
        obligations.len()
    );
    Ok(Site { files, summary })
}

/// Write the book: `book.toml` and `src/`.
pub fn write(site: &Site, out: &Path, o: &Opts) -> std::io::Result<()> {
    let src = out.join("src");
    if src.exists() {
        std::fs::remove_dir_all(&src)?;
    }
    for (path, text) in &site.files {
        let p = src.join(path);
        if let Some(d) = p.parent() {
            std::fs::create_dir_all(d)?;
        }
        std::fs::write(p, text)?;
    }
    std::fs::write(
        out.join("book.toml"),
        format!(
            "[book]\ntitle = \"Planarian's guarantees ({})\"\nsrc = \"src\"\n\n[output.html]\ngit-repository-url = \"https://github.com/{}\"\nno-section-label = true\n",
            o.snapshot, o.repo
        ),
    )
}

/// `planarian-gym site [--out DIR] [--results FILE] [--commit SHA]
/// [--repo OWNER/NAME] [--snapshot NAME] [--others a,b]`: exit 1 with every
/// unresolved reference, 0 with the book written.
pub fn main(args: &[String]) -> i32 {
    let get = |k: &str| args.iter().position(|a| a == k).and_then(|i| args.get(i + 1)).cloned();
    let out = PathBuf::from(get("--out").unwrap_or_else(|| "target/site".into()));
    let commit = get("--commit").or_else(|| {
        std::process::Command::new("git")
            .args(["rev-parse", "HEAD"])
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
    });
    let o = Opts {
        commit: commit.unwrap_or_else(|| "HEAD".into()),
        repo: get("--repo").unwrap_or_else(|| "aubrika/planarian".into()),
        snapshot: get("--snapshot").unwrap_or_else(|| "local".into()),
        others: get("--others")
            .map(|s| s.split(',').filter(|x| !x.is_empty()).map(String::from).collect())
            .unwrap_or_default(),
    };
    let results = get("--results").map(PathBuf::from);
    let src = match Sources::load(Path::new("."), results.as_deref()) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("site: {e}");
            return 1;
        }
    };
    match build(&src, &o) {
        Ok(site) => match write(&site, &out, &o) {
            Ok(()) => {
                println!("guarantees site (SPEC §17c): {} in {}", site.summary, out.display());
                0
            }
            Err(e) => {
                eprintln!("site: {e}");
                1
            }
        },
        Err(errors) => {
            eprintln!("guarantees site (SPEC §17c): {} unresolved reference(s)", errors.len());
            for e in errors {
                eprintln!("  ERROR: {e}");
            }
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opts() -> Opts {
        Opts { commit: "0123456789abcdef".into(), repo: "o/r".into(), snapshot: "main".into(), others: vec![] }
    }

    /// A small repository that resolves completely.
    fn sources() -> Sources {
        let mut crates = BTreeMap::new();
        crates.insert(
            "txn".to_string(),
            (
                "planarian-txn".to_string(),
                vec![(
                    "crates/txn/src/chain.rs".to_string(),
                    "/// Every record follows its predecessor.\npub fn follows(x: u8) -> bool { true }\n".to_string(),
                )],
            ),
        );
        Sources {
            spec: "# Planarian — Spec v9.9\n\n## 7. Principles and invariants\n\n| I1 | The journal is chained (§12c); X-1 limits it. | A (proof) |\n| I2 | Another one. | A |\n\n## 12. Executor\n\n### 12c. Journal\n\ntext\n\n## 28. Changes from v9.8\n\n- I1: chained now.\n".into(),
            history: "# History\n\n## 27. Changes from v9.7\n\n- Invariants I1–I2 added.\n".into(),
            ratio: "[[invariant]]\nid = \"I1\"\ndischarged = [\"txn::follows\"]\nassumes = [\"P5\"]\ntested = [\"gym chain-edited\"]\n".into(),
            assumptions: "| **P5** SHA-256 is collision-resistant | — |\n\nproof-validity trust (V8–V8) underlies every proof\n\n| **V8** Verus is sound. | every proof |\n".into(),
            bypasses: "| X-1 | Root edits the journal | All | Detection | E | all |\n".into(),
            catalog: "[[fault]]\nid = \"chain-edited\"\nsummary = \"Edit a record\"\nharness = [\"fake\"]\nscoring = \"must-pass\"\nspec = [\"I1\"]\n[fault.required_post]\nreports = [\"JournalChainBroken\"]\n".into(),
            results: Some("PASS         chain-edited\n".into()),
            crates,
        }
    }

    #[test]
    fn a_resolving_repository_builds_the_invariant_page() {
        let site = build(&sources(), &opts()).unwrap_or_else(|e| panic!("{e:?}"));
        let page = |p: &str| site.files.iter().find(|(f, _)| f == Path::new(p)).map(|(_, t)| t.clone()).unwrap();
        let i1 = page("invariants/I1.md");
        // The prototype's sections, in its order.
        let order = [
            "## How it is proved",
            "## What it rests on",
            "## How it is tested",
            "## Known limits",
            "## History",
            "## See also",
        ];
        let at: Vec<usize> = order.iter().map(|h| i1.find(h).unwrap_or_else(|| panic!("{h} missing"))).collect();
        assert!(at.windows(2).all(|w| w[0] < w[1]), "sections out of order");
        assert!(i1.starts_with("# I1 · The journal is chained"));
        assert!(i1.contains("`planarian` @ [`0123456`]"), "names its commit");
        assert!(i1.contains("Spec v9.9"));
        assert!(i1.contains("[chain.rs:2](https://github.com/o/r/blob/0123456789abcdef/crates/txn/src/chain.rs#L2)"));
        assert!(i1.contains("Every record follows its predecessor."), "the doc comment is what it guarantees");
        assert!(i1.contains("[P5](../assumptions/P5.md)"));
        assert!(i1.contains("Every proof also rests on [V8]"));
        assert!(i1.contains("fake: PASS"), "the run's verdict");
        assert!(i1.contains("[X-1](../bypasses/X-1.md)"), "an `all` row limits it");
        assert!(
            i1.contains("| v9.9 | [I1](../invariants/I1.md): chained now |"),
            "history from §28, which produced the current spec:\n{i1}"
        );
        assert!(i1.contains("| v9.8 | Invariants [I1]"), "the changes from v9.7 produced v9.8");
        assert!(i1.contains("[§12c](../spec/12c.md)"));
        assert!(i1.contains("rustdoc/planarian_txn/chain/index.html"));
        assert!(page("assumptions/P5.md").contains("[I1](../invariants/I1.md)"));
        assert!(page("index.md").contains("Not yet accounted in `docs/verification-ratio.toml`: I2."));
        assert!(site.files.iter().any(|(f, _)| f == Path::new("spec/27.md")), "the history's sections are spec pages");
    }

    #[test]
    fn every_unresolved_reference_fails_the_build() {
        type Edit = Box<dyn Fn(&mut Sources)>;
        let cases: Vec<(&str, Edit)> = vec![
            ("obligation", Box::new(|s: &mut Sources| s.ratio = s.ratio.replace("txn::follows", "txn::gone"))),
            ("assumption", Box::new(|s: &mut Sources| s.ratio = s.ratio.replace("P5", "P99"))),
            ("bypass cited", Box::new(|s: &mut Sources| s.spec = s.spec.replace("X-1 limits", "X-7 limits"))),
            ("no page", Box::new(|s: &mut Sources| s.ratio.push_str("[[invariant]]\nid = \"I40\"\n"))),
            (
                "gym invariant",
                Box::new(|s: &mut Sources| s.catalog = s.catalog.replace("[\"I1\"]", "[\"I1\", \"I77\"]")),
            ),
            ("gym tested", Box::new(|s: &mut Sources| s.ratio = s.ratio.replace("gym chain-edited", "gym gone-*"))),
            (
                "bypass column",
                Box::new(|s: &mut Sources| {
                    s.bypasses = "| X-1 | Root edits the journal | All | Detection | E |\n".into()
                }),
            ),
            ("bypass invariant", Box::new(|s: &mut Sources| s.bypasses = s.bypasses.replace("| all |", "| I55 |"))),
            (
                "dangling link",
                Box::new(|s: &mut Sources| s.spec = s.spec.replace("Another one.", "Another one, unlike I30.")),
            ),
        ];
        for (what, edit) in cases {
            let mut s = sources();
            edit(&mut s);
            assert!(build(&s, &opts()).is_err(), "{what}: an unresolved reference was accepted");
        }
    }

    #[test]
    fn references_are_read_as_the_spec_writes_them() {
        assert_eq!(invariant_refs("invariants (I1–I3) and I10; CI and I/O"), vec![1, 2, 3, 10]);
        assert_eq!(section_refs("§12c and §12 step 4, §17a."), vec!["12c", "12", "17a"]);
        assert_eq!(bypass_refs("X-12 for writers; B-8, not AB-3"), vec!["X-12", "B-8"]);
        assert_eq!(slug_of("22–27. Earlier changes"), "22-27");
        assert_eq!(slug_of("12c. Journal headroom"), "12c");
        assert_eq!(slug_of("Sources"), "sources");
    }

    /// The real repository resolves (where the source tree is present: the
    /// Nix package build copies only the crates).
    #[test]
    fn the_repository_resolves() {
        let root = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../.."));
        if !root.join(SPEC).exists() {
            return;
        }
        let src = Sources::load(root, None).expect("sources");
        if let Err(e) = build(&src, &opts()) {
            panic!("the guarantees site does not resolve:\n{}", e.join("\n"));
        }
    }
}
