//! Intent matcher (SPEC §14): a phrase → a transition, deterministically. No
//! language model; identical behaviour in degraded mode.
//!
//! A fixed set of patterns ("restart X", "stop X for 20 minutes", "start X
//! again", "make text bigger", …) is tried first; token overlap against the
//! change catalog's descriptions is the fallback. The object X resolves
//! against unit names and synonyms and runtime-option keywords.
//!
//! "stop X" is always `StopAndSuppress`, never a bare `StopUnit` or `Suppress`.

use planarian_schema::{ChangeId, Confidence, Millis, Timestamp, Transition, UnitDefs, UnitId, Until, Value};
use serde::{Deserialize, Serialize};

pub const PROPOSE: Confidence = Confidence(800);
pub const CONFIRM: Confidence = Confidence(500);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeOption {
    pub path: String,
    pub keywords: Vec<String>,
    /// Current value, as a decimal string for fractional settings ("1.25").
    pub current: Option<Value>,
    /// Step for "bigger/smaller", in thousandths.
    pub step_milli: i64,
    pub min_milli: i64,
    pub max_milli: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogEntry {
    pub id: ChangeId,
    pub description: String,
}

#[derive(Clone, Debug, Default)]
pub struct Index {
    pub units: Vec<(UnitId, Vec<String>)>,
    pub changes: Vec<CatalogEntry>,
    pub options: Vec<RuntimeOption>,
}

impl Index {
    pub fn new(defs: &UnitDefs, changes: Vec<CatalogEntry>, options: Vec<RuntimeOption>) -> Index {
        let units = defs
            .values()
            .map(|d| {
                let mut names = vec![d.id.name.clone(), d.id.name.replace(['-', '_', '.'], " ")];
                names.extend(d.synonyms.iter().cloned());
                (d.id.clone(), names.into_iter().map(|n| normalize(&n)).collect())
            })
            .collect();
        Index { units, changes, options }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Match {
    pub transition: Transition,
    pub confidence: Confidence,
    /// What was understood, in plain words.
    pub understood: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Interpretation {
    /// ≥ 0.8: propose with `Source::Intent`.
    Propose(Match),
    /// 0.5–0.8: ask the user to confirm one of the top two.
    Confirm(Vec<Match>),
    /// < 0.5. Phase A says so; Phase B summons the model.
    Unmatched,
}

pub fn normalize(s: &str) -> String {
    let cleaned: String =
        s.to_lowercase().chars().map(|c| if c.is_alphanumeric() || c == '\'' { c } else { ' ' }).collect();
    cleaned.replace('\'', "").split_whitespace().collect::<Vec<_>>().join(" ")
}

fn tokens(s: &str) -> Vec<&str> {
    const STOP: [&str; 8] = ["the", "my", "a", "an", "please", "service", "it", "now"];
    s.split(' ').filter(|t| !t.is_empty() && !STOP.contains(t)).collect()
}

/// Score how well `object` names `candidate` (per-mille): exact = 1000,
/// otherwise the share of the longer side's tokens that match.
fn name_score(object: &str, candidate: &str) -> u16 {
    if object == candidate {
        return 1000;
    }
    let a = tokens(object);
    let b = tokens(candidate);
    if a.is_empty() || b.is_empty() {
        return 0;
    }
    let hits = a.iter().filter(|t| b.contains(t)).count();
    (hits * 1000 / a.len().max(b.len())) as u16
}

fn resolve_unit(object: &str, idx: &Index) -> Vec<(UnitId, u16)> {
    let mut scored: Vec<(UnitId, u16)> = idx
        .units
        .iter()
        .map(|(id, names)| (id.clone(), names.iter().map(|n| name_score(object, n)).max().unwrap_or(0)))
        .filter(|(_, s)| *s > 0)
        .collect();
    scored.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    scored
}

fn parse_until(rest: &str, now: Timestamp) -> Option<Until> {
    let rest = rest.trim();
    // "while I work on it": open-ended; the user lifts it ("done with X").
    if rest.is_empty()
        || rest.starts_with("while ")
        || rest == "until i say"
        || rest == "until i say so"
        || rest == "until further notice"
    {
        return Some(Until::Explicit);
    }
    if rest == "until reboot" || rest == "until next boot" || rest == "until i reboot" {
        return Some(Until::NextBoot);
    }
    let words: Vec<&str> = rest.split(' ').collect();
    if let ["for", n, unit] = words[..] {
        let n: u64 = match n {
            "a" | "an" | "one" => 1,
            "two" => 2,
            "five" => 5,
            "ten" => 10,
            "twenty" => 20,
            "thirty" => 30,
            n => n.parse().ok()?,
        };
        let secs = match unit {
            "minute" | "minutes" | "min" | "mins" => 60,
            "hour" | "hours" => 3600,
            _ => return None,
        };
        return Some(Until::At(now.plus(Millis::secs(n * secs))));
    }
    None
}

fn until_words(u: &Until) -> String {
    match u {
        Until::Explicit => "until you say otherwise".into(),
        Until::NextBoot => "until the next boot".into(),
        Until::At(t) => format!("until {}", t.0),
    }
}

fn unit_matches(object: &str, idx: &Index, mk: impl Fn(&UnitId) -> (Transition, String)) -> Vec<Match> {
    resolve_unit(object, idx)
        .into_iter()
        .take(2)
        .map(|(id, score)| {
            let (transition, understood) = mk(&id);
            Match { transition, confidence: Confidence(score.saturating_sub(50).max(score / 2)), understood }
        })
        .collect()
}

fn milli(v: &Value) -> Option<i64> {
    match v {
        Value::Int(i) => Some(i * 1000),
        Value::Str(s) => {
            let (int, frac) = s.split_once('.').unwrap_or((s, ""));
            let frac = format!("{frac:0<3}");
            Some(int.parse::<i64>().ok()? * 1000 + frac.get(..3)?.parse::<i64>().ok()?)
        }
        _ => None,
    }
}

fn from_milli(m: i64) -> Value {
    let s = format!("{}.{:03}", m / 1000, m % 1000);
    Value::Str(s.trim_end_matches('0').trim_end_matches('.').to_string())
}

fn option_matches(object: &str, bigger: bool, idx: &Index) -> Vec<Match> {
    let mut out = vec![];
    for o in &idx.options {
        let score = o.keywords.iter().map(|k| name_score(object, &normalize(k))).max().unwrap_or(0);
        if score == 0 {
            continue;
        }
        let Some(cur) = o.current.as_ref().and_then(milli) else { continue };
        let next = (cur + if bigger { o.step_milli } else { -o.step_milli }).clamp(o.min_milli, o.max_milli);
        if next == cur {
            continue;
        }
        out.push(Match {
            transition: Transition::SetRuntimeOption { path: o.path.clone(), value: from_milli(next) },
            confidence: Confidence(score.saturating_sub(50)),
            understood: format!("set {} from {} to {}", o.path, from_milli(cur).render(), from_milli(next).render()),
        });
    }
    out
}

trait Render {
    fn render(&self) -> String;
}

impl Render for Value {
    fn render(&self) -> String {
        match self {
            Value::Bool(b) => b.to_string(),
            Value::Int(i) => i.to_string(),
            Value::Str(s) => s.clone(),
            Value::List(l) => format!("{l:?}"),
        }
    }
}

fn catalog_matches(phrase: &str, idx: &Index) -> Vec<Match> {
    let p = tokens(phrase);
    let mut out: Vec<Match> = idx
        .changes
        .iter()
        .filter_map(|c| {
            let d_norm = normalize(&c.description);
            let d = tokens(&d_norm);
            let hits = p.iter().filter(|t| d.contains(t)).count();
            if hits == 0 {
                return None;
            }
            // Never above the propose threshold: a catalog change from fuzzy words
            // is always confirmed first.
            let score = (hits * 1000 / p.len().max(1)).min(790) as u16;
            Some(Match {
                transition: Transition::ApplyChange { change: c.id.clone(), args: Default::default() },
                confidence: Confidence(score),
                understood: format!("apply \"{}\" (needs its settings)", c.description),
            })
        })
        .collect();
    out.sort_by_key(|m| std::cmp::Reverse(m.confidence));
    out
}

/// Interpret a phrase. `now` resolves "for N minutes".
pub fn interpret(phrase: &str, idx: &Index, now: Timestamp) -> Interpretation {
    let p = normalize(phrase);
    let mut matches: Vec<Match> = vec![];

    let strip = |s: &str, prefixes: &[&str]| -> Option<String> {
        prefixes.iter().find_map(|pre| s.strip_prefix(pre).map(|r| r.trim().to_string()))
    };

    if let Some(obj) = strip(&p, &["restart ", "reconnect ", "reload ", "kick "]) {
        matches.extend(unit_matches(&obj, idx, |id| (Transition::RestartUnit(id.clone()), format!("restart {id}"))));
    }
    if let Some(rest) = strip(&p, &["stop ", "pause ", "disable ", "turn off "]) {
        // Split "X [for N minutes | until …]".
        let cut = ["for ", "until ", "while "].iter().filter_map(|k| rest.find(&format!(" {k}"))).min();
        let (obj, tail) = match cut {
            Some(i) => (rest[..i].to_string(), rest[i..].trim().to_string()),
            None => (rest.clone(), String::new()),
        };
        if let Some(until) = parse_until(&tail, now) {
            matches.extend(unit_matches(&obj, idx, |id| {
                (
                    Transition::StopAndSuppress {
                        unit: id.clone(),
                        until: until.clone(),
                        reason: format!("asked: \"{phrase}\""),
                    },
                    format!("stop {id} and leave it stopped {}", until_words(&until)),
                )
            }));
        }
    }
    if let Some(obj) = p.strip_prefix("turn ").and_then(|r| r.strip_suffix(" off")) {
        matches.extend(unit_matches(obj, idx, |id| {
            (
                Transition::StopAndSuppress {
                    unit: id.clone(),
                    until: Until::Explicit,
                    reason: format!("asked: \"{phrase}\""),
                },
                format!("stop {id} and leave it stopped until you say otherwise"),
            )
        }));
    }
    let start_again =
        strip(&p, &["start ", "resume ", "unpause ", "done with ", "im done with ", "i am done with ", "turn on "])
            .map(|o| o.trim_end_matches(" again").to_string())
            .or_else(|| p.strip_prefix("turn ").and_then(|r| r.strip_suffix(" on")).map(String::from));
    if let Some(obj) = start_again {
        matches.extend(unit_matches(&obj, idx, |id| {
            (Transition::LiftOverride(id.clone()), format!("let {id} run again and repair it if needed"))
        }));
    }
    for (pre, bigger) in [("make ", true), ("make ", false)] {
        if let Some(rest) = p.strip_prefix(pre) {
            let words = if bigger { ["bigger", "larger"] } else { ["smaller", "tinier"] };
            for w in words {
                if let Some(obj) = rest.strip_suffix(&format!(" {w}")) {
                    matches.extend(option_matches(obj, bigger, idx));
                }
            }
        }
    }
    if matches.is_empty() {
        matches = catalog_matches(&p, idx);
    }

    matches.sort_by_key(|m| std::cmp::Reverse(m.confidence));
    match matches.first() {
        Some(m) if m.confidence >= PROPOSE && matches.get(1).is_none_or(|n| n.confidence < m.confidence) => {
            Interpretation::Propose(m.clone())
        }
        Some(m) if m.confidence >= CONFIRM => Interpretation::Confirm(matches.into_iter().take(2).collect()),
        _ => Interpretation::Unmatched,
    }
}

#[cfg(test)]
mod tests;
