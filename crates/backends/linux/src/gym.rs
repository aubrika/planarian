//! Fault injection for the gym's VM harness (`--features gym-hooks`; never in
//! the shipped package). Before a hooked backend call, read
//! `/run/planarian-gym/hooks.json`:
//!
//! ```json
//! { "activate_live": { "delay_secs": 120, "uncancellable": false },
//!   "activate_live@revert_to": { "result": "Failed" },
//!   "jobs_tagged": { "result": "None" } }
//! ```
//!
//! `delay_secs` sleeps before the call (for `activate_live`, inside the
//! activation unit, which `uncancellable` makes ignore being stopped);
//! `withhold` makes the call and then never answers (sleeps for a day);
//! `result` replaces the call. A key with `@<generation id>` applies only to
//! that generation.

use planarian_schema::{GenerationId, Outcome};
use std::time::Duration;

pub const HOOKS: &str = "/run/planarian-gym/hooks.json";

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Hook {
    pub delay: Option<Duration>,
    pub uncancellable: bool,
    pub withhold: bool,
    pub result: Option<String>,
}

pub fn hook(call: &str, g: Option<GenerationId>) -> Hook {
    let Ok(text) = std::fs::read_to_string(HOOKS) else { return Hook::default() };
    let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) else { return Hook::default() };
    let specific = g.and_then(|g| v.get(format!("{call}@{}", g.0)));
    let Some(h) = specific.or_else(|| v.get(call)) else { return Hook::default() };
    Hook {
        delay: h.get("delay_secs").and_then(|d| d.as_u64()).map(Duration::from_secs),
        uncancellable: h.get("uncancellable").and_then(|u| u.as_bool()).unwrap_or(false),
        withhold: h.get("withhold").and_then(|w| w.as_bool()).unwrap_or(false),
        result: h.get("result").and_then(|r| r.as_str()).map(String::from),
    }
}

/// Apply a hook around an `Outcome`-returning call.
pub fn around(call: &str, g: Option<GenerationId>, f: impl FnOnce() -> Outcome) -> Outcome {
    apply(hook(call, g), f)
}

pub fn apply(h: Hook, f: impl FnOnce() -> Outcome) -> Outcome {
    if let Some(d) = h.delay {
        std::thread::sleep(d);
    }
    if let Some(r) = h.result {
        return match r.as_str() {
            "Succeeded" => Outcome::Succeeded,
            other => Outcome::Failed(format!("gym hook: {other}")),
        };
    }
    let o = f();
    if h.withhold {
        std::thread::sleep(Duration::from_secs(86_400));
    }
    o
}
