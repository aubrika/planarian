//! Kani harnesses for exec orchestration (SPEC §17a). The kernel's decision
//! rules are checked in `planarian-txn`; the executor's own pure rule is
//! approval-token expiry. Run: `cargo kani -p planarian-exec`.

use crate::token_expired;
use planarian_schema::{TOKEN_LIFETIME, Timestamp};

/// Approval tokens (§12 step 4), timed on the boot clock (§12h: the values
/// here are `CLOCK_BOOTTIME`, which moving the wall clock cannot move): never
/// expired at or before issue, expired exactly once 24 hours have passed,
/// and once expired they stay expired. No clock value makes the check
/// overflow.
#[kani::proof]
fn approval_tokens_expire_after_their_lifetime() {
    let (issued, now, later): (u64, u64, u64) = (kani::any(), kani::any(), kani::any());
    let expired = token_expired(Timestamp(now), Timestamp(issued));
    if now <= issued {
        assert!(!expired);
    }
    if issued <= u64::MAX - TOKEN_LIFETIME.0 {
        assert_eq!(expired, now > issued + TOKEN_LIFETIME.0);
    }
    if expired && later >= now {
        assert!(token_expired(Timestamp(later), Timestamp(issued)));
    }
}

// ---------- The residue classifier (§11, Q5; U3) ----------

use crate::residue::{EndingFacts, Residue, classify};
use planarian_schema::Ending;

fn any_ending() -> Ending {
    match kani::any::<u8>() % 3 {
        0 => Ending::Exited(kani::any()),
        1 => Ending::Signal(kani::any()),
        _ => Ending::OomKill,
    }
}

fn any_facts() -> EndingFacts {
    EndingFacts {
        was_up: kani::any(),
        now_down: kani::any(),
        stopped_cleanly: kani::any(),
        ended: if kani::any() { Some(any_ending()) } else { None },
        service: kani::any(),
        touched_by_planarian: kani::any(),
        expected: kani::any(),
        requirement_crashed: kani::any(),
        security: kani::any(),
        stops_are_faults: kani::any(),
        systemd_restarts: kani::any(),
        lenient: kani::any(),
    }
}

/// A security-sensitive unit's stop is never taken as intended: it is
/// alarmed (§11, Q5).
#[kani::proof]
fn residue_security_is_never_intended() {
    let f = any_facts();
    let r = classify(&f);
    if f.security {
        assert!(!matches!(r, Residue::Intended(_)));
    }
}

/// Crash signals, exit statuses and OOM kills of a failed unit are faults,
/// never a person's stop (§11, Q5).
#[kani::proof]
fn residue_crashes_are_faults() {
    let f = any_facts();
    if !f.stopped_cleanly && !f.ended.is_some_and(|e| e.is_termination()) {
        assert!(matches!(classify(&f), Residue::NotAStop | Residue::Fault));
    }
}

/// What Planarian did itself, or what went down with a crash, is never a
/// residue; nor is anything under a posture that does not infer intent, a
/// unit systemd restarts, or one that must keep running.
#[kani::proof]
fn residue_is_inferred_only_where_allowed() {
    let f = any_facts();
    let r = classify(&f);
    if f.touched_by_planarian || f.requirement_crashed || !f.service || !f.expected {
        assert!(r == Residue::NotAStop);
    }
    if let Residue::Intended(e) = r {
        assert!(f.lenient && !f.systemd_restarts && !f.stops_are_faults && !f.security);
        assert!(f.was_up && f.now_down);
        // What it records is a termination signal, never a crash.
        assert!(e.is_termination());
    }
}
