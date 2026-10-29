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
