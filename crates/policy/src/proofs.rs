//! The properties SPEC §7 and §17a ask of `decide`, proved about
//! `decide_spec`; `decide` is proved equal to it (its `ensures`).

use crate::*;
#[allow(unused_imports)]
use vstd::prelude::*;

verus! {

pub open spec fn is_reject(d: Decision) -> bool {
    match d {
        Decision::Reject(_) => true,
        Decision::Allow(_) => false,
    }
}

/// AskFirst, or refused.
pub open spec fn asks_or_rejects(d: Decision) -> bool {
    match d {
        Decision::Reject(_) => true,
        Decision::Allow(t) => t == Tier::AskFirst,
    }
}

/// The tier's rank; a Reject ranks above every tier.
pub open spec fn strictness(d: Decision) -> int {
    match d {
        Decision::Allow(t) => t.rank() as int,
        Decision::Reject(_) => 4,
    }
}

/// `x` is the same Reject as `y`, or a tier at least as high as `y`'s.
pub open spec fn at_least_as_strict(x: Decision, y: Decision) -> bool {
    (is_reject(y) && x == y) || (!is_reject(x) && !is_reject(y) && strictness(x) >= strictness(y))
}

/// The inputs agree on everything `decide` reads except the settings' `max_tier`.
pub open spec fn same_but_autonomy(a: Input, b: Input) -> bool {
    &&& *a.transition == *b.transition
    &&& *a.facts == *b.facts
    &&& a.known_good == b.known_good
    &&& a.live_tested == b.live_tested
    &&& *a.cumulative == *b.cumulative
    &&& *a.authz == *b.authz
    &&& a.settings.user_controllable_units == b.settings.user_controllable_units
    &&& a.settings.user_controllable_changes == b.settings.user_controllable_changes
    &&& a.settings.user_controllable_options == b.settings.user_controllable_options
    &&& *a.tables == *b.tables
    &&& *a.locked == *b.locked
    &&& a.revert_to == b.revert_to
}

/// I5: the autonomy setting never turns a Reject into a tier or a tier into
/// a Reject, never changes a Reject's reason, never yields a tier above itself
/// other than AskFirst, and raising it never makes a decision stricter.
pub proof fn i5_autonomy_never_touches_reject(a: Input, b: Input)
    requires
        same_but_autonomy(a, b),
    ensures
        uncapped_spec(a) == uncapped_spec(b),
        is_reject(decide_spec(a)) == is_reject(decide_spec(b)),
        is_reject(decide_spec(a)) ==> decide_spec(a) == decide_spec(b),
        is_reject(decide_spec(a)) ==> decide_spec(a) == uncapped_spec(a),
        !is_reject(decide_spec(a)) ==> (strictness(decide_spec(a)) <= a.settings.max_tier.rank()
            || decide_spec(a) == Decision::Allow(Tier::AskFirst)),
        a.settings.max_tier.rank() <= b.settings.max_tier.rank() ==> at_least_as_strict(
            decide_spec(a),
            decide_spec(b),
        ),
{
}

/// I11 (classification): when this change's diff, or the session's
/// cumulative diff, touches a non-Routine option, the decision is AskFirst
/// or a Reject.
pub proof fn i11_non_routine_session_asks(i: Input)
    requires
        cumulative_spec(i),
    ensures
        asks_or_rejects(decide_spec(i)),
{
}

/// The inputs agree on everything except the session's cumulative diff.
pub open spec fn same_but_session(a: Input, b: Input) -> bool {
    &&& *a.transition == *b.transition
    &&& *a.facts == *b.facts
    &&& a.known_good == b.known_good
    &&& a.live_tested == b.live_tested
    &&& *a.authz == *b.authz
    &&& *a.settings == *b.settings
    &&& *a.tables == *b.tables
    &&& *a.locked == *b.locked
    &&& a.revert_to == b.revert_to
}

/// I11 (monotonicity): a change inside a session is decided at least as
/// strictly as the same change on its own.
pub proof fn i11_session_only_raises(a: Input, b: Input)
    requires
        same_but_session(a, b),
        b.cumulative.options.entries@.len() == 0,
    ensures
        at_least_as_strict(decide_spec(a), decide_spec(b)),
{
    assert(!diff_non_routine(*b.tables, *b.cumulative));
}

/// The global floors (§11), for every transition kind.
pub proof fn global_floors(i: Input)
    ensures
        i.facts.recovery == Recovery::NonReversible ==> asks_or_rejects(decide_spec(i)),
        ((i.facts.disruption == Disruption::SessionLoss || i.facts.disruption == Disruption::DataInterruption)
            && !(is_user(i.authz.caller) && i.authz.owns_affected_session)) ==> asks_or_rejects(decide_spec(i)),
        (i.facts.disruption == Disruption::ConnectivityLoss && !(is_user(i.authz.caller)
            && i.authz.local_session)) ==> asks_or_rejects(decide_spec(i)),
{
}

/// I10, and probe tampering (§17a): a change to a canonical probe's
/// definition never runs below AskFirst.
pub proof fn i10_canonical_probe_changes_ask(i: Input)
    requires
        i.facts.touches_canonical_probe,
    ensures
        asks_or_rejects(decide_spec(i)),
{
}

/// Unauthorized callers are refused before anything else is considered.
pub proof fn unauthorized_is_refused_first(i: Input)
    requires
        !authorized_spec(*i.transition, *i.facts, *i.authz, *i.settings),
    ensures
        decide_spec(i) == Decision::Reject(RejectReason::Unauthorized),
{
}

/// The core is never a target.
pub proof fn core_is_never_a_target(i: Input)
    requires
        i.facts.touches_core || i.facts.sensitivity.core,
    ensures
        decide_spec(i) == Decision::Reject(RejectReason::CoreTarget) || decide_spec(i) == Decision::Reject(
            RejectReason::Unauthorized,
        ),
{
}

/// Only an administrator can clear the recovery interlock (§12c).
pub proof fn only_administrators_resolve(i: Input)
    requires
        i.transition is Resolve,
    ensures
        !is_reject(decide_spec(i)) ==> is_user(i.authz.caller) && i.authz.admin,
{
}

/// A user who is not an administrator cannot change generations, drivers,
/// models, snapshots or the store.
pub proof fn users_cannot_change_generations(i: Input)
    requires
        is_user(i.authz.caller),
        !i.authz.admin,
        i.transition is SwitchGeneration || i.transition is Revert || i.transition is Rollback
            || i.transition is LoadModel || i.transition is RestoreSnapshot || i.transition is CollectGarbage
            || i.transition is BindDriver || i.transition is Resolve,
    ensures
        decide_spec(i) == Decision::Reject(RejectReason::Unauthorized),
{
}

/// I14: the `caller` recorded in the derived facts carries no authority;
/// only the daemon-established `Authorization` does.
pub proof fn i14_facts_caller_is_not_authority(a: Input, b: Input)
    requires
        *a.transition == *b.transition,
        a.facts.affected_units == b.facts.affected_units,
        a.facts.sensitivity == b.facts.sensitivity,
        a.facts.disruption == b.facts.disruption,
        a.facts.recovery == b.facts.recovery,
        a.facts.touches_manifest == b.facts.touches_manifest,
        a.facts.touches_canonical_probe == b.facts.touches_canonical_probe,
        a.facts.changes_desired == b.facts.changes_desired,
        a.facts.touches_core == b.facts.touches_core,
        a.facts.config_diff == b.facts.config_diff,
        a.known_good == b.known_good,
        a.live_tested == b.live_tested,
        *a.cumulative == *b.cumulative,
        *a.authz == *b.authz,
        *a.settings == *b.settings,
        *a.tables == *b.tables,
        *a.locked == *b.locked,
        a.revert_to == b.revert_to,
    ensures
        decide_spec(a) == decide_spec(b),
{
}

} // verus!
