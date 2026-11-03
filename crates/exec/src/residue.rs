//! The residue classifier (§11, owner decision Q5; U3 in docs/assumptions.md):
//! which unit endings Planarian did not cause are a person's stop, taken as
//! intended until the next boot, and which are faults or alarms. Pure, so
//! its rules are checked by Kani (`kani.rs`) in Phase A and by Verus in C.

use planarian_schema::Ending;

/// What the daemon observed about one unit between two ticks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EndingFacts {
    /// Running or Degraded at the last tick.
    pub was_up: bool,
    /// Failed or Stopped now.
    pub now_down: bool,
    /// Stopped (inactive), not Failed.
    pub stopped_cleanly: bool,
    /// How the main process ended, if the supervisor says.
    pub ended: Option<Ending>,
    /// A service (only services have a residue).
    pub service: bool,
    /// Planarian acted on it, or changed the generation, since the last tick.
    pub touched_by_planarian: bool,
    /// Desired present under the current conditions.
    pub expected: bool,
    /// A unit it Requires crashed this tick: it went down with that fault.
    pub requirement_crashed: bool,
    /// Security-sensitive.
    pub security: bool,
    /// `inferStops = false` (B-11).
    pub stops_are_faults: bool,
    /// systemd restarts it (`Restart=`).
    pub systemd_restarts: bool,
    /// The posture infers intent (Relaxed or Standard).
    pub lenient: bool,
    /// A network tool (`UnitDef.holds`): §12d holds its traffic when it
    /// fails or is stopped outside Planarian and it is protecting.
    pub network_tool: bool,
    /// A hold is in place for it now (`SystemState.holds`, or the host's
    /// `/run/planarian/hold/<unit>`), read after any attempt to apply one.
    pub held: bool,
    /// The daemon has asked the host to hold it for this stop; the host's
    /// condition (the footprint, a release) decides, as OnFailure= does.
    pub hold_tried: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Residue {
    /// Not a stop outside Planarian (it did not go down, Planarian caused
    /// it, it is not desired, or it went down with a crash).
    NotAStop,
    /// A fault: a crash, a non-zero exit or the OOM killer; or a stop the
    /// posture or systemd's own restart leaves to the incident manager.
    Fault,
    /// A security-sensitive unit stopped outside Planarian: alarmed and
    /// started again.
    AlarmSecurity(Ending),
    /// A unit that must keep running (`inferStops = false`): alarmed and
    /// started again.
    AlarmMustRun(Ending),
    /// Taken as intended: an inferred override until the next boot.
    Intended(Ending),
    /// §12d: a network tool stopped outside Planarian, not yet held. Ask
    /// the host to hold it, then classify again with `hold_tried`.
    HoldFirst(Ending),
    /// §12d, §11: its traffic is held, so the stop is "always a fault, §11
    /// residue": restarted at once without asking (`restarts_held_unit`)
    /// and alarmed, never taken as intended, whatever its sensitivity.
    AlarmHeld(Ending),
}

pub fn classify(f: &EndingFacts) -> Residue {
    let went_down_unexplained =
        f.was_up && f.now_down && f.service && !f.touched_by_planarian && f.expected && !f.requirement_crashed;
    if !went_down_unexplained {
        return Residue::NotAStop;
    }
    // A unit inactive (not failed) after running was stopped on request
    // (`systemctl stop`), whatever its exit status; a failed one counts only
    // if a termination signal ended it.
    let e = match f.ended {
        Some(e) if e.is_termination() => e,
        _ if f.stopped_cleanly => Ending::Signal(15),
        _ => return Residue::Fault,
    };
    if f.network_tool && !f.hold_tried {
        return Residue::HoldFirst(e);
    }
    // A network tool the host declined to hold (not protecting) is not a
    // network-security unit (§12d): the residue rule below applies.
    if f.security {
        return Residue::AlarmSecurity(e);
    }
    if f.stops_are_faults {
        return Residue::AlarmMustRun(e);
    }
    if f.lenient && !f.systemd_restarts { Residue::Intended(e) } else { Residue::Fault }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn ending() -> impl Strategy<Value = Ending> {
        prop_oneof![any::<i32>().prop_map(Ending::Exited), any::<i32>().prop_map(Ending::Signal), Just(Ending::OomKill)]
    }

    /// Each flag leans (4 in 5) towards the value that reaches `Intended`
    /// (an unexplained stop of an untagged service under a lenient
    /// posture), so the property meets that path often, not one case in
    /// thousands; every combination is still generated.
    fn lean(towards: bool) -> impl Strategy<Value = bool> {
        proptest::bool::weighted(if towards { 0.8 } else { 0.2 })
    }

    fn facts() -> impl Strategy<Value = EndingFacts> {
        (
            (lean(true), lean(true), lean(true), lean(true), lean(false), lean(true), lean(false)),
            (lean(false), lean(false), lean(false), lean(true), any::<bool>(), any::<bool>(), any::<bool>()),
            proptest::option::weighted(0.9, prop_oneof![4 => Just(Ending::Signal(15)), 1 => ending()]),
        )
            .prop_map(
                |(
                    (was_up, now_down, stopped_cleanly, service, touched_by_planarian, expected, requirement_crashed),
                    (security, stops_are_faults, systemd_restarts, lenient, network_tool, held, hold_tried),
                    ended,
                )| EndingFacts {
                    was_up,
                    now_down,
                    stopped_cleanly,
                    ended,
                    service,
                    touched_by_planarian,
                    expected,
                    requirement_crashed,
                    security,
                    stops_are_faults,
                    systemd_restarts,
                    lenient,
                    network_tool,
                    held,
                    hold_tried,
                },
            )
    }

    /// main's classifier before #55, verbatim (the reference for the frame
    /// condition: where #55 does not apply, nothing changes).
    fn classify_before(f: &EndingFacts) -> Residue {
        let went_down_unexplained =
            f.was_up && f.now_down && f.service && !f.touched_by_planarian && f.expected && !f.requirement_crashed;
        if !went_down_unexplained {
            return Residue::NotAStop;
        }
        let e = match f.ended {
            Some(e) if e.is_termination() => e,
            _ if f.stopped_cleanly => Ending::Signal(15),
            _ => return Residue::Fault,
        };
        if f.security {
            return Residue::AlarmSecurity(e);
        }
        if f.stops_are_faults {
            return Residue::AlarmMustRun(e);
        }
        if f.lenient && !f.systemd_restarts { Residue::Intended(e) } else { Residue::Fault }
    }

    proptest! {
        #![proptest_config(ProptestConfig { cases: 1024, ..ProptestConfig::default() })]

        /// The frame condition (prop-auditor, #55): a unit not held, and not
        /// a network tool awaiting its hold attempt (not one, or asked and
        /// declined), is classified exactly as before. So #55 holds only what
        /// §12d holds: not every network tool, not every lenient unit.
        #[test]
        fn outside_a_hold_the_classifier_is_unchanged(f in facts()) {
            if !f.held && (!f.network_tool || f.hold_tried) {
                prop_assert_eq!(classify(&f), classify_before(&f), "{:?}", f);
            }
        }

        /// §12d, §11: a unit whose traffic is held is never taken as
        /// intended; and a network tool's stop is never taken as intended
        /// before the host has been asked to hold it (and declined).
        #[test]
        fn held_or_unasked_network_tools_are_never_intended(f in facts()) {
            let r = classify(&f);
            if f.held {
                prop_assert!(!matches!(r, Residue::Intended(_)), "{f:?} -> {r:?}");
            }
            if f.network_tool && !f.hold_tried {
                prop_assert!(!matches!(r, Residue::Intended(_)), "{f:?} -> {r:?}");
            }
            // A hold is only asked for a network tool, once.
            if matches!(r, Residue::HoldFirst(_)) {
                prop_assert!(f.network_tool && !f.hold_tried && !f.held);
            }
        }
    }
}
