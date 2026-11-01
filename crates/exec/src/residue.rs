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
    if f.security {
        return Residue::AlarmSecurity(e);
    }
    if f.stops_are_faults {
        return Residue::AlarmMustRun(e);
    }
    if f.lenient && !f.systemd_restarts { Residue::Intended(e) } else { Residue::Fault }
}
