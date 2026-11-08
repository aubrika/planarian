//! The network-tool rule (SPEC §12d "Which units"), over the effective
//! settings of a unit file. A restatement of `isNetworkToolUnchecked` in
//! nix/module.nix for units that exist only as files; `module-eval` holds the
//! two equal on every combination of the rule's inputs.

use crate::syntax::{CapSet, Settings};

pub const NET_CAPS: [&str; 2] = ["CAP_NET_ADMIN", "CAP_NET_RAW"];
pub const DEVICE_NEEDLES: [&str; 2] = ["/dev/net/tun", "/dev/ppp"];

/// A unit able to change how traffic leaves the machine: it holds
/// CAP_NET_ADMIN or CAP_NET_RAW (ambient, or root's bounding set), could gain
/// one (a bounding set that allows it and `NoNewPrivileges=` unset), or is
/// given /dev/net/tun or /dev/ppp explicitly.
pub fn is_network_tool(s: &Settings) -> bool {
    let root = match &s.user {
        None => true,
        Some(u) => u == "root" || u == "0",
    } && !s.dynamic_user.unwrap_or(false);
    let ambient_grants = s.ambient.effective(None).is_some_and(|c: CapSet| c.grants(&NET_CAPS));
    // The bounding set allows a network capability, or is unset (everything).
    let bounding_allows = s.bounding.effective(None).is_none_or(|c| c.grants(&NET_CAPS));
    let no_new_privs = s.no_new_privileges.unwrap_or(false);
    let device = s
        .device_allow
        .iter()
        .chain(&s.bind_paths)
        .chain(&s.bind_read_only_paths)
        .any(|w| DEVICE_NEEDLES.iter().any(|n| w.contains(n)));
    ambient_grants || (root && bounding_allows) || (bounding_allows && !no_new_privs) || device
}
