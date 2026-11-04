//! Independent construction cases for scoped literals and shell assignments.

use crate::dns::{self, Charge, Lookup, Owners, Target, World};
use planarian_schema::UnitId;
use proptest::prelude::*;
use std::collections::BTreeSet;
use std::net::IpAddr;

fn expected(mask: u8) -> BTreeSet<UnitId> {
    ["creator", "router"]
        .into_iter()
        .enumerate()
        .filter(|(bit, _)| mask & (1 << bit) != 0)
        .map(|(_, name)| UnitId::service(name))
        .collect()
}

fn scoped_charge(targets: &[Target], index: u32, name: &str, mask: u8, present: bool) -> Charge {
    let virtual_ifaces = [name.to_string()].into();
    let owners = |iface: &str| {
        if iface != name {
            return Owners::default();
        }
        Owners {
            creators: (mask & 1 != 0).then(|| UnitId::service("creator")).into_iter().collect(),
            routers: (mask & 2 != 0).then(|| UnitId::service("router")).into_iter().collect(),
        }
    };
    let lookup = |_: &IpAddr| -> Lookup { panic!("a scoped address must not use an unscoped route lookup") };
    let ifname = |i: u32| (present && i == index).then(|| name.to_string());
    dns::charges(
        targets,
        None,
        &World { virtual_ifaces: &virtual_ifaces, owners: &owners, lookup: &lookup, ifname: &ifname },
    )
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    // Construct one real interface and its independent owner set. Both
    // spellings must name that interface, including when it has no owner.
    #[test]
    fn named_and_numeric_dns_scopes_charge_the_same_interface(index in 1u32..10_000, mask in 0u8..4) {
        let name = format!("tun{index}");
        let named = dns::resolv_servers(&format!("nameserver fe80::53%{name}\n"));
        let numeric = dns::resolv_servers(&format!("nameserver fe80::53%{index}\n"));
        let want = Charge { owners: expected(mask), unknown: mask == 0 };
        prop_assert_eq!(scoped_charge(&named, index, &name, mask, true), want.clone());
        prop_assert_eq!(scoped_charge(&numeric, index, &name, mask, true), want);
    }

    // Failure to resolve the index cannot turn its digits into a physical
    // interface, or fall back to an unscoped lookup.
    #[test]
    fn a_missing_numeric_scope_is_unknown(index in 1u32..u32::MAX) {
        let targets = dns::resolv_servers(&format!("nameserver fe80::53%{index}\n"));
        let got = scoped_charge(&targets, index, "tun0", 3, false);
        prop_assert!(got.unknown);
        prop_assert!(got.owners.is_empty());
    }

    // These URI spellings are construction data, not an oracle that
    // repeats the parser. The bare numeric zone 25 has no encoded suffix.
    #[test]
    fn plain_and_rfc_uri_scopes_keep_the_virtual_owners(mask in 0u8..4, port in 1u16..u16::MAX) {
        for (scope, zone, index, name) in [
            ("%tun0", "tun0", 7, "tun0"), ("%7", "7", 7, "tun0"),
            ("%25tun0", "tun0", 7, "tun0"), ("%257", "7", 7, "tun0"),
            ("%25", "25", 25, "tun25"), ("%2525", "25", 25, "tun25"),
        ] {
            let text = format!("https_proxy=http://[fe80::53{scope}]:{port}\n");
            let targets = dns::proxy_hosts(&text);
            prop_assert_eq!(&targets, &vec![Target::Addr {
                addr: "fe80::53".parse().unwrap(), zone: Some(zone.into()),
            }], "{}", text);
            let want = Charge { owners: expected(mask), unknown: mask == 0 };
            prop_assert_eq!(scoped_charge(&targets, index, name, mask, true), want, "{}", text);
        }
    }

    // Shell wrappers do not change a literal assignment's value. Each
    // expected address is constructed before adding quotes and comments.
    #[test]
    fn quotes_comments_and_semicolons_preserve_literal_proxy_assignments(
        octets in any::<[u8; 3]>(), port in 1u16..u16::MAX,
    ) {
        let address: IpAddr = std::net::Ipv4Addr::new(10, octets[0], octets[1], octets[2]).into();
        let url = format!("http://{address}:{port}");
        let want = vec![Target::Addr { addr: address, zone: None }];
        for prefix in ["", "export ", "declare -x "] {
            for quote in ["", "'", "\""] {
                for tail in ["", " # corporate proxy", "\t# comment", "; # comment", "; export OTHER=value"] {
                    let text = format!("{prefix}https_proxy={quote}{url}{quote}{tail}\n");
                    prop_assert_eq!(dns::proxy_hosts(&text), want.clone(), "{}", text);
                }
            }
        }
    }
}

#[test]
fn uri_percent_decoding_does_not_change_a_dns_numeric_scope() {
    assert_eq!(
        dns::resolv_servers("nameserver fe80::53%25\n"),
        vec![Target::Addr { addr: "fe80::53".parse().unwrap(), zone: Some("25".into()) }],
    );
    let targets = dns::resolv_servers("nameserver fe80::53%25\n");
    assert_eq!(scoped_charge(&targets, 25, "tun25", 3, true).owners, expected(3));
    assert_eq!(
        dns::resolv_servers("nameserver fe80::53%25tun0\n"),
        vec![Target::Addr { addr: "fe80::53".parse().unwrap(), zone: Some("25tun0".into()) }],
    );
}

#[test]
fn invalid_scopes_cannot_become_a_physical_interface() {
    for zone in ["0", "4294967296", "18446744073709551615"] {
        let targets = dns::resolv_servers(&format!("nameserver fe80::53%{zone}\n"));
        assert!(scoped_charge(&targets, 7, "tun0", 3, false).unknown, "{zone}");
    }
    assert_eq!(dns::resolv_servers("nameserver 192.0.2.1%7\n"), vec![Target::Unreadable]);
    assert!(dns::proxy_hosts("https_proxy=http://192.0.2.1%7:3128\n").is_empty());
}

#[test]
fn proxy_scope_boundaries_keep_bare_25_and_fail_closed_on_invalid_indices() {
    assert!(dns::proxy_hosts("https_proxy=http://[fe80::53%]:3128\n").is_empty());
    for (scope, zone) in [("%0", "0"), ("%250", "0"), ("%4294967296", "4294967296"), ("%254294967296", "4294967296")] {
        let targets = dns::proxy_hosts(&format!("https_proxy=http://[fe80::53{scope}]:3128\n"));
        assert_eq!(targets, vec![Target::Addr { addr: "fe80::53".parse().unwrap(), zone: Some(zone.into()) }]);
        assert_eq!(scoped_charge(&targets, 25, "tun25", 3, true), Charge { owners: BTreeSet::new(), unknown: true });
    }
}

#[test]
fn unsupported_hostnames_and_expansions_are_not_executed_or_made_into_literals() {
    for value in ["http://proxy.example:3128", "$(printf http://10.8.0.5:3128)", "http://$PROXY:3128"] {
        assert!(dns::proxy_hosts(&format!("https_proxy={value}\n")).is_empty(), "{value}");
    }
}

#[test]
fn quoted_scoped_proxy_with_trailing_comment_is_one_literal() {
    let targets = dns::proxy_hosts("export https_proxy=\"http://[fe80::53%25tun0]:3128\" # corporate proxy\n");
    assert_eq!(targets, vec![Target::Addr { addr: "fe80::53".parse().unwrap(), zone: Some("tun0".into()) }]);
    assert_eq!(scoped_charge(&targets, 7, "tun0", 3, true).owners, expected(3));
}

#[test]
fn literal_credentials_and_escaped_assignment_words_preserve_the_ip_host() {
    let want = vec![Target::Addr { addr: "10.8.0.5".parse().unwrap(), zone: None }];
    for value in ["'http://user:pa$ss@10.8.0.5:3128'", "http://user:pass\\;extra@10.8.0.5:3128"] {
        assert_eq!(dns::proxy_hosts(&format!("https_proxy={value} # comment\n")), want, "{value}");
    }
}

#[test]
fn the_scope_and_assignment_mutants_are_caught() {
    use dns::{MUTANT, Mutant};
    let targets = dns::resolv_servers("nameserver fe80::53%7\n");
    MUTANT.with(|m| m.set(Mutant::NumericScopeIsName));
    let got = scoped_charge(&targets, 7, "tun0", 3, true);
    MUTANT.with(|m| m.set(Mutant::None));
    assert_ne!(got.owners, expected(3), "the numeric-name mutant must be caught");

    MUTANT.with(|m| m.set(Mutant::ProxyDropsScoped));
    let got = dns::proxy_hosts("https_proxy=http://[fe80::53%25tun0]:3128\n");
    MUTANT.with(|m| m.set(Mutant::None));
    assert!(got.is_empty(), "the scope-prefilter mutant must be caught");

    MUTANT.with(|m| m.set(Mutant::BareScopeIsDelimiter));
    let got = dns::proxy_hosts("https_proxy=http://[fe80::53%25]:3128\n");
    MUTANT.with(|m| m.set(Mutant::None));
    assert!(got.is_empty(), "the bare-zone delimiter mutant must be caught");

    MUTANT.with(|m| m.set(Mutant::AssignmentKeepsSyntax));
    let got = dns::proxy_hosts("export https_proxy=http://10.8.0.5:3128 # corporate proxy\n");
    MUTANT.with(|m| m.set(Mutant::None));
    assert!(got.is_empty(), "the trim-only assignment mutant must be caught");
}
