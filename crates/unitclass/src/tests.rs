//! Tests for the parser, the rule and the tree walk. The properties draw a
//! semantic configuration, render it as unit-file text in random syntax, and
//! check the parser recovers it and the rule agrees with an independent model.
//! The named unit tests each pin one parse rule (mutation evidence: disabling
//! the rule fails its test).

use crate::rule::is_network_tool;
use crate::syntax::{self, CAPABILITIES, CapSet, Caps, Error, Settings};
use crate::tree;
use proptest::prelude::*;
use std::collections::BTreeSet;
use std::fs;

// ---- the model: a semantic configuration, and the rule on it -------------

#[derive(Clone, Debug, PartialEq)]
enum CapCfg {
    Unset,
    Reset,
    Plain(BTreeSet<&'static str>),
    Inverted(BTreeSet<&'static str>),
}

#[derive(Clone, Debug)]
struct Cfg {
    user: Option<&'static str>,
    dynamic: Option<bool>,
    bounding: CapCfg,
    ambient: CapCfg,
    nnp: Option<bool>,
    device: Vec<&'static str>,
    bind: Vec<&'static str>,
    bind_ro: Vec<&'static str>,
}

const NET: [&str; 2] = ["CAP_NET_ADMIN", "CAP_NET_RAW"];

/// The rule, restated from SPEC §12d directly on the model (not through the
/// parser's types), as the independent oracle.
fn model_tool(c: &Cfg) -> bool {
    let grants = |s: &CapCfg| match s {
        CapCfg::Unset | CapCfg::Reset => false,
        CapCfg::Plain(set) => NET.iter().any(|n| set.contains(n)),
        CapCfg::Inverted(set) => NET.iter().any(|n| !set.contains(n)),
    };
    let root = matches!(c.user, None | Some("root") | Some("0")) && c.dynamic != Some(true);
    let bounding_open = matches!(c.bounding, CapCfg::Unset) || grants(&c.bounding);
    let nnp = c.nnp == Some(true);
    let dev =
        c.device.iter().chain(&c.bind).chain(&c.bind_ro).any(|w| w.contains("/dev/net/tun") || w.contains("/dev/ppp"));
    grants(&c.ambient) || (root && bounding_open) || (bounding_open && !nnp) || dev
}

fn expected(c: &Cfg) -> Settings {
    let caps = |s: &CapCfg| match s {
        CapCfg::Unset => Caps::Unset,
        CapCfg::Reset => Caps::Reset,
        CapCfg::Plain(set) => Caps::Set(CapSet { inverted: false, caps: set.clone(), ambiguous: false }),
        CapCfg::Inverted(set) => Caps::Set(CapSet { inverted: true, caps: set.clone(), ambiguous: false }),
    };
    Settings {
        user: c.user.map(str::to_string),
        dynamic_user: c.dynamic,
        bounding: caps(&c.bounding),
        ambient: caps(&c.ambient),
        no_new_privileges: c.nnp,
        device_allow: c.device.iter().map(|s| s.to_string()).collect(),
        bind_paths: c.bind.iter().map(|s| s.to_string()).collect(),
        bind_read_only_paths: c.bind_ro.iter().map(|s| s.to_string()).collect(),
        ..Settings::default()
    }
}

// ---- rendering in random syntax ------------------------------------------

#[derive(Clone, Debug, Default)]
struct Style {
    reset_prefix: bool,
    split: bool,
    continuation: bool,
    comments: bool,
    tabs: bool,
    blank_lines: bool,
    lower_caps: bool,
    numeric_caps: bool,
    bool_spelling: usize,
    decoys: bool,
    reversed: bool,
}

const STYLE_FLAGS: usize = 9;

fn style_from_mask(mask: u32) -> Style {
    Style {
        reset_prefix: mask & 1 != 0,
        split: mask & 2 != 0,
        continuation: mask & 4 != 0,
        comments: mask & 8 != 0,
        tabs: mask & 16 != 0,
        blank_lines: mask & 32 != 0,
        lower_caps: mask & 64 != 0,
        numeric_caps: mask & 128 != 0,
        decoys: mask & 256 != 0,
        ..Style::default()
    }
}

fn cap_token(name: &str, st: &Style, salt: usize) -> String {
    let id = CAPABILITIES.iter().position(|c| *c == name).unwrap();
    if st.numeric_caps && salt.is_multiple_of(2) {
        id.to_string()
    } else if st.lower_caps {
        name.to_ascii_lowercase()
    } else {
        name.to_string()
    }
}

fn eq(st: &Style) -> &'static str {
    if st.tabs { "\t=\t" } else { "=" }
}

fn bool_text(b: bool, spelling: usize) -> &'static str {
    const T: [&str; 4] = ["yes", "true", "on", "1"];
    const F: [&str; 4] = ["no", "false", "off", "0"];
    if b { T[spelling % 4] } else { F[spelling % 4] }
}

/// Lines setting one capability list to `cfg`.
fn cap_lines(key: &str, cfg: &CapCfg, st: &Style) -> Vec<String> {
    let mut out = Vec::new();
    match cfg {
        CapCfg::Unset => {}
        CapCfg::Reset => out.push(format!("{key}{}", eq(st))),
        CapCfg::Plain(set) | CapCfg::Inverted(set) => {
            let inverted = matches!(cfg, CapCfg::Inverted(_));
            if st.reset_prefix {
                // Noise the reset erases.
                out.push(format!("{key}{}CAP_SYS_TIME", eq(st)));
                out.push(format!("{key}{}", eq(st)));
            }
            let toks: Vec<String> = set.iter().enumerate().map(|(i, c)| cap_token(c, st, i)).collect();
            // A plain list may be spread over several assignments; an inverted
            // one is a single assignment.
            let chunks: Vec<Vec<String>> = if st.split && !inverted && toks.len() > 1 {
                toks.chunks(1).map(|c| c.to_vec()).collect()
            } else {
                vec![toks]
            };
            for (i, chunk) in chunks.iter().enumerate() {
                let body = if st.continuation && chunk.len() > 1 {
                    format!("{} \\\n  {}", chunk[0], chunk[1..].join(" "))
                } else {
                    chunk.join(" ")
                };
                let tilde = if inverted { "~" } else { "" };
                out.push(format!("{key}{}{tilde}{body}", eq(st)));
                if st.comments && i == 0 {
                    out.push("# a comment between assignments".into());
                }
            }
        }
    }
    out
}

fn word_lines(key: &str, words: &[&str], st: &Style) -> Vec<String> {
    if words.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::new();
    if st.reset_prefix {
        out.push(format!("{key}{}/dev/null", eq(st)));
        out.push(format!("{key}{}", eq(st)));
    }
    if st.split {
        for w in words {
            out.push(format!("{key}{}{w}", eq(st)));
        }
    } else {
        out.push(format!("{key}{}{}", eq(st), words.join(" ")));
    }
    out
}

/// The files (main first, then drop-ins with their names) for `c`.
fn render(c: &Cfg, st: &Style) -> Vec<(String, String)> {
    let forced;
    let st = if st.decoys && !st.reset_prefix {
        forced = Style { reset_prefix: true, ..st.clone() };
        &forced
    } else {
        st
    };
    // One group of lines per setting; the groups commute, the lines within one do not.
    let mut groups: Vec<Vec<String>> = Vec::new();
    if let Some(u) = c.user {
        groups.push(vec![format!("User{}{u}", eq(st))]);
    }
    if let Some(d) = c.dynamic {
        groups.push(vec![format!("DynamicUser{}{}", eq(st), bool_text(d, st.bool_spelling))]);
    }
    groups.push(cap_lines("CapabilityBoundingSet", &c.bounding, st));
    groups.push(cap_lines("AmbientCapabilities", &c.ambient, st));
    if let Some(n) = c.nnp {
        groups.push(vec![format!("NoNewPrivileges{}{}", eq(st), bool_text(n, st.bool_spelling))]);
    }
    groups.push(word_lines("DeviceAllow", &c.device, st));
    groups.push(word_lines("BindPaths", &c.bind, st));
    groups.push(word_lines("BindReadOnlyPaths", &c.bind_ro, st));
    if st.reversed {
        groups.reverse();
    }
    let service: Vec<String> = groups.into_iter().flatten().collect();
    let mut body = String::from("[Unit]\nDescription=x\n\n[Service]\nExecStart=/bin/true\n");
    for l in &service {
        body.push_str(l);
        body.push('\n');
        if st.blank_lines {
            body.push('\n');
        }
    }
    // A second [Service] section later in the file merges with the first.
    let mut files = vec![("x.service".to_string(), body)];
    if st.decoys {
        // Decoy assignments in the main file, overridden by the real values in
        // a drop-in (drop-ins sort after the main file). A decoy is only used
        // where the real file overrides it: a scalar the configuration sets, a
        // list or capability set it sets (the real lines then start with a
        // reset, which erases the decoy).
        let mut decoy = String::from("[Service]\n");
        if c.user.is_some() {
            decoy.push_str("User=decoy\n");
        }
        if c.dynamic.is_some() {
            decoy.push_str(&format!("DynamicUser={}\n", if c.dynamic == Some(true) { "no" } else { "yes" }));
        }
        if c.nnp.is_some() {
            decoy.push_str(&format!("NoNewPrivileges={}\n", if c.nnp == Some(true) { "no" } else { "yes" }));
        }
        for (key, cfg) in [("CapabilityBoundingSet", &c.bounding), ("AmbientCapabilities", &c.ambient)] {
            if !matches!(cfg, CapCfg::Unset | CapCfg::Reset) {
                decoy.push_str(&format!("{key}=CAP_CHOWN\n"));
            }
        }
        for (key, w) in [("DeviceAllow", &c.device), ("BindPaths", &c.bind), ("BindReadOnlyPaths", &c.bind_ro)] {
            if !w.is_empty() {
                decoy.push_str(&format!("{key}=/dev/net/tun\n"));
            }
        }
        let real = files.remove(0).1.replace("ExecStart=/bin/true\n", "");
        files.push(("x.service".into(), format!("{decoy}ExecStart=/bin/true\n")));
        files.push(("20-real.conf".into(), real));
    }
    files
}

fn effective_of(files: &[(String, String)]) -> Result<Settings, Error> {
    let mut all = Vec::new();
    let mut files: Vec<_> = files.to_vec();
    // The main file first, then the drop-ins sorted by file name.
    let main = files.remove(0);
    files.sort_by(|a, b| a.0.cmp(&b.0));
    all.extend(syntax::parse(&main.0, &main.1)?);
    for (n, t) in &files {
        all.extend(syntax::parse(n, t)?);
    }
    let mut s = Settings::default();
    s.apply(&all)?;
    Ok(s)
}

// ---- generators -----------------------------------------------------------

fn cap_pool() -> Vec<&'static str> {
    vec!["CAP_NET_ADMIN", "CAP_NET_RAW", "CAP_CHOWN", "CAP_SYS_TIME", "CAP_KILL", "CAP_BPF"]
}

fn cap_cfg() -> impl Strategy<Value = CapCfg> {
    prop_oneof![
        Just(CapCfg::Unset),
        Just(CapCfg::Reset),
        proptest::sample::subsequence(cap_pool(), 1..=4).prop_map(|v| CapCfg::Plain(v.into_iter().collect())),
        proptest::sample::subsequence(cap_pool(), 1..=4).prop_map(|v| CapCfg::Inverted(v.into_iter().collect())),
    ]
}

fn words() -> impl Strategy<Value = Vec<&'static str>> {
    proptest::sample::subsequence(
        vec![
            "/dev/null",
            "/dev/net/tun",
            "/dev/ppp",
            "/dev/snd",
            "/var/lib/x:/var/lib/y",
            "-/dev/net/tun:/dev/net/tun",
        ],
        0..=3,
    )
}

fn cfg() -> impl Strategy<Value = Cfg> {
    (
        proptest::option::of(proptest::sample::select(vec!["root", "0", "nobody", "dnsmasq", "1000"])),
        proptest::option::of(any::<bool>()),
        cap_cfg(),
        cap_cfg(),
        proptest::option::of(any::<bool>()),
        words(),
        words(),
        words(),
    )
        .prop_map(|(user, dynamic, bounding, ambient, nnp, device, bind, bind_ro)| Cfg {
            user,
            dynamic,
            bounding,
            ambient,
            nnp,
            device,
            bind,
            bind_ro,
        })
}

fn style() -> impl Strategy<Value = Style> {
    (0u32..256, 0usize..4, any::<bool>()).prop_map(|(mask, bool_spelling, reversed)| Style {
        bool_spelling,
        reversed,
        ..style_from_mask(mask)
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// parse(render(c)) == c, and the rule agrees with the model.
    #[test]
    fn rendering_then_parsing_recovers_the_configuration(c in cfg(), st in style()) {
        let files = render(&c, &st);
        let s = effective_of(&files).expect("a well-formed unit parses");
        prop_assert_eq!(&s, &expected(&c), "files: {:#?}", files);
        prop_assert_eq!(is_network_tool(&s), model_tool(&c));
    }

    /// Fail closed: any unknown construct in [Service], or a setting that
    /// cannot be read, makes the unit a tool, whatever else the unit says.
    #[test]
    fn an_unreadable_construct_makes_the_unit_a_tool(c in cfg(), st in style(), which in 0usize..5) {
        // A configuration that is not a tool by itself.
        let mut c = c;
        c.user = Some("nobody");
        c.dynamic = Some(true);
        c.nnp = Some(true);
        c.bounding = CapCfg::Reset;
        c.ambient = CapCfg::Unset;
        c.device.clear(); c.bind.clear(); c.bind_ro.clear();
        prop_assert!(!model_tool(&c));
        let mut files = render(&c, &st);
        let bad = ["this line has no equals sign", "user=root", "capabilityboundingset=CAP_NET_ADMIN", "NoNewPrivileges=maybe", "DeviceAllow"][which];
        files[0].1.push_str(&format!("{bad}\n"));
        let tool = match effective_of(&files) {
            Err(_) => true,
            Ok(s) => is_network_tool(&s),
        };
        prop_assert!(tool, "{bad:?} must make the unit a tool");
    }
}

/// Each construct alone and in pairs, deterministically, on a configuration
/// that uses every setting (so each flag changes the text).
#[test]
fn every_construct_alone_and_in_pairs_round_trips() {
    let c = Cfg {
        user: Some("nobody"),
        dynamic: Some(false),
        bounding: CapCfg::Plain(["CAP_NET_RAW", "CAP_CHOWN"].into_iter().collect()),
        ambient: CapCfg::Inverted(["CAP_KILL", "CAP_SYS_TIME"].into_iter().collect()),
        nnp: Some(true),
        device: vec!["/dev/null", "/dev/net/tun"],
        bind: vec!["/dev/ppp"],
        bind_ro: vec!["/dev/snd", "/var/lib/x:/var/lib/y"],
    };
    let mut masks = vec![0u32];
    for i in 0..STYLE_FLAGS {
        masks.push(1 << i);
        for j in (i + 1)..STYLE_FLAGS {
            masks.push((1 << i) | (1 << j));
        }
    }
    for mask in masks {
        for spelling in 0..4 {
            let mut st = style_from_mask(mask);
            st.bool_spelling = spelling;
            // The decoy style needs every setting present, which `c` has.
            let files = render(&c, &st);
            let s = effective_of(&files).unwrap_or_else(|e| panic!("mask {mask:b}: {e}\n{files:#?}"));
            assert_eq!(s, expected(&c), "mask {mask:b} spelling {spelling}\n{files:#?}");
            assert_eq!(is_network_tool(&s), model_tool(&c));
        }
    }
}

// ---- one named test per parse rule ---------------------------------------

fn settings(text: &str) -> Settings {
    let mut s = Settings::default();
    s.apply(&syntax::parse("t", text).unwrap()).unwrap();
    s
}

fn set(names: &[&'static str], inverted: bool) -> Caps {
    Caps::Set(CapSet { inverted, caps: names.iter().copied().collect(), ambiguous: false })
}

#[test]
fn an_empty_assignment_resets_a_list() {
    assert_eq!(
        settings("[Service]\nCapabilityBoundingSet=CAP_NET_ADMIN\nCapabilityBoundingSet=\n").bounding,
        Caps::Reset
    );
    assert_eq!(settings("[Service]\nDeviceAllow=/dev/net/tun\nDeviceAllow=\n").device_allow, Vec::<String>::new());
}

#[test]
fn plain_assignments_accumulate() {
    let s = settings("[Service]\nAmbientCapabilities=CAP_KILL\nAmbientCapabilities=CAP_NET_RAW\n");
    assert_eq!(s.ambient, set(&["CAP_KILL", "CAP_NET_RAW"], false));
}

#[test]
fn an_inverted_assignment_is_an_inverted_set() {
    assert_eq!(
        settings("[Service]\nCapabilityBoundingSet=~CAP_NET_ADMIN CAP_NET_RAW\n").bounding,
        set(&["CAP_NET_ADMIN", "CAP_NET_RAW"], true)
    );
    assert_eq!(settings("[Service]\nCapabilityBoundingSet= ~ CAP_NET_ADMIN\n").bounding, set(&["CAP_NET_ADMIN"], true));
}

#[test]
fn an_inverted_assignment_merging_with_another_is_ambiguous_and_grants() {
    let s = settings("[Service]\nCapabilityBoundingSet=CAP_KILL\nCapabilityBoundingSet=~CAP_NET_ADMIN\n");
    let Caps::Set(c) = s.bounding else { panic!() };
    assert!(c.ambiguous && c.grants(&["CAP_NET_ADMIN"]));
}

#[test]
fn a_reset_then_an_inverted_assignment_is_that_inverted_set() {
    assert_eq!(
        settings(
            "[Service]\nCapabilityBoundingSet=CAP_KILL\nCapabilityBoundingSet=\nCapabilityBoundingSet=~CAP_KILL\n"
        )
        .bounding,
        set(&["CAP_KILL"], true)
    );
}

#[test]
fn capability_names_are_case_insensitive_and_ids_are_decimal() {
    assert_eq!(
        settings("[Service]\nAmbientCapabilities=cap_net_admin 13\n").ambient,
        set(&["CAP_NET_ADMIN", "CAP_NET_RAW"], false)
    );
}

#[test]
fn an_unknown_capability_is_ambiguous_and_grants() {
    let Caps::Set(c) = settings("[Service]\nCapabilityBoundingSet=CAP_FUTURE_UNKNOWN\n").bounding else { panic!() };
    assert!(c.ambiguous && c.grants(&["CAP_NET_ADMIN"]));
    let Caps::Set(c) = settings("[Service]\nCapabilityBoundingSet=99\n").bounding else { panic!() };
    assert!(c.ambiguous);
}

#[test]
fn a_backslash_joins_the_next_line() {
    assert_eq!(
        settings("[Service]\nAmbientCapabilities=CAP_KILL \\\n  CAP_NET_RAW\n").ambient,
        set(&["CAP_KILL", "CAP_NET_RAW"], false)
    );
}

#[test]
fn a_comment_inside_a_continuation_is_skipped() {
    assert_eq!(
        settings("[Service]\nAmbientCapabilities=CAP_KILL \\\n# note\n  CAP_NET_RAW\n").ambient,
        set(&["CAP_KILL", "CAP_NET_RAW"], false)
    );
}

#[test]
fn a_blank_line_ends_a_continuation() {
    let s = settings("[Service]\nAmbientCapabilities=CAP_KILL \\\n\nNoNewPrivileges=yes\n");
    assert_eq!(s.ambient, set(&["CAP_KILL"], false));
    assert_eq!(s.no_new_privileges, Some(true));
}

#[test]
fn comments_and_blank_lines_are_ignored() {
    assert_eq!(settings("# c\n; c\n\n[Service]\n# c\nUser=x\n").user.as_deref(), Some("x"));
}

#[test]
fn boolean_spellings() {
    for t in ["1", "yes", "true", "on", "YES", "True"] {
        assert_eq!(settings(&format!("[Service]\nNoNewPrivileges={t}\n")).no_new_privileges, Some(true), "{t}");
    }
    for f in ["0", "no", "false", "off", "Off"] {
        assert_eq!(settings(&format!("[Service]\nDynamicUser={f}\n")).dynamic_user, Some(false), "{f}");
    }
    assert_eq!(settings("[Service]\nNoNewPrivileges=yes\nNoNewPrivileges=\n").no_new_privileges, None);
}

#[test]
fn an_invalid_boolean_is_an_error() {
    let r = syntax::parse("t", "[Service]\nNoNewPrivileges=maybe\n").and_then(|a| Settings::default().apply(&a));
    assert!(matches!(r, Err(Error::BadValue { .. })));
}

#[test]
fn a_service_line_without_an_equals_sign_is_an_error() {
    assert!(matches!(syntax::parse("t", "[Service]\nnonsense\n"), Err(Error::NoAssignment { .. })));
    assert!(syntax::parse("t", "[Install]\nnonsense\n").is_ok(), "outside [Service] it is ignored");
}

#[test]
fn a_malformed_section_header_is_an_error() {
    assert!(matches!(syntax::parse("t", "[Service\nUser=x\n"), Err(Error::BadSection { .. })));
    assert!(matches!(syntax::parse("t", "[]\n"), Err(Error::BadSection { .. })));
}

#[test]
fn a_misspelled_setting_is_an_error() {
    let r = syntax::parse("t", "[Service]\ncapabilityboundingset=CAP_NET_ADMIN\n")
        .and_then(|a| Settings::default().apply(&a));
    assert!(matches!(r, Err(Error::NearMiss { .. })));
}

#[test]
fn settings_outside_service_are_ignored() {
    let s = settings("[Unit]\nUser=nobody\nCapabilityBoundingSet=CAP_KILL\n");
    assert_eq!(s, Settings::default());
}

#[test]
fn the_service_section_merges_across_repeats() {
    let s = settings("[Service]\nUser=a\n[Unit]\nAfter=x.service\n[Service]\nDynamicUser=yes\n");
    assert_eq!(
        (s.user.as_deref(), s.dynamic_user, s.after.as_slice()),
        (Some("a"), Some(true), &["x.service".to_string()][..])
    );
}

#[test]
fn the_rule_on_the_defaults_and_on_the_hardened_corners() {
    assert!(is_network_tool(&Settings::default()), "root with no bounding set");
    let s = settings("[Service]\nUser=nobody\nNoNewPrivileges=yes\n");
    assert!(!is_network_tool(&s));
    let s = settings("[Service]\nUser=nobody\nNoNewPrivileges=yes\nAmbientCapabilities=CAP_NET_RAW\n");
    assert!(is_network_tool(&s));
    let s = settings("[Service]\nCapabilityBoundingSet=\n");
    assert!(!is_network_tool(&s), "root with an empty bounding set holds no capability and cannot gain one");
    let s = settings("[Service]\nUser=nobody\nNoNewPrivileges=yes\nBindReadOnlyPaths=/dev/net/tun\n");
    assert!(is_network_tool(&s));
}

// ---- the tree walk --------------------------------------------------------

fn write(p: &std::path::Path, text: &str) {
    fs::create_dir_all(p.parent().unwrap()).unwrap();
    fs::write(p, text).unwrap();
}

const HARDENED: &str = "[Service]\nUser=nobody\nNoNewPrivileges=yes\nCapabilityBoundingSet=\n";

fn pkg(dir: &std::path::Path, name: &str, unit: &str, text: &str) -> std::path::PathBuf {
    let p = dir.join(name);
    write(&p.join("lib/systemd/system").join(unit), text);
    p
}

fn classify_pkgs(pkgs: &[std::path::PathBuf]) -> Vec<String> {
    let roots: Vec<_> = pkgs.iter().flat_map(|p| tree::package_roots(p)).collect();
    tree::classify(&roots, &|_| false).unwrap().into_iter().map(|c| c.name).collect()
}

#[test]
fn a_drop_in_can_make_a_hardened_unit_a_tool_and_the_reverse() {
    let d = tempfile::tempdir().unwrap();
    let p = pkg(d.path(), "a", "a.service", HARDENED);
    assert!(classify_pkgs(std::slice::from_ref(&p)).is_empty());
    write(&p.join("lib/systemd/system/a.service.d/10-net.conf"), "[Service]\nAmbientCapabilities=CAP_NET_ADMIN\n");
    assert_eq!(classify_pkgs(std::slice::from_ref(&p)), vec!["a"]);
    write(&p.join("lib/systemd/system/a.service.d/20-reset.conf"), "[Service]\nAmbientCapabilities=\n");
    assert!(classify_pkgs(&[p]).is_empty(), "the later drop-in's reset wins: drop-ins apply sorted by file name");
}

#[test]
fn drop_ins_apply_sorted_by_file_name_whatever_the_directory() {
    let d = tempfile::tempdir().unwrap();
    let p = pkg(d.path(), "a", "foo-bar.service", HARDENED);
    // A prefix drop-in named 10 grants; the unit's own named 05 would lose to it.
    write(&p.join("lib/systemd/system/foo-.service.d/10-grant.conf"), "[Service]\nAmbientCapabilities=CAP_NET_RAW\n");
    write(&p.join("lib/systemd/system/foo-bar.service.d/05-reset.conf"), "[Service]\nAmbientCapabilities=\n");
    assert_eq!(classify_pkgs(&[p]), vec!["foo-bar"]);
}

#[test]
fn prefix_type_wide_and_template_drop_ins_apply() {
    for dir in ["foo-.service.d", "service.d"] {
        let d = tempfile::tempdir().unwrap();
        let p = pkg(d.path(), "a", "foo-bar.service", HARDENED);
        write(
            &p.join("lib/systemd/system").join(dir).join("10.conf"),
            "[Service]\nAmbientCapabilities=CAP_NET_ADMIN\n",
        );
        assert_eq!(classify_pkgs(&[p]), vec!["foo-bar"], "{dir}");
    }
    let d = tempfile::tempdir().unwrap();
    let p = pkg(d.path(), "a", "tun@.service", HARDENED);
    write(&p.join("lib/systemd/system/tun@.service.d/10.conf"), "[Service]\nAmbientCapabilities=CAP_NET_ADMIN\n");
    assert_eq!(classify_pkgs(&[p]), vec!["tun@"], "a template is listed with its @");
    let d = tempfile::tempdir().unwrap();
    let p = pkg(d.path(), "a", "tun@office.service", HARDENED);
    write(&p.join("lib/systemd/system/tun@.service.d/10.conf"), "[Service]\nAmbientCapabilities=CAP_NET_ADMIN\n");
    assert_eq!(classify_pkgs(&[p]), vec!["tun@office"], "an instance takes its template's drop-ins");
}

#[test]
fn drop_ins_from_a_second_package_apply_to_the_first_packages_unit() {
    let d = tempfile::tempdir().unwrap();
    let a = pkg(d.path(), "a", "a.service", HARDENED);
    let b = d.path().join("b");
    write(&b.join("lib/systemd/system/a.service.d/10.conf"), "[Service]\nBindPaths=/dev/net/tun\n");
    assert_eq!(classify_pkgs(&[a, b]), vec!["a"]);
}

#[test]
fn the_same_drop_in_name_in_two_packages_is_a_collision_and_the_unit_a_tool() {
    let d = tempfile::tempdir().unwrap();
    let a = pkg(d.path(), "a", "a.service", HARDENED);
    write(&a.join("lib/systemd/system/a.service.d/10.conf"), "[Service]\nUser=nobody\n");
    let b = d.path().join("b");
    write(&b.join("lib/systemd/system/a.service.d/10.conf"), "[Service]\nUser=nobody\n");
    assert_eq!(classify_pkgs(&[a, b]), vec!["a"]);
}

#[test]
fn an_unreadable_drop_in_makes_the_unit_a_tool() {
    let d = tempfile::tempdir().unwrap();
    let p = pkg(d.path(), "a", "a.service", HARDENED);
    fs::create_dir_all(p.join("lib/systemd/system/a.service.d/10.conf")).unwrap(); // a directory, not a file
    assert_eq!(classify_pkgs(&[p]), vec!["a"]);
}

#[test]
fn an_unparsable_unit_file_is_a_tool_and_a_masked_one_is_not() {
    let d = tempfile::tempdir().unwrap();
    let p = pkg(d.path(), "a", "bad.service", "[Service\nUser=nobody\n");
    std::os::unix::fs::symlink("/dev/null", p.join("lib/systemd/system/masked.service")).unwrap();
    assert_eq!(classify_pkgs(&[p]), vec!["bad"]);
}

#[test]
fn a_unit_in_two_packages_is_a_tool_if_either_file_says_so() {
    let d = tempfile::tempdir().unwrap();
    let a = pkg(d.path(), "a", "u.service", HARDENED);
    let b = pkg(d.path(), "b", "u.service", "[Service]\n");
    assert_eq!(classify_pkgs(&[a, b]), vec!["u"]);
}

#[test]
fn the_hold_is_verified_in_the_merged_tree() {
    let d = tempfile::tempdir().unwrap();
    let root = d.path().join("units");
    write(&root.join("t.service"), "[Service]\nExecStart=/bin/true\n");
    write(&root.join("t.service.d/50-planarian-hold.conf"), &tree::hold_dropin(true, true));
    assert_eq!(tree::hold_problem(&root, "t", true), None);
    // A later drop-in with an empty OnFailure= strips the hold.
    write(&root.join("t.service.d/90-strip.conf"), "[Unit]\nOnFailure=\n");
    assert!(tree::hold_problem(&root, "t", true).unwrap().contains("OnFailure="));
    fs::remove_file(root.join("t.service.d/90-strip.conf")).unwrap();
    // The same for After=, only where ordering after netwatch is wanted.
    write(&root.join("t.service.d/90-strip.conf"), "[Unit]\nAfter=\n");
    assert!(tree::hold_problem(&root, "t", true).unwrap().contains("After="));
    assert_eq!(
        tree::hold_problem(&root, "t", false),
        None,
        "a unit in the startup chain is not ordered after netwatch"
    );
    // overrides.conf (NixOS's own drop-in for a declared unit) is read like any.
    fs::remove_file(root.join("t.service.d/90-strip.conf")).unwrap();
    write(&root.join("t.service.d/overrides.conf"), "[Unit]\nOnFailure=\n");
    assert!(tree::hold_problem(&root, "t", true).is_some());
    // A tool with no unit file in the tree (a disabled service) or a masked one
    // cannot fail, so it is not a problem.
    assert_eq!(tree::hold_problem(&root, "missing", true), None);
    std::os::unix::fs::symlink("/dev/null", root.join("masked.service")).unwrap();
    assert_eq!(tree::hold_problem(&root, "masked", true), None);
    // A template instance reads its template's file.
    write(&root.join("w@.service"), "[Service]\nExecStart=/bin/true\n");
    write(&root.join("w@.service.d/50-planarian-hold.conf"), &tree::hold_dropin(true, true));
    assert_eq!(tree::hold_problem(&root, "w@office", true), None);
    assert_eq!(tree::hold_problem(&root, "w@", true), None);
}

#[test]
fn the_hold_check_reads_the_hold_leniently() {
    let d = tempfile::tempdir().unwrap();
    let root = d.path().join("units");
    // A unit file the classifier rejects (a bad header, a line without '=') still has its hold checked.
    write(
        &root.join("t.service"),
        "[Unit]\nDescription=x\n[Service\nUser=nobody\n[Service]\nnonsense\nExecStart=/bin/true\n",
    );
    write(&root.join("t.service.d/50-planarian-hold.conf"), &tree::hold_dropin(true, true));
    assert_eq!(tree::hold_problem(&root, "t", true), None);
    write(&root.join("t.service.d/90-strip.conf"), "[Unit]\nOnFailure=\n");
    assert!(tree::hold_problem(&root, "t", true).is_some());
}

#[test]
fn the_generated_drop_in_matches_the_nix_holddropins_text() {
    assert_eq!(
        tree::hold_dropin(true, true),
        "[Unit]\nOnFailure=planarian-hold@%N.service\nAfter=planarian-netwatch.service\n"
    );
    assert_eq!(tree::hold_dropin(true, false), "[Unit]\nOnFailure=planarian-hold@%N.service\n");
    assert_eq!(tree::hold_dropin(false, true), "[Unit]\nOnFailure=planarian-hold@%N.service\n");
}
