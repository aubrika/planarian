//! The change catalog (SPEC §9). Every `ApplyChange` names an entry here.
//! An entry validates its arguments against permitted values and produces
//! flat option assignments for `planarian/overrides.nix`. It never produces
//! raw Nix. Risk is not read from here: the executor derives it from the
//! evaluated generation (I14). `affected_modules` is only a hint.
//!
//! The permitted values and the option each entry writes are owner
//! configuration (`services.planarian.catalog` in the module), exported as
//! JSON and loaded into `CatalogConfig`.

use planarian_schema::{ChangeId, OverrideSet, Value};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ListenAddress {
    pub option: String,
    pub permitted: Vec<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct CatalogConfig {
    /// Service name → its `enable` option, e.g. `"sshd" → "services.openssh.enable"`.
    pub services: BTreeMap<String, String>,
    pub font_scale_option: String,
    pub font_scales: Vec<String>,
    pub keyboard_layout_options: Vec<String>,
    pub keyboard_layouts: Vec<String>,
    pub wifi_option: String,
    pub wifi_networks: Vec<String>,
    pub listen_addresses: BTreeMap<String, ListenAddress>,
    /// Test-only entries for the gym (`gym:<name>`, e.g. `gym:kernel-param`):
    /// set `option` to one of `permitted`, given as the argument `arg`. Ids
    /// not starting with `gym:` are ignored.
    pub gym_choices: BTreeMap<String, GymChoice>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct GymChoice {
    pub option: String,
    pub arg: String,
    pub permitted: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ArgKind {
    Bool,
    OneOf(Vec<String>),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArgSpec {
    pub name: String,
    pub kind: ArgKind,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub id: ChangeId,
    pub description: String,
    pub args: Vec<ArgSpec>,
    /// A hint for the intent matcher and a test assertion; never a policy input.
    pub affected_modules: Vec<String>,
    /// Entries the diagnoser may use (§13: tagged `repair:`).
    pub repair: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CatalogError {
    NotInCatalog(ChangeId),
    MissingArg(String),
    NotPermitted { arg: String, value: String },
    WrongType(String),
}

impl std::fmt::Display for CatalogError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CatalogError::NotInCatalog(c) => write!(f, "no catalog entry {:?}", c.0),
            CatalogError::MissingArg(a) => write!(f, "missing argument {a}"),
            CatalogError::NotPermitted { arg, value } => write!(f, "{arg} = {value:?} is not a permitted value"),
            CatalogError::WrongType(a) => write!(f, "argument {a} has the wrong type"),
        }
    }
}

fn one_of(name: &str, values: &[String]) -> ArgSpec {
    ArgSpec { name: name.into(), kind: ArgKind::OneOf(values.to_vec()) }
}

pub fn entries(cfg: &CatalogConfig) -> Vec<Entry> {
    let services: Vec<String> = cfg.services.keys().cloned().collect();
    let mut out = vec![
        Entry {
            id: ChangeId("service-enable".into()),
            description: "Turn a service on or off".into(),
            args: vec![one_of("service", &services), ArgSpec { name: "enabled".into(), kind: ArgKind::Bool }],
            affected_modules: cfg.services.values().cloned().collect(),
            repair: false,
        },
        Entry {
            id: ChangeId("repair:reenable-predicted".into()),
            description: "Re-enable a service the manifest expects to be running".into(),
            args: vec![one_of("service", &services)],
            affected_modules: cfg.services.values().cloned().collect(),
            repair: true,
        },
    ];
    if !cfg.font_scale_option.is_empty() {
        out.push(Entry {
            id: ChangeId("font-scale".into()),
            description: "Set the font scale for text".into(),
            args: vec![one_of("scale", &cfg.font_scales)],
            affected_modules: vec![cfg.font_scale_option.clone()],
            repair: false,
        });
    }
    if !cfg.keyboard_layout_options.is_empty() {
        out.push(Entry {
            id: ChangeId("keyboard-layout".into()),
            description: "Set the keyboard layout".into(),
            args: vec![one_of("layout", &cfg.keyboard_layouts)],
            affected_modules: cfg.keyboard_layout_options.clone(),
            repair: false,
        });
    }
    if !cfg.wifi_option.is_empty() {
        out.push(Entry {
            id: ChangeId("wifi-select".into()),
            description: "Choose the preferred Wi-Fi network".into(),
            args: vec![one_of("ssid", &cfg.wifi_networks)],
            affected_modules: vec![cfg.wifi_option.clone()],
            repair: false,
        });
    }
    if !cfg.listen_addresses.is_empty() {
        out.push(Entry {
            id: ChangeId("listen-address".into()),
            description: "Set a service's listen address".into(),
            args: vec![
                one_of("service", &cfg.listen_addresses.keys().cloned().collect::<Vec<_>>()),
                one_of("addr", &cfg.listen_addresses.values().flat_map(|l| l.permitted.clone()).collect::<Vec<_>>()),
            ],
            affected_modules: cfg.listen_addresses.values().map(|l| l.option.clone()).collect(),
            repair: false,
        });
    }
    for (id, c) in cfg.gym_choices.iter().filter(|(id, _)| id.starts_with("gym:")) {
        out.push(Entry {
            id: ChangeId(id.clone()),
            description: format!("(gym) set {}", c.option),
            args: vec![one_of(&c.arg, &c.permitted)],
            affected_modules: vec![c.option.clone()],
            repair: false,
        });
    }
    out
}

fn arg_str<'a>(args: &'a BTreeMap<String, Value>, name: &str) -> Result<&'a str, CatalogError> {
    match args.get(name) {
        Some(Value::Str(s)) => Ok(s),
        Some(_) => Err(CatalogError::WrongType(name.into())),
        None => Err(CatalogError::MissingArg(name.into())),
    }
}

fn permitted<'a>(name: &str, value: &'a str, allowed: &[String]) -> Result<&'a str, CatalogError> {
    if allowed.iter().any(|a| a == value) {
        Ok(value)
    } else {
        Err(CatalogError::NotPermitted { arg: name.into(), value: value.into() })
    }
}

/// Run an entry's handler: validated option assignments to merge into the
/// override file.
pub fn handle(
    cfg: &CatalogConfig,
    change: &ChangeId,
    args: &BTreeMap<String, Value>,
) -> Result<OverrideSet, CatalogError> {
    let mut a = BTreeMap::new();
    match change.0.as_str() {
        "service-enable" | "repair:reenable-predicted" => {
            let services: Vec<String> = cfg.services.keys().cloned().collect();
            let svc = permitted("service", arg_str(args, "service")?, &services)?;
            let enabled = if change.0 == "service-enable" {
                match args.get("enabled") {
                    Some(Value::Bool(b)) => *b,
                    Some(_) => return Err(CatalogError::WrongType("enabled".into())),
                    None => return Err(CatalogError::MissingArg("enabled".into())),
                }
            } else {
                true
            };
            a.insert(cfg.services[svc].clone(), Value::Bool(enabled));
        }
        "font-scale" if !cfg.font_scale_option.is_empty() => {
            let scale = permitted("scale", arg_str(args, "scale")?, &cfg.font_scales)?;
            a.insert(cfg.font_scale_option.clone(), Value::Str(scale.into()));
        }
        "keyboard-layout" if !cfg.keyboard_layout_options.is_empty() => {
            let layout = permitted("layout", arg_str(args, "layout")?, &cfg.keyboard_layouts)?;
            for opt in &cfg.keyboard_layout_options {
                a.insert(opt.clone(), Value::Str(layout.into()));
            }
        }
        "wifi-select" if !cfg.wifi_option.is_empty() => {
            let ssid = permitted("ssid", arg_str(args, "ssid")?, &cfg.wifi_networks)?;
            a.insert(cfg.wifi_option.clone(), Value::Str(ssid.into()));
        }
        "listen-address" => {
            let svcs: Vec<String> = cfg.listen_addresses.keys().cloned().collect();
            let svc = permitted("service", arg_str(args, "service")?, &svcs)?;
            let la = &cfg.listen_addresses[svc];
            let addr = permitted("addr", arg_str(args, "addr")?, &la.permitted)?;
            a.insert(la.option.clone(), Value::Str(addr.into()));
        }
        id if id.starts_with("gym:") && cfg.gym_choices.contains_key(id) => {
            let c = &cfg.gym_choices[id];
            let v = permitted(&c.arg, arg_str(args, &c.arg)?, &c.permitted)?;
            a.insert(c.option.clone(), Value::Str(v.into()));
        }
        _ => return Err(CatalogError::NotInCatalog(change.clone())),
    }
    Ok(OverrideSet { assignments: a })
}

/// The `ApplyChange` that persists a runtime option (§12a write-back).
pub fn writeback(path: &str, value: &Value) -> Option<(ChangeId, BTreeMap<String, Value>)> {
    let (id, arg) = match path {
        "font.scale" => ("font-scale", "scale"),
        "keyboard.layout" => ("keyboard-layout", "layout"),
        "wifi.network" => ("wifi-select", "ssid"),
        _ => return None,
    };
    Some((ChangeId(id.into()), [(arg.to_string(), value.clone())].into()))
}

/// `base` with `change`'s assignments applied on top.
pub fn merge(base: &OverrideSet, change: &OverrideSet) -> OverrideSet {
    let mut a = base.assignments.clone();
    a.extend(change.assignments.clone());
    OverrideSet { assignments: a }
}

fn nix_string(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '$' => out.push_str("\\$"),
            '\n' => out.push_str("\\n"),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn nix_value(v: &Value) -> String {
    match v {
        Value::Bool(b) => b.to_string(),
        Value::Int(i) => i.to_string(),
        Value::Str(s) => nix_string(s),
        Value::List(l) => format!("[ {} ]", l.iter().map(nix_value).collect::<Vec<_>>().join(" ")),
    }
}

/// Option paths are dotted identifiers; quote any segment that isn't a plain one.
fn nix_path(path: &str) -> String {
    path.split('.')
        .map(|seg| {
            let plain = !seg.is_empty()
                && seg.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '\'')
                && !seg.starts_with(|c: char| c.is_ascii_digit() || c == '-' || c == '\'');
            if plain { seg.to_string() } else { nix_string(seg) }
        })
        .collect::<Vec<_>>()
        .join(".")
}

/// The full text of `planarian/overrides.nix`. Deterministic, so its content
/// hash identifies the override set (§9 step 4).
pub fn render(set: &OverrideSet) -> String {
    let mut out = String::from(
        "# Generated by Planarian. Do not edit: changes go through `planarian` / `ask`.\n\
         # Each assignment is lib.mkOverride 90, so your own settings (priority 100)\n\
         # lose to it, and lib.mkForce (priority 50) wins over it.\n\
         { lib, ... }:\n{\n",
    );
    for (path, v) in &set.assignments {
        out.push_str(&format!("  {} = lib.mkOverride 90 {};\n", nix_path(path), nix_value(v)));
    }
    out.push_str("}\n");
    out
}

/// Parse a file produced by `render` back into assignments. Only the exact
/// rendered form is accepted; anything else is `None`.
pub fn parse(text: &str) -> Option<OverrideSet> {
    let mut a = BTreeMap::new();
    for line in text.lines() {
        let line = line.trim();
        let Some(rest) = line.strip_suffix(';') else { continue };
        let Some((path, val)) = rest.split_once(" = lib.mkOverride 90 ") else { continue };
        let path = path.split('.').map(|s| s.trim_matches('"').to_string()).collect::<Vec<_>>().join(".");
        let v = if val == "true" || val == "false" {
            Value::Bool(val == "true")
        } else if let Ok(i) = val.parse::<i64>() {
            Value::Int(i)
        } else if val.starts_with('"') && val.ends_with('"') && val.len() >= 2 {
            Value::Str(
                val[1..val.len() - 1]
                    .replace("\\\"", "\"")
                    .replace("\\$", "$")
                    .replace("\\n", "\n")
                    .replace("\\\\", "\\"),
            )
        } else {
            return None;
        };
        a.insert(path, v);
    }
    let set = OverrideSet { assignments: a };
    (render(&set) == text).then_some(set)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> CatalogConfig {
        CatalogConfig {
            services: [
                ("sshd".into(), "services.openssh.enable".into()),
                ("avahi".into(), "services.avahi.enable".into()),
            ]
            .into(),
            font_scale_option: "planarian.reference.fontScale".into(),
            font_scales: ["0.75", "1", "1.25", "1.5", "2"].map(String::from).into(),
            keyboard_layout_options: vec!["services.xserver.xkb.layout".into(), "console.keyMap".into()],
            keyboard_layouts: vec!["us".into(), "de".into()],
            wifi_option: "planarian.reference.wifiNetwork".into(),
            wifi_networks: vec!["home".into()],
            listen_addresses: [(
                "gym-web".into(),
                ListenAddress {
                    option: "services.gym-web.listenAddress".into(),
                    permitted: vec!["127.0.0.1".into(), "192.0.2.10".into()],
                },
            )]
            .into(),
            gym_choices: [
                (
                    "gym:kernel-param".into(),
                    GymChoice {
                        option: "gym.kernelParam".into(),
                        arg: "param".into(),
                        permitted: vec!["virtio_gpu.modeset=0".into()],
                    },
                ),
                (
                    "kernel-param".into(),
                    GymChoice { option: "boot.x".into(), arg: "param".into(), permitted: vec!["y".into()] },
                ),
            ]
            .into(),
        }
    }

    fn args(kv: &[(&str, Value)]) -> BTreeMap<String, Value> {
        kv.iter().map(|(k, v)| (k.to_string(), v.clone())).collect()
    }

    #[test]
    fn handlers_validate_and_assign() {
        let c = cfg();
        let font = handle(&c, &ChangeId("font-scale".into()), &args(&[("scale", Value::Str("1.25".into()))])).unwrap();
        assert_eq!(font.assignments["planarian.reference.fontScale"], Value::Str("1.25".into()));
        assert_eq!(
            handle(&c, &ChangeId("font-scale".into()), &args(&[("scale", Value::Str("9".into()))])),
            Err(CatalogError::NotPermitted { arg: "scale".into(), value: "9".into() })
        );
        let off = handle(
            &c,
            &ChangeId("service-enable".into()),
            &args(&[("service", Value::Str("sshd".into())), ("enabled", Value::Bool(false))]),
        )
        .unwrap();
        assert_eq!(off.assignments["services.openssh.enable"], Value::Bool(false));
        assert!(
            handle(
                &c,
                &ChangeId("service-enable".into()),
                &args(&[("service", Value::Str("planariad".into())), ("enabled", Value::Bool(false))])
            )
            .is_err(),
            "not on the allowlist"
        );
        assert_eq!(
            handle(&c, &ChangeId("manifest-probe-edit".into()), &BTreeMap::new()),
            Err(CatalogError::NotInCatalog(ChangeId("manifest-probe-edit".into())))
        );
        let kb =
            handle(&c, &ChangeId("keyboard-layout".into()), &args(&[("layout", Value::Str("de".into()))])).unwrap();
        assert_eq!(kb.assignments.len(), 2);
        let la = handle(
            &c,
            &ChangeId("listen-address".into()),
            &args(&[("service", Value::Str("gym-web".into())), ("addr", Value::Str("192.0.2.10".into()))]),
        )
        .unwrap();
        assert_eq!(la.assignments["services.gym-web.listenAddress"], Value::Str("192.0.2.10".into()));
        assert_eq!(entries(&c).len(), 7, "the six shipped kinds and one gym: choice");
    }

    #[test]
    fn render_parse_roundtrip() {
        let set = OverrideSet {
            assignments: [
                ("services.openssh.enable".to_string(), Value::Bool(false)),
                ("planarian.reference.fontScale".to_string(), Value::Str("1.25".into())),
                ("services.gym-web.x".to_string(), Value::Str("a \"q\" $x".into())),
                ("boot.n".to_string(), Value::Int(3)),
            ]
            .into(),
        };
        let text = render(&set);
        assert!(text.contains("services.openssh.enable = lib.mkOverride 90 false;"));
        assert!(text.contains("\\$x"), "no antiquotation injection");
        let back = parse(&text).unwrap();
        assert_eq!(render(&back), text);
        assert!(parse("{ lib, ... }: { x = import /etc/evil; }").is_none());
        assert_eq!(parse(&render(&OverrideSet::default())), Some(OverrideSet::default()));
    }

    #[test]
    fn gym_choices_only_with_the_prefix() {
        let c = cfg();
        let ids: Vec<String> = entries(&c).into_iter().map(|e| e.id.0).collect();
        assert!(ids.contains(&"gym:kernel-param".to_string()));
        assert!(!ids.contains(&"kernel-param".to_string()), "a choice without gym: is not an entry");
        let args = [("param".to_string(), Value::Str("virtio_gpu.modeset=0".into()))].into();
        let set = handle(&c, &ChangeId("gym:kernel-param".into()), &args).unwrap();
        assert_eq!(set.assignments["gym.kernelParam"], Value::Str("virtio_gpu.modeset=0".into()));
        let bad = [("param".to_string(), Value::Str("init=/bin/sh".into()))].into();
        assert!(matches!(
            handle(&c, &ChangeId("gym:kernel-param".into()), &bad),
            Err(CatalogError::NotPermitted { .. })
        ));
        assert!(matches!(handle(&c, &ChangeId("kernel-param".into()), &args), Err(CatalogError::NotInCatalog(_))));
    }
}

#[cfg(test)]
mod golden {
    /// The flake template ships an empty override file; the parser only accepts
    /// the exact rendered form, so the two must stay identical.
    #[test]
    fn template_override_file_is_the_rendered_empty_set() {
        let shipped = include_str!("../../../nix/template/planarian/overrides.nix");
        assert_eq!(shipped, super::render(&planarian_schema::OverrideSet::default()));
    }
}
