//! The part of systemd's unit-file syntax and merge semantics that the
//! network-tool rule reads (B-23; docs/raw-unit-classification.md §3).
//!
//! Anything this module cannot parse about one of the settings it reads is an
//! [`Error`], and an error makes the unit a network tool (rule 21): it never
//! reads as "unset" when unset would be the open direction.

use std::collections::BTreeSet;

/// The capability names systemd knows, in kernel numbering (the same list and
/// order as `nix/capabilities.nix`, so a decimal id names the same one).
pub const CAPABILITIES: [&str; 41] = [
    "CAP_CHOWN",
    "CAP_DAC_OVERRIDE",
    "CAP_DAC_READ_SEARCH",
    "CAP_FOWNER",
    "CAP_FSETID",
    "CAP_KILL",
    "CAP_SETGID",
    "CAP_SETUID",
    "CAP_SETPCAP",
    "CAP_LINUX_IMMUTABLE",
    "CAP_NET_BIND_SERVICE",
    "CAP_NET_BROADCAST",
    "CAP_NET_ADMIN",
    "CAP_NET_RAW",
    "CAP_IPC_LOCK",
    "CAP_IPC_OWNER",
    "CAP_SYS_MODULE",
    "CAP_SYS_RAWIO",
    "CAP_SYS_CHROOT",
    "CAP_SYS_PTRACE",
    "CAP_SYS_PACCT",
    "CAP_SYS_ADMIN",
    "CAP_SYS_BOOT",
    "CAP_SYS_NICE",
    "CAP_SYS_RESOURCE",
    "CAP_SYS_TIME",
    "CAP_SYS_TTY_CONFIG",
    "CAP_MKNOD",
    "CAP_LEASE",
    "CAP_AUDIT_WRITE",
    "CAP_AUDIT_CONTROL",
    "CAP_SETFCAP",
    "CAP_MAC_OVERRIDE",
    "CAP_MAC_ADMIN",
    "CAP_SYSLOG",
    "CAP_WAKE_ALARM",
    "CAP_BLOCK_SUSPEND",
    "CAP_AUDIT_READ",
    "CAP_PERFMON",
    "CAP_BPF",
    "CAP_CHECKPOINT_RESTORE",
];

/// The settings the rule reads, in `[Service]`.
pub const SERVICE_KEYS: [&str; 8] = [
    "User",
    "DynamicUser",
    "CapabilityBoundingSet",
    "AmbientCapabilities",
    "NoNewPrivileges",
    "DeviceAllow",
    "BindPaths",
    "BindReadOnlyPaths",
];

/// Why a unit could not be read exactly.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// `[` without `]`, or an empty section name.
    BadSection { file: String, line: String },
    /// A `[Service]` line with no `=`.
    NoAssignment { file: String, line: String },
    /// A key that names one of the settings, spelled in a way systemd would
    /// not read as that setting (a different case).
    NearMiss { file: String, key: String },
    /// A value the setting's parser does not accept (a boolean).
    BadValue { file: String, key: String, value: String },
    /// The same drop-in file name in two directories: which one systemd keeps
    /// is not established, so neither is trusted.
    Collision { name: String },
    /// A file that could not be read.
    Unreadable { file: String, why: String },
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::BadSection { file, line } => write!(f, "{file}: malformed section header {line:?}"),
            Error::NoAssignment { file, line } => write!(f, "{file}: [Service] line without '=': {line:?}"),
            Error::NearMiss { file, key } => write!(f, "{file}: {key:?} is not spelled as systemd reads a setting"),
            Error::BadValue { file, key, value } => write!(f, "{file}: {key}={value:?} is not a value systemd accepts"),
            Error::Collision { name } => write!(f, "drop-in {name} exists in more than one directory"),
            Error::Unreadable { file, why } => write!(f, "{file}: {why}"),
        }
    }
}

/// One `Key=Value` as systemd reads it (continuations joined, comments gone).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Assignment {
    pub section: String,
    pub key: String,
    pub value: String,
    pub file: String,
}

/// Parse a unit file or drop-in into its assignments, exactly: a line it
/// cannot read is an [`Error`] (the classifier's mode).
pub fn parse(file: &str, text: &str) -> Result<Vec<Assignment>, Error> {
    parse_with(file, text, true)
}

/// As [`parse`], but a line that cannot be read is skipped, as systemd skips
/// it. The hold check's mode: it reads two `[Unit]` settings and must not
/// fail a system build over a unit file's other syntax.
pub fn parse_lenient(file: &str, text: &str) -> Vec<Assignment> {
    parse_with(file, text, false).unwrap_or_default()
}

fn parse_with(file: &str, text: &str, strict: bool) -> Result<Vec<Assignment>, Error> {
    let mut out = Vec::new();
    let mut section = String::new();
    let mut pending: Option<String> = None;
    let mut logical: Vec<String> = Vec::new();
    for raw in text.lines() {
        let line = raw.trim();
        if pending.is_some() && (line.starts_with('#') || line.starts_with(';')) {
            continue; // a comment inside a continuation is skipped
        }
        if pending.is_none() && (line.is_empty() || line.starts_with('#') || line.starts_with(';')) {
            continue;
        }
        if line.is_empty() {
            logical.extend(pending.take()); // a blank line ends a continuation
            continue;
        }
        let (body, cont) = match line.strip_suffix('\\') {
            Some(b) => (b.trim_end(), true),
            None => (line, false),
        };
        let joined = match pending.take() {
            Some(mut p) => {
                p.push(' ');
                p.push_str(body);
                p
            }
            None => body.to_string(),
        };
        if cont {
            pending = Some(joined);
        } else {
            logical.push(joined);
        }
    }
    logical.extend(pending.take());
    for line in logical {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix('[') {
            match rest.strip_suffix(']') {
                Some(name) if !name.trim().is_empty() => {
                    section = name.trim().to_string();
                    continue;
                }
                _ if strict => return Err(Error::BadSection { file: file.into(), line: line.into() }),
                _ => {
                    section = String::new(); // the keys under a bad header are not read
                    continue;
                }
            }
        }
        match line.split_once('=') {
            Some((k, v)) => out.push(Assignment {
                section: section.clone(),
                key: k.trim().to_string(),
                value: v.trim().to_string(),
                file: file.into(),
            }),
            None if strict && section == "Service" => {
                return Err(Error::NoAssignment { file: file.into(), line: line.into() });
            }
            None => {}
        }
    }
    Ok(out)
}

/// A capability set as one setting holds it.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct CapSet {
    pub inverted: bool,
    pub caps: BTreeSet<&'static str>,
    /// Syntax that cannot be read exactly (an unknown name or id, `~` inside
    /// the list, an inverted assignment that merges with another). It grants.
    pub ambiguous: bool,
}

impl CapSet {
    /// Does this set grant any of `want`? (The Nix rule's `grants`: an
    /// ambiguous set grants; an inverted set grants what it does not exclude.)
    pub fn grants(&self, want: &[&str]) -> bool {
        self.ambiguous
            || if self.inverted {
                want.iter().any(|c| !self.caps.contains(c))
            } else {
                want.iter().any(|c| self.caps.contains(c))
            }
    }
}

fn capability(word: &str) -> Option<&'static str> {
    let upper = word.to_ascii_uppercase();
    if let Some(c) = CAPABILITIES.iter().find(|c| **c == upper) {
        return Some(c);
    }
    if !word.is_empty() && word.bytes().all(|b| b.is_ascii_digit()) {
        return word.parse::<usize>().ok().and_then(|i| CAPABILITIES.get(i)).copied();
    }
    None
}

/// What a capability-set setting holds after its assignments.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Caps {
    /// No assignment: the unit-file default (everything for a bounding set,
    /// nothing for ambient capabilities).
    Unset,
    /// An empty assignment: reset to the empty set; later ones accumulate.
    Reset,
    Set(CapSet),
}

impl Caps {
    fn assign(&mut self, value: &str) {
        if value.is_empty() {
            *self = Caps::Reset;
            return;
        }
        // A leading `~` (as the Nix parser reads it: the joined words with the
        // first `~` removed, then split again).
        let words: Vec<&str> = value.split_whitespace().collect();
        let inverted = words.first().is_some_and(|w| w.starts_with('~'));
        let joined = words.join(" ");
        let body = if inverted { joined.trim_start_matches('~').trim_start() } else { joined.as_str() };
        let tokens: Vec<&str> = body.split_whitespace().collect();
        let mut new = CapSet { inverted, ..CapSet::default() };
        for t in &tokens {
            if t.starts_with('~') {
                new.ambiguous = true;
                continue;
            }
            match capability(t) {
                Some(c) => {
                    new.caps.insert(c);
                }
                None => new.ambiguous = true,
            }
        }
        *self = match std::mem::replace(self, Caps::Unset) {
            Caps::Unset | Caps::Reset => Caps::Set(new),
            Caps::Set(mut old) => {
                // Plain lists accumulate. Anything involving an inverted list
                // merges differently from one joined assignment; it is read
                // as granting (as `capabilities.nix` does).
                if old.inverted || new.inverted {
                    old.ambiguous = true;
                } else {
                    old.caps.extend(new.caps);
                }
                old.ambiguous |= new.ambiguous;
                Caps::Set(old)
            }
        };
    }

    /// The set in force, with `unset` standing for the setting's default.
    pub fn effective(&self, unset: Option<CapSet>) -> Option<CapSet> {
        match self {
            Caps::Unset => unset,
            Caps::Reset => Some(CapSet::default()),
            Caps::Set(s) => Some(s.clone()),
        }
    }
}

/// The effective values of the settings the rule and the hold check read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Settings {
    pub user: Option<String>,
    pub dynamic_user: Option<bool>,
    pub bounding: Caps,
    pub ambient: Caps,
    pub no_new_privileges: Option<bool>,
    pub device_allow: Vec<String>,
    pub bind_paths: Vec<String>,
    pub bind_read_only_paths: Vec<String>,
    /// `[Unit]`: only the hold check reads these.
    pub on_failure: Vec<String>,
    pub after: Vec<String>,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            user: None,
            dynamic_user: None,
            bounding: Caps::Unset,
            ambient: Caps::Unset,
            no_new_privileges: None,
            device_allow: Vec::new(),
            bind_paths: Vec::new(),
            bind_read_only_paths: Vec::new(),
            on_failure: Vec::new(),
            after: Vec::new(),
        }
    }
}

fn boolean(file: &str, key: &str, value: &str) -> Result<Option<bool>, Error> {
    if value.is_empty() {
        return Ok(None);
    }
    match value.to_ascii_lowercase().as_str() {
        "1" | "yes" | "true" | "on" => Ok(Some(true)),
        "0" | "no" | "false" | "off" => Ok(Some(false)),
        _ => Err(Error::BadValue { file: file.into(), key: key.into(), value: value.into() }),
    }
}

fn list(into: &mut Vec<String>, value: &str) {
    if value.is_empty() {
        into.clear();
    } else {
        into.extend(value.split_whitespace().map(str::to_string));
    }
}

impl Settings {
    /// Apply only the `[Unit]` lists the hold check reads (`OnFailure=`,
    /// `After=`), whatever else the unit says.
    pub fn apply_hold<'a>(&mut self, assignments: impl IntoIterator<Item = &'a Assignment>) {
        for a in assignments.into_iter().filter(|a| a.section == "Unit") {
            match a.key.as_str() {
                "OnFailure" => list(&mut self.on_failure, &a.value),
                "After" => list(&mut self.after, &a.value),
                _ => {}
            }
        }
    }

    /// Apply assignments in order (main file, then drop-ins by file name).
    pub fn apply<'a>(&mut self, assignments: impl IntoIterator<Item = &'a Assignment>) -> Result<(), Error> {
        for a in assignments {
            if a.section == "Service" {
                if let Some(exact) = SERVICE_KEYS.iter().find(|k| k.eq_ignore_ascii_case(&a.key))
                    && *exact != a.key
                {
                    return Err(Error::NearMiss { file: a.file.clone(), key: a.key.clone() });
                }
                match a.key.as_str() {
                    "User" => self.user = if a.value.is_empty() { None } else { Some(a.value.clone()) },
                    "DynamicUser" => self.dynamic_user = boolean(&a.file, &a.key, &a.value)?,
                    "NoNewPrivileges" => self.no_new_privileges = boolean(&a.file, &a.key, &a.value)?,
                    "CapabilityBoundingSet" => self.bounding.assign(&a.value),
                    "AmbientCapabilities" => self.ambient.assign(&a.value),
                    "DeviceAllow" => list(&mut self.device_allow, &a.value),
                    "BindPaths" => list(&mut self.bind_paths, &a.value),
                    "BindReadOnlyPaths" => list(&mut self.bind_read_only_paths, &a.value),
                    _ => {}
                }
            } else if a.section == "Unit" {
                match a.key.as_str() {
                    "OnFailure" => list(&mut self.on_failure, &a.value),
                    "After" => list(&mut self.after, &a.value),
                    _ => {}
                }
            }
        }
        Ok(())
    }
}
