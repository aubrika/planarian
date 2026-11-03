//! The files that carry DNS and proxy steering, read and watched (B-22 a,
//! feature `loader`). The decisions are `dns::reconcile`'s; this module reads
//! the content ([`Files::observe`]) and finds out who wrote it
//! ([`Files::writers`]), with fanotify on the directories that hold the files.
//!
//! **Who wrote.** A fanotify mark on a directory, `FAN_CLOSE_WRITE |
//! FAN_MODIFY` on its children, hands over a file descriptor to each file
//! written and the writer's pid. `nix`'s wrapper has no FID/name reporting,
//! but names are not needed: a program that replaces `resolv.conf` writes a
//! temporary file and renames it over, and the temporary file's inode *is*
//! the new `resolv.conf`'s. So each event is kept as `(device, inode) →
//! (unit, when)`, the unit read from `/proc/<pid>/cgroup` at once, and when
//! an object's inode is looked up its writer is found by that. A changed
//! inode with no record, or a record whose process was in no unit (or gone),
//! is an unknown writer ([`Writer::Unknown`]); no fanotify at all (refused
//! in a container) makes every change one. Records expire after
//! [`WINDOW`] and are bounded.

use crate::dns::{Key, Obs, Writer};
use crate::host::unit_of_cgroup;
use crate::model::ChangeKind;
use nix::sys::fanotify::{EventFFlags, Fanotify, InitFlags, MarkFlags, MaskFlags};
use planarian_schema::UnitId;
use std::collections::{BTreeMap, HashMap};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// How long a write is remembered for its object to be found by inode.
pub const WINDOW: Duration = Duration::from_secs(30);
/// The most writes remembered.
const MAX_RECORDS: usize = 512;

/// A file's identity: device and inode.
type Inode = (u64, u64);

pub struct Files {
    /// Where the files are (`/`; a temporary tree in tests).
    root: PathBuf,
    fan: Option<Fanotify>,
    marked: std::collections::BTreeSet<PathBuf>,
    written: HashMap<Inode, (Option<UnitId>, Instant)>,
    /// Each object's inode at the last observation.
    seen: BTreeMap<Key, Option<Inode>>,
    /// Why there is no attribution (logged once).
    pub refused: Option<String>,
}

/// What [`Files::observe`] read.
#[derive(Default)]
pub struct Observed {
    pub objects: BTreeMap<Key, Obs>,
    pub inodes: BTreeMap<Key, Inode>,
}

impl Files {
    pub fn new(root: &Path) -> Files {
        let (fan, refused) = match Fanotify::init(
            InitFlags::FAN_CLOEXEC | InitFlags::FAN_NONBLOCK | InitFlags::FAN_CLASS_NOTIF,
            EventFFlags::O_RDONLY,
        ) {
            Ok(f) => (Some(f), None),
            Err(e) => (None, Some(format!("fanotify: {e}"))),
        };
        Files {
            root: root.to_path_buf(),
            fan,
            marked: Default::default(),
            written: HashMap::new(),
            seen: BTreeMap::new(),
            refused,
        }
    }

    fn at(&self, p: &str) -> PathBuf {
        self.root.join(p.trim_start_matches('/'))
    }

    /// The directories to watch: those of the files read, and the directory
    /// `resolv.conf` really lives in (a symlink to `/run/...`).
    fn dirs(&self) -> Vec<PathBuf> {
        let mut d = vec![self.at("/etc"), self.at("/etc/profile.d")];
        if let Ok(real) = std::fs::canonicalize(self.at("/etc/resolv.conf"))
            && let Some(parent) = real.parent()
        {
            d.push(parent.to_path_buf());
        }
        d.retain(|p| p.is_dir());
        d
    }

    /// Put a mark on each directory not yet marked; a mark that fails is
    /// retried next time.
    pub fn mark(&mut self) {
        let Some(fan) = &self.fan else { return };
        for dir in self.dirs() {
            if self.marked.contains(&dir) {
                continue;
            }
            let Ok(f) = std::fs::File::open(&dir) else { continue };
            let mask = MaskFlags::FAN_CLOSE_WRITE | MaskFlags::FAN_MODIFY | MaskFlags::FAN_EVENT_ON_CHILD;
            if fan.mark(MarkFlags::FAN_MARK_ADD, mask, &f, None::<&str>).is_ok() {
                self.marked.insert(dir);
            }
        }
    }

    /// (Tests) Whether a write to this file is remembered.
    #[cfg(test)]
    pub(crate) fn recorded(&self, inode: (u64, u64)) -> bool {
        self.written.contains_key(&inode)
    }

    /// (Tests) A watcher with no fanotify, as in a container that refuses it.
    #[cfg(test)]
    pub(crate) fn without_fanotify(mut self) -> Files {
        self.fan = None;
        self
    }

    /// Read every pending event: remember who wrote which file. Returns
    /// whether any arrived.
    pub fn drain(&mut self) -> bool {
        let Some(fan) = &self.fan else { return false };
        let mut any = false;
        while let Ok(events) = fan.read_events() {
            if events.is_empty() {
                break;
            }
            for ev in events {
                any = true;
                let Some(fd) = ev.fd() else { continue };
                let Ok(st) = rustix::fs::fstat(fd) else { continue };
                // The writer's unit, now: it may be gone in a moment.
                let unit = std::fs::read_to_string(format!("/proc/{}/cgroup", ev.pid()))
                    .ok()
                    .and_then(|c| c.lines().find_map(|l| l.strip_prefix("0::").and_then(unit_of_cgroup)));
                let key: Inode = (st.st_dev, st.st_ino);
                // Keep a known unit over an unknown one for the same file.
                let keep = self.written.get(&key).is_some_and(|(u, _)| u.is_some() && unit.is_none());
                if !keep {
                    self.written.insert(key, (unit, Instant::now()));
                }
            }
        }
        let now = Instant::now();
        self.written.retain(|_, (_, t)| now.duration_since(*t) < WINDOW);
        if self.written.len() > MAX_RECORDS {
            let mut by_age: Vec<_> = self.written.iter().map(|(k, (_, t))| (*t, *k)).collect();
            by_age.sort();
            for (_, k) in by_age.into_iter().take(self.written.len() - MAX_RECORDS) {
                self.written.remove(&k);
            }
        }
        any
    }

    /// Read the files: resolv.conf, the proxy files (`/etc/environment`,
    /// NixOS's `/etc/set-environment`, `/etc/profile.d/*`), and each
    /// resolved link's state, whose interface `ifname` names.
    pub fn observe(&self, ifname: &mut dyn FnMut(u32) -> Option<String>) -> Observed {
        let mut out = Observed::default();
        let read = |key: Key, path: PathBuf, steers: fn(&str) -> bool, iface: Option<String>, out: &mut Observed| {
            let (Ok(text), Ok(meta)) = (std::fs::read_to_string(&path), std::fs::metadata(&path)) else { return };
            out.inodes.insert(key.clone(), (meta.dev(), meta.ino()));
            out.objects.insert(key, Obs { steers: steers(&text), iface });
        };
        read(
            (ChangeKind::Dns, "resolv.conf".into()),
            self.at("/etc/resolv.conf"),
            crate::dns::resolv_steers,
            None,
            &mut out,
        );
        let mut proxies = vec![self.at("/etc/environment"), self.at("/etc/set-environment")];
        if let Ok(rd) = std::fs::read_dir(self.at("/etc/profile.d")) {
            let mut v: Vec<_> = rd.filter_map(Result::ok).map(|e| e.path()).collect();
            v.sort();
            proxies.extend(v);
        }
        for p in proxies {
            let shown = format!("/{}", p.strip_prefix(&self.root).unwrap_or(&p).display());
            read((ChangeKind::Proxy, shown), p, crate::dns::proxy_steers, None, &mut out);
        }
        if let Ok(rd) = std::fs::read_dir(self.at("/run/systemd/resolve/netif")) {
            for e in rd.filter_map(Result::ok) {
                let Some(idx) = e.file_name().to_str().and_then(|n| n.parse::<u32>().ok()) else { continue };
                let Some(name) = ifname(idx) else { continue };
                // A link's state has no write to attribute (resolved writes it):
                // its inode is not kept.
                let Ok(text) = std::fs::read_to_string(e.path()) else { continue };
                out.objects.insert(
                    (ChangeKind::Dns, format!("link {name}")),
                    Obs { steers: crate::dns::netif_steers(&text), iface: Some(name) },
                );
            }
        }
        out
    }

    /// Who wrote each object since the last pass: the record for its inode
    /// (consumed), else unknown if its inode changed with no record, else
    /// nobody. No fanotify: any inode change is unknown.
    pub fn writers(&mut self, obs: &Observed) -> BTreeMap<Key, Writer> {
        let mut out = BTreeMap::new();
        for (key, inode) in &obs.inodes {
            let before = self.seen.insert(key.clone(), Some(*inode)).flatten();
            let w = match self.written.remove(inode) {
                Some((Some(u), _)) => Writer::Unit(u),
                Some((None, _)) => Writer::Unknown,
                None if before.is_some_and(|b| b != *inode) => Writer::Unknown,
                None => Writer::NoWrite,
            };
            out.insert(key.clone(), w);
        }
        self.seen.retain(|k, _| obs.inodes.contains_key(k));
        out
    }
}
