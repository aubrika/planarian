//! The files that carry DNS and proxy steering, read (B-22 a, feature
//! `loader`). The rule is `dns::charges`'s; this module only reads the
//! settings into addresses ([`Files::observe`]) and tells when they may have
//! changed ([`Files::signature`]), by looking at the few files themselves, so
//! there is no watcher to attribute a writer: the charge goes to the owners
//! of the interface that carries the address, not to whoever wrote it.

use crate::dns::{Key, Target};
use crate::model::ChangeKind;
use std::collections::BTreeMap;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

pub struct Files {
    /// Where the files are (`/`; a temporary tree in tests).
    root: PathBuf,
}

/// The settings found: per object, the addresses it names and, for a resolved
/// link, the interface they belong to.
pub type Settings = BTreeMap<Key, (Vec<Target>, Option<String>)>;

impl Files {
    pub fn new(root: &Path) -> Files {
        Files { root: root.to_path_buf() }
    }

    fn at(&self, p: &str) -> PathBuf {
        self.root.join(p.trim_start_matches('/'))
    }

    /// The proxy files: `/etc/environment`, NixOS's `/etc/set-environment`
    /// and `/etc/profile.d/*`.
    fn proxy_files(&self) -> Vec<PathBuf> {
        let mut v = vec![self.at("/etc/environment"), self.at("/etc/set-environment")];
        if let Ok(rd) = std::fs::read_dir(self.at("/etc/profile.d")) {
            let mut d: Vec<_> = rd.filter_map(Result::ok).map(|e| e.path()).collect();
            d.sort();
            v.extend(d);
        }
        v
    }

    /// Every file read, with (device, inode, size, mtime): a cheap check that
    /// nothing may have changed since the last pass. A replace-by-rename
    /// changes the inode; an in-place write changes the mtime or size.
    pub fn signature(&self) -> Vec<(PathBuf, u64, u64, u64, i64, i64)> {
        let mut files = self.proxy_files();
        files.push(self.at("/etc/resolv.conf"));
        if let Ok(rd) = std::fs::read_dir(self.at("/run/systemd/resolve/netif")) {
            files.extend(rd.filter_map(Result::ok).map(|e| e.path()));
        }
        files.push(self.at("/run/systemd/resolve/resolv.conf"));
        files
            .into_iter()
            .filter_map(|p| {
                let m = std::fs::metadata(&p).ok()?;
                Some((p, m.dev(), m.ino(), m.size(), m.mtime(), m.mtime_nsec()))
            })
            .collect()
    }

    /// Read the settings: resolv.conf, the proxy files, and each resolved
    /// link's state (`/run/systemd/resolve/netif/<ifindex>`), whose interface
    /// `ifname` names. A file that is not there is no object (so it steers
    /// for nobody now).
    pub fn observe(&self, ifname: &mut dyn FnMut(u32) -> Option<String>) -> Settings {
        let mut out = Settings::new();
        if let Ok(text) = std::fs::read_to_string(self.at("/etc/resolv.conf")) {
            out.insert((ChangeKind::Dns, "resolv.conf".into()), (crate::dns::resolv_servers(&text), None));
        }
        for p in self.proxy_files() {
            if let Ok(text) = std::fs::read_to_string(&p) {
                let shown = format!("/{}", p.strip_prefix(&self.root).unwrap_or(&p).display());
                out.insert((ChangeKind::Proxy, shown), (crate::dns::proxy_hosts(&text), None));
            }
        }
        if let Ok(rd) = std::fs::read_dir(self.at("/run/systemd/resolve/netif")) {
            for e in rd.filter_map(Result::ok) {
                let Some(idx) = e.file_name().to_str().and_then(|n| n.parse::<u32>().ok()) else { continue };
                let Some(name) = ifname(idx) else { continue };
                let Ok(text) = std::fs::read_to_string(e.path()) else { continue };
                out.insert((ChangeKind::Dns, format!("link {name}")), (crate::dns::netif_servers(&text), Some(name)));
            }
        }
        // resolved's global servers (`DNS=` in resolved.conf, set over D-Bus):
        // its state file is the one resolved hands to resolv.conf's stub.
        if let Ok(text) = std::fs::read_to_string(self.at("/run/systemd/resolve/resolv.conf")) {
            out.insert((ChangeKind::Dns, "resolved".into()), (crate::dns::resolv_servers(&text), None));
        }
        out
    }
}
