//! Which unit a cgroup id belongs to, kept as systemd creates them (crate
//! docs, "Attribution"). systemd makes a unit's cgroup before it starts the
//! unit's first process, so an inotify watch on `system.slice` (and each
//! slice under it) records the id before the unit can change anything. Ids
//! are never forgotten when a cgroup goes: they are 64-bit and not reused
//! within a boot, so a short-lived unit (a oneshot that exits at once) is
//! still charged with what it did. A cgroup made and removed before netwatch
//! sees it at all stays unknown: unattributed, fail closed.

use crate::host::{read_cgroups, unit_of_cgroup};
use planarian_schema::UnitId;
use rustix::fs::inotify;
use std::collections::{BTreeMap, BTreeSet};
use std::os::fd::OwnedFd;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

/// Ids kept at most; the oldest gone ones are dropped first.
pub const KEEP: usize = 65_536;

pub struct Cgroups {
    root: PathBuf,
    ids: BTreeMap<u64, UnitId>,
    inotify: Option<OwnedFd>,
    watched: BTreeMap<i32, PathBuf>,
}

impl Cgroups {
    /// Watch `root/system.slice` and every slice below it, then walk.
    /// Without inotify (refused), lookups still fall back to walking.
    pub fn new(root: &Path) -> Cgroups {
        let inotify = inotify::init(inotify::CreateFlags::CLOEXEC | inotify::CreateFlags::NONBLOCK).ok();
        let mut c = Cgroups { root: root.to_path_buf(), ids: BTreeMap::new(), inotify, watched: BTreeMap::new() };
        c.watch_tree(&root.join("system.slice"));
        c.walk();
        c
    }

    /// The inotify descriptor, for the loop to wait on.
    pub fn fd(&self) -> Option<&OwnedFd> {
        self.inotify.as_ref()
    }

    /// Walk the tree; ids are merged, never replaced. Returns the units
    /// running now.
    pub fn walk(&mut self) -> BTreeSet<String> {
        let (ids, running) = read_cgroups(&self.root);
        if self.ids.len() + ids.len() > KEEP {
            // Drop the oldest ids no longer standing.
            let gone: Vec<u64> = self.ids.keys().filter(|i| !ids.contains_key(i)).copied().collect();
            for i in gone.into_iter().take(self.ids.len() + ids.len() - KEEP) {
                self.ids.remove(&i);
            }
        }
        self.ids.extend(ids);
        running
    }

    /// Record every cgroup created since the last call.
    pub fn drain(&mut self) {
        let Some(fd) = self.inotify.as_ref() else { return };
        let mut buf = [std::mem::MaybeUninit::<u8>::uninit(); 4096];
        let mut created = Vec::new();
        let mut reader = inotify::Reader::new(fd, &mut buf);
        while let Ok(ev) = reader.next() {
            if !ev.events().contains(inotify::ReadFlags::ISDIR) {
                continue;
            }
            if let (Some(dir), Some(name)) = (self.watched.get(&ev.wd()), ev.file_name()) {
                created.push(dir.join(name.to_string_lossy().as_ref()));
            }
        }
        for dir in created {
            self.record(&dir);
            if dir.extension().is_some_and(|e| e == "slice") {
                // A new slice: watch it, then catch what was made in it
                // before the watch.
                self.watch_tree(&dir);
            }
        }
    }

    /// The unit `id` belongs to: known, or newly created, or found by a walk.
    pub fn unit(&mut self, id: u64) -> Option<UnitId> {
        if !self.ids.contains_key(&id) {
            self.drain();
        }
        if !self.ids.contains_key(&id) {
            self.walk();
        }
        self.ids.get(&id).cloned()
    }

    fn record(&mut self, dir: &Path) {
        if let (Ok(meta), Ok(rel)) = (std::fs::metadata(dir), dir.strip_prefix(&self.root))
            && let Some(u) = unit_of_cgroup(&rel.to_string_lossy())
        {
            self.ids.insert(meta.ino(), u);
        }
    }

    fn watch_tree(&mut self, dir: &Path) {
        if let Some(fd) = self.inotify.as_ref()
            && let Ok(wd) = inotify::add_watch(fd, dir, inotify::WatchFlags::CREATE | inotify::WatchFlags::ONLYDIR)
        {
            self.watched.insert(wd, dir.to_path_buf());
        }
        for e in std::fs::read_dir(dir).into_iter().flatten().flatten() {
            let p = e.path();
            if !e.file_type().is_ok_and(|t| t.is_dir()) {
                continue;
            }
            self.record(&p);
            if p.extension().is_some_and(|x| x == "slice") {
                self.watch_tree(&p);
            }
        }
    }
}
