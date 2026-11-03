//! Which unit a cgroup id belongs to, kept as systemd creates them (crate
//! docs, "Attribution"). systemd makes a unit's cgroup before it starts the
//! unit's first process, so an inotify watch on `system.slice` (and each
//! slice under it) records the id before the unit can change anything. An id
//! is kept after its cgroup goes, which is safe because ids are 64-bit and
//! not reused within a boot: a short-lived unit (a oneshot that exits at
//! once) is still charged with what it did. It is forgotten only once its
//! cgroup has been gone for two walks (a tick apart, so no event of it is
//! still unread) and its unit has no footprint claim, so the map stays
//! bounded on a long-lived host. A cgroup made and removed before netwatch
//! sees it at all stays unknown: unattributed, fail closed.
//!
//! The same watch sees unit cgroups removed (IN_DELETE, with a `stat` of
//! each live invocation's cgroup at most every [`ABSENCE_MS`] as the
//! fallback), which is how an invocation comes to read `ended` (crate docs,
//! "The hold's order").

use crate::host::{read_cgroups, unit_of_cgroup};
use planarian_schema::UnitId;
use rustix::fs::inotify;
use std::collections::{BTreeMap, BTreeSet};
use std::os::fd::OwnedFd;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

pub struct Cgroups {
    root: PathBuf,
    ids: BTreeMap<u64, UnitId>,
    inotify: Option<OwnedFd>,
    watched: BTreeMap<i32, PathBuf>,
    /// Ids whose cgroup was gone at the last walk.
    gone: BTreeSet<u64>,
    /// Each unit's latest invocation (crate docs, "The hold's order").
    invocations: BTreeMap<UnitId, Inv>,
    /// Unit cgroups made whose InvocationID systemd had not set yet.
    pending: BTreeSet<PathBuf>,
    /// When absence was last checked (the fallback for a missed IN_DELETE).
    absence_at: Option<std::time::Instant>,
}

/// A unit's latest invocation, as its cgroup shows it.
#[derive(Clone, Debug)]
struct Inv {
    dir: PathBuf,
    id: Option<String>,
    /// Its cgroup was seen gone at the start of this drain: `ended` once
    /// the ring has been drained after ([`Cgroups::finish`]).
    removing: bool,
    ended: bool,
}

/// How often, at most, the unit cgroups' absence is checked by `stat`.
pub const ABSENCE_MS: u64 = 250;

impl Cgroups {
    /// Watch `root/system.slice` and every slice below it, then walk.
    /// Without inotify (refused), lookups still fall back to walking.
    pub fn new(root: &Path) -> Cgroups {
        let inotify = inotify::init(inotify::CreateFlags::CLOEXEC | inotify::CreateFlags::NONBLOCK).ok();
        let mut c = Cgroups {
            root: root.to_path_buf(),
            ids: BTreeMap::new(),
            inotify,
            watched: BTreeMap::new(),
            gone: BTreeSet::new(),
            invocations: BTreeMap::new(),
            pending: BTreeSet::new(),
            absence_at: None,
        };
        c.watch_tree(&root.join("system.slice"));
        c.merge();
        c
    }

    /// As if inotify were refused (or its queue overflowed): removals
    /// are seen by the absence check alone.
    #[cfg(test)]
    pub(crate) fn without_inotify(mut self) -> Cgroups {
        self.inotify = None;
        self.watched.clear();
        self
    }

    /// The inotify descriptor, for the loop to wait on.
    pub fn fd(&self) -> Option<&OwnedFd> {
        self.inotify.as_ref()
    }

    /// A tick's walk: merge what stands (never replace), then forget the
    /// ids gone for two walks whose unit has no claim (`claimed`: every unit
    /// the footprint claims anything for). Returns the units running now.
    pub fn walk(&mut self, claimed: &BTreeSet<UnitId>) -> BTreeSet<String> {
        let (ids, running) = read_cgroups(&self.root);
        let gone: BTreeSet<u64> = self.ids.keys().filter(|i| !ids.contains_key(i)).copied().collect();
        let before = std::mem::take(&mut self.gone);
        self.ids.retain(|i, u| !(before.contains(i) && gone.contains(i) && !claimed.contains(u)));
        self.gone = gone.into_iter().filter(|i| self.ids.contains_key(i)).collect();
        self.ids.extend(ids);
        self.read_invocations();
        running
    }

    /// How many ids are known (kept or standing).
    pub fn len(&self) -> usize {
        self.ids.len()
    }

    /// Whether no id is known.
    pub fn is_empty(&self) -> bool {
        self.ids.is_empty()
    }

    /// Merge what stands now, forgetting nothing.
    fn merge(&mut self) {
        let (ids, _) = read_cgroups(&self.root);
        self.ids.extend(ids);
    }

    /// Record every cgroup created since the last call, and every unit
    /// cgroup removed: in order, so a stop then a start of the same unit is
    /// a removal then a new invocation.
    pub fn drain(&mut self) {
        let mut seen = Vec::new();
        if let Some(fd) = self.inotify.as_ref() {
            let mut buf = [std::mem::MaybeUninit::<u8>::uninit(); 4096];
            let mut reader = inotify::Reader::new(fd, &mut buf);
            while let Ok(ev) = reader.next() {
                if !ev.events().contains(inotify::ReadFlags::ISDIR) {
                    continue;
                }
                let deleted = ev.events().contains(inotify::ReadFlags::DELETE);
                if let (Some(dir), Some(name)) = (self.watched.get(&ev.wd()), ev.file_name()) {
                    seen.push((deleted, dir.join(name.to_string_lossy().as_ref())));
                }
            }
        }
        // InvocationIDs systemd had not yet set when their cgroup was made.
        let pending = std::mem::take(&mut self.pending);
        for dir in pending {
            self.read_invocation(&dir, false);
        }
        for (deleted, dir) in seen {
            if deleted {
                self.removed(&dir);
                continue;
            }
            self.record(&dir);
            self.read_invocation(&dir, true);
            if dir.extension().is_some_and(|e| e == "slice") {
                // A new slice: watch it, then catch what was made in it
                // before the watch.
                self.watch_tree(&dir);
            }
        }
        // The fallback for an IN_DELETE not delivered (the queue overflowed,
        // or no inotify): a live invocation whose cgroup is gone is removed.
        let due = self.absence_at.is_none_or(|t| t.elapsed() >= std::time::Duration::from_millis(ABSENCE_MS));
        if due {
            self.absence_at = Some(std::time::Instant::now());
            let gone: Vec<PathBuf> = self
                .invocations
                .values()
                .filter(|i| !i.ended && !i.removing && !i.dir.exists())
                .map(|i| i.dir.clone())
                .collect();
            for dir in gone {
                self.removed(&dir);
            }
        }
    }

    /// Called once the ring has been drained after [`Cgroups::drain`]: every
    /// invocation seen removed at that drain has `ended` (all it did was
    /// submitted before its last process exited, so before its cgroup could
    /// be removed). Returns those units.
    pub fn finish(&mut self) -> Vec<UnitId> {
        let mut ended = Vec::new();
        for (u, i) in self.invocations.iter_mut() {
            if i.removing {
                i.removing = false;
                i.ended = true;
                ended.push(u.clone());
            }
        }
        ended
    }

    /// Each unit's latest invocation, as its footprint carries it.
    pub fn invocations(&self) -> impl Iterator<Item = (&UnitId, crate::Invocation)> {
        self.invocations.iter().map(|(u, i)| (u, crate::Invocation { id: i.id.clone(), ended: i.ended }))
    }

    /// A unit cgroup seen gone: its live invocation is being removed. Only
    /// an invocation this netwatch read while its cgroup stood is ever
    /// ended, so a restarted netwatch never ends one it did not see go.
    fn removed(&mut self, dir: &Path) {
        if let Some(i) = self.invocations.values_mut().find(|i| i.dir == dir && !i.ended) {
            i.removing = true;
        }
        self.pending.remove(dir);
    }

    /// The unit `id` belongs to: known, or newly created, or found by a walk.
    pub fn unit(&mut self, id: u64) -> Option<UnitId> {
        if !self.ids.contains_key(&id) {
            self.drain();
        }
        if !self.ids.contains_key(&id) {
            self.merge();
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

    /// The units running now, merging what stands (forgetting nothing, and
    /// unlike a tick's walk, pruning nothing).
    pub fn running(&mut self) -> BTreeSet<String> {
        let (ids, running) = read_cgroups(&self.root);
        self.ids.extend(ids);
        running
    }

    /// Read the InvocationID of a unit's own cgroup (`<name>.service`; its
    /// sub-cgroups carry none). `created`: the cgroup was just made, so a new
    /// invocation began even if its id is not readable yet (systemd sets it
    /// just after making the cgroup: retried at each drain, and `protecting
    /// unknown` until then). Otherwise an id changed is a new invocation too
    /// (a restart whose IN_CREATE was missed).
    fn read_invocation(&mut self, dir: &Path, created: bool) {
        if dir.extension().is_none_or(|e| e != "service") {
            return;
        }
        let Some(u) = dir.strip_prefix(&self.root).ok().and_then(|r| unit_of_cgroup(&r.to_string_lossy())) else {
            return;
        };
        let id = invocation_of(dir);
        let stands = dir.exists();
        if id.is_none() && stands {
            self.pending.insert(dir.to_path_buf());
        }
        let fresh = Inv { dir: dir.to_path_buf(), id: id.clone(), removing: false, ended: false };
        match self.invocations.get_mut(&u) {
            None if id.is_some() || created => {
                self.invocations.insert(u, fresh);
            }
            None => {}
            Some(i) if created || (id.is_some() && id != i.id) || (i.ended && stands && id != i.id) => *i = fresh,
            Some(i) if i.id.is_none() && !i.ended && !i.removing => i.id = id,
            Some(_) => {}
        }
    }

    /// Re-read the InvocationIDs of every unit cgroup standing.
    fn read_invocations(&mut self) {
        let mut stack = vec![self.root.join("system.slice")];
        while let Some(dir) = stack.pop() {
            for e in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
                let p = e.path();
                if !e.file_type().is_ok_and(|t| t.is_dir()) {
                    continue;
                }
                if p.extension().is_some_and(|x| x == "slice") {
                    stack.push(p);
                } else {
                    self.read_invocation(&p, false);
                }
            }
        }
    }

    fn watch_tree(&mut self, dir: &Path) {
        if let Some(fd) = self.inotify.as_ref()
            && let Ok(wd) = inotify::add_watch(
                fd,
                dir,
                inotify::WatchFlags::CREATE | inotify::WatchFlags::DELETE | inotify::WatchFlags::ONLYDIR,
            )
        {
            self.watched.insert(wd, dir.to_path_buf());
        }
        for e in std::fs::read_dir(dir).into_iter().flatten().flatten() {
            let p = e.path();
            if !e.file_type().is_ok_and(|t| t.is_dir()) {
                continue;
            }
            self.record(&p);
            self.read_invocation(&p, false);
            if p.extension().is_some_and(|x| x == "slice") {
                self.watch_tree(&p);
            }
        }
    }
}

/// A cgroup's systemd InvocationID (`trusted.invocation_id`, 16 bytes), as
/// 32 lowercase hex; also `user.invocation_id`, which newer systemd sets
/// too. `None` if neither is set (yet) or it is malformed.
pub fn invocation_of(dir: &Path) -> Option<String> {
    for name in ["trusted.invocation_id", "user.invocation_id"] {
        let mut buf = [0u8; 64];
        if let Ok(n) = rustix::fs::getxattr(dir, name, &mut buf[..])
            && let Some(id) = invocation_hex(&buf[..n])
        {
            return Some(id);
        }
    }
    None
}

/// The xattr's value as 32 lowercase hex: 16 raw bytes, or (as some
/// systemd versions write it) the 32 hex characters themselves.
pub fn invocation_hex(v: &[u8]) -> Option<String> {
    match v.len() {
        16 => Some(v.iter().map(|b| format!("{b:02x}")).collect()),
        32 if v.iter().all(u8::is_ascii_hexdigit) => Some(String::from_utf8_lossy(v).to_ascii_lowercase()),
        _ => None,
    }
}
