//! Durable storage under the journal (§12c): a preallocated log, an atomically
//! replaced checkpoint, a fixed-size `RecoveryFailed` sentinel, and the per-
//! transaction fence epochs that backends check before mutating.
//!
//! `MemStore` is the in-memory store for the fake harness. Cloning it gives
//! another "process" a handle on the same storage; it can tear writes on
//! demand. `FileStore` is the on-disk layout under `/var/lib/planarian/journal/`.

use planarian_schema::TxnId;
use std::collections::BTreeMap;
use std::io;
use std::sync::{Arc, Condvar, Mutex, MutexGuard};

pub const DEFAULT_CAPACITY: u64 = 64 * 1024 * 1024;
pub const SENTINEL_SIZE: usize = 4096;

pub trait Store {
    /// Held while a journal handle reads-then-appends; serializes all handles
    /// (across processes for `FileStore`). Released on drop.
    type Guard;
    fn lock(&self) -> io::Result<Self::Guard>;
    fn capacity(&self) -> u64;
    /// Up to `len` bytes at `off`; shorter at the end of the preallocation.
    fn read_at(&self, off: u64, len: usize) -> io::Result<Vec<u8>>;
    fn write_at(&self, off: u64, bytes: &[u8]) -> io::Result<()>;
    fn sync(&self) -> io::Result<()>;
    fn read_checkpoint(&self) -> io::Result<Option<Vec<u8>>>;
    /// Atomic: either the old checkpoint or the complete new one survives.
    fn write_checkpoint(&self, bytes: &[u8]) -> io::Result<()>;
    fn read_sentinel(&self) -> io::Result<Option<Vec<u8>>>;
    fn write_sentinel(&self, bytes: &[u8]) -> io::Result<()>;
    /// The epoch backends fence on. Written before the journal's Takeover record.
    fn fence(&self, txn: TxnId) -> io::Result<Option<u64>>;
    fn set_fence(&self, txn: TxnId, epoch: u64) -> io::Result<()>;
}

// ---------- In-memory ----------

#[derive(Debug, Default)]
struct MemInner {
    log: Vec<u8>,
    checkpoint: Option<Vec<u8>>,
    sentinel: Option<Vec<u8>>,
    fences: BTreeMap<TxnId, u64>,
    /// Fault injection: the next log write stores only this many bytes, then fails.
    tear_next_write: Option<usize>,
    /// Fault injection: the next checkpoint write fails without replacing the old one.
    fail_next_checkpoint: bool,
    /// Fault injection: log writes fail with ENOSPC.
    enospc: bool,
}

#[derive(Clone, Debug)]
pub struct MemStore {
    inner: Arc<Mutex<MemInner>>,
    lock: Arc<(Mutex<bool>, Condvar)>,
    capacity: u64,
}

/// Owned guard for `MemStore::lock`.
#[derive(Debug)]
pub struct MemGuard(Arc<(Mutex<bool>, Condvar)>);

impl Drop for MemGuard {
    fn drop(&mut self) {
        let (m, cv) = &*self.0;
        *m.lock().unwrap_or_else(|e| e.into_inner()) = false;
        cv.notify_one();
    }
}

impl MemStore {
    pub fn new(capacity: u64) -> MemStore {
        MemStore {
            inner: Arc::new(Mutex::new(MemInner { log: vec![0; capacity as usize], ..Default::default() })),
            lock: Arc::new((Mutex::new(false), Condvar::new())),
            capacity,
        }
    }

    fn inner(&self) -> MutexGuard<'_, MemInner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn tear_next_write(&self, keep: usize) {
        self.inner().tear_next_write = Some(keep);
    }

    pub fn fail_next_checkpoint(&self) {
        self.inner().fail_next_checkpoint = true;
    }

    pub fn set_enospc(&self, on: bool) {
        self.inner().enospc = on;
    }
}

impl Store for MemStore {
    type Guard = MemGuard;

    fn lock(&self) -> io::Result<MemGuard> {
        let (m, cv) = &*self.lock;
        let mut held = m.lock().unwrap_or_else(|e| e.into_inner());
        while *held {
            held = cv.wait(held).unwrap_or_else(|e| e.into_inner());
        }
        *held = true;
        Ok(MemGuard(self.lock.clone()))
    }

    fn capacity(&self) -> u64 {
        self.capacity
    }

    fn read_at(&self, off: u64, len: usize) -> io::Result<Vec<u8>> {
        let inner = self.inner();
        let start = (off as usize).min(inner.log.len());
        let end = start.saturating_add(len).min(inner.log.len());
        Ok(inner.log[start..end].to_vec())
    }

    fn write_at(&self, off: u64, bytes: &[u8]) -> io::Result<()> {
        let mut inner = self.inner();
        if inner.enospc {
            return Err(io::Error::from_raw_os_error(28));
        }
        let off = off as usize;
        if off + bytes.len() > inner.log.len() {
            return Err(io::Error::from_raw_os_error(28));
        }
        if let Some(keep) = inner.tear_next_write.take() {
            let keep = keep.min(bytes.len());
            inner.log[off..off + keep].copy_from_slice(&bytes[..keep]);
            return Err(io::Error::other("torn write (injected)"));
        }
        inner.log[off..off + bytes.len()].copy_from_slice(bytes);
        Ok(())
    }

    fn sync(&self) -> io::Result<()> {
        Ok(())
    }

    fn read_checkpoint(&self) -> io::Result<Option<Vec<u8>>> {
        Ok(self.inner().checkpoint.clone())
    }

    fn write_checkpoint(&self, bytes: &[u8]) -> io::Result<()> {
        let mut inner = self.inner();
        if std::mem::take(&mut inner.fail_next_checkpoint) {
            return Err(io::Error::other("interrupted checkpoint write (injected)"));
        }
        inner.checkpoint = Some(bytes.to_vec());
        Ok(())
    }

    fn read_sentinel(&self) -> io::Result<Option<Vec<u8>>> {
        Ok(self.inner().sentinel.clone())
    }

    fn write_sentinel(&self, bytes: &[u8]) -> io::Result<()> {
        let mut s = vec![0; SENTINEL_SIZE];
        let n = bytes.len().min(SENTINEL_SIZE);
        s[..n].copy_from_slice(&bytes[..n]);
        self.inner().sentinel = Some(s);
        Ok(())
    }

    fn fence(&self, txn: TxnId) -> io::Result<Option<u64>> {
        Ok(self.inner().fences.get(&txn).copied())
    }

    fn set_fence(&self, txn: TxnId, epoch: u64) -> io::Result<()> {
        self.inner().fences.insert(txn, epoch);
        Ok(())
    }
}

// ---------- On disk ----------

/// `dir/journal` (preallocated), `dir/checkpoint`, `dir/sentinel` (4 KB,
/// reserved at install), `dir/lock`, and fences at `dir/../txn/<txn>/lease`.
///
/// Filesystem-specific setup (`chattr +C` on btrfs, a dataset reservation on
/// ZFS) is the installer's job (§12c). This type only `fallocate`s.
#[derive(Debug)]
pub struct FileStore {
    dir: std::path::PathBuf,
    txn_dir: std::path::PathBuf,
    journal: std::fs::File,
    capacity: u64,
}

impl FileStore {
    pub fn open(dir: &std::path::Path, txn_dir: &std::path::Path, capacity: u64) -> io::Result<FileStore> {
        use std::fs::{File, OpenOptions};
        std::fs::create_dir_all(dir)?;
        std::fs::create_dir_all(txn_dir)?;
        let path = dir.join("journal");
        let fresh = !path.exists();
        let journal = OpenOptions::new().read(true).write(true).create(true).truncate(false).open(&path)?;
        if fresh || journal.metadata()?.len() < capacity {
            rustix::fs::fallocate(&journal, rustix::fs::FallocateFlags::empty(), 0, capacity)?;
            journal.sync_all()?;
            File::open(dir)?.sync_all()?;
        }
        let sentinel = dir.join("sentinel");
        if !sentinel.exists() {
            let f = File::create(&sentinel)?;
            rustix::fs::fallocate(&f, rustix::fs::FallocateFlags::empty(), 0, SENTINEL_SIZE as u64)?;
            f.sync_all()?;
        }
        Ok(FileStore { dir: dir.to_owned(), txn_dir: txn_dir.to_owned(), journal, capacity })
    }

    fn replace_atomically(&self, target: &std::path::Path, bytes: &[u8]) -> io::Result<()> {
        use std::io::Write;
        let parent = target.parent().expect("target has a parent");
        let tmp =
            parent.join(format!(".{}.tmp", target.file_name().expect("target has a file name").to_string_lossy()));
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        std::fs::rename(&tmp, target)?;
        std::fs::File::open(parent)?.sync_all()
    }
}

impl Store for FileStore {
    /// The open lock file; closing it releases the flock.
    type Guard = std::fs::File;

    fn lock(&self) -> io::Result<std::fs::File> {
        let lock = std::fs::OpenOptions::new().create(true).truncate(false).write(true).open(self.dir.join("lock"))?;
        rustix::fs::flock(&lock, rustix::fs::FlockOperation::LockExclusive)?;
        Ok(lock)
    }

    fn capacity(&self) -> u64 {
        self.capacity
    }

    fn read_at(&self, off: u64, len: usize) -> io::Result<Vec<u8>> {
        use std::os::unix::fs::FileExt;
        let end = off.saturating_add(len as u64).min(self.capacity);
        let mut buf = vec![0; end.saturating_sub(off) as usize];
        self.journal.read_exact_at(&mut buf, off)?;
        Ok(buf)
    }

    fn write_at(&self, off: u64, bytes: &[u8]) -> io::Result<()> {
        use std::os::unix::fs::FileExt;
        if off + bytes.len() as u64 > self.capacity {
            return Err(io::Error::from_raw_os_error(28));
        }
        self.journal.write_all_at(bytes, off)
    }

    fn sync(&self) -> io::Result<()> {
        self.journal.sync_data()
    }

    fn read_checkpoint(&self) -> io::Result<Option<Vec<u8>>> {
        match std::fs::read(self.dir.join("checkpoint")) {
            Ok(b) => Ok(Some(b)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn write_checkpoint(&self, bytes: &[u8]) -> io::Result<()> {
        self.replace_atomically(&self.dir.join("checkpoint"), bytes)
    }

    fn read_sentinel(&self) -> io::Result<Option<Vec<u8>>> {
        let b = std::fs::read(self.dir.join("sentinel"))?;
        Ok(if b.iter().all(|x| *x == 0) { None } else { Some(b) })
    }

    fn write_sentinel(&self, bytes: &[u8]) -> io::Result<()> {
        use std::os::unix::fs::FileExt;
        // In place: the file was preallocated at install, so this cannot need space.
        let f = std::fs::OpenOptions::new().write(true).open(self.dir.join("sentinel"))?;
        let n = bytes.len().min(SENTINEL_SIZE);
        f.write_all_at(&bytes[..n], 0)?;
        f.sync_data()
    }

    fn fence(&self, txn: TxnId) -> io::Result<Option<u64>> {
        match std::fs::read_to_string(self.txn_dir.join(txn.0.to_string()).join("lease")) {
            Ok(s) => Ok(s.trim().parse().ok()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn set_fence(&self, txn: TxnId, epoch: u64) -> io::Result<()> {
        let d = self.txn_dir.join(txn.0.to_string());
        std::fs::create_dir_all(&d)?;
        self.replace_atomically(&d.join("lease"), format!("{epoch}\n").as_bytes())
    }
}
