//! The write-ahead journal (§12, §12c).
//!
//! Frame (format 2): `len: u32 | crc32c: u32 | seq: u64 | prev: [u8; 32] |
//! payload`, little-endian, where `len` counts `prev` and the payload. The
//! CRC covers a format tag, `seq`, `prev` and the payload.
//!
//! **Hash chain (I18).** `prev` is the chain head before this record, and the
//! head after it is SHA-256(`prev` ‖ `seq` ‖ payload); the first record after
//! an empty journal chains from zero, and the checkpoint carries the head at
//! its seq in its own `prev`. A scan accepts frames only while each is
//! intact, its seq is exactly one more than the last, and its `prev` is the
//! current head. An intact frame that does not chain is an integrity failure.
//! A frame that fails its CRC is the torn tail only if no intact record with
//! a later seq follows it; then its header is zeroed and it is never
//! interpreted. Otherwise a record in the middle was damaged or edited, which
//! is an integrity failure too, and nothing is truncated: the evidence stays.
//!
//! The chain has no key: it detects damage and naive edits, not an attacker
//! with root who rewrites every later record and the checkpoint consistently
//! (measured boot, Phase E, anchors the head outside the disk).
//!
//! Compaction is checkpoint-then-truncate. The ledger is written as the
//! checkpoint (atomic replace), then the log restarts at offset 0. Bytes left
//! over from before compaction all carry seq ≤ the checkpoint's seq, so they can
//! never pass as the next record.
//!
//! Several handles (the daemon and the watchdog) may share a store. Every
//! append takes the store lock and first catches up on records others wrote.

use crate::chain::{self, Follows, Link, Verdict};
use crate::ledger::{Entry, InterlockEntry, Ledger, LedgerError, Record};
use crate::store::Store;
use planarian_schema::{GenerationId, Hash, Timestamp, Transition, TxnId};
use std::io;

const HEADER: usize = 16;
const PREV: usize = 32;
/// Prefixed to the CRC input, so a frame of another format never passes.
const FORMAT: &[u8] = b"planarian-journal-2";

#[derive(Debug)]
pub enum JournalError {
    Io(io::Error),
    /// The preallocation cannot hold the record (compact, or take the sentinel path).
    Full,
    Ledger(LedgerError),
    Corrupt(String),
    /// The hash chain is broken, or a record before the tail is damaged (I18).
    /// An `Integrity` failure (§12d); the journal is left as found.
    Integrity(String),
    /// Written by an earlier Planarian (journal format 1, before the chain).
    Legacy,
}

impl From<io::Error> for JournalError {
    fn from(e: io::Error) -> Self {
        if e.raw_os_error() == Some(28) { JournalError::Full } else { JournalError::Io(e) }
    }
}

impl From<LedgerError> for JournalError {
    fn from(e: LedgerError) -> Self {
        JournalError::Ledger(e)
    }
}

/// A journal handle with the store lock held (see `Journal::locked`).
pub struct Locked<'a, S: Store>(&'a mut Journal<S>);

impl<S: Store> Locked<'_, S> {
    pub fn ledger(&self) -> &Ledger {
        &self.0.ledger
    }

    pub fn store(&self) -> &S {
        &self.0.store
    }

    pub fn append(&mut self, at: Timestamp, record: Record) -> Result<Entry, JournalError> {
        self.0.append_locked(at, record)
    }
}

pub struct Journal<S: Store> {
    store: S,
    ledger: Ledger,
    /// Byte offset of the next record in the log.
    offset: u64,
    /// The checkpoint seq this handle's ledger incorporates.
    checkpoint_seq: u64,
    /// The hash chain's head after the last record this handle has read (I18).
    head: Hash,
    /// During a reload: the sentinel's transaction and bytes, not yet applied
    /// (§12c). Its interlock is applied just before a `Resolved` that names it,
    /// or after the scan.
    pending_sentinel: Option<(TxnId, Vec<u8>)>,
}

/// The chain head after a record (I18).
pub fn chain(prev: &Hash, seq: u64, payload: &[u8]) -> Hash {
    let mut b = Vec::with_capacity(PREV + 8 + payload.len());
    b.extend_from_slice(&prev.0);
    b.extend_from_slice(&seq.to_le_bytes());
    b.extend_from_slice(payload);
    Hash::of(&b)
}

fn crc(body: &[u8]) -> u32 {
    crc32c::crc32c_append(crc32c::crc32c(FORMAT), body)
}

fn frame(seq: u64, prev: &Hash, payload: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(8 + PREV + payload.len());
    body.extend_from_slice(&seq.to_le_bytes());
    body.extend_from_slice(&prev.0);
    body.extend_from_slice(payload);
    let mut out = Vec::with_capacity(HEADER + PREV + payload.len());
    out.extend_from_slice(&((PREV + payload.len()) as u32).to_le_bytes());
    out.extend_from_slice(&crc(&body).to_le_bytes());
    out.extend_from_slice(&body);
    out
}

/// An intact frame: its seq, the chain head before it, its payload, and its size.
struct Frame<'a> {
    seq: u64,
    prev: Hash,
    payload: &'a [u8],
    size: usize,
}

/// Parse a frame header + body from `bytes`; `None` if it is not intact.
fn unframe(bytes: &[u8]) -> Option<Frame<'_>> {
    if bytes.len() < HEADER {
        return None;
    }
    let len = u32::from_le_bytes(bytes[0..4].try_into().ok()?) as usize;
    let sum = u32::from_le_bytes(bytes[4..8].try_into().ok()?);
    if len < PREV || bytes.len() < HEADER + len {
        return None;
    }
    let body = &bytes[8..HEADER + len];
    if crc(body) != sum {
        return None;
    }
    let seq = u64::from_le_bytes(body[0..8].try_into().ok()?);
    let prev = Hash(body[8..8 + PREV].try_into().ok()?);
    Some(Frame { seq, prev, payload: &body[8 + PREV..], size: HEADER + len })
}

/// Fault injection (tests and the gym): rewrite the payload of the `nth`
/// record in the log (0-based, from offset 0) with `edit`, keeping its `prev`
/// and recomputing its CRC, as someone editing the file would. The chain then
/// breaks at the record after it (I18). False if there is no such record or
/// the edit changes the payload's length.
pub fn tamper<S: Store>(store: &S, nth: usize, edit: impl FnOnce(&mut Vec<u8>)) -> io::Result<bool> {
    let mut off = 0u64;
    for i in 0.. {
        let header = store.read_at(off, HEADER)?;
        if header.len() < HEADER {
            return Ok(false);
        }
        let len = u32::from_le_bytes(header[0..4].try_into().expect("4 bytes")) as usize;
        let bytes = store.read_at(off, HEADER + len)?;
        let Some(f) = unframe(&bytes) else { return Ok(false) };
        if i == nth {
            let mut payload = f.payload.to_vec();
            edit(&mut payload);
            if payload.len() != f.payload.len() {
                return Ok(false);
            }
            store.write_at(off, &frame(f.seq, &f.prev, &payload))?;
            store.sync()?;
            return Ok(true);
        }
        off += f.size as u64;
    }
    Ok(false)
}

/// Fault injection (tests and the gym): remove the `nth` record and re-frame
/// every record after it one seq lower, each with its own `prev` and a valid
/// CRC, so every frame is intact and the seqs run on; zero what is left at
/// the end. The chain then breaks at the record after the deleted one (I18).
/// False if there is no such record.
pub fn delete<S: Store>(store: &S, nth: usize) -> io::Result<bool> {
    let mut off = 0u64;
    let mut at = None;
    let mut rest: Vec<(u64, Hash, Vec<u8>)> = vec![];
    for i in 0.. {
        let header = store.read_at(off, HEADER)?;
        if header.len() < HEADER {
            break;
        }
        let len = u32::from_le_bytes(header[0..4].try_into().expect("4 bytes")) as usize;
        let bytes = store.read_at(off, HEADER + len)?;
        let Some(f) = unframe(&bytes) else { break };
        if i == nth {
            at = Some(off);
        } else if at.is_some() {
            rest.push((f.seq - 1, f.prev, f.payload.to_vec()));
        }
        off += f.size as u64;
    }
    let Some(start) = at else { return Ok(false) };
    let mut out = vec![];
    for (seq, prev, payload) in &rest {
        out.extend_from_slice(&frame(*seq, prev, payload));
    }
    let end = start + out.len() as u64;
    out.resize((off - start) as usize, 0);
    store.write_at(start, &out)?;
    debug_assert!(end <= off);
    store.sync()?;
    Ok(true)
}

/// Whether `bytes` start with an intact frame of format 1 (no chain, plain CRC).
fn legacy_frame(bytes: &[u8]) -> bool {
    if bytes.len() < HEADER {
        return false;
    }
    let len = u32::from_le_bytes(bytes[0..4].try_into().expect("4 bytes")) as usize;
    let sum = u32::from_le_bytes(bytes[4..8].try_into().expect("4 bytes"));
    len > 0 && bytes.len() >= HEADER + len && crc32c::crc32c(&bytes[8..HEADER + len]) == sum
}

impl<S: Store> Journal<S> {
    /// Load the checkpoint, replay the log, truncate a torn tail.
    pub fn open(store: S) -> Result<Journal<S>, JournalError> {
        let mut j = Journal {
            store,
            ledger: Ledger::default(),
            offset: 0,
            checkpoint_seq: 0,
            head: Hash::ZERO,
            pending_sentinel: None,
        };
        {
            let _g = j.store.lock()?;
            j.reload()?;
        }
        Ok(j)
    }

    fn load_checkpoint(&self) -> Result<Option<(u64, Ledger, Hash)>, JournalError> {
        let Some(bytes) = self.store.read_checkpoint()? else {
            let first = self.store.read_at(0, HEADER)?;
            let len = if first.len() == HEADER { u32::from_le_bytes(first[0..4].try_into().expect("4")) } else { 0 };
            if len > 0 && legacy_frame(&self.store.read_at(0, HEADER + len as usize)?) {
                return Err(JournalError::Legacy);
            }
            return Ok(None);
        };
        let Some(f) = unframe(&bytes) else {
            return Err(if legacy_frame(&bytes) {
                JournalError::Legacy
            } else {
                JournalError::Corrupt("checkpoint fails its CRC".into())
            });
        };
        let (seq, payload) = (f.seq, f.payload);
        let ledger: Ledger =
            serde_json::from_slice(payload).map_err(|e| JournalError::Corrupt(format!("checkpoint: {e}")))?;
        if ledger.last_seq != seq {
            return Err(JournalError::Corrupt("checkpoint seq disagrees with its ledger".into()));
        }
        // The proofs show `apply` keeps the ledger invariant; a ledger read
        // from disk is checked against it instead.
        if !ledger.well_formed() {
            return Err(JournalError::Corrupt("checkpoint breaks the ledger invariant".into()));
        }
        Ok(Some((seq, ledger, f.prev)))
    }

    fn checkpoint_seq_on_disk(&self) -> Result<u64, JournalError> {
        Ok(match self.store.read_checkpoint()? {
            Some(b) => unframe(&b).map(|f| f.seq).unwrap_or(0),
            None => 0,
        })
    }

    fn reload(&mut self) -> Result<(), JournalError> {
        match self.load_checkpoint()? {
            Some((seq, ledger, head)) => {
                self.ledger = ledger;
                self.checkpoint_seq = seq;
                self.head = head;
            }
            None => {
                self.ledger = Ledger::default();
                self.checkpoint_seq = 0;
                self.head = Hash::ZERO;
            }
        }
        self.offset = 0;
        // The sentinel's interlock came after the records already in the log
        // when it was written, and before any `Resolved` that names it.
        self.pending_sentinel = self.store.read_sentinel()?.and_then(|b| sentinel_txn(&b).map(|t| (t, b)));
        let scanned = self.scan(true);
        let pending = self.pending_sentinel.take();
        scanned?;
        // Not resolved in the log (or no Resolved since the checkpoint).
        if let Some((_, bytes)) = pending {
            self.apply_sentinel(&bytes);
        }
        Ok(())
    }

    /// At compaction: the checkpoint now carries the resolution, so the
    /// sentinel of a resolved transaction is zeroed and a reload does not set
    /// the interlock again. (A crash before the zeroing leaves it set: the
    /// safe side; resolving again clears it.)
    fn clear_resolved_sentinel(&mut self) -> Result<(), JournalError> {
        if let Some(t) = self.store.read_sentinel()?.as_deref().and_then(sentinel_txn)
            && !self.ledger.interlock.contains_key(&t)
        {
            self.store.write_sentinel(&[0; crate::store::SENTINEL_SIZE])?;
        }
        Ok(())
    }

    /// Read records from `self.offset` onward; the first frame that is not
    /// intact, or whose seq does not follow, ends the scan.
    ///
    /// `reload` (scanning from offset 0 after loading the checkpoint) differs in
    /// two ways. A leading run of frames at or below the checkpoint's seq is
    /// skipped, which happens only if a crash came between writing a checkpoint
    /// and resetting the log. And the frame that ends the scan has its header
    /// zeroed (torn-tail truncation). When catching up from a later offset,
    /// nothing is skipped: a frame there with an old seq is a leftover from
    /// before a compaction, and skipping it would move the write offset past it.
    fn scan(&mut self, reload: bool) -> Result<(), JournalError> {
        let truncate = reload;
        let mut skipping = reload && self.offset == 0;
        let mut prev: Option<u64> = None;
        loop {
            let header = self.store.read_at(self.offset, HEADER)?;
            let len = if header.len() == HEADER {
                u32::from_le_bytes(header[0..4].try_into().expect("4 bytes")) as usize
            } else {
                0
            };
            let bytes = if len == 0 { header } else { self.store.read_at(self.offset, HEADER + len)? };
            let Some(f) = unframe(&bytes) else {
                if truncate && bytes.iter().take(HEADER).any(|b| *b != 0) {
                    return self.stop_at_tail(truncate);
                }
                // A zeroed header is the end of the log only if no intact
                // later record follows it; otherwise a record was erased (I18).
                // (An erased header leaves the record's prev hash right after
                // it; a fresh tail is zeros there, and needs no search.)
                let after = self.store.read_at(self.offset + HEADER as u64, PREV)?;
                if truncate
                    && after.iter().any(|b| *b != 0)
                    && let Some(seq) = self.later_record()?
                {
                    return Err(JournalError::Integrity(format!(
                        "the record at byte {} was erased, but record {seq} follows it",
                        self.offset
                    )));
                }
                return Ok(());
            };
            let (seq, payload, size) = (f.seq, f.payload, f.size);
            let consecutive = prev.is_none_or(|p| seq == p + 1);
            if !consecutive {
                return self.stop_at_tail(truncate);
            }
            if skipping && seq <= self.ledger.last_seq {
                prev = Some(seq);
                self.offset += size as u64;
                continue;
            }
            skipping = false;
            match chain::follows(self.ledger.last_seq, &self.head, seq, &f.prev) {
                Follows::Yes => {}
                Follows::OutOfSequence => return self.stop_at_tail(truncate),
                Follows::Unchained => {
                    return Err(JournalError::Integrity(format!(
                        "record {seq} does not follow the hash chain (it may have been edited)"
                    )));
                }
            }
            let entry: Entry = match serde_json::from_slice(payload) {
                Ok(e) => e,
                Err(_) => return self.stop_at_tail(truncate),
            };
            if entry.seq != seq {
                return self.stop_at_tail(truncate);
            }
            if let Record::Resolved { txn, .. } = &entry.record
                && self.pending_sentinel.as_ref().is_some_and(|(t, _)| t == txn)
                && let Some((_, bytes)) = self.pending_sentinel.take()
            {
                self.apply_sentinel(&bytes);
            }
            self.ledger.apply(entry)?;
            self.head = chain(&f.prev, seq, payload);
            prev = Some(seq);
            self.offset += size as u64;
        }
    }

    /// The scan stopped at `self.offset`. On reload that is the torn tail,
    /// truncated, unless an intact record with a later seq follows it: then a
    /// record before the tail was damaged or edited (I18), and nothing is
    /// truncated.
    fn stop_at_tail(&mut self, truncate: bool) -> Result<(), JournalError> {
        if truncate {
            if let Some(seq) = self.later_record()? {
                return Err(JournalError::Integrity(format!(
                    "the record at byte {} is damaged, but record {seq} follows it",
                    self.offset
                )));
            }
            self.store.write_at(self.offset, &[0; HEADER])?;
            self.store.sync()?;
        }
        Ok(())
    }

    /// An intact frame after `self.offset` whose seq is past the ledger's: the
    /// sign of a damaged record rather than a torn tail. Bytes left over from
    /// before a compaction all carry seqs at or below the checkpoint's.
    fn later_record(&self) -> Result<Option<u64>, JournalError> {
        let start = self.offset + 1;
        let rest = self.store.read_at(start, self.store.capacity().saturating_sub(start) as usize)?;
        let mut i = 0;
        while i + HEADER <= rest.len() {
            if let Some(f) = unframe(&rest[i..])
                && f.seq > self.ledger.last_seq
            {
                return Ok(Some(f.seq));
            }
            i += 1;
        }
        Ok(None)
    }

    /// Re-read the whole segment from the checkpoint and check that it still
    /// chains to the head this handle holds (I18): catches a retained record
    /// edited on disk after it was read. Read-only.
    pub fn verify_chain(&mut self) -> Result<(), JournalError> {
        let _g = self.store.lock()?;
        let (start, ckpt) = match self.load_checkpoint()? {
            Some((seq, _, h)) => (h, seq),
            None => (Hash::ZERO, 0),
        };
        let mut off = 0u64;
        let mut links = Vec::new();
        while off < self.offset {
            let header = self.store.read_at(off, HEADER)?;
            let len = if header.len() == HEADER {
                u32::from_le_bytes(header[0..4].try_into().expect("4 bytes")) as usize
            } else {
                0
            };
            let bytes = self.store.read_at(off, HEADER + len)?;
            let Some(f) = unframe(&bytes) else {
                return Err(JournalError::Integrity(format!("the record at byte {off} is damaged")));
            };
            if f.seq <= ckpt {
                off += f.size as u64;
                continue;
            }
            links.push(Link { seq: f.seq, prev: f.prev, next: chain(&f.prev, f.seq, f.payload) });
            off += f.size as u64;
        }
        // Verified: accepts exactly a chained segment, else names its first break.
        let head = match chain::verify(ckpt, start, &links) {
            Verdict::Chained { head, .. } => head,
            Verdict::Break { at, .. } => {
                return Err(JournalError::Integrity(format!(
                    "record {} does not follow the hash chain",
                    links[at].seq
                )));
            }
        };
        if ckpt == self.checkpoint_seq && head != self.head {
            return Err(JournalError::Integrity("the journal no longer matches what was read".into()));
        }
        Ok(())
    }

    /// The chain head after the last record (carried by the next checkpoint).
    pub fn head(&self) -> Hash {
        self.head
    }

    /// Catch up on records written by other handles since this one last looked.
    fn refresh(&mut self) -> Result<(), JournalError> {
        if self.checkpoint_seq_on_disk()? != self.checkpoint_seq {
            // Someone compacted: the log restarted at offset 0.
            return self.reload();
        }
        self.scan(false)
    }

    pub fn ledger(&self) -> &Ledger {
        &self.ledger
    }

    pub fn store(&self) -> &S {
        &self.store
    }

    /// Re-read the shared journal and return the current ledger.
    pub fn sync_ledger(&mut self) -> Result<&Ledger, JournalError> {
        let _g = self.store.lock()?;
        self.refresh()?;
        Ok(&self.ledger)
    }

    /// Validate, write, fsync, then apply (write-ahead). Returns the entry.
    pub fn append(&mut self, at: Timestamp, record: Record) -> Result<Entry, JournalError> {
        let _g = self.store.lock()?;
        self.refresh()?;
        self.append_locked(at, record)
    }

    /// Run `f` with the store lock held, after catching up. Used for
    /// read-decide-append sequences that must not interleave with another
    /// handle (lease takeover).
    pub fn locked<R>(&mut self, f: impl FnOnce(&mut Locked<'_, S>) -> R) -> Result<R, JournalError> {
        let _g = self.store.lock()?;
        self.refresh()?;
        Ok(f(&mut Locked(self)))
    }

    fn append_locked(&mut self, at: Timestamp, record: Record) -> Result<Entry, JournalError> {
        // The next seq and the current head (verified: what is appended
        // always follows the chain, `chain::appending_keeps_the_chain`).
        let (seq, prev) = chain::next_link(self.ledger.last_seq, &self.head);
        let entry = Entry { seq, at, record };
        self.ledger.validate(&entry)?;
        let payload = serde_json::to_vec(&entry).map_err(|e| JournalError::Corrupt(e.to_string()))?;
        let bytes = frame(seq, &prev, &payload);
        if self.offset + bytes.len() as u64 > self.store.capacity() {
            return Err(JournalError::Full);
        }
        self.store.write_at(self.offset, &bytes)?;
        self.store.sync()?;
        self.ledger.apply(entry.clone())?;
        self.head = chain(&prev, seq, &payload);
        self.offset += bytes.len() as u64;
        Ok(entry)
    }

    /// The entries in the current log segment (everything since the last
    /// checkpoint), in order.
    pub fn segment(&mut self) -> Result<Vec<Entry>, JournalError> {
        let _g = self.store.lock()?;
        let mut out = vec![];
        let mut off = 0u64;
        loop {
            let header = self.store.read_at(off, HEADER)?;
            if header.len() < HEADER {
                break;
            }
            let len = u32::from_le_bytes(header[0..4].try_into().expect("4 bytes")) as usize;
            let bytes = self.store.read_at(off, HEADER + len)?;
            let Some(f) = unframe(&bytes) else { break };
            if f.seq <= self.checkpoint_seq || out.last().is_some_and(|e: &Entry| e.seq + 1 != f.seq) {
                break;
            }
            match serde_json::from_slice::<Entry>(f.payload) {
                Ok(e) => out.push(e),
                Err(_) => break,
            }
            off += f.size as u64;
        }
        Ok(out)
    }

    /// Byte offset where the next record will be written.
    pub fn offset(&self) -> u64 {
        self.offset
    }

    /// Fraction of the preallocation in use, in per-mille.
    pub fn usage_permille(&self) -> u64 {
        self.offset * 1000 / self.store.capacity().max(1)
    }

    /// Compaction triggers at 75% full (§12c).
    pub fn needs_compaction(&self) -> bool {
        self.usage_permille() >= 750
    }

    /// Checkpoint-then-truncate. If the checkpoint write fails, nothing changes.
    pub fn compact(&mut self) -> Result<(), JournalError> {
        let _g = self.store.lock()?;
        self.refresh()?;
        let payload = serde_json::to_vec(&self.ledger).map_err(|e| JournalError::Corrupt(e.to_string()))?;
        self.store.write_checkpoint(&frame(self.ledger.last_seq, &self.head, &payload))?;
        self.checkpoint_seq = self.ledger.last_seq;
        self.store.write_at(0, &[0; HEADER])?;
        self.store.sync()?;
        self.offset = 0;
        self.clear_resolved_sentinel()
    }

    /// The fixed-size fallback when a recovery-path record cannot be written
    /// (§12c): marks the transaction RecoveryFailed outside the journal and sets
    /// the interlock.
    pub fn write_sentinel(&mut self, txn: TxnId, note: &str) -> Result<(), JournalError> {
        let text = format!("RecoveryFailed txn={} {}", txn.0, note);
        self.store.write_sentinel(text.as_bytes())?;
        self.apply_sentinel(text.as_bytes());
        Ok(())
    }

    fn apply_sentinel(&mut self, bytes: &[u8]) {
        let Some(txn) = sentinel_txn(bytes) else { return };
        let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
        let text = String::from_utf8_lossy(&bytes[..end]).into_owned();
        if self.ledger.interlock.contains_key(&txn) {
            return;
        }
        let (transition, revert_to) = match self.ledger.live.get(&txn) {
            Some(l) => (l.txn.transition.clone(), l.txn.revert_to),
            None => (Transition::Rollback, GenerationId(0)),
        };
        self.ledger.add_interlock(InterlockEntry {
            txn,
            transition,
            failed_from: "sentinel".into(),
            base_override: None,
            candidate_override: None,
            revert_to,
            note: text,
        });
    }
}

/// The transaction a sentinel names (`RecoveryFailed txn=<id> …`), if any.
fn sentinel_txn(bytes: &[u8]) -> Option<TxnId> {
    let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    let text = std::str::from_utf8(&bytes[..end]).ok()?;
    let id = text.strip_prefix("RecoveryFailed txn=")?.split_whitespace().next()?;
    id.parse::<u64>().ok().map(TxnId)
}
