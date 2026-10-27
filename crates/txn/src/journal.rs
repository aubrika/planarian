//! The write-ahead journal (§12, §12c).
//!
//! Frame: `len: u32 | crc32c: u32 | seq: u64 | payload`, little-endian. The CRC
//! covers `seq` and the payload. A scan accepts frames only while each is
//! intact and its seq is exactly one more than the last; the first frame that
//! fails is the torn tail. Its header is zeroed and it is never interpreted.
//!
//! Compaction is checkpoint-then-truncate. The ledger is written as the
//! checkpoint (atomic replace), then the log restarts at offset 0. Bytes left
//! over from before compaction all carry seq ≤ the checkpoint's seq, so they can
//! never pass as the next record.
//!
//! Several handles (the daemon and the watchdog) may share a store. Every
//! append takes the store lock and first catches up on records others wrote.

use crate::ledger::{Entry, InterlockEntry, Ledger, LedgerError, Record};
use crate::store::Store;
use planarian_schema::{GenerationId, Timestamp, Transition, TxnId};
use std::io;

const HEADER: usize = 16;

#[derive(Debug)]
pub enum JournalError {
    Io(io::Error),
    /// The preallocation cannot hold the record (compact, or take the sentinel path).
    Full,
    Ledger(LedgerError),
    Corrupt(String),
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
}

fn frame(seq: u64, payload: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(8 + payload.len());
    body.extend_from_slice(&seq.to_le_bytes());
    body.extend_from_slice(payload);
    let mut out = Vec::with_capacity(HEADER + payload.len());
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(&crc32c::crc32c(&body).to_le_bytes());
    out.extend_from_slice(&body);
    out
}

/// Parse a frame header + body from `bytes`; `None` if it is not intact.
fn unframe(bytes: &[u8]) -> Option<(u64, &[u8], usize)> {
    if bytes.len() < HEADER {
        return None;
    }
    let len = u32::from_le_bytes(bytes[0..4].try_into().ok()?) as usize;
    let crc = u32::from_le_bytes(bytes[4..8].try_into().ok()?);
    if len == 0 || bytes.len() < HEADER + len {
        return None;
    }
    let body = &bytes[8..HEADER + len];
    if crc32c::crc32c(body) != crc {
        return None;
    }
    let seq = u64::from_le_bytes(body[0..8].try_into().ok()?);
    Some((seq, &body[8..], HEADER + len))
}

impl<S: Store> Journal<S> {
    /// Load the checkpoint, replay the log, truncate a torn tail.
    pub fn open(store: S) -> Result<Journal<S>, JournalError> {
        let mut j = Journal { store, ledger: Ledger::default(), offset: 0, checkpoint_seq: 0 };
        {
            let _g = j.store.lock()?;
            j.reload()?;
        }
        Ok(j)
    }

    fn load_checkpoint(&self) -> Result<Option<(u64, Ledger)>, JournalError> {
        let Some(bytes) = self.store.read_checkpoint()? else {
            return Ok(None);
        };
        let (seq, payload, _) =
            unframe(&bytes).ok_or_else(|| JournalError::Corrupt("checkpoint fails its CRC".into()))?;
        let ledger: Ledger =
            serde_json::from_slice(payload).map_err(|e| JournalError::Corrupt(format!("checkpoint: {e}")))?;
        if ledger.last_seq != seq {
            return Err(JournalError::Corrupt("checkpoint seq disagrees with its ledger".into()));
        }
        Ok(Some((seq, ledger)))
    }

    fn checkpoint_seq_on_disk(&self) -> Result<u64, JournalError> {
        Ok(match self.store.read_checkpoint()? {
            Some(b) => unframe(&b).map(|(seq, _, _)| seq).unwrap_or(0),
            None => 0,
        })
    }

    fn reload(&mut self) -> Result<(), JournalError> {
        match self.load_checkpoint()? {
            Some((seq, ledger)) => {
                self.ledger = ledger;
                self.checkpoint_seq = seq;
            }
            None => {
                self.ledger = Ledger::default();
                self.checkpoint_seq = 0;
            }
        }
        self.offset = 0;
        self.scan(true)?;
        if let Some(bytes) = self.store.read_sentinel()? {
            self.apply_sentinel(&bytes);
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
            let Some((seq, payload, size)) = unframe(&bytes) else {
                if truncate && bytes.iter().take(HEADER).any(|b| *b != 0) {
                    self.store.write_at(self.offset, &[0; HEADER])?;
                    self.store.sync()?;
                }
                return Ok(());
            };
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
            if seq != self.ledger.last_seq + 1 {
                return self.stop_at_tail(truncate);
            }
            let entry: Entry = match serde_json::from_slice(payload) {
                Ok(e) => e,
                Err(_) => return self.stop_at_tail(truncate),
            };
            if entry.seq != seq {
                return self.stop_at_tail(truncate);
            }
            self.ledger.apply(&entry)?;
            prev = Some(seq);
            self.offset += size as u64;
        }
    }

    fn stop_at_tail(&mut self, truncate: bool) -> Result<(), JournalError> {
        if truncate {
            self.store.write_at(self.offset, &[0; HEADER])?;
            self.store.sync()?;
        }
        Ok(())
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
        let entry = Entry { seq: self.ledger.last_seq + 1, at, record };
        self.ledger.validate(&entry)?;
        let payload = serde_json::to_vec(&entry).map_err(|e| JournalError::Corrupt(e.to_string()))?;
        let bytes = frame(entry.seq, &payload);
        if self.offset + bytes.len() as u64 > self.store.capacity() {
            return Err(JournalError::Full);
        }
        self.store.write_at(self.offset, &bytes)?;
        self.store.sync()?;
        self.ledger.apply(&entry)?;
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
            let Some((seq, payload, size)) = unframe(&bytes) else { break };
            if seq <= self.checkpoint_seq || out.last().is_some_and(|e: &Entry| e.seq + 1 != seq) {
                break;
            }
            match serde_json::from_slice::<Entry>(payload) {
                Ok(e) => out.push(e),
                Err(_) => break,
            }
            off += size as u64;
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
        self.store.write_checkpoint(&frame(self.ledger.last_seq, &payload))?;
        self.checkpoint_seq = self.ledger.last_seq;
        self.store.write_at(0, &[0; HEADER])?;
        self.store.sync()?;
        self.offset = 0;
        Ok(())
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
        let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
        let Ok(text) = std::str::from_utf8(&bytes[..end]) else { return };
        let Some(id) = text.strip_prefix("RecoveryFailed txn=").and_then(|s| s.split_whitespace().next()) else {
            return;
        };
        let Ok(id) = id.parse::<u64>() else { return };
        let txn = TxnId(id);
        if self.ledger.interlock.contains_key(&txn) {
            return;
        }
        let (transition, revert_to) = match self.ledger.live.get(&txn) {
            Some(l) => (l.txn.transition.clone(), l.txn.revert_to),
            None => (Transition::Rollback, GenerationId(0)),
        };
        self.ledger.interlock.insert(
            txn,
            InterlockEntry {
                txn,
                transition,
                failed_from: "sentinel".into(),
                base_override: None,
                candidate_override: None,
                revert_to,
                note: text.into(),
            },
        );
    }
}
