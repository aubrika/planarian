//! The two Phase A hooks (§9, §10): a signed external desired-state source,
//! verified and cached with no producer and no network, and a signed health
//! report emitted locally with the minimal disclosure profile.
//!
//! Both are Ed25519 over the exact bytes of a JSON document, with a domain
//! tag so a signature for one can never pass as the other. Signatures sit
//! next to the document as `<file>.sig`: 128 lowercase hex digits.
//!
//! I/O stays here and in `main`; the core only receives a verified document
//! (`Core::set_external`) and hands out the state the report is built from.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use planarian_schema::{GenerationId, Incident, IncidentState, SystemState, Timestamp, UnitDefs, UnitStatus};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

const DESIRED_TAG: &[u8] = b"planarian desired-state v1\0";
const HEALTH_TAG: &[u8] = b"planarian health-report v1\0";

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn unhex(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok()).collect()
}

fn tagged(tag: &[u8], doc: &[u8]) -> Vec<u8> {
    [tag, doc].concat()
}

fn sig_path(p: &Path) -> PathBuf {
    let mut s = p.as_os_str().to_owned();
    s.push(".sig");
    s.into()
}

// ---------- External desired-state source (§9) ----------

/// `services.planarian.externalSource`: declared in the generation, so
/// changing it is Security-sensitive (it is under `services.planarian`).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExternalSourceConfig {
    /// The Ed25519 public key, 64 hex digits.
    pub public_key: String,
    /// Where a producer (none in Phase A) drops the document; `<path>.sig` beside it.
    pub path: PathBuf,
}

/// The signed document. Its units join the generation's manifest; a unit the
/// manifest declares is the manifest's (the generation wins).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DesiredDoc {
    /// Strictly increasing per producer: an older document never replaces a newer one.
    pub seq: u64,
    pub issued: Timestamp,
    /// Who produced it, for the provenance in reports (§9, future-work T5).
    #[serde(default)]
    pub issuer: String,
    #[serde(default)]
    pub units: UnitDefs,
}

/// A document that passed verification, with the bytes it was verified over.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Verified {
    pub doc: DesiredDoc,
    pub bytes: Vec<u8>,
    pub sig: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Poll {
    /// Nothing at the path, or the same document as the cache.
    Unchanged,
    /// A newer valid document: now in force and cached.
    Accepted(Verified),
    /// Validly signed but not taken: older than the cache, a second document
    /// with the cache's sequence number, or unparseable. The cache stays in force.
    Refused(String),
    /// Unreadable: the cache stays in force (a stale or unreachable source, §9).
    Stale(String),
    /// An invalid signature (§12d Integrity).
    Integrity(String),
}

pub struct ExternalSource {
    key: VerifyingKey,
    path: PathBuf,
    cache: PathBuf,
    pub current: Option<Verified>,
}

impl ExternalSource {
    /// The key must parse; a bad key in the generation is a configuration error.
    pub fn new(cfg: &ExternalSourceConfig, cache_dir: &Path) -> Result<ExternalSource, String> {
        let raw = unhex(&cfg.public_key).ok_or("externalSource.publicKey: not hex")?;
        let raw: [u8; 32] = raw.try_into().map_err(|_| "externalSource.publicKey: not 32 bytes")?;
        let key = VerifyingKey::from_bytes(&raw).map_err(|e| format!("externalSource.publicKey: {e}"))?;
        Ok(ExternalSource {
            key,
            path: cfg.path.clone(),
            cache: cache_dir.join("external-desired.json"),
            current: None,
        })
    }

    fn verify(&self, bytes: &[u8], sig_hex: &str) -> Result<(), String> {
        let sig = unhex(sig_hex).ok_or("signature is not hex")?;
        let sig = Signature::from_slice(&sig).map_err(|e| format!("signature: {e}"))?;
        self.key.verify(&tagged(DESIRED_TAG, bytes), &sig).map_err(|_| "signature does not verify".to_string())
    }

    fn read(&self, path: &Path) -> Result<(Vec<u8>, String), String> {
        let bytes = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
        let sig = std::fs::read_to_string(sig_path(path)).map_err(|e| format!("{}: {e}", sig_path(path).display()))?;
        Ok((bytes, sig))
    }

    fn check(&self, bytes: Vec<u8>, sig: &str) -> Result<Result<Verified, String>, String> {
        self.verify(&bytes, sig)?;
        let parsed = serde_json::from_slice::<DesiredDoc>(&bytes).map_err(|e| format!("signed but unreadable: {e}"));
        Ok(parsed.map(|doc| Verified { doc, bytes, sig: unhex(sig).unwrap_or_default() }))
    }

    /// At start: the cache, re-verified. A cache that no longer verifies was
    /// altered on disk: Integrity. No cache is fine.
    pub fn load_cache(&mut self) -> Result<(), String> {
        if !self.cache.exists() {
            return Ok(());
        }
        let (bytes, sig) = self.read(&self.cache).map_err(|e| format!("external source cache: {e}"))?;
        match self.check(bytes, &sig) {
            Ok(Ok(v)) => {
                self.current = Some(v);
                Ok(())
            }
            Ok(Err(e)) | Err(e) => Err(format!("external source cache: {e}")),
        }
    }

    pub fn poll(&mut self) -> Poll {
        if !self.path.exists() {
            return Poll::Unchanged;
        }
        let (bytes, sig) = match self.read(&self.path) {
            Ok(r) => r,
            Err(e) => return Poll::Stale(e),
        };
        if self.current.as_ref().is_some_and(|c| c.bytes == bytes && hex(&c.sig) == sig.trim()) {
            return Poll::Unchanged;
        }
        let v = match self.check(bytes, &sig) {
            Err(e) => return Poll::Integrity(format!("external desired-state source {}: {e}", self.path.display())),
            Ok(Err(e)) => return Poll::Refused(e),
            Ok(Ok(v)) => v,
        };
        if let Some(c) = &self.current {
            if v.doc.seq < c.doc.seq {
                return Poll::Refused(format!(
                    "sequence {} is older than the {} in force (a replayed document)",
                    v.doc.seq, c.doc.seq
                ));
            }
            if v.doc.seq == c.doc.seq {
                if v.bytes == c.bytes {
                    return Poll::Unchanged;
                }
                return Poll::Refused(format!("a second, different document with sequence {}", v.doc.seq));
            }
        }
        if let Err(e) = self.store(&v) {
            return Poll::Stale(format!("could not cache it: {e}"));
        }
        self.current = Some(v.clone());
        Poll::Accepted(v)
    }

    fn store(&self, v: &Verified) -> std::io::Result<()> {
        if let Some(d) = self.cache.parent() {
            std::fs::create_dir_all(d)?;
        }
        let tmp = self.cache.with_extension("tmp");
        std::fs::write(sig_path(&tmp), hex(&v.sig))?;
        std::fs::write(&tmp, &v.bytes)?;
        std::fs::rename(sig_path(&tmp), sig_path(&self.cache))?;
        std::fs::rename(&tmp, &self.cache)
    }
}

/// Sign a desired-state document (for tests and the gym; Phase A has no producer).
pub fn sign_desired(key: &SigningKey, bytes: &[u8]) -> String {
    hex(&key.sign(&tagged(DESIRED_TAG, bytes)).to_bytes())
}

// ---------- Signed health report (§10) ----------

/// Computed by the core, never chosen by a requester. Phase A has Minimal
/// only; expanding it is Security-sensitive (it would be a new option under
/// `services.planarian`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum DisclosureProfile {
    /// Unit statuses and incident kinds: no versions, paths, probe ids,
    /// reasons or log content.
    #[default]
    Minimal,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncidentSummary {
    pub kind: String,
    pub state: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthReport {
    pub format: u32,
    pub profile: DisclosureProfile,
    pub at: Timestamp,
    /// Generation identities: numbers only, never store paths.
    pub generation: GenerationId,
    pub known_good: GenerationId,
    /// Unit → status kind (`Running`, `Failed`, ...), with no payload.
    pub units: BTreeMap<String, String>,
    pub incidents: Vec<IncidentSummary>,
}

/// The variant name of a status, dropping its payload (probe ids, reasons).
pub fn status_kind(s: &UnitStatus) -> &'static str {
    match s {
        UnitStatus::Running => "Running",
        UnitStatus::Degraded(_) => "Degraded",
        UnitStatus::Stopped => "Stopped",
        UnitStatus::Overridden(_) => "Overridden",
        UnitStatus::Unknown => "Unknown",
        UnitStatus::Failed(_) => "Failed",
        UnitStatus::Absent => "Absent",
        UnitStatus::Detected => "Detected",
        UnitStatus::Bound => "Bound",
        UnitStatus::Transitioning => "Transitioning",
        UnitStatus::NotExpected => "NotExpected",
    }
}

fn incident_state(s: &IncidentState) -> &'static str {
    match s {
        IncidentState::Open => "Open",
        IncidentState::Cooldown { .. } => "Cooldown",
        IncidentState::Escalated { .. } => "Escalated",
        IncidentState::Closed => "Closed",
        IncidentState::Regressed { .. } => "Regressed",
    }
}

pub fn report<'a>(
    profile: DisclosureProfile,
    s: &SystemState,
    defs: &UnitDefs,
    incidents: impl IntoIterator<Item = &'a Incident>,
) -> HealthReport {
    match profile {
        DisclosureProfile::Minimal => HealthReport {
            format: 1,
            profile,
            at: s.observed_at,
            generation: s.generation,
            known_good: s.known_good,
            units: s.units.keys().map(|id| (id.to_string(), status_kind(&s.status(id, defs)).to_string())).collect(),
            incidents: incidents
                .into_iter()
                .filter(|i| !matches!(i.state, IncidentState::Closed))
                .map(|i| IncidentSummary { kind: format!("{:?}", i.kind), state: incident_state(&i.state).into() })
                .collect(),
        },
    }
}

/// The core's report key: created on first use, readable by root only. The
/// public half is written beside it for whoever checks the reports.
pub fn health_key(dir: &Path) -> std::io::Result<SigningKey> {
    use std::os::unix::fs::OpenOptionsExt;
    let p = dir.join("health.key");
    if let Ok(b) = std::fs::read(&p)
        && let Ok(seed) = <[u8; 32]>::try_from(b.as_slice())
    {
        return Ok(SigningKey::from_bytes(&seed));
    }
    let key = SigningKey::generate(&mut rand_core::OsRng);
    std::fs::create_dir_all(dir)?;
    let tmp = dir.join("health.key.tmp");
    let _ = std::fs::remove_file(&tmp);
    let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&tmp)?;
    std::io::Write::write_all(&mut f, &key.to_bytes())?;
    f.sync_all()?;
    std::fs::rename(&tmp, &p)?;
    std::fs::write(dir.join("health.pub"), hex(key.verifying_key().as_bytes()))?;
    Ok(key)
}

/// Write `health-report.json` and its signature (local only in Phase A).
pub fn emit(dir: &Path, key: &SigningKey, r: &HealthReport) -> std::io::Result<PathBuf> {
    let bytes = serde_json::to_vec_pretty(r).map_err(std::io::Error::other)?;
    let p = dir.join("health-report.json");
    let tmp = dir.join("health-report.json.tmp");
    std::fs::write(sig_path(&tmp), hex(&key.sign(&tagged(HEALTH_TAG, &bytes)).to_bytes()))?;
    std::fs::write(&tmp, &bytes)?;
    std::fs::rename(sig_path(&tmp), sig_path(&p))?;
    std::fs::rename(&tmp, &p)?;
    Ok(p)
}

/// Check a report against the core's public key.
pub fn verify_report(public: &VerifyingKey, bytes: &[u8], sig_hex: &str) -> bool {
    let Some(sig) = unhex(sig_hex).and_then(|s| Signature::from_slice(&s).ok()) else { return false };
    public.verify(&tagged(HEALTH_TAG, bytes), &sig).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(n: u8) -> SigningKey {
        SigningKey::from_bytes(&[n; 32])
    }

    fn dir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("planarian-hooks-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn put(path: &Path, k: &SigningKey, doc: &DesiredDoc) {
        let bytes = serde_json::to_vec(doc).unwrap();
        std::fs::write(sig_path(path), sign_desired(k, &bytes)).unwrap();
        std::fs::write(path, bytes).unwrap();
    }

    fn source(d: &Path, k: &SigningKey) -> ExternalSource {
        let cfg = ExternalSourceConfig { public_key: hex(k.verifying_key().as_bytes()), path: d.join("in/doc.json") };
        std::fs::create_dir_all(d.join("in")).unwrap();
        ExternalSource::new(&cfg, &d.join("cache")).unwrap()
    }

    fn doc(seq: u64) -> DesiredDoc {
        DesiredDoc { seq, issued: Timestamp(seq * 1000), issuer: "test".into(), units: Default::default() }
    }

    #[test]
    fn accepts_caches_and_keeps_the_newest() {
        let d = dir("accept");
        let k = key(1);
        let mut s = source(&d, &k);
        assert_eq!(s.poll(), Poll::Unchanged, "no document yet");
        put(&d.join("in/doc.json"), &k, &doc(2));
        assert!(matches!(s.poll(), Poll::Accepted(v) if v.doc.seq == 2));
        assert_eq!(s.poll(), Poll::Unchanged);
        // A replayed older document, validly signed, never replaces the newer.
        put(&d.join("in/doc.json"), &k, &doc(1));
        assert!(matches!(s.poll(), Poll::Refused(m) if m.contains("older")));
        assert_eq!(s.current.as_ref().unwrap().doc.seq, 2);
        // Equivocation: a different document with the same sequence number.
        let mut other = doc(2);
        other.issuer = "someone else".into();
        put(&d.join("in/doc.json"), &k, &other);
        assert!(matches!(s.poll(), Poll::Refused(m) if m.contains("second")));
        // The source vanishes: the cache stays in force, across a restart too.
        std::fs::remove_file(d.join("in/doc.json")).unwrap();
        assert_eq!(s.poll(), Poll::Unchanged);
        let mut again = source(&d, &k);
        again.load_cache().unwrap();
        assert_eq!(again.current.unwrap().doc.seq, 2);
    }

    #[test]
    fn an_invalid_signature_is_an_integrity_failure() {
        let d = dir("invalid");
        let k = key(1);
        let mut s = source(&d, &k);
        // Signed by another key.
        put(&d.join("in/doc.json"), &key(2), &doc(5));
        assert!(matches!(s.poll(), Poll::Integrity(_)));
        assert!(s.current.is_none());
        // Signed correctly, then edited.
        put(&d.join("in/doc.json"), &k, &doc(5));
        assert!(matches!(s.poll(), Poll::Accepted(_)));
        let mut bytes = std::fs::read(d.join("in/doc.json")).unwrap();
        bytes.extend_from_slice(b" ");
        std::fs::write(d.join("in/doc.json"), bytes).unwrap();
        assert!(matches!(s.poll(), Poll::Integrity(_)));
        // A health-report signature over the same bytes never passes (domain tag).
        let bytes = serde_json::to_vec(&doc(9)).unwrap();
        std::fs::write(d.join("in/doc.json"), &bytes).unwrap();
        std::fs::write(sig_path(&d.join("in/doc.json")), hex(&k.sign(&tagged(HEALTH_TAG, &bytes)).to_bytes())).unwrap();
        assert!(matches!(s.poll(), Poll::Integrity(_)));
    }

    #[test]
    fn an_edited_cache_is_an_integrity_failure() {
        let d = dir("cache");
        let k = key(1);
        let mut s = source(&d, &k);
        put(&d.join("in/doc.json"), &k, &doc(3));
        assert!(matches!(s.poll(), Poll::Accepted(_)));
        let c = d.join("cache/external-desired.json");
        let text = std::fs::read_to_string(&c).unwrap().replace("\"seq\":3", "\"seq\":4");
        std::fs::write(&c, text).unwrap();
        assert!(source(&d, &k).load_cache().is_err());
    }

    #[test]
    fn a_bad_key_is_refused() {
        let cfg = ExternalSourceConfig { public_key: "abcd".into(), path: "/nonexistent".into() };
        assert!(ExternalSource::new(&cfg, Path::new("/nonexistent")).is_err());
    }

    #[test]
    fn the_minimal_report_discloses_kinds_only_and_verifies() {
        use planarian_schema::{Observed, Reason, UnitId};
        let mut s = planarian_schema::fixtures::empty_state(1000);
        s.units.insert(
            UnitId::service("gym-web"),
            (Observed::Failed(Reason::DriverError("/secret/path v1.2".into())), vec![]),
        );
        let r = report(DisclosureProfile::Minimal, &s, &UnitDefs::new(), []);
        let text = serde_json::to_string(&r).unwrap();
        assert!(!text.contains("secret") && !text.contains("1.2"), "{text}");
        assert!(r.units.values().all(|v| !v.contains('(')));

        let d = dir("report");
        let k = health_key(&d).unwrap();
        assert_eq!(health_key(&d).unwrap().to_bytes(), k.to_bytes(), "the key persists");
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(d.join("health.key")).unwrap().permissions().mode() & 0o777, 0o600);
        let p = emit(&d, &k, &r).unwrap();
        let bytes = std::fs::read(&p).unwrap();
        let sig = std::fs::read_to_string(sig_path(&p)).unwrap();
        let public = VerifyingKey::from_bytes(
            &unhex(&std::fs::read_to_string(d.join("health.pub")).unwrap()).unwrap().try_into().unwrap(),
        )
        .unwrap();
        assert!(verify_report(&public, &bytes, &sig));
        assert!(!verify_report(&public, &[bytes.as_slice(), b" "].concat(), &sig));
    }
}
