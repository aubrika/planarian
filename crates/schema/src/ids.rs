//! Identifiers, hashes and time.
//!
//! Time is integer milliseconds rather than `SystemTime`/`Duration`. Integers keep
//! the type inside the Verus subset, make the fake clock exact, and give the
//! journal a stable encoding (docs/deviations.md).

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use std::fmt;
use vstd::prelude::*;

#[derive(Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Hash(pub [u8; 32]);

impl Hash {
    pub const ZERO: Hash = Hash([0; 32]);

    pub fn of(bytes: &[u8]) -> Hash {
        Hash(Sha256::digest(bytes).into())
    }

    pub fn to_hex(&self) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut s = String::with_capacity(64);
        for b in self.0 {
            s.push(HEX[(b >> 4) as usize] as char);
            s.push(HEX[(b & 0xf) as usize] as char);
        }
        s
    }

    pub fn from_hex(s: &str) -> Option<Hash> {
        let bytes = s.as_bytes();
        if bytes.len() != 64 {
            return None;
        }
        let nib = |c: u8| match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            _ => None,
        };
        let mut out = [0u8; 32];
        for (i, pair) in bytes.chunks(2).enumerate() {
            out[i] = (nib(pair[0])? << 4) | nib(pair[1])?;
        }
        Some(Hash(out))
    }
}

impl fmt::Debug for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hash({})", &self.to_hex()[..12])
    }
}

impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl Serialize for Hash {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for Hash {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Hash::from_hex(&s).ok_or_else(|| serde::de::Error::custom("expected 64 lowercase hex digits"))
    }
}

macro_rules! newtype {
    ($(#[$m:meta])* $name:ident($inner:ty)) => {
        $(#[$m])*
        #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(pub $inner);
    };
}

newtype!(ProbeId(String));
newtype!(
    #[derive(Copy)]
    IncidentId(u64)
);
newtype!(
    #[derive(Copy)]
    PolicyVersion(Hash)
);
newtype!(JobId(String));

newtype!(
    /// A duration in milliseconds.
    #[derive(Copy, Default)]
    Millis(u64)
);

// The identifiers a `Transition` carries, visible to the `policy` proofs. Serde
// derives are `external_derive`: Verus does not verify serialization.
verus! {

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[derive(Serialize, Deserialize)]
#[serde(transparent)]
#[verifier::external_derive]
pub struct GenerationId(pub u64);

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[derive(Serialize, Deserialize)]
#[serde(transparent)]
#[verifier::external_derive]
pub struct StorePath(pub String);

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[derive(Serialize, Deserialize)]
#[serde(transparent)]
#[verifier::external_derive]
pub struct ChangeId(pub String);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[derive(Serialize, Deserialize)]
#[serde(transparent)]
#[verifier::external_derive]
pub struct TxnId(pub u64);

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[derive(Serialize, Deserialize)]
#[serde(transparent)]
#[verifier::external_derive]
pub struct ModelId(pub String);

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[derive(Serialize, Deserialize)]
#[serde(transparent)]
#[verifier::external_derive]
pub struct SnapshotId(pub String);

/// Milliseconds since the Unix epoch.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[derive(Serialize, Deserialize)]
#[serde(transparent)]
#[verifier::external_derive]
pub struct Timestamp(pub u64);

} // verus!

impl Timestamp {
    pub fn plus(self, d: Millis) -> Timestamp {
        Timestamp(self.0.saturating_add(d.0))
    }
}

impl Millis {
    pub const fn secs(s: u64) -> Millis {
        Millis(s * 1000)
    }
}

/// Durable identity of one mutation attempt (§12). Journaled and fsynced before
/// the backend call it names; the backend tags the call with it and fences on
/// `(txn, epoch)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct OpId {
    pub txn: TxnId,
    pub epoch: u64,
    pub seq: u64,
}

impl fmt::Display for OpId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.txn.0, self.epoch, self.seq)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_hex_roundtrip() {
        let h = Hash::of(b"planarian");
        assert_eq!(Hash::from_hex(&h.to_hex()), Some(h));
        assert_eq!(Hash::from_hex("zz"), None);
        let json = serde_json::to_string(&h).unwrap();
        assert_eq!(serde_json::from_str::<Hash>(&json).unwrap(), h);
    }
}
