//! `PathMap`: a map keyed by option path, stored as a vector sorted by key.
//!
//! It stands in for `BTreeMap<String, V>` where the `policy` proofs read the
//! keys: vstd only specifies `BTreeMap` for key types with an ordering spec,
//! which `String` lacks, while a `Vec` is specified unconditionally. The
//! methods keep the entries sorted and unique; the proofs do not depend on
//! that, only on which keys are present. Serialized as a JSON object, as the
//! `BTreeMap` was.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::BTreeMap;
use vstd::prelude::*;

verus! {

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PathMap<V> {
    /// Sorted by key, keys unique. Read freely; change only through the methods.
    pub entries: Vec<(String, V)>,
}

} // verus!

impl<V> Default for PathMap<V> {
    fn default() -> Self {
        PathMap { entries: Vec::new() }
    }
}

impl<V> PathMap<V> {
    pub fn new() -> Self {
        Self::default()
    }

    fn find(&self, key: &str) -> Result<usize, usize> {
        self.entries.binary_search_by(|(k, _)| k.as_str().cmp(key))
    }

    pub fn get(&self, key: &str) -> Option<&V> {
        self.find(key).ok().map(|i| &self.entries[i].1)
    }

    pub fn contains_key(&self, key: &str) -> bool {
        self.find(key).is_ok()
    }

    pub fn insert(&mut self, key: String, value: V) -> Option<V> {
        match self.find(&key) {
            Ok(i) => Some(std::mem::replace(&mut self.entries[i].1, value)),
            Err(i) => {
                self.entries.insert(i, (key, value));
                None
            }
        }
    }

    pub fn remove(&mut self, key: &str) -> Option<V> {
        self.find(key).ok().map(|i| self.entries.remove(i).1)
    }

    pub fn retain(&mut self, mut keep: impl FnMut(&String, &mut V) -> bool) {
        self.entries.retain_mut(|(k, v)| keep(k, v));
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&String, &V)> {
        self.entries.iter().map(|(k, v)| (k, v))
    }

    pub fn keys(&self) -> impl Iterator<Item = &String> {
        self.entries.iter().map(|(k, _)| k)
    }

    pub fn values(&self) -> impl Iterator<Item = &V> {
        self.entries.iter().map(|(_, v)| v)
    }
}

impl<V> FromIterator<(String, V)> for PathMap<V> {
    fn from_iter<I: IntoIterator<Item = (String, V)>>(iter: I) -> Self {
        let mut m = PathMap::new();
        for (k, v) in iter {
            m.insert(k, v);
        }
        m
    }
}

impl<V, const N: usize> From<[(String, V); N]> for PathMap<V> {
    fn from(items: [(String, V); N]) -> Self {
        items.into_iter().collect()
    }
}

impl<V> From<BTreeMap<String, V>> for PathMap<V> {
    fn from(m: BTreeMap<String, V>) -> Self {
        // Already sorted and unique.
        PathMap { entries: m.into_iter().collect() }
    }
}

impl<'a, V> IntoIterator for &'a PathMap<V> {
    type Item = (&'a String, &'a V);
    type IntoIter = std::iter::Map<std::slice::Iter<'a, (String, V)>, fn(&'a (String, V)) -> (&'a String, &'a V)>;

    fn into_iter(self) -> Self::IntoIter {
        self.entries.iter().map(|(k, v)| (k, v))
    }
}

impl<V> IntoIterator for PathMap<V> {
    type Item = (String, V);
    type IntoIter = std::vec::IntoIter<(String, V)>;

    fn into_iter(self) -> Self::IntoIter {
        self.entries.into_iter()
    }
}

impl<V: Serialize> Serialize for PathMap<V> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_map(self.iter())
    }
}

impl<'de, V: Deserialize<'de>> Deserialize<'de> for PathMap<V> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Ok(BTreeMap::<String, V>::deserialize(d)?.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn behaves_like_a_btreemap() {
        let mut m: PathMap<i32> = [("b".to_string(), 2), ("a".to_string(), 1)].into();
        assert_eq!(m.keys().map(String::as_str).collect::<Vec<_>>(), ["a", "b"]);
        assert_eq!(m.insert("a".into(), 3), Some(1));
        assert_eq!(m.insert("c".into(), 4), None);
        assert_eq!(m.get("a"), Some(&3));
        m.retain(|k, _| k != "b");
        assert_eq!(m.remove("c"), Some(4));
        assert_eq!(m.len(), 1);
        let json = serde_json::to_string(&m).unwrap();
        assert_eq!(json, r#"{"a":3}"#);
        assert_eq!(serde_json::from_str::<PathMap<i32>>(&json).unwrap(), m);
    }
}
