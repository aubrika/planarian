//! The fault catalog on disk: a directory of TOML files (`00-format.toml`,
//! then one file per family), read in filename order and concatenated into
//! one TOML document, or a single file. Ids are unique across the files.

use std::path::Path;
use toml::Value as T;

/// The Phase A catalog, relative to the repository root.
pub const DIR: &str = "crates/gym/catalog/phase-a";

/// The catalog's text: a file's, or a directory's `*.toml` files in
/// filename order, concatenated.
pub fn read_text(path: &Path) -> Result<String, String> {
    if !path.is_dir() {
        return std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()));
    }
    let mut files: Vec<_> = std::fs::read_dir(path)
        .map_err(|e| format!("{}: {e}", path.display()))?
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "toml"))
        .collect();
    files.sort();
    if files.is_empty() {
        return Err(format!("{}: no .toml files", path.display()));
    }
    let mut text = String::new();
    for f in files {
        text.push_str(&std::fs::read_to_string(&f).map_err(|e| format!("{}: {e}", f.display()))?);
        text.push('\n');
    }
    Ok(text)
}

/// The entries, with every id present and unique.
pub fn entries(path: &Path) -> Result<Vec<T>, String> {
    let text = read_text(path)?;
    let doc: T = toml::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))?;
    let faults = doc.get("fault").and_then(T::as_array).cloned().unwrap_or_default();
    let mut seen = std::collections::BTreeSet::new();
    for e in &faults {
        let id = e.get("id").and_then(T::as_str).ok_or_else(|| format!("{}: an entry has no id", path.display()))?;
        if !seen.insert(id.to_string()) {
            return Err(format!("{}: id {id} is used twice", path.display()));
        }
    }
    Ok(faults)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The shipped catalog loads as a directory, its ids are unique, and a
    /// duplicate id across two files is refused.
    #[test]
    fn the_catalog_is_a_directory_of_unique_ids() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("catalog/phase-a");
        let all = entries(&dir).unwrap();
        assert!(all.len() > 100);
        let tmp = std::env::temp_dir().join(format!("planarian-catalog-test-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        std::fs::write(tmp.join("a.toml"), "[[fault]]\nid = \"x\"\n").unwrap();
        std::fs::write(tmp.join("b.toml"), "[[fault]]\nid = \"x\"\n").unwrap();
        assert!(entries(&tmp).unwrap_err().contains("used twice"));
        std::fs::write(tmp.join("b.toml"), "[[fault]]\nid = \"y\"\n").unwrap();
        let ids: Vec<_> = entries(&tmp).unwrap().iter().map(|e| e["id"].as_str().unwrap().to_string()).collect();
        let _ = std::fs::remove_dir_all(&tmp);
        assert_eq!(ids, ["x", "y"], "filename order");
    }
}
