//! `RuntimeOptionBackend` (§12a). Phase A applies Wi-Fi selection live through
//! NetworkManager. Font scale and keyboard layout have no live mechanism here;
//! they take effect through their write-back (the catalog change), and `set`
//! says so.

use crate::admitted;
use crate::cmd::run;
use planarian_schema::{OpId, Outcome, RuntimeOptionBackend, Value};
use std::path::PathBuf;
use std::time::Duration;

#[derive(Clone, Debug)]
pub struct Runtime {
    txn_dir: PathBuf,
}

impl Runtime {
    pub fn new(txn_dir: PathBuf) -> Runtime {
        Runtime { txn_dir }
    }
}

/// The active Wi-Fi connection from `nmcli -t -f NAME,TYPE connection show --active`.
pub fn active_wifi(text: &str) -> Option<String> {
    text.lines().find_map(|l| {
        let (name, kind) = l.rsplit_once(':')?;
        (kind == "802-11-wireless").then(|| name.replace("\\:", ":"))
    })
}

impl RuntimeOptionBackend for Runtime {
    fn get(&self, path: &str) -> Option<Value> {
        match path {
            "wifi.network" => {
                let o =
                    run(&["nmcli", "-t", "-f", "NAME,TYPE", "connection", "show", "--active"], Duration::from_secs(5));
                active_wifi(&o.stdout).map(Value::Str)
            }
            _ => None,
        }
    }

    fn set(&self, path: &str, value: &Value, op: &OpId) -> Outcome {
        if !admitted(&self.txn_dir, op) {
            return Outcome::fenced();
        }
        match (path, value) {
            ("wifi.network", Value::Str(ssid)) => {
                let o = run(&["nmcli", "connection", "up", "id", ssid], Duration::from_secs(60));
                if o.ok() { Outcome::Succeeded } else { Outcome::Failed(o.tail()) }
            }
            _ => Outcome::Failed(format!("{path} has no live mechanism; it applies through the configuration")),
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn wifi() {
        assert_eq!(super::active_wifi("Wired:802-3-ethernet\nhome\\:5G:802-11-wireless\n"), Some("home:5G".into()));
        assert_eq!(super::active_wifi(""), None);
    }
}
