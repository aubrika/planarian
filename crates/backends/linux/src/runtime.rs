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
    /// The Wi-Fi networks the catalog permits (`services.planarian.catalog.wifiNetworks`);
    /// empty: any saved Wi-Fi connection.
    pub wifi_permitted: Vec<String>,
}

impl Runtime {
    pub fn new(txn_dir: PathBuf) -> Runtime {
        Runtime { txn_dir, wifi_permitted: vec![] }
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
                // Only a saved Wi-Fi connection the catalog permits: `nmcli
                // connection up` as root would bring up any profile (a VPN, a
                // bridge, another user's connection).
                if !self.wifi_permitted.is_empty() && !self.wifi_permitted.contains(ssid) {
                    return Outcome::Failed(format!("{ssid} is not a permitted Wi-Fi network"));
                }
                let saved = run(&["nmcli", "-t", "-f", "NAME,TYPE", "connection", "show"], Duration::from_secs(10));
                if !wifi_connections(&saved.stdout).contains(ssid) {
                    return Outcome::Failed(format!("{ssid} is not a saved Wi-Fi connection"));
                }
                let o = run(&["nmcli", "connection", "up", "id", ssid], Duration::from_secs(60));
                if o.ok() { Outcome::Succeeded } else { Outcome::Failed(o.tail()) }
            }
            _ => Outcome::Failed(format!("{path} has no live mechanism; it applies through the configuration")),
        }
    }

    fn alternatives(&self, path: &str) -> Vec<Value> {
        if path != "wifi.network" {
            return vec![];
        }
        let t = Duration::from_secs(20);
        let saved = run(&["nmcli", "-t", "-f", "NAME,TYPE", "connection", "show"], t);
        let active = run(&["nmcli", "-t", "-f", "NAME,TYPE", "connection", "show", "--active"], t);
        let scan = run(&["nmcli", "-t", "-f", "SSID", "device", "wifi", "list", "--rescan", "yes"], t);
        let in_range: Vec<String> = scan.stdout.lines().map(|l| l.replace("\\:", ":")).collect();
        let current = active_wifi(&active.stdout);
        wifi_connections(&saved.stdout)
            .into_iter()
            .filter(|name| Some(name) != current.as_ref())
            .filter(|name| {
                // A connection's SSID, which is what the scan reports.
                let ssid = run(&["nmcli", "-g", "802-11-wireless.ssid", "connection", "show", name], t);
                in_range.iter().any(|s| s == ssid.stdout.trim())
            })
            .map(Value::Str)
            .collect()
    }
}

/// Saved Wi-Fi connections from `nmcli -t -f NAME,TYPE connection show`.
pub fn wifi_connections(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|l| {
            let (name, kind) = l.rsplit_once(':')?;
            (kind == "802-11-wireless").then(|| name.replace("\\:", ":"))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    #[test]
    fn wifi() {
        assert_eq!(super::active_wifi("Wired:802-3-ethernet\nhome\\:5G:802-11-wireless\n"), Some("home:5G".into()));
        assert_eq!(super::active_wifi(""), None);
        assert_eq!(
            super::wifi_connections("Wired:802-3-ethernet\ngym-ap-a:802-11-wireless\ngym-ap-b:802-11-wireless\n"),
            vec!["gym-ap-a".to_string(), "gym-ap-b".to_string()]
        );
    }
}
