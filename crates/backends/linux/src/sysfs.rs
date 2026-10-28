//! `InventoryBackend` over sysfs: which configured devices are present, which
//! driver each is bound to, and bind/unbind through the driver interface.
//!
//! Devices come from the manifest (`services.planarian.devices.<name>.sysfs`),
//! e.g. `snd-hda0 → /sys/bus/pci/devices/0000:00:1b.0`.

use crate::admitted;
use planarian_schema::{DeviceInfo, DriverRef, InventoryBackend, OpId, Outcome, Resources, UnitId};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Device unit name → its sysfs device directory.
pub type DeviceMap = BTreeMap<String, PathBuf>;

#[derive(Clone, Debug)]
pub struct Sysfs {
    devices: DeviceMap,
    txn_dir: PathBuf,
    /// `/sys` (a test tree in tests).
    root: PathBuf,
}

/// `/sys/bus/<bus>/devices/<id>` → (bus, id).
pub fn bus_and_id(dev: &Path) -> Option<(String, String)> {
    let canonical = std::fs::canonicalize(dev).unwrap_or_else(|_| dev.to_path_buf());
    let id = canonical.file_name()?.to_string_lossy().into_owned();
    let subsystem =
        std::fs::read_link(canonical.join("subsystem")).ok().or_else(|| std::fs::read_link(dev.join("subsystem")).ok());
    let bus = match subsystem {
        Some(s) => s.file_name()?.to_string_lossy().into_owned(),
        None => {
            // /sys/bus/<bus>/devices/<id> form.
            let parts: Vec<String> = dev.components().map(|c| c.as_os_str().to_string_lossy().into_owned()).collect();
            let i = parts.iter().position(|p| p == "bus")?;
            parts.get(i + 1)?.clone()
        }
    };
    Some((bus, id))
}

impl Sysfs {
    pub fn new(devices: DeviceMap, txn_dir: PathBuf) -> Sysfs {
        Sysfs { devices, txn_dir, root: "/sys".into() }
    }

    #[cfg(test)]
    fn at(root: &Path, devices: DeviceMap, txn_dir: PathBuf) -> Sysfs {
        Sysfs { devices, txn_dir, root: root.into() }
    }

    fn path(&self, device: &UnitId) -> Option<&PathBuf> {
        self.devices.get(&device.name)
    }

    fn driver_of(dev: &Path) -> Option<DriverRef> {
        let link = std::fs::read_link(dev.join("driver")).ok()?;
        Some(DriverRef { name: link.file_name()?.to_string_lossy().into_owned(), module: None })
    }

    fn write(path: &Path, value: &str) -> Outcome {
        match std::fs::write(path, value) {
            Ok(()) => Outcome::Succeeded,
            Err(e) => Outcome::Failed(format!("{}: {e}", path.display())),
        }
    }
}

fn meminfo() -> (u64, u64) {
    let text = std::fs::read_to_string("/proc/meminfo").unwrap_or_default();
    let get = |k: &str| {
        text.lines()
            .find(|l| l.starts_with(k))
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(0)
            / 1024
    };
    (get("MemTotal:"), get("MemAvailable:"))
}

impl InventoryBackend for Sysfs {
    fn devices(&self) -> Result<Vec<DeviceInfo>, Outcome> {
        Ok(self
            .devices
            .iter()
            .filter(|(_, p)| p.exists())
            .map(|(name, p)| DeviceInfo { id: UnitId::device(name), driver: Self::driver_of(p) })
            .collect())
    }

    fn resources(&self) -> Result<Resources, Outcome> {
        let (total, available) = meminfo();
        Ok(Resources { mem_total_mb: total, mem_available_mb: available, fs_free_bytes: BTreeMap::new() })
    }

    fn bound_driver(&self, device: &UnitId) -> Result<Option<DriverRef>, Outcome> {
        let p = self.path(device).ok_or_else(|| Outcome::Failed(format!("{device} has no sysfs path")))?;
        Ok(Self::driver_of(p))
    }

    fn bind(&self, device: &UnitId, driver: &DriverRef, op: &OpId) -> Outcome {
        if !admitted(&self.txn_dir, op) {
            return Outcome::fenced();
        }
        let Some(p) = self.path(device) else { return Outcome::Failed(format!("{device} has no sysfs path")) };
        let Some((bus, id)) = bus_and_id(p) else {
            return Outcome::Failed(format!("cannot tell the bus of {}", p.display()));
        };
        match Self::driver_of(p) {
            Some(d) if d.name == driver.name => return Outcome::Succeeded,
            // The kernel refuses to bind a device another driver holds.
            Some(_) => {
                if let Outcome::Failed(e) = Self::write(&p.join("driver/unbind"), &id) {
                    return Outcome::Failed(e);
                }
            }
            None => {}
        }
        if let Some(m) = &driver.module {
            let o = crate::cmd::run(&["modprobe", "-d", &m.0, &driver.name], std::time::Duration::from_secs(30));
            if !o.ok() {
                return Outcome::Failed(o.tail());
            }
        }
        // A driver binds through `bind` only to devices in its own ID table;
        // a generic one (vfio-pci, pci-stub) matches none. `driver_override`
        // names the driver the device may bind to; it is cleared after, so
        // the device is left with its binding and no lasting override.
        let ov = p.join("driver_override");
        let overriding = ov.exists();
        if overriding && let Outcome::Failed(e) = Self::write(&ov, &driver.name) {
            return Outcome::Failed(e);
        }
        let o = Self::write(&self.root.join(format!("bus/{bus}/drivers/{}/bind", driver.name)), &id);
        if overriding {
            let _ = Self::write(&ov, "\n");
        }
        o
    }

    fn unbind(&self, device: &UnitId, op: &OpId) -> Outcome {
        if !admitted(&self.txn_dir, op) {
            return Outcome::fenced();
        }
        let Some(p) = self.path(device) else { return Outcome::Failed(format!("{device} has no sysfs path")) };
        if Self::driver_of(p).is_none() {
            return Outcome::Succeeded;
        }
        let Some((_, id)) = bus_and_id(p) else { return Outcome::Failed("cannot tell the device id".into()) };
        Self::write(&p.join("driver/unbind"), &id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bus_from_path() {
        assert_eq!(
            bus_and_id(Path::new("/sys/bus/pci/devices/0000:00:1b.0")),
            Some(("pci".into(), "0000:00:1b.0".into()))
        );
    }

    #[test]
    fn bind_overrides_the_driver_match_and_clears_it() {
        let d = tempfile::tempdir().unwrap();
        let dev = d.path().join("bus/pci/devices/0000:00:1b.0");
        std::fs::create_dir_all(&dev).unwrap();
        std::fs::write(dev.join("driver_override"), "(null)\n").unwrap();
        let drv = d.path().join("bus/pci/drivers/vfio-pci");
        std::fs::create_dir_all(&drv).unwrap();
        let held = d.path().join("bus/pci/drivers/snd_hda_intel");
        std::fs::create_dir_all(&held).unwrap();
        std::os::unix::fs::symlink(&held, dev.join("driver")).unwrap();
        let txn = d.path().join("txn");
        std::fs::create_dir_all(txn.join("7")).unwrap();
        std::fs::write(txn.join("7/lease"), "1").unwrap();
        let s = Sysfs::at(d.path(), [("snd-hda0".to_string(), dev.clone())].into(), txn);
        let op = OpId { txn: planarian_schema::TxnId(7), epoch: 1, seq: 1 };
        let o = s.bind(&UnitId::device("snd-hda0"), &DriverRef { name: "vfio-pci".into(), module: None }, &op);
        assert_eq!(o, Outcome::Succeeded);
        assert_eq!(std::fs::read_to_string(held.join("unbind")).unwrap(), "0000:00:1b.0", "the holder lets go first");
        assert_eq!(std::fs::read_to_string(drv.join("bind")).unwrap(), "0000:00:1b.0");
        assert_eq!(std::fs::read_to_string(dev.join("driver_override")).unwrap(), "\n", "cleared after binding");
    }

    #[test]
    fn driver_and_presence_from_a_fake_tree() {
        let d = tempfile::tempdir().unwrap();
        let dev = d.path().join("bus/pci/devices/0000:00:1b.0");
        std::fs::create_dir_all(&dev).unwrap();
        std::fs::create_dir_all(d.path().join("bus/pci/drivers/snd_hda_intel")).unwrap();
        std::os::unix::fs::symlink(d.path().join("bus/pci/drivers/snd_hda_intel"), dev.join("driver")).unwrap();
        let s = Sysfs::new(
            [("snd-hda0".to_string(), dev.clone()), ("gone".to_string(), d.path().join("nope"))].into(),
            d.path().into(),
        );
        let devs = s.devices().unwrap();
        assert_eq!(devs.len(), 1);
        assert_eq!(devs[0].driver.as_ref().unwrap().name, "snd_hda_intel");
    }
}
