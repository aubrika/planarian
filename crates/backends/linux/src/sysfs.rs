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
        Sysfs { devices, txn_dir }
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
        if Self::driver_of(p).as_ref().map(|d| &d.name) == Some(&driver.name) {
            return Outcome::Succeeded;
        }
        if let Some(m) = &driver.module {
            let o = crate::cmd::run(&["modprobe", "-d", &m.0, &driver.name], std::time::Duration::from_secs(30));
            if !o.ok() {
                return Outcome::Failed(o.tail());
            }
        }
        Self::write(&PathBuf::from(format!("/sys/bus/{bus}/drivers/{}/bind", driver.name)), &id)
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
