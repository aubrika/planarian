//! The real backends for Phase A on NixOS 26.05 (§5), behind the schema's
//! backend traits.
//!
//! The process-spawning modules talk to the system through its own command-
//! line tools (`systemctl`, `loginctl`, `nix`, `systemd-run`, `nmcli`). Their
//! output formats are stable, and that keeps the dependency set small (see
//! docs/deviations.md: §17 names zbus). Every mutating call first checks its
//! OpId's epoch against the transaction's fence file and refuses a stale one
//! before touching anything (§12 fencing).

pub mod cmd;
#[cfg(feature = "gym-hooks")]
pub mod gym;
pub mod logind;
pub mod nixos;
pub mod probe;
pub mod process;
pub mod runtime;
pub mod sysfs;
pub mod systemd;

use planarian_schema::{Backends, OpId};
use std::path::{Path, PathBuf};

/// Filesystem locations. Defaults match the NixOS module.
#[derive(Clone, Debug)]
pub struct Paths {
    /// `/var/lib/planarian`
    pub state: PathBuf,
    /// The owner's configuration (a flake directory), e.g. `/etc/nixos`.
    pub owner: PathBuf,
    /// The flake output holding this machine, e.g. `nixosConfigurations.laptop`.
    pub flake_attr: String,
    pub profile: PathBuf,
    pub gcroots: PathBuf,
}

impl Default for Paths {
    fn default() -> Self {
        Paths {
            state: "/var/lib/planarian".into(),
            owner: "/etc/nixos".into(),
            flake_attr: "nixosConfigurations.default".into(),
            profile: "/nix/var/nix/profiles/system".into(),
            gcroots: "/nix/var/nix/gcroots/planarian".into(),
        }
    }
}

impl Paths {
    pub fn txn_dir(&self) -> PathBuf {
        self.state.join("txn")
    }

    pub fn journal_dir(&self) -> PathBuf {
        self.state.join("journal")
    }
}

/// §12 fencing: a mutating call is refused unless its epoch is the one in the
/// transaction's fence file.
pub fn admitted(txn_dir: &Path, op: &OpId) -> bool {
    let p = txn_dir.join(op.txn.0.to_string()).join("lease");
    let fence = std::fs::read_to_string(p).ok().and_then(|s| s.trim().parse::<u64>().ok());
    planarian_txn::kernel::fence_admits(fence, op.epoch)
}

/// Everything, for the daemon and the watchdog.
#[derive(Clone, Debug)]
pub struct Real {
    pub systemd: systemd::Systemd,
    pub nixos: nixos::Nixos,
    pub sysfs: sysfs::Sysfs,
    pub probes: probe::Probes,
    pub logind: logind::Logind,
    pub runtime: runtime::Runtime,
    pub process: process::Processes,
}

impl Real {
    pub fn new(paths: Paths, devices: sysfs::DeviceMap) -> Real {
        let txn_dir = paths.txn_dir();
        Real {
            systemd: systemd::Systemd::new(txn_dir.clone()),
            nixos: nixos::Nixos::new(paths.clone()),
            sysfs: sysfs::Sysfs::new(devices, txn_dir.clone()),
            probes: probe::Probes,
            logind: logind::Logind::default(),
            runtime: runtime::Runtime::new(txn_dir),
            process: process::Processes,
        }
    }
}

impl Backends for Real {
    type Units = systemd::Systemd;
    type Gens = nixos::Nixos;
    type Inv = sysfs::Sysfs;
    type Probes = probe::Probes;
    type Sessions = logind::Logind;
    type Runtime = runtime::Runtime;
    type Procs = process::Processes;
    type Clock = process::Processes;

    fn units(&self) -> &systemd::Systemd {
        &self.systemd
    }
    fn generations(&self) -> &nixos::Nixos {
        &self.nixos
    }
    fn inventory(&self) -> &sysfs::Sysfs {
        &self.sysfs
    }
    fn probes(&self) -> &probe::Probes {
        &self.probes
    }
    fn sessions(&self) -> &logind::Logind {
        &self.logind
    }
    fn runtime(&self) -> &runtime::Runtime {
        &self.runtime
    }
    fn processes(&self) -> &process::Processes {
        &self.process
    }
    fn clock(&self) -> &process::Processes {
        &self.process
    }
}
