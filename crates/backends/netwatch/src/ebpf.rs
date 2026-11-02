//! The event the eBPF program reports (`crates/backends/netwatch-ebpf`,
//! `Event`): `#[repr(C)] { cgroup: u64, tgid: u32, hook: u32, len: u32,
//! captured: u32, data: [u8; CAPTURE] }`, native-endian. Parsed by hand: no
//! unsafe, and a short buffer is an error rather than a misread.

pub const CAPTURE: usize = 512;
pub const EVENT_SIZE: usize = 8 + 4 * 4 + CAPTURE;

pub const HOOK_RTNETLINK: u32 = 1;
pub const HOOK_NFNETLINK: u32 = 2;
pub const HOOK_GENL: u32 = 3;
/// `nfnetlink_rcv_batch`: an nftables batch (its header is the batch's).
pub const HOOK_NFBATCH: u32 = 4;
/// `nf_setsockopt`: a legacy table change; `data` is `pf` then the option.
pub const HOOK_SOCKOPT: u32 = 5;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Event {
    pub cgroup: u64,
    pub tgid: u32,
    pub hook: u32,
    /// The message's own length.
    pub len: u32,
    /// The captured bytes of it (`captured` long).
    pub data: Vec<u8>,
}

impl Event {
    pub fn parse(b: &[u8]) -> Option<Event> {
        if b.len() < EVENT_SIZE {
            return None;
        }
        let u32_at = |o: usize| u32::from_ne_bytes(b[o..o + 4].try_into().unwrap());
        let captured = (u32_at(20) as usize).min(CAPTURE);
        Some(Event {
            cgroup: u64::from_ne_bytes(b[0..8].try_into().unwrap()),
            tgid: u32_at(8),
            hook: u32_at(12),
            len: u32_at(16),
            data: b[24..24 + captured].to_vec(),
        })
    }

    /// Whether the message was longer than what was captured.
    pub fn truncated(&self) -> bool {
        self.len as usize > self.data.len()
    }

    /// `nlmsg_type`, from the captured header.
    pub fn nlmsg_type(&self) -> Option<u16> {
        self.data.get(4..6).map(|b| u16::from_ne_bytes(b.try_into().unwrap()))
    }
}
