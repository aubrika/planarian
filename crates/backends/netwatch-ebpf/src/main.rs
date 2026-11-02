//! netwatch's eBPF program (SPEC §12d "Which units"): an fentry probe on
//! each netlink receive path that can change how traffic leaves the
//! machine (`rtnetlink_rcv_msg`: links, addresses, routes, rules;
//! `nfnetlink_rcv_msg`: nftables; `genl_rcv_msg`: generic netlink, e.g.
//! WireGuard). Each message is reported to userspace with the sender's
//! cgroup id; userspace parses it. The kernel side stays small so the
//! verifier has little to prove. The event layout is `Event`, mirrored by
//! `planarian-backend-netwatch` (its `ebpf` module; a test checks the size).

#![no_std]
#![no_main]

use aya_ebpf::helpers::{bpf_get_current_cgroup_id, bpf_get_current_pid_tgid, bpf_probe_read_kernel_buf};
use aya_ebpf::macros::{fentry, map};
use aya_ebpf::maps::RingBuf;
use aya_ebpf::programs::FEntryContext;

/// Bytes of each message copied to userspace (headers and the first
/// attributes; a longer message is flagged truncated).
const CAP: usize = 512;

pub const HOOK_RTNETLINK: u32 = 1;
pub const HOOK_NFNETLINK: u32 = 2;
pub const HOOK_GENL: u32 = 3;

#[repr(C)]
pub struct Event {
    pub cgroup: u64,
    pub tgid: u32,
    pub hook: u32,
    /// The message's own length (`nlmsg_len`).
    pub len: u32,
    /// How many bytes of it are in `data`.
    pub captured: u32,
    pub data: [u8; CAP],
}

/// 256 KiB of events; an overflow is reported by userspace as a lost event.
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Count of events that did not fit (userspace reads it: a lost event).
#[map]
static LOST: aya_ebpf::maps::Array<u64> = aya_ebpf::maps::Array::with_max_entries(1, 0);

#[inline(always)]
fn report(ctx: &FEntryContext, hook: u32) -> u32 {
    // rtnetlink_rcv_msg, nfnetlink_rcv_msg and genl_rcv_msg all take
    // (struct sk_buff *skb, struct nlmsghdr *nlh, struct netlink_ext_ack *).
    let nlh: *const u8 = unsafe { ctx.arg(1) };
    let Some(mut entry) = EVENTS.reserve::<Event>(0) else {
        if let Some(n) = LOST.get_ptr_mut(0) {
            unsafe { *n += 1 };
        }
        return 0;
    };
    let ev = entry.as_mut_ptr();
    unsafe {
        (*ev).cgroup = bpf_get_current_cgroup_id();
        (*ev).tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
        (*ev).hook = hook;
        let mut len = [0u8; 4];
        let _ = bpf_probe_read_kernel_buf(nlh, &mut len);
        let len = u32::from_ne_bytes(len);
        (*ev).len = len;
        // Copy the whole capture window; past the message's end the bytes
        // are whatever follows it, and userspace reads only `len` of them.
        let ok = bpf_probe_read_kernel_buf(nlh, &mut (*ev).data).is_ok();
        (*ev).captured = if !ok { 0 } else if (len as usize) < CAP { len } else { CAP as u32 };
    }
    entry.submit(0);
    0
}

#[fentry(function = "rtnetlink_rcv_msg")]
pub fn rtnetlink(ctx: FEntryContext) -> u32 {
    report(&ctx, HOOK_RTNETLINK)
}

#[fentry(function = "nfnetlink_rcv_msg")]
pub fn nfnetlink(ctx: FEntryContext) -> u32 {
    report(&ctx, HOOK_NFNETLINK)
}

#[fentry(function = "genl_rcv_msg")]
pub fn genl(ctx: FEntryContext) -> u32 {
    report(&ctx, HOOK_GENL)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
