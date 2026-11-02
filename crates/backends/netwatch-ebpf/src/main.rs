//! netwatch's eBPF program (SPEC §12d "Which units"): an fentry probe on
//! each netlink receive path that can change how traffic leaves the
//! machine (`rtnetlink_rcv_msg`: links, addresses, routes, rules;
//! `nfnetlink_rcv_msg` and `nfnetlink_rcv_batch`: nftables, whose changes
//! come as batches; `nf_setsockopt`: legacy iptables and its kin, which use
//! setsockopt; `genl_rcv_msg`: generic netlink, e.g. WireGuard). Each message is reported to userspace with the sender's
//! cgroup id; userspace parses it. The kernel side stays small so the
//! verifier has little to prove. The event layout is `Event`, mirrored by
//! `planarian-backend-netwatch` (its `ebpf` module; a test checks the size).

#![no_std]
#![no_main]

use aya_ebpf::helpers::{
    bpf_get_current_cgroup_id, bpf_get_current_pid_tgid, bpf_get_current_task, bpf_probe_read_kernel_buf,
    bpf_probe_read_kernel_str_bytes,
};
use aya_ebpf::macros::{fentry, kprobe, map};
use aya_ebpf::maps::RingBuf;
use aya_ebpf::programs::{FEntryContext, ProbeContext};

/// Bytes of each message copied to userspace (headers and the first
/// attributes; a longer message is flagged truncated).
const CAP: usize = 512;

/// The sender's cgroup path, leaf first: up to `LEVELS` names of `NAME`
/// bytes each (NUL-terminated), and `CG_ROOT` in `cgflags` when the walk
/// reached the root (so the names are the whole path).
const LEVELS: usize = 4;
const NAME: usize = 96;
pub const CG_ROOT: u32 = 1 << 31;

pub const HOOK_RTNETLINK: u32 = 1;
pub const HOOK_NFNETLINK: u32 = 2;
pub const HOOK_GENL: u32 = 3;
pub const HOOK_NFBATCH: u32 = 4;
pub const HOOK_SOCKOPT: u32 = 5;
pub const HOOK_NETDEV: u32 = 6;

#[repr(C)]
pub struct Event {
    pub cgroup: u64,
    pub tgid: u32,
    pub hook: u32,
    /// The message's own length (`nlmsg_len`).
    pub len: u32,
    /// How many bytes of it are in `data`.
    pub captured: u32,
    /// The inode of the network namespace the request acts on (the kernel's
    /// own `sock_net(skb->sk)`, or the socket's for `setsockopt`); 0 when
    /// it could not be read (userspace fails closed).
    pub netns: u32,
    /// How many names are in `cgpath` (low bits), and `CG_ROOT`.
    pub cgflags: u32,
    pub cgpath: [[u8; NAME]; LEVELS],
    pub data: [u8; CAP],
}

/// Where the sender's cgroup names are, set by the loader from BTF like
/// the netns offsets: `task->cgroups`, `css_set->dfl_cgrp`, `cgroup->kn`,
/// `kernfs_node->name` and its parent. `CG_TASK_CGROUPS` 0 means "not
/// set": no names are read (userspace falls back to the cgroup id).
#[unsafe(no_mangle)]
static CG_TASK_CGROUPS: u32 = 0;
#[unsafe(no_mangle)]
static CG_CSS_DFL: u32 = 0;
#[unsafe(no_mangle)]
static CG_CGROUP_KN: u32 = 0;
#[unsafe(no_mangle)]
static CG_KN_NAME: u32 = 0;
#[unsafe(no_mangle)]
static CG_KN_PARENT: u32 = 0;

/// Fill `ev.cgpath` and `ev.cgflags` with the current task's cgroup path.
#[inline(always)]
fn cgroup_path(ev: *mut Event) {
    let (cgroups, dfl, kn_off, name_off, parent_off) = unsafe {
        (
            core::ptr::read_volatile(&CG_TASK_CGROUPS),
            core::ptr::read_volatile(&CG_CSS_DFL),
            core::ptr::read_volatile(&CG_CGROUP_KN),
            core::ptr::read_volatile(&CG_KN_NAME),
            core::ptr::read_volatile(&CG_KN_PARENT),
        )
    };
    unsafe { (*ev).cgflags = 0 };
    if cgroups == 0 {
        return;
    }
    let task = unsafe { bpf_get_current_task() } as usize as *const u8;
    let mut kn = read_ptr(read_ptr(read_ptr(task, cgroups), dfl), kn_off);
    let mut n = 0u32;
    for i in 0..=LEVELS {
        if kn.is_null() {
            return;
        }
        let parent = read_ptr(kn, parent_off);
        if parent.is_null() {
            // `kn` is the root: the names so far are the whole path.
            unsafe { (*ev).cgflags = n | CG_ROOT };
            return;
        }
        if i == LEVELS {
            break;
        }
        let name = read_ptr(kn, name_off);
        if name.is_null() {
            return;
        }
        let slot = unsafe { &mut (*ev).cgpath[i] };
        if unsafe { bpf_probe_read_kernel_str_bytes(name, slot) }.is_err() {
            return;
        }
        n += 1;
        unsafe { (*ev).cgflags = n };
        kn = parent;
    }
}

/// Where a request's netns is, set by the loader from the running kernel's
/// BTF before load (Rust eBPF has no CO-RE): `skb->sk`, then
/// `sk->__sk_common.skc_net.net`, then `net->ns.inum`. `NETNS_SKB_SK` 0
/// means "not set": every netns reads as 0.
#[unsafe(no_mangle)]
static NETNS_SKB_SK: u32 = 0;
#[unsafe(no_mangle)]
static NETNS_SK_NET: u32 = 0;
#[unsafe(no_mangle)]
static NETNS_NET_INUM: u32 = 0;

#[inline(always)]
fn read_ptr(p: *const u8, off: u32) -> *const u8 {
    if p.is_null() {
        return core::ptr::null();
    }
    let mut b = [0u8; 8];
    match unsafe { bpf_probe_read_kernel_buf(p.wrapping_add(off as usize), &mut b) } {
        Ok(()) => u64::from_ne_bytes(b) as usize as *const u8,
        Err(_) => core::ptr::null(),
    }
}

/// The netns inode of socket `sk`, or 0.
#[inline(always)]
fn netns_of_sock(sk: *const u8) -> u32 {
    let (sk_net, inum) = unsafe { (core::ptr::read_volatile(&NETNS_SK_NET), core::ptr::read_volatile(&NETNS_NET_INUM)) };
    let net = read_ptr(sk, sk_net);
    if net.is_null() {
        return 0;
    }
    let mut b = [0u8; 4];
    match unsafe { bpf_probe_read_kernel_buf(net.wrapping_add(inum as usize), &mut b) } {
        Ok(()) => u32::from_ne_bytes(b),
        Err(_) => 0,
    }
}

/// The netns a netlink request acts on: that of the kernel socket it
/// arrived on (`skb->sk`), as the receive functions themselves take it.
#[inline(always)]
fn netns_of_skb(skb: *const u8) -> u32 {
    let off = unsafe { core::ptr::read_volatile(&NETNS_SKB_SK) };
    if off == 0 {
        return 0;
    }
    netns_of_sock(read_ptr(skb, off))
}

/// 512 KiB of events (about 560 at 928 bytes each); an overflow is
/// reported by userspace as a lost event.
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(512 * 1024, 0);

/// Count of events that did not fit (userspace reads it: a lost event).
#[map]
static LOST: aya_ebpf::maps::Array<u64> = aya_ebpf::maps::Array::with_max_entries(1, 0);

/// Report one netlink message: `nlh` is the receive function's second
/// argument (rtnetlink_rcv_msg, nfnetlink_rcv_msg and genl_rcv_msg take
/// (skb, nlh, extack); nfnetlink_rcv_batch takes (skb, nlh, subsys, genid)).
/// A null `nlh` (an argument that could not be read) reports an empty
/// capture, which userspace reads as unreadable: the sender is marked
/// unattributed (fail closed).
#[inline(always)]
fn report(skb: *const u8, nlh: *const u8, hook: u32) -> u32 {
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
        (*ev).netns = netns_of_skb(skb);
        cgroup_path(ev);
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
    report(ctx.arg(0), ctx.arg(1), HOOK_RTNETLINK)
}

/// nfnetlink is a module on NixOS kernels (CONFIG_NETFILTER_NETLINK=m), so
/// its functions are not in vmlinux's BTF and fentry cannot name them with
/// this aya: a kprobe, by symbol, once the module is loaded (lane-nix loads
/// it at boot). It still runs in the sender's context.
#[kprobe(function = "nfnetlink_rcv_msg")]
pub fn nfnetlink(ctx: ProbeContext) -> u32 {
    report(ctx.arg(0).unwrap_or(core::ptr::null()), ctx.arg(1).unwrap_or(core::ptr::null()), HOOK_NFNETLINK)
}

/// nftables batches bypass `nfnetlink_rcv_msg`: `nfnetlink_rcv_batch(skb,
/// nlh, subsys_id, genid)` sees each one (its `nlh` is the batch's first).
#[kprobe(function = "nfnetlink_rcv_batch")]
pub fn nfbatch(ctx: ProbeContext) -> u32 {
    report(ctx.arg(0).unwrap_or(core::ptr::null()), ctx.arg(1).unwrap_or(core::ptr::null()), HOOK_NFBATCH)
}

/// Legacy iptables, ip6tables, arptables and ebtables change their tables
/// with `setsockopt`, not netlink; `nf_setsockopt(sk, pf, val, opt, len)` is
/// the one kernel entry for all of them. Reported with `pf` in `data[0]`
/// and the option (`val`) in `data[4..8]`; there is no message.
#[fentry(function = "nf_setsockopt")]
pub fn sockopt(ctx: FEntryContext) -> u32 {
    let sk: *const u8 = ctx.arg(0);
    let pf: u8 = ctx.arg(1);
    let val: i32 = ctx.arg(2);
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
        (*ev).hook = HOOK_SOCKOPT;
        (*ev).netns = netns_of_sock(sk);
        cgroup_path(ev);
        (*ev).len = 8;
        (*ev).captured = 8;
        (*ev).data[0] = pf;
        let v = val.to_ne_bytes();
        (*ev).data[4] = v[0];
        (*ev).data[5] = v[1];
        (*ev).data[6] = v[2];
        (*ev).data[7] = v[3];
    }
    entry.submit(0);
    0
}

/// Where `register_netdevice` finds the device's name and netns, set by
/// the loader from BTF: `net_device.name`, `net_device.nd_net.net`.
#[unsafe(no_mangle)]
static NETDEV_NAME: u32 = 0;
#[unsafe(no_mangle)]
static NETDEV_NET: u32 = 0;

/// Every interface the kernel registers, of every kind, in its creator's
/// context: a tun or tap made by `ioctl(TUNSETIFF)` (classic OpenVPN,
/// wireguard-go, tailscaled), which no netlink message announces, as well
/// as netlink-made links (veth, wireguard, dummy). `data` is the name
/// (`IFNAMSIZ`, NUL-terminated); `netns` the device's own netns.
#[fentry(function = "register_netdevice")]
pub fn netdev(ctx: FEntryContext) -> u32 {
    let dev: *const u8 = ctx.arg(0);
    let (name_off, net_off, inum) = unsafe {
        (core::ptr::read_volatile(&NETDEV_NAME), core::ptr::read_volatile(&NETDEV_NET), core::ptr::read_volatile(&NETNS_NET_INUM))
    };
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
        (*ev).hook = HOOK_NETDEV;
        (*ev).netns = 0;
        if name_off != 0 && !dev.is_null() {
            let net = read_ptr(dev, net_off);
            if !net.is_null() {
                let mut b = [0u8; 4];
                if bpf_probe_read_kernel_buf(net.wrapping_add(inum as usize), &mut b).is_ok() {
                    (*ev).netns = u32::from_ne_bytes(b);
                }
            }
        }
        cgroup_path(ev);
        let data = &mut (*ev).data;
        let ok = name_off != 0
            && !dev.is_null()
            && bpf_probe_read_kernel_buf(dev.wrapping_add(name_off as usize), &mut data[..16]).is_ok();
        (*ev).len = 16;
        (*ev).captured = if ok { 16 } else { 0 };
    }
    entry.submit(0);
    0
}

#[fentry(function = "genl_rcv_msg")]
pub fn genl(ctx: FEntryContext) -> u32 {
    report(ctx.arg(0), ctx.arg(1), HOOK_GENL)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
