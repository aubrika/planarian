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
use aya_ebpf::macros::{fentry, fexit, kprobe, map};
use aya_ebpf::maps::RingBuf;
use aya_ebpf::programs::{FEntryContext, FExitContext, ProbeContext};

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
pub const HOOK_NETMOVE: u32 = 7;
pub const HOOK_NETRENAME: u32 = 8;

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
/// `NETDEV_SET` is 1 once they are: `name` was at offset 0 before 6.8, so
/// an offset cannot double as the sentinel.
#[unsafe(no_mangle)]
static NETDEV_SET: u32 = 0;
#[unsafe(no_mangle)]
static NETDEV_NAME: u32 = 0;
#[unsafe(no_mangle)]
static NETDEV_NET: u32 = 0;

/// Every interface the kernel registers, of every kind, in its creator's
/// context: a tun or tap made by `ioctl(TUNSETIFF)` (classic OpenVPN,
/// wireguard-go, tailscaled), which no netlink message announces, as well
/// as netlink-made links (veth, wireguard, dummy). At *exit*, and only on
/// success: on entry the name may still be a template (`tun%d`, `veth%d`),
/// which `register_netdevice` resolves itself (reviewer, #42). `data` is
/// the name (`IFNAMSIZ`, NUL-terminated); `netns` the device's own netns.
#[fexit(function = "register_netdevice")]
pub fn netdev(ctx: FExitContext) -> u32 {
    let dev: *const u8 = ctx.arg(0);
    let ret: i32 = ctx.arg(1);
    if ret != 0 {
        return 0; // not registered: nothing was made
    }
    let (set, name_off, net_off, inum) = unsafe {
        (
            core::ptr::read_volatile(&NETDEV_SET),
            core::ptr::read_volatile(&NETDEV_NAME),
            core::ptr::read_volatile(&NETDEV_NET),
            core::ptr::read_volatile(&NETNS_NET_INUM),
        )
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
        if set != 0 && !dev.is_null() {
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
        let ok = set != 0
            && !dev.is_null()
            && bpf_probe_read_kernel_buf(dev.wrapping_add(name_off as usize), &mut data[..16]).is_ok();
        (*ev).len = 16;
        (*ev).captured = if ok { 16 } else { 0 };
    }
    entry.submit(0);
    0
}

/// The netns of a `struct net *`, or 0.
#[inline(always)]
fn netns_of_net(net: *const u8) -> u32 {
    if net.is_null() {
        return 0;
    }
    let inum = unsafe { core::ptr::read_volatile(&NETNS_NET_INUM) };
    let mut b = [0u8; 4];
    match unsafe { bpf_probe_read_kernel_buf(net.wrapping_add(inum as usize), &mut b) } {
        Ok(()) => u32::from_ne_bytes(b),
        Err(_) => 0,
    }
}

/// The netns a device is in now (`net_device.nd_net`), or 0.
#[inline(always)]
fn netns_of_dev(dev: *const u8) -> u32 {
    let (set, net_off) = unsafe { (core::ptr::read_volatile(&NETDEV_SET), core::ptr::read_volatile(&NETDEV_NET)) };
    if set == 0 || dev.is_null() {
        return 0;
    }
    netns_of_net(read_ptr(dev, net_off))
}

/// Where `__dev_change_net_namespace` found the device: the netns inode (4
/// bytes, native-endian) then the name (`IFNAMSIZ`), written at entry and
/// read at exit. The function runs under the RTNL lock (it asserts it), so
/// there is never more than one call in flight and one slot is enough. All
/// zeros means "not seen at entry": userspace fails closed.
#[map]
static MOVE_SRC: aya_ebpf::maps::Array<[u8; 20]> = aya_ebpf::maps::Array::with_max_entries(1, 0);

/// A device is about to change network namespace: remember where it is and
/// what it is called (the exit sees only where it went, and a name the
/// kernel may have re-resolved).
#[fentry(function = "__dev_change_net_namespace")]
pub fn netmove_enter(ctx: FEntryContext) -> u32 {
    let dev: *const u8 = ctx.arg(0);
    let Some(slot) = MOVE_SRC.get_ptr_mut(0) else { return 0 };
    let slot = unsafe { &mut *slot };
    *slot = [0u8; 20];
    let inum = netns_of_dev(dev).to_ne_bytes();
    let name_off = unsafe { core::ptr::read_volatile(&NETDEV_NAME) };
    let set = unsafe { core::ptr::read_volatile(&NETDEV_SET) };
    if set == 0 || dev.is_null() {
        return 0;
    }
    let mut name = [0u8; 16];
    if unsafe { bpf_probe_read_kernel_buf(dev.wrapping_add(name_off as usize), &mut name) }.is_err() {
        return 0;
    }
    for i in 0..4 {
        slot[i] = inum[i];
    }
    for i in 0..16 {
        slot[4 + i] = name[i];
    }
    0
}

/// A device changed network namespace (the function returned and the device
/// is in the target): a link moved by `ip link set … netns`, `IFLA_NET_NS_*`
/// or `IFLA_NEW_NETNSID`, in the mover's context. Reported with `netns` the
/// target's inode and in `data`: the device's name now (16 bytes), the source
/// netns inode (4) and the source name (16), from `MOVE_SRC`. A call that
/// failed leaves the device where it was (its netns is not the target's) and
/// reports nothing; one whose netns the probe could not read reports `netns`
/// 0 (userspace fails closed).
///
/// The slot's cases: a call that fails is cleared here and reports nothing
/// (inert: nothing moved). An exit with no entry (attached mid-call) finds
/// the slot all zeros: source 0, which userspace reads as unreadable and
/// fails closed. An exit that cannot reserve a ring entry counts in `LOST`
/// (userspace: a loss nothing can place) and leaves the slot for the next
/// entry to overwrite. An entry cannot be left without its exit while both
/// are attached: the exit runs on every return.
///
/// Note the cost of a source of 0 (an exit with no entry): userspace reads
/// it as `Scope::Unknown`, which marks the *global* unattributed marker, and
/// that stands until the watch restarts. It happens only for a move already
/// under way when the probes attached (the attach is before the snapshot),
/// so it is rare and fails closed.
#[fexit(function = "__dev_change_net_namespace")]
pub fn netmove(ctx: FExitContext) -> u32 {
    let dev: *const u8 = ctx.arg(0);
    let target: *const u8 = ctx.arg(1);
    let target_inum = netns_of_net(target);
    let now = netns_of_dev(dev);
    let slot = MOVE_SRC.get_ptr_mut(0);
    let moved = target_inum == 0 || now == 0 || now == target_inum;
    if !moved {
        if let Some(slot) = slot {
            unsafe { *slot = [0u8; 20] };
        }
        return 0;
    }
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
        (*ev).hook = HOOK_NETMOVE;
        (*ev).netns = if now == target_inum { target_inum } else { 0 };
        cgroup_path(ev);
        let name_off = core::ptr::read_volatile(&NETDEV_NAME);
        let set = core::ptr::read_volatile(&NETDEV_SET);
        let data = &mut (*ev).data;
        for b in data[..36].iter_mut() {
            *b = 0;
        }
        let ok = set != 0
            && !dev.is_null()
            && bpf_probe_read_kernel_buf(dev.wrapping_add(name_off as usize), &mut data[..16]).is_ok();
        if let Some(slot) = slot {
            for i in 0..20 {
                data[16 + i] = (*slot)[i];
            }
            *slot = [0u8; 20];
        }
        (*ev).len = 36;
        (*ev).captured = if ok { 36 } else { 0 };
    }
    entry.submit(0);
    0
}

/// `netif_change_name` runs under RTNL too. It may run after the namespace
/// move returns (rtnetlink's combined move+name request), so the move event
/// alone cannot supply the final host name. Keep a separate slot: no task
/// can interleave a second rename while RTNL is held.
#[map]
static RENAME_SRC: aya_ebpf::maps::Array<[u8; 16]> = aya_ebpf::maps::Array::with_max_entries(1, 0);

#[fentry(function = "netif_change_name")]
pub fn netrename_enter(ctx: FEntryContext) -> u32 {
    let dev: *const u8 = ctx.arg(0);
    let Some(slot) = RENAME_SRC.get_ptr_mut(0) else { return 0 };
    unsafe { *slot = [0u8; 16] };
    let (set, name_off) = unsafe { (core::ptr::read_volatile(&NETDEV_SET), core::ptr::read_volatile(&NETDEV_NAME)) };
    if set != 0 && !dev.is_null() {
        let mut name = [0u8; 16];
        if unsafe { bpf_probe_read_kernel_buf(dev.wrapping_add(name_off as usize), &mut name) }.is_ok() {
            unsafe { *slot = name };
        }
    }
    0
}

/// Observe the resulting name, even when a failed rollback returns an error
/// after changing it. A failed call is inert only when both readable names
/// prove it unchanged. An absent entry or unreadable name fails closed;
/// ring loss uses the usual LOST gate.
#[fexit(function = "netif_change_name")]
pub fn netrename(ctx: FExitContext) -> u32 {
    let dev: *const u8 = ctx.arg(0);
    let ret: i32 = ctx.arg(2);
    let slot = RENAME_SRC.get_ptr_mut(0);
    if ret != 0 {
        let (set, name_off) = unsafe { (core::ptr::read_volatile(&NETDEV_SET), core::ptr::read_volatile(&NETDEV_NAME)) };
        let mut now = [0u8; 16];
        let mut unchanged = set != 0
            && !dev.is_null()
            && unsafe { bpf_probe_read_kernel_buf(dev.wrapping_add(name_off as usize), &mut now) }.is_ok();
        if let Some(slot) = slot {
            // Linux's NETDEV_CHANGENAME notifier can fail its rollback too:
            // the function then returns an error with the new name standing.
            unchanged &= unsafe { (*slot)[0] != 0 };
            for i in 0..16 {
                unchanged &= unsafe { (*slot)[i] == now[i] };
            }
            if unchanged {
                unsafe { *slot = [0u8; 16] };
                return 0;
            }
        }
    }
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
        (*ev).hook = HOOK_NETRENAME;
        (*ev).netns = netns_of_dev(dev);
        cgroup_path(ev);
        let data = &mut (*ev).data;
        for b in data[..32].iter_mut() {
            *b = 0;
        }
        if let Some(slot) = slot {
            for i in 0..16 {
                data[i] = (*slot)[i];
            }
            *slot = [0u8; 16];
        }
        let set = core::ptr::read_volatile(&NETDEV_SET);
        let name_off = core::ptr::read_volatile(&NETDEV_NAME);
        let ok = set != 0
            && !dev.is_null()
            && bpf_probe_read_kernel_buf(dev.wrapping_add(name_off as usize), &mut data[16..32]).is_ok();
        (*ev).len = 32;
        (*ev).captured = if ok { 32 } else { 0 };
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
