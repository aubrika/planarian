//! Just enough of the kernel's BTF (`/sys/kernel/btf/vmlinux`) to find
//! where a struct member lives, so the probes can read the netns of a
//! request on any kernel: Rust eBPF has no CO-RE, so the loader resolves
//! the offsets here and hands them to the object as globals (crate docs,
//! "Namespaces"). Read-only and bounds-checked; malformed input is an error.

const MAGIC: u16 = 0xEB9F;
const KIND_INT: u32 = 1;
const KIND_ARRAY: u32 = 3;
const KIND_STRUCT: u32 = 4;
const KIND_UNION: u32 = 5;
const KIND_ENUM: u32 = 6;
const KIND_TYPEDEF: u32 = 8;
const KIND_VOLATILE: u32 = 9;
const KIND_CONST: u32 = 10;
const KIND_RESTRICT: u32 = 11;
const KIND_FUNC_PROTO: u32 = 13;
const KIND_VAR: u32 = 14;
const KIND_DATASEC: u32 = 15;
const KIND_DECL_TAG: u32 = 17;
const KIND_TYPE_TAG: u32 = 18;
const KIND_ENUM64: u32 = 19;

struct Member {
    name: u32,
    ty: u32,
    bit_offset: u32,
}

struct Ty {
    name: u32,
    kind: u32,
    /// The referenced type (typedef, const, volatile, …).
    refers: u32,
    members: Vec<Member>,
}

pub struct Btf {
    /// Indexed by type id; id 0 is void.
    types: Vec<Ty>,
    strings: Vec<u8>,
}

fn u32_at(b: &[u8], at: usize) -> Result<u32, String> {
    b.get(at..at + 4).map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]])).ok_or_else(|| format!("BTF: short at {at}"))
}

impl Btf {
    pub fn parse(b: &[u8]) -> Result<Btf, String> {
        if b.get(0..2) != Some(&MAGIC.to_le_bytes()[..]) {
            return Err("BTF: bad magic (or big-endian)".into());
        }
        let hdr = u32_at(b, 4)? as usize;
        let (type_off, type_len) = (u32_at(b, 8)? as usize, u32_at(b, 12)? as usize);
        let (str_off, str_len) = (u32_at(b, 16)? as usize, u32_at(b, 20)? as usize);
        let types_b = b.get(hdr + type_off..hdr + type_off + type_len).ok_or("BTF: type section out of range")?;
        let strings = b.get(hdr + str_off..hdr + str_off + str_len).ok_or("BTF: string section out of range")?.to_vec();
        let mut types = vec![Ty { name: 0, kind: 0, refers: 0, members: vec![] }];
        let mut at = 0;
        while at < types_b.len() {
            let (name, info, size_or_type) = (u32_at(types_b, at)?, u32_at(types_b, at + 4)?, u32_at(types_b, at + 8)?);
            at += 12;
            let vlen = (info & 0xffff) as usize;
            let kind = (info >> 24) & 0x1f;
            let kind_flag = info >> 31 == 1;
            let mut members = Vec::new();
            let extra = match kind {
                KIND_INT | KIND_VAR | KIND_DECL_TAG => 4,
                KIND_ARRAY => 12,
                KIND_STRUCT | KIND_UNION => {
                    for i in 0..vlen {
                        let m = at + 12 * i;
                        let off = u32_at(types_b, m + 8)?;
                        let bit_offset = if kind_flag { off & 0x00ff_ffff } else { off };
                        members.push(Member { name: u32_at(types_b, m)?, ty: u32_at(types_b, m + 4)?, bit_offset });
                    }
                    12 * vlen
                }
                KIND_ENUM | KIND_FUNC_PROTO => 8 * vlen,
                KIND_DATASEC | KIND_ENUM64 => 12 * vlen,
                _ => 0,
            };
            at += extra;
            types.push(Ty { name, kind, refers: size_or_type, members });
        }
        Ok(Btf { types, strings })
    }

    fn name(&self, off: u32) -> &[u8] {
        let s = self.strings.get(off as usize..).unwrap_or(&[]);
        &s[..s.iter().position(|&c| c == 0).unwrap_or(s.len())]
    }

    /// Through typedefs and qualifiers to the type itself.
    fn resolve(&self, mut id: u32) -> Option<&Ty> {
        for _ in 0..32 {
            let t = self.types.get(id as usize)?;
            match t.kind {
                KIND_TYPEDEF | KIND_VOLATILE | KIND_CONST | KIND_RESTRICT | KIND_TYPE_TAG => id = t.refers,
                _ => return Some(t),
            }
        }
        None
    }

    /// A member by name, looking into anonymous structs and unions; its
    /// type id and bit offset from the start of `t`.
    fn member(&self, t: &Ty, name: &str) -> Option<(u32, u32)> {
        for m in &t.members {
            if self.name(m.name) == name.as_bytes() {
                return Some((m.ty, m.bit_offset));
            }
            if m.name == 0
                && let Some(inner) = self.resolve(m.ty)
                && matches!(inner.kind, KIND_STRUCT | KIND_UNION)
                && let Some((ty, off)) = self.member(inner, name)
            {
                return Some((ty, m.bit_offset + off));
            }
        }
        None
    }

    /// The byte offset of `path` (member, member of that, …) in `struct
    /// strukt`.
    pub fn offset(&self, strukt: &str, path: &[&str]) -> Result<u32, String> {
        let what = || format!("struct {strukt}.{}", path.join("."));
        let mut t = self
            .types
            .iter()
            .find(|t| t.kind == KIND_STRUCT && self.name(t.name) == strukt.as_bytes())
            .ok_or_else(|| format!("BTF: no {}", what()))?;
        let mut bits = 0;
        for (i, name) in path.iter().enumerate() {
            let (ty, off) = self.member(t, name).ok_or_else(|| format!("BTF: no member {name} in {}", what()))?;
            bits += off;
            if i + 1 < path.len() {
                t = self
                    .resolve(ty)
                    .filter(|t| matches!(t.kind, KIND_STRUCT | KIND_UNION))
                    .ok_or_else(|| format!("BTF: {name} is not a struct in {}", what()))?;
            }
        }
        if bits % 8 != 0 {
            return Err(format!("BTF: {} is a bitfield", what()));
        }
        Ok(bits / 8)
    }
}

/// Where the probes find a request's network namespace (crate docs,
/// "Namespaces"): `skb->sk`, `sk->__sk_common.skc_net.net`, and
/// `net->ns.inum`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetnsOffsets {
    pub skb_sk: u32,
    pub sk_net: u32,
    pub net_inum: u32,
}

impl NetnsOffsets {
    pub fn from_btf(btf: &Btf) -> Result<NetnsOffsets, String> {
        Ok(NetnsOffsets {
            skb_sk: btf.offset("sk_buff", &["sk"])?,
            sk_net: btf.offset("sock", &["__sk_common", "skc_net", "net"])?,
            net_inum: btf.offset("net", &["ns", "inum"])?,
        })
    }
}
