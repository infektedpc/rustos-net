//! IPv4: addresses, headers, checksum, fragmentation reassembly.
//!
//! Header layout (20 bytes minimum, IHL in 32-bit words):
//! version/IHL | DSCP/ECN | total length | identification |
//! flags/fragment offset | TTL | protocol | header checksum |
//! src | dst | options... | payload.

use alloc::vec::Vec;
use core::fmt;
use crate::NetError;

/// One's-complement checksum over `data` (RFC 1071). Pads an odd
/// trailing byte with zero. Returns the value to *store* in the
/// checksum field; a correct packet checksums to 0 when the stored
/// value is included.
pub fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut chunks = data.chunks_exact(2);
    for pair in &mut chunks {
        sum += u16::from_be_bytes([pair[0], pair[1]]) as u32;
    }
    if let Some(&last) = chunks.remainder().first() {
        sum += (last as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// True if `data` (including its stored checksum) verifies.
pub fn checksum_valid(data: &[u8]) -> bool {
    checksum(data) == 0
}

/// An IPv4 address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Ipv4Addr(pub [u8; 4]);

impl Ipv4Addr {
    pub const UNSPECIFIED: Ipv4Addr = Ipv4Addr([0, 0, 0, 0]);
    pub const BROADCAST: Ipv4Addr = Ipv4Addr([255, 255, 255, 255]);
    pub const LOOPBACK: Ipv4Addr = Ipv4Addr([127, 0, 0, 1]);

    pub const fn new(a: u8, b: u8, c: u8, d: u8) -> Self {
        Self([a, b, c, d])
    }

    pub fn octets(&self) -> [u8; 4] {
        self.0
    }

    pub fn is_broadcast(&self) -> bool {
        self.0 == [255, 255, 255, 255]
    }

    pub fn is_loopback(&self) -> bool {
        self.0[0] == 127
    }

    pub fn is_multicast(&self) -> bool {
        (224..=239).contains(&self.0[0])
    }

    /// RFC 1918 private ranges (10/8, 172.16/12, 192.168/16).
    pub fn is_private(&self) -> bool {
        self.0[0] == 10
            || (self.0[0] == 172 && (16..=31).contains(&self.0[1]))
            || (self.0[0] == 192 && self.0[1] == 168)
    }

    /// Parse "a.b.c.d".
    pub fn parse(s: &str) -> Option<Self> {
        let mut out = [0u8; 4];
        let mut parts = s.split('.');
        for i in 0..4 {
            let p = parts.next()?;
            if p.is_empty() || p.len() > 3 || !p.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            out[i] = p.parse().ok()?;
        }
        if parts.next().is_some() {
            return None;
        }
        Some(Self(out))
    }
}

impl fmt::Display for Ipv4Addr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}.{}", self.0[0], self.0[1], self.0[2], self.0[3])
    }
}

/// IP protocol numbers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Protocol(pub u8);

impl Protocol {
    pub const ICMP: Protocol = Protocol(1);
    pub const TCP: Protocol = Protocol(6);
    pub const UDP: Protocol = Protocol(17);
}

pub const IPV4_HEADER_LEN: usize = 20;
pub const IPV4_MIN_MTU: usize = 576;
pub const IPV4_MAX_PACKET: usize = 65535;

/// An IPv4 header (options are not stored; IHL > 5 is parsed and
/// skipped, options bytes are dropped on parse).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv4Header {
    pub dscp: u8,
    pub total_length: u16,
    pub identification: u16,
    /// Don't-fragment flag.
    pub dont_fragment: bool,
    /// More-fragments flag.
    pub more_fragments: bool,
    /// Fragment offset, in 8-byte units.
    pub fragment_offset: u16,
    pub ttl: u8,
    pub protocol: Protocol,
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
}

impl Ipv4Header {
    pub fn new(src: Ipv4Addr, dst: Ipv4Addr, protocol: Protocol, payload_len: usize) -> Self {
        Self {
            dscp: 0,
            total_length: (IPV4_HEADER_LEN + payload_len) as u16,
            identification: 0,
            dont_fragment: false,
            more_fragments: false,
            fragment_offset: 0,
            ttl: 64,
            protocol,
            src,
            dst,
        }
    }

    pub fn header_len(&self) -> usize {
        IPV4_HEADER_LEN
    }

    pub fn is_fragment(&self) -> bool {
        self.more_fragments || self.fragment_offset != 0
    }

    pub fn parse(bytes: &[u8]) -> Result<(Self, usize), NetError> {
        if bytes.len() < IPV4_HEADER_LEN {
            return Err(NetError::TooShort);
        }
        let version = bytes[0] >> 4;
        if version != 4 {
            return Err(NetError::Unsupported);
        }
        let ihl = ((bytes[0] & 0x0f) as usize) * 4;
        if ihl < IPV4_HEADER_LEN || bytes.len() < ihl {
            return Err(NetError::TooShort);
        }
        if !checksum_valid(&bytes[..ihl]) {
            return Err(NetError::BadChecksum);
        }
        let flags_frag = u16::from_be_bytes([bytes[6], bytes[7]]);
        Ok((
            Self {
                dscp: bytes[1],
                total_length: u16::from_be_bytes([bytes[2], bytes[3]]),
                identification: u16::from_be_bytes([bytes[4], bytes[5]]),
                dont_fragment: flags_frag & 0x4000 != 0,
                more_fragments: flags_frag & 0x2000 != 0,
                fragment_offset: flags_frag & 0x1fff,
                ttl: bytes[8],
                protocol: Protocol(bytes[9]),
                src: Ipv4Addr(bytes[12..16].try_into().unwrap()),
                dst: Ipv4Addr(bytes[16..20].try_into().unwrap()),
            },
            ihl,
        ))
    }

    /// Serialize the header (20 bytes, checksum filled in).
    pub fn to_bytes(&self) -> [u8; IPV4_HEADER_LEN] {
        let mut out = [0u8; IPV4_HEADER_LEN];
        out[0] = (4 << 4) | 5;
        out[1] = self.dscp;
        out[2..4].copy_from_slice(&self.total_length.to_be_bytes());
        out[4..6].copy_from_slice(&self.identification.to_be_bytes());
        let mut flags_frag: u16 = self.fragment_offset & 0x1fff;
        if self.dont_fragment {
            flags_frag |= 0x4000;
        }
        if self.more_fragments {
            flags_frag |= 0x2000;
        }
        out[6..8].copy_from_slice(&flags_frag.to_be_bytes());
        out[8] = self.ttl;
        out[9] = self.protocol.0;
        // checksum field left zero while computing
        out[12..16].copy_from_slice(&self.src.0);
        out[16..20].copy_from_slice(&self.dst.0);
        let sum = checksum(&out);
        out[10..12].copy_from_slice(&sum.to_be_bytes());
        out
    }
}

/// A parsed IPv4 packet: header + payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv4Packet {
    pub header: Ipv4Header,
    pub payload: Vec<u8>,
}

impl Ipv4Packet {
    pub fn new(header: Ipv4Header, payload: Vec<u8>) -> Self {
        Self { header, payload }
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, NetError> {
        let (header, ihl) = Ipv4Header::parse(bytes)?;
        let total = header.total_length as usize;
        if total < ihl || bytes.len() < total {
            return Err(NetError::TooShort);
        }
        Ok(Self {
            header,
            payload: bytes[ihl..total].to_vec(),
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(IPV4_HEADER_LEN + self.payload.len());
        out.extend_from_slice(&self.header.to_bytes());
        out.extend_from_slice(&self.payload);
        out
    }

    /// Dispatch by protocol number.
    pub fn protocol(&self) -> Protocol {
        self.header.protocol
    }
}

/// Reassembles fragmented IPv4 packets.
///
/// Limits (documented, deliberate): at most 4 concurrent datagrams,
/// at most 8 fragments per datagram, datagrams over 64 KiB are
/// rejected. A datagram is complete when the last fragment (MF=0)
/// has arrived and fragments cover [0, total) contiguously.
pub struct FragmentReassembler {
    entries: Vec<Reassembly>,
    /// Tick counter (seconds); entries older than `timeout_secs`
    /// are dropped by `tick`.
    now: u64,
    timeout_secs: u64,
}

struct Reassembly {
    id: (Ipv4Addr, Ipv4Addr, u16, Protocol),
    fragments: Vec<(usize, Vec<u8>, bool)>, // (byte offset, data, more_fragments)
    total_len: Option<usize>,
    created_at: u64,
}

impl FragmentReassembler {
    pub fn new() -> Self {
        Self { entries: Vec::new(), now: 0, timeout_secs: 30 }
    }

    pub fn tick(&mut self, secs: u64) {
        self.now += secs;
        self.entries.retain(|e| self.now - e.created_at < self.timeout_secs);
    }

    /// Feed one packet. Returns `Some(payload)` when the datagram
    /// is complete (or was never fragmented), else `None`.
    /// A non-fragmented packet returns its payload immediately.
    pub fn feed(&mut self, packet: Ipv4Packet) -> Option<Vec<u8>> {
        if !packet.header.is_fragment() {
            return Some(packet.payload);
        }
        let key = (
            packet.header.src,
            packet.header.dst,
            packet.header.identification,
            packet.header.protocol,
        );
        let offset = packet.header.fragment_offset as usize * 8;
        let more = packet.header.more_fragments;
        let idx = match self.entries.iter().position(|e| e.id == key) {
            Some(i) => i,
            None => {
                if self.entries.len() >= 4 {
                    return None;
                }
                self.entries.push(Reassembly {
                    id: key,
                    fragments: Vec::new(),
                    total_len: None,
                    created_at: self.now,
                });
                self.entries.len() - 1
            }
        };
        let entry = &mut self.entries[idx];
        if entry.fragments.len() >= 8 {
            return None;
        }
        if !more {
            entry.total_len = Some(offset + packet.payload.len());
        }
        entry.fragments.push((offset, packet.payload, more));
        entry.fragments.sort_by_key(|f| f.0);
        let total = entry.total_len?;
        // Check contiguous coverage from 0 to total.
        let mut covered = 0usize;
        for (off, data, _) in &entry.fragments {
            if *off > covered {
                return None; // gap
            }
            covered = covered.max(off + data.len());
            if covered >= total {
                break;
            }
        }
        if covered < total {
            return None;
        }
        let mut out = Vec::with_capacity(total);
        for (off, data, _) in &entry.fragments {
            let end = off + data.len();
            if out.len() < *off {
                out.resize(*off, 0);
            }
            if out.len() < end {
                out.resize(end, 0);
            }
            out[*off..end].copy_from_slice(data);
        }
        out.truncate(total);
        self.entries.remove(idx);
        Some(out)
    }
}

impl Default for FragmentReassembler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_known_vector() {
        // RFC 1071 example: 0x0001 f203 f4f5 f6f7 -> 0x220d.
        let data = [0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7];
        assert_eq!(checksum(&data), 0x220d);
        // A header with its checksum stored verifies to 0.
        let header = Ipv4Header::new(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 2),
            Protocol::UDP,
            8,
        );
        let bytes = header.to_bytes();
        assert!(checksum_valid(&bytes));
        // Corrupt one byte: fails.
        let mut bad = bytes;
        bad[12] ^= 0xff;
        assert!(!checksum_valid(&bad));
    }

    #[test]
    fn header_roundtrip() {
        let mut header = Ipv4Header::new(
            Ipv4Addr::new(192, 168, 1, 10),
            Ipv4Addr::new(192, 168, 1, 1),
            Protocol::TCP,
            4,
        );
        header.identification = 0x1234;
        header.ttl = 128;
        let packet = Ipv4Packet::new(header, vec![1, 2, 3, 4]);
        let bytes = packet.to_bytes();
        let back = Ipv4Packet::parse(&bytes).unwrap();
        assert_eq!(back.header.identification, 0x1234);
        assert_eq!(back.header.ttl, 128);
        assert_eq!(back.header.src, Ipv4Addr::new(192, 168, 1, 10));
        assert_eq!(back.payload, vec![1, 2, 3, 4]);
    }

    #[test]
    fn header_rejects_bad_version_and_checksum() {
        let mut header = Ipv4Header::new(Ipv4Addr::LOOPBACK, Ipv4Addr::LOOPBACK, Protocol::ICMP, 0);
        let mut bytes = header.to_bytes().to_vec();
        bytes[0] = (6 << 4) | 5;
        assert_eq!(Ipv4Packet::parse(&bytes), Err(NetError::Unsupported));
        let mut bytes = header.to_bytes().to_vec();
        bytes[10] ^= 0xff;
        assert_eq!(Ipv4Packet::parse(&bytes), Err(NetError::BadChecksum));
        header.total_length = 9999;
        // total_length longer than the buffer: TooShort.
        let packet = Ipv4Packet::new(header, vec![]);
        assert_eq!(Ipv4Packet::parse(&packet.to_bytes()), Err(NetError::TooShort));
    }

    #[test]
    fn addr_classification_and_parse() {
        assert!(Ipv4Addr::new(10, 1, 2, 3).is_private());
        assert!(Ipv4Addr::new(192, 168, 0, 1).is_private());
        assert!(Ipv4Addr::new(172, 20, 0, 1).is_private());
        assert!(!Ipv4Addr::new(8, 8, 8, 8).is_private());
        assert!(Ipv4Addr::new(224, 0, 0, 1).is_multicast());
        assert!(Ipv4Addr::LOOPBACK.is_loopback());
        assert_eq!(Ipv4Addr::parse("10.0.0.1"), Some(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(Ipv4Addr::parse("10.0.0"), None);
        assert_eq!(Ipv4Addr::parse("10.0.0.256"), None);
        assert_eq!(Ipv4Addr::parse("a.b.c.d"), None);
        assert_eq!(alloc::format!("{}", Ipv4Addr::new(1, 2, 3, 4)), "1.2.3.4");
    }

    #[test]
    fn reassembly_two_fragments() {
        let mut re = FragmentReassembler::new();
        let payload: Vec<u8> = (0..32u8).collect();
        let mut h1 = Ipv4Header::new(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2), Protocol::UDP, 32);
        h1.identification = 42;
        h1.more_fragments = true;
        h1.fragment_offset = 0;
        let mut h2 = h1.clone();
        h2.more_fragments = false;
        h2.fragment_offset = 2; // byte offset 16
        // Second fragment first: incomplete.
        assert!(re.feed(Ipv4Packet::new(h2, payload[16..].to_vec())).is_none());
        // First fragment completes it.
        let out = re.feed(Ipv4Packet::new(h1, payload[..16].to_vec())).unwrap();
        assert_eq!(out, payload);
        // Unfragmented passes straight through.
        let h = Ipv4Header::new(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2), Protocol::UDP, 3);
        assert_eq!(re.feed(Ipv4Packet::new(h, vec![7, 8, 9])), Some(vec![7, 8, 9]));
    }

    #[test]
    fn reassembly_expires_stale_entries() {
        let mut re = FragmentReassembler::new();
        let mut h = Ipv4Header::new(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2), Protocol::UDP, 16);
        h.identification = 7;
        h.more_fragments = true;
        assert!(re.feed(Ipv4Packet::new(h.clone(), vec![0u8; 16])).is_none());
        re.tick(31);
        // Stale entry dropped; a fresh first fragment starts a new entry.
        assert!(re.feed(Ipv4Packet::new(h, vec![0u8; 16])).is_none());
    }
}
