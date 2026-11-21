//! ARP (RFC 826): address resolution, cache, pending queue.
//!
//! Packet layout (28 bytes for Ethernet/IPv4):
//! hw type (2) | proto type (2) | hw len (1) | proto len (1) |
//! opcode (2) | sender MAC (6) | sender IP (4) |
//! target MAC (6) | target IP (4).

use alloc::vec::Vec;
use crate::ethernet::MacAddr;
use crate::ipv4::Ipv4Addr;
use crate::NetError;

pub const ARP_PACKET_LEN: usize = 28;
pub const ARP_HW_ETHERNET: u16 = 1;
pub const ARP_PROTO_IPV4: u16 = 0x0800;

/// ARP opcodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArpOpcode(pub u16);

impl ArpOpcode {
    pub const REQUEST: ArpOpcode = ArpOpcode(1);
    pub const REPLY: ArpOpcode = ArpOpcode(2);
}

/// An ARP packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArpPacket {
    pub opcode: ArpOpcode,
    pub sender_mac: MacAddr,
    pub sender_ip: Ipv4Addr,
    pub target_mac: MacAddr,
    pub target_ip: Ipv4Addr,
}

impl ArpPacket {
    pub fn request(sender_mac: MacAddr, sender_ip: Ipv4Addr, target_ip: Ipv4Addr) -> Self {
        Self {
            opcode: ArpOpcode::REQUEST,
            sender_mac,
            sender_ip,
            target_mac: MacAddr::ZERO,
            target_ip,
        }
    }

    pub fn reply(sender_mac: MacAddr, sender_ip: Ipv4Addr, target_mac: MacAddr, target_ip: Ipv4Addr) -> Self {
        Self {
            opcode: ArpOpcode::REPLY,
            sender_mac,
            sender_ip,
            target_mac,
            target_ip,
        }
    }

    /// Gratuitous ARP: a reply announcing our own address (used on
    /// link-up and to detect address conflicts).
    pub fn gratuitous(mac: MacAddr, ip: Ipv4Addr) -> Self {
        Self::reply(mac, ip, MacAddr::BROADCAST, ip)
    }

    pub fn is_request(&self) -> bool {
        self.opcode == ArpOpcode::REQUEST
    }

    pub fn is_reply(&self) -> bool {
        self.opcode == ArpOpcode::REPLY
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, NetError> {
        if bytes.len() < ARP_PACKET_LEN {
            return Err(NetError::TooShort);
        }
        let hw = u16::from_be_bytes([bytes[0], bytes[1]]);
        let proto = u16::from_be_bytes([bytes[2], bytes[3]]);
        if hw != ARP_HW_ETHERNET || proto != ARP_PROTO_IPV4 || bytes[4] != 6 || bytes[5] != 4 {
            return Err(NetError::Unsupported);
        }
        Ok(Self {
            opcode: ArpOpcode(u16::from_be_bytes([bytes[6], bytes[7]])),
            sender_mac: MacAddr(bytes[8..14].try_into().unwrap()),
            sender_ip: Ipv4Addr(bytes[14..18].try_into().unwrap()),
            target_mac: MacAddr(bytes[18..24].try_into().unwrap()),
            target_ip: Ipv4Addr(bytes[24..28].try_into().unwrap()),
        })
    }

    pub fn to_bytes(&self) -> [u8; ARP_PACKET_LEN] {
        let mut out = [0u8; ARP_PACKET_LEN];
        out[0..2].copy_from_slice(&ARP_HW_ETHERNET.to_be_bytes());
        out[2..4].copy_from_slice(&ARP_PROTO_IPV4.to_be_bytes());
        out[4] = 6;
        out[5] = 4;
        out[6..8].copy_from_slice(&self.opcode.0.to_be_bytes());
        out[8..14].copy_from_slice(&self.sender_mac.0);
        out[14..18].copy_from_slice(&self.sender_ip.0);
        out[18..24].copy_from_slice(&self.target_mac.0);
        out[24..28].copy_from_slice(&self.target_ip.0);
        out
    }
}

const ARP_CACHE_SIZE: usize = 16;
/// Default cache entry lifetime, seconds.
pub const ARP_TTL_SECS: u64 = 300;

#[derive(Debug, Clone, Copy)]
struct ArpEntry {
    ip: Ipv4Addr,
    mac: MacAddr,
    /// Age in seconds when inserted (see `ArpCache::now`).
    inserted_at: u64,
}

/// ARP cache with expiry and a queue of packets waiting on
/// resolution. The kernel calls `tick(secs)` from its timer; a
/// `lookup` miss means the caller should emit a request and
/// `queue_packet` the payload until the reply arrives.
pub struct ArpCache {
    entries: [Option<ArpEntry>; ARP_CACHE_SIZE],
    pending: Vec<(Ipv4Addr, Vec<u8>)>,
    now: u64,
    ttl_secs: u64,
}

impl ArpCache {
    pub fn new() -> Self {
        Self {
            entries: [None; ARP_CACHE_SIZE],
            pending: Vec::new(),
            now: 0,
            ttl_secs: ARP_TTL_SECS,
        }
    }

    pub fn with_ttl(ttl_secs: u64) -> Self {
        let mut c = Self::new();
        c.ttl_secs = ttl_secs;
        c
    }

    /// Advance the clock; expired entries are dropped lazily on
    /// lookup and eagerly here.
    pub fn tick(&mut self, secs: u64) {
        self.now += secs;
        for slot in self.entries.iter_mut() {
            if let Some(e) = slot {
                if self.now - e.inserted_at >= self.ttl_secs {
                    *slot = None;
                }
            }
        }
    }

    pub fn insert(&mut self, ip: Ipv4Addr, mac: MacAddr) {
        // Refresh an existing entry first.
        for slot in self.entries.iter_mut() {
            if let Some(e) = slot {
                if e.ip == ip {
                    *slot = Some(ArpEntry { ip, mac, inserted_at: self.now });
                    return;
                }
            }
        }
        // Otherwise take the first free slot, else evict slot 0 (FIFO).
        for slot in self.entries.iter_mut() {
            if slot.is_none() {
                *slot = Some(ArpEntry { ip, mac, inserted_at: self.now });
                return;
            }
        }
        self.entries[0] = Some(ArpEntry { ip, mac, inserted_at: self.now });
    }

    pub fn lookup(&mut self, ip: Ipv4Addr) -> Option<MacAddr> {
        for slot in self.entries.iter_mut() {
            if let Some(e) = slot {
                if e.ip == ip {
                    if self.now - e.inserted_at >= self.ttl_secs {
                        *slot = None;
                        return None;
                    }
                    return Some(e.mac);
                }
            }
        }
        None
    }

    pub fn len(&self) -> usize {
        self.entries.iter().filter(|e| e.is_some()).count()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Queue a payload (e.g. an IP packet) waiting for `ip` to resolve.
    pub fn queue_packet(&mut self, ip: Ipv4Addr, payload: Vec<u8>) {
        self.pending.push((ip, payload));
    }

    /// Drain queued payloads for `ip` after a reply resolved it.
    /// Returns the payloads in queue order.
    pub fn drain_pending(&mut self, ip: Ipv4Addr) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        let mut i = 0;
        while i < self.pending.len() {
            if self.pending[i].0 == ip {
                out.push(self.pending.remove(i).1);
            } else {
                i += 1;
            }
        }
        out
    }

    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }

    /// Handle an incoming ARP packet. Returns a reply packet to send
    /// when the packet is a request for `our_ip`, else `None`.
    /// Any valid packet also refreshes the cache with the sender.
    pub fn handle_packet(&mut self, packet: &ArpPacket, our_mac: MacAddr, our_ip: Ipv4Addr) -> Option<ArpPacket> {
        self.insert(packet.sender_ip, packet.sender_mac);
        if packet.is_request() && packet.target_ip == our_ip {
            Some(ArpPacket::reply(our_mac, our_ip, packet.sender_mac, packet.sender_ip))
        } else {
            None
        }
    }
}

impl Default for ArpCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ME_MAC: MacAddr = MacAddr([0x52, 0x54, 0x00, 0x12, 0x34, 0x56]);
    const ME_IP: Ipv4Addr = Ipv4Addr([10, 0, 0, 1]);
    const PEER_MAC: MacAddr = MacAddr([0x52, 0x54, 0x00, 0x65, 0x43, 0x21]);
    const PEER_IP: Ipv4Addr = Ipv4Addr([10, 0, 0, 2]);

    #[test]
    fn packet_roundtrip() {
        let req = ArpPacket::request(ME_MAC, ME_IP, PEER_IP);
        assert!(req.is_request());
        let back = ArpPacket::parse(&req.to_bytes()).unwrap();
        assert_eq!(back, req);
        let rep = ArpPacket::reply(PEER_MAC, PEER_IP, ME_MAC, ME_IP);
        assert!(rep.is_reply());
        assert_eq!(ArpPacket::parse(&rep.to_bytes()).unwrap(), rep);
        assert_eq!(ArpPacket::parse(&[0u8; 27]), Err(NetError::TooShort));
        let mut bad = req.to_bytes();
        bad[0] = 0;
        bad[1] = 99;
        assert_eq!(ArpPacket::parse(&bad), Err(NetError::Unsupported));
    }

    #[test]
    fn cache_insert_lookup_expire() {
        let mut cache = ArpCache::with_ttl(10);
        assert!(cache.lookup(PEER_IP).is_none());
        cache.insert(PEER_IP, PEER_MAC);
        assert_eq!(cache.lookup(PEER_IP), Some(PEER_MAC));
        assert_eq!(cache.len(), 1);
        // Re-insert refreshes the expiry.
        cache.tick(9);
        cache.insert(PEER_IP, PEER_MAC);
        cache.tick(9);
        assert_eq!(cache.lookup(PEER_IP), Some(PEER_MAC));
        cache.tick(2);
        assert_eq!(cache.lookup(PEER_IP), None);
        assert!(cache.is_empty());
    }

    #[test]
    fn cache_evicts_when_full() {
        let mut cache = ArpCache::new();
        for i in 0..20u8 {
            cache.insert(Ipv4Addr::new(10, 0, 0, i), MacAddr::new([0, 0, 0, 0, 0, i]));
        }
        assert_eq!(cache.len(), 16);
    }

    #[test]
    fn pending_queue_drains_on_resolve() {
        let mut cache = ArpCache::new();
        cache.queue_packet(PEER_IP, vec![1, 2, 3]);
        cache.queue_packet(Ipv4Addr::new(10, 0, 0, 9), vec![9]);
        cache.queue_packet(PEER_IP, vec![4, 5]);
        assert_eq!(cache.pending_len(), 3);
        let drained = cache.drain_pending(PEER_IP);
        assert_eq!(drained, vec![vec![1, 2, 3], vec![4, 5]]);
        assert_eq!(cache.pending_len(), 1);
    }

    #[test]
    fn handle_request_for_us_replies_and_caches_peer() {
        let mut cache = ArpCache::new();
        let req = ArpPacket::request(PEER_MAC, PEER_IP, ME_IP);
        let reply = cache.handle_packet(&req, ME_MAC, ME_IP).unwrap();
        assert_eq!(reply.sender_ip, ME_IP);
        assert_eq!(reply.target_ip, PEER_IP);
        assert_eq!(reply.target_mac, PEER_MAC);
        assert_eq!(cache.lookup(PEER_IP), Some(PEER_MAC));
        // Request for someone else: no reply, but peer is still cached.
        let other = ArpPacket::request(PEER_MAC, PEER_IP, Ipv4Addr::new(10, 0, 0, 99));
        assert!(cache.handle_packet(&other, ME_MAC, ME_IP).is_none());
        // Gratuitous ARP announces our own address.
        let g = ArpPacket::gratuitous(ME_MAC, ME_IP);
        assert_eq!(g.target_ip, ME_IP);
        assert!(g.is_reply());
    }
}
