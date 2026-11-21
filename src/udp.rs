//! UDP (RFC 768): headers, pseudo-header checksum, port dispatch.
//!
//! Header layout (8 bytes): src port | dst port | length | checksum.
//! The checksum covers a 12-byte pseudo-header (src IP, dst IP,
//! zero, protocol, UDP length) plus the UDP header and payload.
//! A transmitted checksum of zero means "no checksum" — this crate
//! always computes one, and accepts zero on receive.

use alloc::vec::Vec;
use crate::ipv4::{checksum, Ipv4Addr, Protocol};
use crate::NetError;

pub const UDP_HEADER_LEN: usize = 8;

/// A UDP datagram.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpPacket {
    pub src_port: u16,
    pub dst_port: u16,
    pub payload: Vec<u8>,
}

impl UdpPacket {
    pub fn new(src_port: u16, dst_port: u16, payload: Vec<u8>) -> Self {
        Self { src_port, dst_port, payload }
    }

    pub fn length(&self) -> u16 {
        (UDP_HEADER_LEN + self.payload.len()) as u16
    }

    /// Checksum over pseudo-header + header + payload. `src`/`dst`
    /// are the IPv4 endpoints.
    pub fn compute_checksum(&self, src: Ipv4Addr, dst: Ipv4Addr) -> u16 {
        let mut data = Vec::with_capacity(12 + UDP_HEADER_LEN + self.payload.len());
        data.extend_from_slice(&src.0);
        data.extend_from_slice(&dst.0);
        data.push(0);
        data.push(Protocol::UDP.0);
        data.extend_from_slice(&self.length().to_be_bytes());
        data.extend_from_slice(&self.src_port.to_be_bytes());
        data.extend_from_slice(&self.dst_port.to_be_bytes());
        data.extend_from_slice(&self.length().to_be_bytes());
        data.extend_from_slice(&[0, 0]); // checksum field
        data.extend_from_slice(&self.payload);
        let sum = checksum(&data);
        if sum == 0 {
            0xffff // a transmitted zero means "no checksum"
        } else {
            sum
        }
    }

    pub fn parse(bytes: &[u8], src: Ipv4Addr, dst: Ipv4Addr) -> Result<Self, NetError> {
        if bytes.len() < UDP_HEADER_LEN {
            return Err(NetError::TooShort);
        }
        let src_port = u16::from_be_bytes([bytes[0], bytes[1]]);
        let dst_port = u16::from_be_bytes([bytes[2], bytes[3]]);
        let length = u16::from_be_bytes([bytes[4], bytes[5]]) as usize;
        if length < UDP_HEADER_LEN || length > bytes.len() {
            return Err(NetError::TooShort);
        }
        let stored = u16::from_be_bytes([bytes[6], bytes[7]]);
        if stored != 0 {
            // Verify: recompute over the packet with the checksum
            // field as stored; the one's-complement sum must be 0.
            // Rebuild the pseudo-header + packet and check.
            let mut data = Vec::with_capacity(12 + length);
            data.extend_from_slice(&src.0);
            data.extend_from_slice(&dst.0);
            data.push(0);
            data.push(Protocol::UDP.0);
            data.extend_from_slice(&(length as u16).to_be_bytes());
            data.extend_from_slice(&bytes[..length]);
            if !crate::ipv4::checksum_valid(&data) {
                return Err(NetError::BadChecksum);
            }
        }
        Ok(Self {
            src_port,
            dst_port,
            payload: bytes[UDP_HEADER_LEN..length].to_vec(),
        })
    }

    pub fn to_bytes(&self, src: Ipv4Addr, dst: Ipv4Addr) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.length() as usize);
        out.extend_from_slice(&self.src_port.to_be_bytes());
        out.extend_from_slice(&self.dst_port.to_be_bytes());
        out.extend_from_slice(&self.length().to_be_bytes());
        let sum = self.compute_checksum(src, dst);
        out.extend_from_slice(&sum.to_be_bytes());
        out.extend_from_slice(&self.payload);
        out
    }
}

/// A received datagram, with its endpoints attached.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpDatagram {
    pub src_ip: Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
    pub payload: Vec<u8>,
}

const MAX_SOCKETS: usize = 16;

/// Port dispatch table: bound ports and their receive queues.
/// A datagram for an unbound port is dropped (and the caller may
/// send an ICMP port-unreachable).
pub struct UdpSocketTable {
    sockets: [Option<UdpSocket>; MAX_SOCKETS],
}

pub struct UdpSocket {
    pub port: u16,
    queue: Vec<UdpDatagram>,
}

impl UdpSocket {
    pub fn recv(&mut self) -> Option<UdpDatagram> {
        if self.queue.is_empty() {
            None
        } else {
            Some(self.queue.remove(0))
        }
    }

    pub fn queued(&self) -> usize {
        self.queue.len()
    }
}

impl UdpSocketTable {
    pub fn new() -> Self {
        Self { sockets: Default::default() }
    }

    /// Bind `port`. Fails if it is already bound or the table is full.
    pub fn bind(&mut self, port: u16) -> Result<(), NetError> {
        if self.sockets.iter().any(|s| matches!(s, Some(s) if s.port == port)) {
            return Err(NetError::InvalidState);
        }
        for slot in self.sockets.iter_mut() {
            if slot.is_none() {
                *slot = Some(UdpSocket { port, queue: Vec::new() });
                return Ok(());
            }
        }
        Err(NetError::QueueFull)
    }

    pub fn unbind(&mut self, port: u16) {
        for slot in self.sockets.iter_mut() {
            if matches!(slot, Some(s) if s.port == port) {
                *slot = None;
            }
        }
    }

    pub fn is_bound(&self, port: u16) -> bool {
        self.sockets.iter().any(|s| matches!(s, Some(s) if s.port == port))
    }

    /// Deliver a parsed datagram. Returns `false` (port unreachable)
    /// when no socket is bound to the destination port.
    pub fn deliver(&mut self, datagram: UdpDatagram) -> bool {
        for slot in self.sockets.iter_mut() {
            if let Some(s) = slot {
                if s.port == datagram.dst_port {
                    s.queue.push(datagram);
                    return true;
                }
            }
        }
        false
    }

    pub fn socket_mut(&mut self, port: u16) -> Option<&mut UdpSocket> {
        self.sockets.iter_mut().find_map(|s| match s {
            Some(s) if s.port == port => Some(s),
            _ => None,
        })
    }
}

impl Default for UdpSocketTable {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: Ipv4Addr = Ipv4Addr([10, 0, 0, 1]);
    const B: Ipv4Addr = Ipv4Addr([10, 0, 0, 2]);

    #[test]
    fn udp_roundtrip_with_checksum() {
        let pkt = UdpPacket::new(1234, 53, b"dns?".to_vec());
        let bytes = pkt.to_bytes(A, B);
        let back = UdpPacket::parse(&bytes, A, B).unwrap();
        assert_eq!(back, pkt);
        // Corrupt the payload: checksum must catch it.
        let mut bad = bytes.clone();
        let n = bad.len();
        bad[n - 1] ^= 0xff;
        assert_eq!(UdpPacket::parse(&bad, A, B), Err(NetError::BadChecksum));
        // Wrong endpoints: checksum must catch it too.
        assert_eq!(UdpPacket::parse(&bytes, A, Ipv4Addr([10, 0, 0, 9])), Err(NetError::BadChecksum));
        // Zero checksum (sender opted out) is accepted.
        let mut zero = bytes.clone();
        zero[6] = 0;
        zero[7] = 0;
        assert!(UdpPacket::parse(&zero, A, B).is_ok());
        assert_eq!(UdpPacket::parse(&[0u8; 7], A, B), Err(NetError::TooShort));
    }

    #[test]
    fn socket_table_bind_deliver_recv() {
        let mut table = UdpSocketTable::new();
        assert!(table.bind(53).is_ok());
        assert_eq!(table.bind(53), Err(NetError::InvalidState)); // double bind
        assert!(table.is_bound(53));
        assert!(!table.is_bound(54));
        let d = UdpDatagram { src_ip: B, src_port: 4000, dst_port: 53, payload: b"q".to_vec() };
        assert!(table.deliver(d));
        assert!(!table.deliver(UdpDatagram { src_ip: B, src_port: 4000, dst_port: 9999, payload: vec![] }));
        let sock = table.socket_mut(53).unwrap();
        assert_eq!(sock.queued(), 1);
        let got = sock.recv().unwrap();
        assert_eq!(got.payload, b"q");
        assert_eq!(got.src_ip, B);
        assert!(sock.recv().is_none());
        table.unbind(53);
        assert!(!table.is_bound(53));
    }
}
