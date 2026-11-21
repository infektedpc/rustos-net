//! Ethernet II frames.
//!
//! Layout: dst MAC (6) | src MAC (6) | EtherType (2, big-endian) |
//! payload (46–1500 bytes on the wire; this crate accepts shorter
//! payloads from tests/mocks and pads on `build` only if asked).

use alloc::vec::Vec;
use core::fmt;
use crate::NetError;

/// A 48-bit MAC address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct MacAddr(pub [u8; 6]);

impl MacAddr {
    pub const BROADCAST: MacAddr = MacAddr([0xff; 6]);
    pub const ZERO: MacAddr = MacAddr([0; 6]);

    pub const fn new(bytes: [u8; 6]) -> Self {
        Self(bytes)
    }

    /// Broadcast: all bits set.
    pub fn is_broadcast(&self) -> bool {
        self.0 == [0xff; 6]
    }

    /// Multicast: least-significant bit of the first octet set.
    /// (Broadcast is also multicast by this bit, callers usually
    /// check `is_broadcast` first.)
    pub fn is_multicast(&self) -> bool {
        self.0[0] & 0x01 != 0
    }

    pub fn is_unicast(&self) -> bool {
        !self.is_multicast()
    }
}

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}

/// EtherType values (big-endian on the wire).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EtherType(pub u16);

impl EtherType {
    pub const IPV4: EtherType = EtherType(0x0800);
    pub const ARP: EtherType = EtherType(0x0806);
    pub const IPV6: EtherType = EtherType(0x86dd);
    pub const VLAN: EtherType = EtherType(0x8100);
}

pub const ETH_HEADER_LEN: usize = 14;
/// Minimum Ethernet payload (frames are padded to 64 bytes on the wire).
pub const ETH_MIN_PAYLOAD: usize = 46;
pub const ETH_MAX_PAYLOAD: usize = 1500;

/// An Ethernet II frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EthernetFrame {
    pub dst: MacAddr,
    pub src: MacAddr,
    pub ethertype: EtherType,
    pub payload: Vec<u8>,
}

impl EthernetFrame {
    pub fn new(dst: MacAddr, src: MacAddr, ethertype: EtherType, payload: Vec<u8>) -> Self {
        Self { dst, src, ethertype, payload }
    }

    /// Parse a frame from wire bytes. Accepts payloads shorter than
    /// 46 bytes (mocks/tests); rejects anything under 14 bytes.
    pub fn parse(bytes: &[u8]) -> Result<Self, NetError> {
        if bytes.len() < ETH_HEADER_LEN {
            return Err(NetError::TooShort);
        }
        let dst = MacAddr(bytes[0..6].try_into().unwrap());
        let src = MacAddr(bytes[6..12].try_into().unwrap());
        let ethertype = EtherType(u16::from_be_bytes([bytes[12], bytes[13]]));
        Ok(Self {
            dst,
            src,
            ethertype,
            payload: bytes[ETH_HEADER_LEN..].to_vec(),
        })
    }

    /// Serialize to wire bytes (no padding added).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(ETH_HEADER_LEN + self.payload.len());
        out.extend_from_slice(&self.dst.0);
        out.extend_from_slice(&self.src.0);
        out.extend_from_slice(&self.ethertype.0.to_be_bytes());
        out.extend_from_slice(&self.payload);
        out
    }

    /// Serialize, padding the payload to the 46-byte Ethernet minimum
    /// (so the frame is >= 64 bytes on the wire).
    pub fn to_bytes_padded(&self) -> Vec<u8> {
        let mut out = self.to_bytes();
        while out.len() < ETH_HEADER_LEN + ETH_MIN_PAYLOAD {
            out.push(0);
        }
        out
    }

    pub fn is_broadcast(&self) -> bool {
        self.dst.is_broadcast()
    }

    pub fn is_for(&self, mac: MacAddr) -> bool {
        self.dst == mac || self.dst.is_broadcast() || self.dst.is_multicast()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mac_broadcast_multicast_unicast() {
        assert!(MacAddr::BROADCAST.is_broadcast());
        assert!(MacAddr::BROADCAST.is_multicast());
        assert!(!MacAddr::ZERO.is_broadcast());
        assert!(!MacAddr::ZERO.is_multicast());
        assert!(MacAddr::ZERO.is_unicast());
        let mcast = MacAddr::new([0x01, 0x00, 0x5e, 0x00, 0x00, 0xfb]);
        assert!(mcast.is_multicast());
        assert!(!mcast.is_broadcast());
        assert_eq!(alloc::format!("{}", MacAddr::new([0x52, 0x54, 0x00, 0x12, 0x34, 0x56])), "52:54:00:12:34:56");
    }

    #[test]
    fn parse_and_build_roundtrip() {
        let frame = EthernetFrame::new(
            MacAddr::BROADCAST,
            MacAddr::new([0x52, 0x54, 0x00, 0x12, 0x34, 0x56]),
            EtherType::IPV4,
            b"hello".to_vec(),
        );
        let bytes = frame.to_bytes();
        assert_eq!(bytes.len(), 19);
        let back = EthernetFrame::parse(&bytes).unwrap();
        assert_eq!(back, frame);
        assert!(back.is_broadcast());
        assert!(back.is_for(MacAddr::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])));
    }

    #[test]
    fn parse_rejects_short_frames() {
        assert_eq!(EthernetFrame::parse(&[0u8; 13]), Err(NetError::TooShort));
        assert_eq!(EthernetFrame::parse(&[]), Err(NetError::TooShort));
        // Exactly a header, empty payload: valid.
        assert!(EthernetFrame::parse(&[0u8; 14]).is_ok());
    }

    #[test]
    fn padded_frame_is_at_least_64_bytes() {
        let frame = EthernetFrame::new(
            MacAddr::BROADCAST,
            MacAddr::ZERO,
            EtherType::ARP,
            b"x".to_vec(),
        );
        assert_eq!(frame.to_bytes_padded().len(), 60);
        let big = EthernetFrame::new(MacAddr::ZERO, MacAddr::ZERO, EtherType::IPV4, vec![0u8; 100]);
        assert_eq!(big.to_bytes_padded().len(), 114);
    }
}
