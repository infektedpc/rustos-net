//! ICMP (RFC 792): echo request/reply (ping) and error messages.
//!
//! Message layout: type (1) | code (1) | checksum (2) |
//! identifier (2) | sequence (2) | payload...

use alloc::vec::Vec;
use crate::ipv4::checksum;
use crate::NetError;

pub const ICMP_ECHO_REPLY: u8 = 0;
pub const ICMP_DEST_UNREACHABLE: u8 = 3;
pub const ICMP_ECHO_REQUEST: u8 = 8;
pub const ICMP_TIME_EXCEEDED: u8 = 11;

/// An ICMP message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IcmpPacket {
    pub icmp_type: u8,
    pub code: u8,
    pub identifier: u16,
    pub sequence: u16,
    pub payload: Vec<u8>,
}

impl IcmpPacket {
    pub fn echo_request(identifier: u16, sequence: u16, payload: Vec<u8>) -> Self {
        Self { icmp_type: ICMP_ECHO_REQUEST, code: 0, identifier, sequence, payload }
    }

    pub fn echo_reply(identifier: u16, sequence: u16, payload: Vec<u8>) -> Self {
        Self { icmp_type: ICMP_ECHO_REPLY, code: 0, identifier, sequence, payload }
    }

    pub fn is_echo_request(&self) -> bool {
        self.icmp_type == ICMP_ECHO_REQUEST
    }

    pub fn is_echo_reply(&self) -> bool {
        self.icmp_type == ICMP_ECHO_REPLY
    }

    /// Build the reply to an echo request (same id/seq/payload).
    pub fn make_echo_reply(&self) -> Option<Self> {
        if !self.is_echo_request() {
            return None;
        }
        Some(Self::echo_reply(self.identifier, self.sequence, self.payload.clone()))
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, NetError> {
        if bytes.len() < 8 {
            return Err(NetError::TooShort);
        }
        if !crate::ipv4::checksum_valid(bytes) {
            return Err(NetError::BadChecksum);
        }
        Ok(Self {
            icmp_type: bytes[0],
            code: bytes[1],
            identifier: u16::from_be_bytes([bytes[4], bytes[5]]),
            sequence: u16::from_be_bytes([bytes[6], bytes[7]]),
            payload: bytes[8..].to_vec(),
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + self.payload.len());
        out.push(self.icmp_type);
        out.push(self.code);
        out.extend_from_slice(&[0, 0]); // checksum placeholder
        out.extend_from_slice(&self.identifier.to_be_bytes());
        out.extend_from_slice(&self.sequence.to_be_bytes());
        out.extend_from_slice(&self.payload);
        let sum = checksum(&out);
        out[2..4].copy_from_slice(&sum.to_be_bytes());
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn echo_roundtrip() {
        let req = IcmpPacket::echo_request(0x1234, 7, b"ping-data".to_vec());
        let bytes = req.to_bytes();
        let back = IcmpPacket::parse(&bytes).unwrap();
        assert_eq!(back, req);
        assert!(back.is_echo_request());
    }

    #[test]
    fn reply_mirrors_request() {
        let req = IcmpPacket::echo_request(42, 3, b"abc".to_vec());
        let reply = req.make_echo_reply().unwrap();
        assert!(reply.is_echo_reply());
        assert_eq!(reply.identifier, 42);
        assert_eq!(reply.sequence, 3);
        assert_eq!(reply.payload, b"abc");
        // A reply is not itself a request.
        assert!(reply.make_echo_reply().is_none());
        // Reply bytes also verify.
        assert!(IcmpPacket::parse(&reply.to_bytes()).is_ok());
    }

    #[test]
    fn bad_checksum_rejected() {
        let req = IcmpPacket::echo_request(1, 1, b"hello".to_vec());
        let mut bytes = req.to_bytes();
        bytes[8] ^= 0xff;
        assert_eq!(IcmpPacket::parse(&bytes), Err(NetError::BadChecksum));
        assert_eq!(IcmpPacket::parse(&[0u8; 7]), Err(NetError::TooShort));
    }
}
