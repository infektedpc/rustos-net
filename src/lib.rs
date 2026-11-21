//! rustos-net — networking stack for a Rust OS.
//!
//! * `ethernet` — Ethernet II frames (MAC addresses, EtherType).
//! * `arp` — ARP cache with expiry + pending-packet queue.
//! * `ipv4` — IPv4 headers, one-complement checksum, fragmentation.
//! * `icmp` — ICMP echo (ping) request/reply.
//! * `udp` — UDP headers, pseudo-header checksum, port dispatch.
//! * `tcp` — TCP headers and the connection state machine.
//! * `socket` — `NetworkDevice` trait, `MockDevice`, `TcpSocket`/`UdpSocket`.
//!
//! The crate is `#![no_std]` outside tests so it can link into a kernel.
//! Tests run on the host with std. A NIC driver (e.g. e1000/virtio-net,
//! a future `rustos-nic` crate) feeds raw frames in through
//! `NetworkDevice` and the stack dispatches them by EtherType/protocol.
//! IRQ note: a PCI NIC is typically on PIC IRQ 10/11, i.e. vectors
//! 42/43 after the remap in `rustos-interrupts` (PIC base 32).
#![cfg_attr(not(test), no_std)]

extern crate alloc;

pub mod arp;
pub mod ethernet;
pub mod icmp;
pub mod ipv4;
pub mod socket;
pub mod tcp;
pub mod udp;

pub use ethernet::{EtherType, EthernetFrame, MacAddr};
pub use ipv4::{Ipv4Addr, Ipv4Packet, Protocol};

/// Errors returned by the stack. Negative values are the errno a
/// syscall layer would return (`-ENOSYS` style, cf. rustos-process).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetError {
    /// Frame/packet shorter than its header.
    TooShort,
    /// Checksum did not verify.
    BadChecksum,
    /// EtherType / protocol / version not supported.
    Unsupported,
    /// No route / no ARP entry for the destination.
    NoRoute,
    /// Destination port has no listener/socket.
    PortUnreachable,
    /// The operation is not valid in the current TCP state.
    InvalidState,
    /// The device's transmit queue is full.
    QueueFull,
    /// A buffer supplied by the caller was too small.
    BufferTooSmall,
}

impl core::fmt::Display for NetError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let s = match self {
            NetError::TooShort => "packet too short",
            NetError::BadChecksum => "bad checksum",
            NetError::Unsupported => "unsupported protocol",
            NetError::NoRoute => "no route to host",
            NetError::PortUnreachable => "port unreachable",
            NetError::InvalidState => "invalid state",
            NetError::QueueFull => "transmit queue full",
            NetError::BufferTooSmall => "buffer too small",
        };
        f.write_str(s)
    }
}
