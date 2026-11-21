//! Socket API over a `NetworkDevice`.
//!
//! The kernel's NIC driver implements `NetworkDevice` (send a raw
//! Ethernet frame, poll for received frames); the stack above it is
//! device-independent, so host tests use `MockDevice`, which records
//! transmitted frames and plays back queued ones.

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use crate::arp::ArpCache;
use crate::ethernet::{EtherType, EthernetFrame, MacAddr};
use crate::ipv4::{Ipv4Addr, Ipv4Header, Ipv4Packet, Protocol};
use crate::tcp::{TcpConnection, TcpSegment};
use crate::udp::{UdpDatagram, UdpPacket, UdpSocketTable};
use crate::NetError;

/// A network interface: raw Ethernet frames in and out.
/// Implemented by a NIC driver (e.g. e1000, virtio-net); the
/// kernel polls `receive` from the NIC's IRQ handler.
pub trait NetworkDevice {
    /// Transmit one raw Ethernet frame.
    fn send(&mut self, frame: &[u8]) -> Result<(), NetError>;
    /// Poll for one received frame, if any.
    fn receive(&mut self) -> Option<Vec<u8>>;
    /// This interface's MAC address.
    fn mac(&self) -> MacAddr;
    /// This interface's IPv4 address.
    fn ip(&self) -> Ipv4Addr;
    /// MTU in bytes (usually 1500).
    fn mtu(&self) -> usize {
        1500
    }
}

/// In-memory device for host tests: records what was sent and
/// plays back frames queued with `inject`.
pub struct MockDevice {
    mac: MacAddr,
    ip: Ipv4Addr,
    pub sent: Vec<Vec<u8>>,
    incoming: VecDeque<Vec<u8>>,
}

impl MockDevice {
    pub fn new(mac: MacAddr, ip: Ipv4Addr) -> Self {
        Self { mac, ip, sent: Vec::new(), incoming: VecDeque::new() }
    }

    /// Queue a frame for `receive` to return.
    pub fn inject(&mut self, frame: Vec<u8>) {
        self.incoming.push_back(frame);
    }

    pub fn sent_count(&self) -> usize {
        self.sent.len()
    }

    pub fn last_sent(&self) -> Option<&[u8]> {
        self.sent.last().map(|v| v.as_slice())
    }
}

impl NetworkDevice for MockDevice {
    fn send(&mut self, frame: &[u8]) -> Result<(), NetError> {
        self.sent.push(frame.to_vec());
        Ok(())
    }

    fn receive(&mut self) -> Option<Vec<u8>> {
        self.incoming.pop_front()
    }

    fn mac(&self) -> MacAddr {
        self.mac
    }

    fn ip(&self) -> Ipv4Addr {
        self.ip
    }
}

/// A UDP socket bound to a local port, sending through a device.
/// Address resolution is the caller's job for now (see `ArpCache`):
/// `send_to` takes the destination MAC directly.
pub struct UdpSocket {
    local_port: u16,
    table: UdpSocketTable,
}

impl UdpSocket {
    pub fn new(local_port: u16) -> Self {
        let mut table = UdpSocketTable::new();
        // Binding in the constructor cannot fail for a fresh table.
        let _ = table.bind(local_port);
        Self { local_port, table }
    }

    pub fn local_port(&self) -> u16 {
        self.local_port
    }

    /// Build + transmit a UDP datagram to `dst_ip`/`dst_port`
    /// via `dst_mac`, through `device`.
    pub fn send_to(
        &self,
        device: &mut dyn NetworkDevice,
        dst_mac: MacAddr,
        dst_ip: Ipv4Addr,
        dst_port: u16,
        payload: &[u8],
    ) -> Result<(), NetError> {
        let udp = UdpPacket::new(self.local_port, dst_port, payload.to_vec());
        let udp_bytes = udp.to_bytes(device.ip(), dst_ip);
        let header = Ipv4Header::new(device.ip(), dst_ip, Protocol::UDP, udp_bytes.len());
        let packet = Ipv4Packet::new(header, udp_bytes);
        let frame = EthernetFrame::new(dst_mac, device.mac(), EtherType::IPV4, packet.to_bytes());
        device.send(&frame.to_bytes())
    }

    /// Poll the device once and dispatch any UDP datagram for us.
    /// Returns `true` if a datagram was queued for this socket.
    pub fn poll(&mut self, device: &mut dyn NetworkDevice) -> bool {
        let Some(bytes) = device.receive() else {
            return false;
        };
        let Ok(frame) = EthernetFrame::parse(&bytes) else {
            return false;
        };
        if frame.ethertype != EtherType::IPV4 {
            return false;
        }
        let Ok(packet) = Ipv4Packet::parse(&frame.payload) else {
            return false;
        };
        if packet.protocol() != Protocol::UDP {
            return false;
        }
        let Ok(udp) = UdpPacket::parse(&packet.payload, packet.header.src, packet.header.dst) else {
            return false;
        };
        if udp.dst_port != self.local_port {
            return false;
        }
        self.table.deliver(UdpDatagram {
            src_ip: packet.header.src,
            src_port: udp.src_port,
            dst_port: udp.dst_port,
            payload: udp.payload,
        })
    }

    pub fn recv(&mut self) -> Option<UdpDatagram> {
        self.table.socket_mut(self.local_port)?.recv()
    }
}

/// A TCP socket: one `TcpConnection` over a device, with an ARP
/// cache for resolving the peer's MAC address.
pub struct TcpSocket {
    conn: TcpConnection,
    arp: ArpCache,
}

impl TcpSocket {
    pub fn new(local_ip: Ipv4Addr, local_port: u16) -> Self {
        Self {
            conn: TcpConnection::new(local_ip, local_port),
            arp: ArpCache::new(),
        }
    }

    pub fn state(&self) -> crate::tcp::TcpState {
        self.conn.state
    }

    /// Learn a peer MAC (e.g. from an ARP reply) so `connect` can
    /// transmit without an ARP request round-trip.
    pub fn learn_arp(&mut self, ip: Ipv4Addr, mac: MacAddr) {
        self.arp.insert(ip, mac);
    }

    fn transmit(&mut self, device: &mut dyn NetworkDevice, seg: &TcpSegment) -> Result<(), NetError> {
        let mac = self.arp.lookup(self.conn.remote_ip).ok_or(NetError::NoRoute)?;
        let tcp_bytes = seg.to_bytes(device.ip(), self.conn.remote_ip);
        let header = Ipv4Header::new(device.ip(), self.conn.remote_ip, Protocol::TCP, tcp_bytes.len());
        let packet = Ipv4Packet::new(header, tcp_bytes);
        let frame = EthernetFrame::new(mac, device.mac(), EtherType::IPV4, packet.to_bytes());
        device.send(&frame.to_bytes())
    }

    /// Active open. Returns `Err(NoRoute)` when the peer MAC is
    /// unknown — the kernel should ARP for it first, then retry.
    pub fn connect(
        &mut self,
        device: &mut dyn NetworkDevice,
        remote_ip: Ipv4Addr,
        remote_port: u16,
        iss: u32,
    ) -> Result<(), NetError> {
        let syn = self.conn.connect(remote_ip, remote_port, iss);
        self.transmit(device, &syn)
    }

    /// Poll the device once, dispatching a TCP segment for this
    /// connection. Returns the actions the connection produced.
    pub fn poll(&mut self, device: &mut dyn NetworkDevice) -> Vec<crate::tcp::TcpAction> {
        let Some(bytes) = device.receive() else {
            return Vec::new();
        };
        let Ok(frame) = EthernetFrame::parse(&bytes) else {
            return Vec::new();
        };
        if frame.ethertype != EtherType::IPV4 {
            return Vec::new();
        }
        let Ok(packet) = Ipv4Packet::parse(&frame.payload) else {
            return Vec::new();
        };
        if packet.protocol() != Protocol::TCP {
            return Vec::new();
        }
        let Ok(seg) = TcpSegment::parse(&packet.payload, packet.header.src, packet.header.dst) else {
            return Vec::new();
        };
        if seg.dst_port != self.conn.local_port {
            return Vec::new();
        }
        let actions = self.conn.on_segment(&seg);
        // Transmit any reply segments the state machine produced.
        let mut replies = Vec::new();
        for action in &actions {
            if let crate::tcp::TcpAction::Send(s) = action {
                replies.push(s.clone());
            }
        }
        for reply in replies {
            let _ = self.transmit(device, &reply);
        }
        actions
    }

    pub fn send_data(&mut self, device: &mut dyn NetworkDevice, data: Vec<u8>) -> Result<(), NetError> {
        let seg = self.conn.send_data(data)?;
        self.transmit(device, &seg)
    }

    pub fn read(&mut self, out: &mut [u8]) -> usize {
        self.conn.read(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::icmp::IcmpPacket;
    use crate::tcp::TcpAction;

    const ME_MAC: MacAddr = MacAddr([0x52, 0x54, 0x00, 0x12, 0x34, 0x56]);
    const PEER_MAC: MacAddr = MacAddr([0x52, 0x54, 0x00, 0x65, 0x43, 0x21]);
    const ME_IP: Ipv4Addr = Ipv4Addr([10, 0, 0, 1]);
    const PEER_IP: Ipv4Addr = Ipv4Addr([10, 0, 0, 2]);

    fn ip_frame(src_mac: MacAddr, dst_mac: MacAddr, src_ip: Ipv4Addr, dst_ip: Ipv4Addr, proto: Protocol, payload: Vec<u8>) -> Vec<u8> {
        let header = Ipv4Header::new(src_ip, dst_ip, proto, payload.len());
        let packet = Ipv4Packet::new(header, payload);
        EthernetFrame::new(dst_mac, src_mac, EtherType::IPV4, packet.to_bytes()).to_bytes()
    }

    #[test]
    fn udp_socket_roundtrip_via_mock_device() {
        let mut dev_a = MockDevice::new(ME_MAC, ME_IP);
        let mut dev_b = MockDevice::new(PEER_MAC, PEER_IP);
        let sock_a = UdpSocket::new(4000);
        let mut sock_b = UdpSocket::new(53);
        sock_a.send_to(&mut dev_a, PEER_MAC, PEER_IP, 53, b"query").unwrap();
        assert_eq!(dev_a.sent_count(), 1);
        // Deliver A's frame to B's device.
        let frame = dev_a.sent[0].clone();
        dev_b.inject(frame);
        assert!(sock_b.poll(&mut dev_b));
        let d = sock_b.recv().unwrap();
        assert_eq!(d.payload, b"query");
        assert_eq!(d.src_ip, ME_IP);
        assert_eq!(d.src_port, 4000);
        // A frame for a different port is ignored.
        let frame = ip_frame(ME_MAC, PEER_MAC, ME_IP, PEER_IP, Protocol::UDP, {
            let udp = UdpPacket::new(4000, 9999, b"x".to_vec());
            udp.to_bytes(ME_IP, PEER_IP)
        });
        dev_b.inject(frame);
        assert!(!sock_b.poll(&mut dev_b));
    }

    #[test]
    fn tcp_socket_handshake_via_mock_devices() {
        let mut dev_client = MockDevice::new(ME_MAC, ME_IP);
        let mut client = TcpSocket::new(ME_IP, 40000);
        client.learn_arp(PEER_IP, PEER_MAC);
        let mut server_conn = TcpConnection::new(PEER_IP, 80);
        server_conn.listen(80);
        // Client SYN -> server device.
        client.connect(&mut dev_client, PEER_IP, 80, 5000).unwrap();
        assert_eq!(dev_client.sent_count(), 1);
        let syn_bytes = dev_client.sent[0].clone();
        // Server parses the SYN and replies SYN-ACK; deliver it back.
        let frame = EthernetFrame::parse(&syn_bytes).unwrap();
        let packet = Ipv4Packet::parse(&frame.payload).unwrap();
        let syn = TcpSegment::parse(&packet.payload, ME_IP, PEER_IP).unwrap();
        let actions = server_conn.on_segment(&syn);
        let syn_ack = match &actions[0] {
            TcpAction::Send(s) => s.clone(),
            _ => panic!("expected SYN-ACK"),
        };
        let syn_ack_bytes = ip_frame(PEER_MAC, ME_MAC, PEER_IP, ME_IP, Protocol::TCP, syn_ack.to_bytes(PEER_IP, ME_IP));
        dev_client.inject(syn_ack_bytes);
        let actions = client.poll(&mut dev_client);
        assert_eq!(client.state(), crate::tcp::TcpState::Established);
        assert!(actions.iter().any(|a| matches!(a, TcpAction::Connected)));
        // Client's ACK was transmitted back.
        assert_eq!(dev_client.sent_count(), 2);
    }

    #[test]
    fn tcp_socket_connect_without_arp_fails() {
        let mut dev = MockDevice::new(ME_MAC, ME_IP);
        let mut client = TcpSocket::new(ME_IP, 40000);
        assert_eq!(client.connect(&mut dev, PEER_IP, 80, 1), Err(NetError::NoRoute));
        assert_eq!(dev.sent_count(), 0);
    }

    #[test]
    fn icmp_echo_flows_through_ethernet_and_ip() {
        // Full-stack shape: ICMP echo inside IPv4 inside Ethernet.
        let icmp = IcmpPacket::echo_request(7, 1, b"ping".to_vec());
        let frame = ip_frame(ME_MAC, PEER_MAC, ME_IP, PEER_IP, Protocol::ICMP, icmp.to_bytes());
        let eth = EthernetFrame::parse(&frame).unwrap();
        assert_eq!(eth.ethertype, EtherType::IPV4);
        let packet = Ipv4Packet::parse(&eth.payload).unwrap();
        assert_eq!(packet.protocol(), Protocol::ICMP);
        let req = IcmpPacket::parse(&packet.payload).unwrap();
        let reply = req.make_echo_reply().unwrap();
        assert_eq!(reply.payload, b"ping");
    }
}
