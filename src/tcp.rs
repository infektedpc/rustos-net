//! TCP (RFC 793): headers, options, and the connection state machine.
//!
//! Header layout (20 bytes minimum): src port | dst port |
//! sequence | acknowledgement | data offset/reserved/flags |
//! window | checksum | urgent pointer | options...
//!
//! This is a *state machine*, not a full stack: no congestion
//! control, no SACK, no window scaling, no selective ACK. It does
//! the handshake, data transfer with sequence tracking, FIN close,
//! RST handling, and retransmission on timeout (the caller drives
//! `on_tick` from the timer, e.g. every 100 ms).

use alloc::vec::Vec;
use crate::ipv4::{checksum, Ipv4Addr, Protocol};
use crate::NetError;

pub const TCP_HEADER_LEN: usize = 20;
/// Retransmission timeout, milliseconds. The caller ticks in ms.
pub const TCP_RTO_MS: u32 = 1000;
pub const TCP_MAX_RETRANSMITS: u32 = 5;

/// TCP flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TcpFlags {
    pub fin: bool,
    pub syn: bool,
    pub rst: bool,
    pub psh: bool,
    pub ack: bool,
    pub urg: bool,
}

impl TcpFlags {
    pub const SYN: TcpFlags = TcpFlags { fin: false, syn: true, rst: false, psh: false, ack: false, urg: false };
    pub const SYN_ACK: TcpFlags = TcpFlags { fin: false, syn: true, rst: false, psh: false, ack: true, urg: false };
    pub const ACK: TcpFlags = TcpFlags { fin: false, syn: false, rst: false, psh: false, ack: true, urg: false };
    pub const FIN_ACK: TcpFlags = TcpFlags { fin: true, syn: false, rst: false, psh: false, ack: true, urg: false };
    pub const RST: TcpFlags = TcpFlags { fin: false, syn: false, rst: true, psh: false, ack: false, urg: false };
    pub const PSH_ACK: TcpFlags = TcpFlags { fin: false, syn: false, rst: false, psh: true, ack: true, urg: false };

    fn from_byte(b: u8) -> Self {
        Self {
            fin: b & 0x01 != 0,
            syn: b & 0x02 != 0,
            rst: b & 0x04 != 0,
            psh: b & 0x08 != 0,
            ack: b & 0x10 != 0,
            urg: b & 0x20 != 0,
        }
    }

    fn to_byte(&self) -> u8 {
        (self.fin as u8)
            | ((self.syn as u8) << 1)
            | ((self.rst as u8) << 2)
            | ((self.psh as u8) << 3)
            | ((self.ack as u8) << 4)
            | ((self.urg as u8) << 5)
    }
}

/// Connection states (RFC 793).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpState {
    Closed,
    Listen,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
}

/// A TCP segment: header + payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpSegment {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: TcpFlags,
    pub window: u16,
    pub payload: Vec<u8>,
}

impl TcpSegment {
    pub fn new(src_port: u16, dst_port: u16, seq: u32, ack: u32, flags: TcpFlags, payload: Vec<u8>) -> Self {
        Self { src_port, dst_port, seq, ack, flags, window: 65535, payload }
    }

    /// Sequence number of the first byte after this segment
    /// (SYN and FIN each consume one sequence number).
    pub fn next_seq(&self) -> u32 {
        self.seq
            .wrapping_add(self.payload.len() as u32)
            .wrapping_add(self.flags.syn as u32)
            .wrapping_add(self.flags.fin as u32)
    }

    pub fn compute_checksum(&self, src: Ipv4Addr, dst: Ipv4Addr) -> u16 {
        let len = (TCP_HEADER_LEN + self.payload.len()) as u16;
        let mut data = Vec::with_capacity(12 + len as usize);
        data.extend_from_slice(&src.0);
        data.extend_from_slice(&dst.0);
        data.push(0);
        data.push(Protocol::TCP.0);
        data.extend_from_slice(&len.to_be_bytes());
        data.extend_from_slice(&self.src_port.to_be_bytes());
        data.extend_from_slice(&self.dst_port.to_be_bytes());
        data.extend_from_slice(&self.seq.to_be_bytes());
        data.extend_from_slice(&self.ack.to_be_bytes());
        data.push((TCP_HEADER_LEN / 4) as u8 * 16);
        data.push(self.flags.to_byte());
        data.extend_from_slice(&self.window.to_be_bytes());
        data.extend_from_slice(&[0, 0]); // checksum
        data.extend_from_slice(&[0, 0]); // urgent pointer
        data.extend_from_slice(&self.payload);
        checksum(&data)
    }

    pub fn parse(bytes: &[u8], src: Ipv4Addr, dst: Ipv4Addr) -> Result<Self, NetError> {
        if bytes.len() < TCP_HEADER_LEN {
            return Err(NetError::TooShort);
        }
        let data_offset = ((bytes[12] >> 4) as usize) * 4;
        if data_offset < TCP_HEADER_LEN || bytes.len() < data_offset {
            return Err(NetError::TooShort);
        }
        let stored = u16::from_be_bytes([bytes[16], bytes[17]]);
        if stored != 0 {
            let len = bytes.len() as u16;
            let mut data = Vec::with_capacity(12 + bytes.len());
            data.extend_from_slice(&src.0);
            data.extend_from_slice(&dst.0);
            data.push(0);
            data.push(Protocol::TCP.0);
            data.extend_from_slice(&len.to_be_bytes());
            data.extend_from_slice(bytes);
            if !crate::ipv4::checksum_valid(&data) {
                return Err(NetError::BadChecksum);
            }
        }
        Ok(Self {
            src_port: u16::from_be_bytes([bytes[0], bytes[1]]),
            dst_port: u16::from_be_bytes([bytes[2], bytes[3]]),
            seq: u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
            ack: u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]),
            flags: TcpFlags::from_byte(bytes[13]),
            window: u16::from_be_bytes([bytes[14], bytes[15]]),
            payload: bytes[data_offset..].to_vec(),
        })
    }

    pub fn to_bytes(&self, src: Ipv4Addr, dst: Ipv4Addr) -> Vec<u8> {
        let mut out = Vec::with_capacity(TCP_HEADER_LEN + self.payload.len());
        out.extend_from_slice(&self.src_port.to_be_bytes());
        out.extend_from_slice(&self.dst_port.to_be_bytes());
        out.extend_from_slice(&self.seq.to_be_bytes());
        out.extend_from_slice(&self.ack.to_be_bytes());
        out.push((TCP_HEADER_LEN / 4) as u8 * 16);
        out.push(self.flags.to_byte());
        out.extend_from_slice(&self.window.to_be_bytes());
        let sum = self.compute_checksum(src, dst);
        out.extend_from_slice(&sum.to_be_bytes());
        out.extend_from_slice(&[0, 0]); // urgent pointer
        out.extend_from_slice(&self.payload);
        out
    }
}

/// What `on_segment` produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TcpAction {
    /// Send this segment in reply.
    Send(TcpSegment),
    /// Payload bytes delivered to the application.
    Data(Vec<u8>),
    /// The connection reached Established.
    Connected,
    /// The connection closed (FIN/RST, or peer closed).
    Closed,
    /// Segment was a duplicate / out of order: ignored.
    Ignored,
}

/// One TCP connection.
pub struct TcpConnection {
    pub state: TcpState,
    pub local_port: u16,
    pub remote_port: u16,
    pub local_ip: Ipv4Addr,
    pub remote_ip: Ipv4Addr,
    /// Our initial sequence number.
    iss: u32,
    /// Next sequence number we will send.
    snd_nxt: u32,
    /// Oldest unacknowledged sequence number.
    snd_una: u32,
    /// Next sequence number we expect from the peer.
    rcv_nxt: u32,
    /// Last segment sent (for retransmission), if any.
    last_sent: Option<TcpSegment>,
    /// Milliseconds since the last segment was sent.
    since_send_ms: u32,
    retransmits: u32,
    /// Bytes received and not yet read by the application.
    recv_buffer: Vec<u8>,
}

impl TcpConnection {
    pub fn new(local_ip: Ipv4Addr, local_port: u16) -> Self {
        Self {
            state: TcpState::Closed,
            local_port,
            remote_port: 0,
            local_ip,
            remote_ip: Ipv4Addr::UNSPECIFIED,
            iss: 0,
            snd_nxt: 0,
            snd_una: 0,
            rcv_nxt: 0,
            last_sent: None,
            since_send_ms: 0,
            retransmits: 0,
            recv_buffer: Vec::new(),
        }
    }

    /// Passive open: wait for a SYN.
    pub fn listen(&mut self, local_port: u16) {
        self.local_port = local_port;
        self.state = TcpState::Listen;
    }

    /// Active open: send a SYN. Returns the SYN segment to transmit.
    /// `iss` is the caller's initial sequence number (tests use a
    /// fixed value; a kernel would randomise it).
    pub fn connect(&mut self, remote_ip: Ipv4Addr, remote_port: u16, iss: u32) -> TcpSegment {
        self.remote_ip = remote_ip;
        self.remote_port = remote_port;
        self.iss = iss;
        self.snd_nxt = iss;
        self.snd_una = iss;
        self.state = TcpState::SynSent;
        self.send_segment(TcpFlags::SYN, Vec::new())
    }

    fn send_segment(&mut self, flags: TcpFlags, payload: Vec<u8>) -> TcpSegment {
        let seg = TcpSegment::new(
            self.local_port,
            self.remote_port,
            self.snd_nxt,
            self.rcv_nxt,
            flags,
            payload,
        );
        self.snd_nxt = seg.next_seq();
        self.snd_una = self.snd_una.min(self.snd_nxt);
        self.last_sent = Some(seg.clone());
        self.since_send_ms = 0;
        seg
    }

    /// Send application data. Only valid in Established.
    pub fn send_data(&mut self, data: Vec<u8>) -> Result<TcpSegment, NetError> {
        if self.state != TcpState::Established {
            return Err(NetError::InvalidState);
        }
        Ok(self.send_segment(TcpFlags::PSH_ACK, data))
    }

    /// Graceful close: send FIN.
    pub fn close(&mut self) -> Result<TcpSegment, NetError> {
        match self.state {
            TcpState::Established => {
                self.state = TcpState::FinWait1;
                Ok(self.send_segment(TcpFlags::FIN_ACK, Vec::new()))
            }
            TcpState::CloseWait => {
                self.state = TcpState::LastAck;
                Ok(self.send_segment(TcpFlags::FIN_ACK, Vec::new()))
            }
            _ => Err(NetError::InvalidState),
        }
    }

    /// Application reads buffered data.
    pub fn read(&mut self, out: &mut [u8]) -> usize {
        let n = out.len().min(self.recv_buffer.len());
        out[..n].copy_from_slice(&self.recv_buffer[..n]);
        self.recv_buffer.drain(..n);
        n
    }

    pub fn buffered(&self) -> usize {
        self.recv_buffer.len()
    }

    /// Drive the retransmission timer. Call with elapsed ms.
    /// Returns a segment to retransmit, or `None`. After
    /// `TCP_MAX_RETRANSMITS` unanswered retransmits the connection
    /// is reset to Closed.
    pub fn on_tick(&mut self, elapsed_ms: u32) -> Option<TcpSegment> {
        if self.last_sent.is_none() || self.state == TcpState::Closed || self.state == TcpState::Listen {
            return None;
        }
        // In Established with everything acked there is nothing to
        // retransmit: snd_una == snd_nxt.
        if self.snd_una == self.snd_nxt && self.state == TcpState::Established {
            return None;
        }
        self.since_send_ms += elapsed_ms;
        if self.since_send_ms >= TCP_RTO_MS {
            self.since_send_ms = 0;
            self.retransmits += 1;
            if self.retransmits > TCP_MAX_RETRANSMITS {
                self.state = TcpState::Closed;
                self.last_sent = None;
                return None;
            }
            return self.last_sent.clone();
        }
        None
    }

    /// Handle an incoming segment. Returns the actions to take.
    pub fn on_segment(&mut self, seg: &TcpSegment) -> Vec<TcpAction> {
        let mut actions = Vec::new();
        if seg.flags.rst {
            self.state = TcpState::Closed;
            self.last_sent = None;
            actions.push(TcpAction::Closed);
            return actions;
        }
        match self.state {
            TcpState::Listen => {
                if seg.flags.syn {
                    // The peer IP is set by the caller (from the IP
                    // header) before `on_segment` is called.
                    self.remote_port = seg.src_port;
                    self.rcv_nxt = seg.seq.wrapping_add(1);
                    self.iss = 1000; // server ISN; a kernel would randomise
                    self.snd_nxt = self.iss;
                    self.snd_una = self.iss;
                    self.state = TcpState::SynReceived;
                    actions.push(TcpAction::Send(self.send_segment(TcpFlags::SYN_ACK, Vec::new())));
                }
            }
            TcpState::SynSent => {
                if seg.flags.syn && seg.flags.ack {
                    if seg.ack != self.snd_nxt {
                        return actions; // ACK for a seq we never sent
                    }
                    self.snd_una = seg.ack;
                    self.rcv_nxt = seg.seq.wrapping_add(1);
                    self.state = TcpState::Established;
                    self.last_sent = None;
                    actions.push(TcpAction::Send(self.send_segment(TcpFlags::ACK, Vec::new())));
                    actions.push(TcpAction::Connected);
                }
            }
            TcpState::SynReceived => {
                if seg.flags.ack && seg.ack == self.snd_nxt {
                    self.snd_una = seg.ack;
                    self.state = TcpState::Established;
                    self.last_sent = None;
                    actions.push(TcpAction::Connected);
                }
            }
            TcpState::Established | TcpState::FinWait1 | TcpState::FinWait2 | TcpState::CloseWait => {
                if seg.flags.ack {
                    // Advance snd_una, but never past snd_nxt.
                    if seg.ack.wrapping_sub(self.snd_una) <= self.snd_nxt.wrapping_sub(self.snd_una) {
                        self.snd_una = seg.ack;
                        if self.snd_una == self.snd_nxt {
                            self.last_sent = None;
                        }
                    }
                }
                if !seg.payload.is_empty() {
                    if seg.seq == self.rcv_nxt {
                        self.rcv_nxt = self.rcv_nxt.wrapping_add(seg.payload.len() as u32);
                        self.recv_buffer.extend_from_slice(&seg.payload);
                        actions.push(TcpAction::Data(seg.payload.clone()));
                        actions.push(TcpAction::Send(self.send_segment(TcpFlags::ACK, Vec::new())));
                    } else {
                        actions.push(TcpAction::Ignored);
                        // Re-ACK so the peer retransmits the missing bytes.
                        actions.push(TcpAction::Send(self.send_segment(TcpFlags::ACK, Vec::new())));
                    }
                }
                if seg.flags.fin {
                    self.rcv_nxt = self.rcv_nxt.wrapping_add(1);
                    match self.state {
                        TcpState::Established => {
                            self.state = TcpState::CloseWait;
                            actions.push(TcpAction::Send(self.send_segment(TcpFlags::ACK, Vec::new())));
                        }
                        TcpState::FinWait1 => {
                            self.state = TcpState::Closing;
                            actions.push(TcpAction::Send(self.send_segment(TcpFlags::ACK, Vec::new())));
                        }
                        TcpState::FinWait2 => {
                            self.state = TcpState::TimeWait;
                            actions.push(TcpAction::Send(self.send_segment(TcpFlags::ACK, Vec::new())));
                            actions.push(TcpAction::Closed);
                        }
                        _ => {}
                    }
                }
                // ACK of our FIN in FinWait1.
                if self.state == TcpState::FinWait1 && seg.flags.ack && seg.ack == self.snd_nxt {
                    self.state = TcpState::FinWait2;
                }
            }
            TcpState::Closing => {
                if seg.flags.ack && seg.ack == self.snd_nxt {
                    self.state = TcpState::TimeWait;
                    actions.push(TcpAction::Closed);
                }
            }
            TcpState::LastAck => {
                if seg.flags.ack && seg.ack == self.snd_nxt {
                    self.state = TcpState::Closed;
                    actions.push(TcpAction::Closed);
                }
            }
            TcpState::TimeWait | TcpState::Closed => {}
        }
        actions
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CLIENT: Ipv4Addr = Ipv4Addr([10, 0, 0, 1]);
    const SERVER: Ipv4Addr = Ipv4Addr([10, 0, 0, 2]);

    fn server() -> TcpConnection {
        let mut s = TcpConnection::new(SERVER, 80);
        s.listen(80);
        s
    }

    #[test]
    fn segment_roundtrip_with_checksum() {
        let seg = TcpSegment::new(1234, 80, 100, 0, TcpFlags::SYN, vec![]);
        let bytes = seg.to_bytes(CLIENT, SERVER);
        let back = TcpSegment::parse(&bytes, CLIENT, SERVER).unwrap();
        assert_eq!(back, seg);
        // Corrupt the sequence number: checksum must catch it.
        let mut bad = bytes.clone();
        bad[4] ^= 0xff;
        assert_eq!(TcpSegment::parse(&bad, CLIENT, SERVER), Err(NetError::BadChecksum));
        assert_eq!(TcpSegment::parse(&[0u8; 19], CLIENT, SERVER), Err(NetError::TooShort));
    }

    #[test]
    fn handshake_client_and_server() {
        let mut client = TcpConnection::new(CLIENT, 40000);
        let mut srv = server();
        // Client -> SYN
        let syn = client.connect(SERVER, 80, 5000);
        assert_eq!(client.state, TcpState::SynSent);
        assert!(syn.flags.syn && !syn.flags.ack);
        // Server -> SYN-ACK
        let srv_actions = srv.on_segment(&syn);
        assert_eq!(srv.state, TcpState::SynReceived);
        let syn_ack = match &srv_actions[0] {
            TcpAction::Send(s) => s.clone(),
            other => panic!("expected Send, got {other:?}"),
        };
        assert!(syn_ack.flags.syn && syn_ack.flags.ack);
        assert_eq!(syn_ack.ack, 5001);
        // Client -> ACK, Established
        let cli_actions = client.on_segment(&syn_ack);
        assert_eq!(client.state, TcpState::Established);
        assert!(cli_actions.iter().any(|a| matches!(a, TcpAction::Connected)));
        // Server -> ACK, Established
        let ack = match &cli_actions[0] {
            TcpAction::Send(s) => s.clone(),
            other => panic!("expected Send, got {other:?}"),
        };
        let srv_actions = srv.on_segment(&ack);
        assert_eq!(srv.state, TcpState::Established);
        assert!(srv_actions.iter().any(|a| matches!(a, TcpAction::Connected)));
    }

    #[test]
    fn data_transfer_and_ack() {
        let mut client = TcpConnection::new(CLIENT, 40000);
        let mut srv = server();
        let syn = client.connect(SERVER, 80, 100);
        let syn_ack = match srv.on_segment(&syn)[0].clone() {
            TcpAction::Send(s) => s,
            _ => panic!("syn-ack"),
        };
        let ack = match client.on_segment(&syn_ack)[0].clone() {
            TcpAction::Send(s) => s,
            _ => panic!("ack"),
        };
        srv.on_segment(&ack);
        // Client sends "hello".
        let data = client.send_data(b"hello".to_vec()).unwrap();
        assert_eq!(data.payload, b"hello");
        let actions = srv.on_segment(&data);
        assert!(actions.iter().any(|a| matches!(a, TcpAction::Data(d) if d == b"hello")));
        let mut buf = [0u8; 5];
        assert_eq!(srv.read(&mut buf), 5);
        assert_eq!(&buf, b"hello");
        // Out-of-order data is ignored (and re-ACKed).
        let mut ooo = data.clone();
        ooo.seq = ooo.seq.wrapping_add(10);
        let actions = srv.on_segment(&ooo);
        assert!(actions.iter().any(|a| matches!(a, TcpAction::Ignored)));
    }

    #[test]
    fn retransmit_on_timeout_then_give_up() {
        let mut client = TcpConnection::new(CLIENT, 40000);
        let syn = client.connect(SERVER, 80, 100);
        // No reply: after 1s the SYN is retransmitted.
        assert!(client.on_tick(500).is_none());
        let resent = client.on_tick(500).unwrap();
        assert_eq!(resent.seq, syn.seq);
        assert!(resent.flags.syn);
        // Keep timing out: eventually the connection gives up.
        for _ in 0..6 {
            let _ = client.on_tick(1000);
        }
        assert_eq!(client.state, TcpState::Closed);
    }

    #[test]
    fn fin_close_handshake() {
        let mut client = TcpConnection::new(CLIENT, 40000);
        let mut srv = server();
        let syn = client.connect(SERVER, 80, 100);
        let syn_ack = match srv.on_segment(&syn)[0].clone() {
            TcpAction::Send(s) => s,
            _ => panic!("syn-ack"),
        };
        let ack = match client.on_segment(&syn_ack)[0].clone() {
            TcpAction::Send(s) => s,
            _ => panic!("ack"),
        };
        srv.on_segment(&ack);
        // Client closes.
        let fin = client.close().unwrap();
        assert_eq!(client.state, TcpState::FinWait1);
        let actions = srv.on_segment(&fin);
        assert_eq!(srv.state, TcpState::CloseWait);
        // Server's ACK moves client to FinWait2.
        let ack2 = actions.iter().find_map(|a| match a {
            TcpAction::Send(s) => Some(s.clone()),
            _ => None,
        }).unwrap();
        client.on_segment(&ack2);
        assert_eq!(client.state, TcpState::FinWait2);
        // Server closes too.
        let fin2 = srv.close().unwrap();
        let actions = client.on_segment(&fin2);
        assert_eq!(client.state, TcpState::TimeWait);
        assert!(actions.iter().any(|a| matches!(a, TcpAction::Closed)));
    }

    #[test]
    fn rst_kills_connection() {
        let mut client = TcpConnection::new(CLIENT, 40000);
        client.connect(SERVER, 80, 100);
        let rst = TcpSegment::new(80, 40000, 1, 0, TcpFlags::RST, vec![]);
        let actions = client.on_segment(&rst);
        assert_eq!(client.state, TcpState::Closed);
        assert!(actions.iter().any(|a| matches!(a, TcpAction::Closed)));
        // Sending data in the wrong state fails.
        assert_eq!(client.send_data(vec![1]), Err(NetError::InvalidState));
    }
}
