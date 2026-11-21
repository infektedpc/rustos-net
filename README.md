# rustos-net

Networking stack for RustOS. `no_std` library, core + alloc only, zero
external crates. Host tests run on std with a mock device.

## Stack diagram

```
userspace (rustos-shell / apps)
        |  socket API (TcpSocket / UdpSocket)
        v
   TCP (state machine)      UDP (port dispatch)
        |                         |
   ICMP (echo)              ARP (cache + pending queue)
        |                         |
            IPv4 (checksum, fragmentation)
        |
   Ethernet II (MAC, EtherType)
        |
   NetworkDevice trait  <-  NIC driver (e1000 / virtio-net, future rustos-nic)
        |
   hardware (PCI NIC, IRQ 10/11 -> vectors 42/43 after PIC remap)
```

## How a frame flows

Inbound: NIC raises an IRQ (see `rustos-interrupts`: PIC IRQ 10/11,
vectors 42/43). The IRQ handler polls the NIC, gets a raw Ethernet
frame, and hands it to the stack:

1. `EthernetFrame::parse` — checks length, reads dst/src MAC + EtherType.
   Frames not addressed to us (and not broadcast/multicast) are dropped.
2. EtherType `0x0806` → `ArpPacket::parse` → `ArpCache::handle_packet`
   (refreshes the cache, answers requests for our IP, drains queued
   packets for a newly resolved peer).
3. EtherType `0x0800` → `Ipv4Packet::parse` (version + header checksum)
   → `FragmentReassembler::feed` → dispatch by protocol:
   - ICMP (1) → `IcmpPacket::parse`; echo requests get an echo reply.
   - UDP (17) → `UdpPacket::parse` (pseudo-header checksum) →
     `UdpSocketTable::deliver` to the bound port's queue.
   - TCP (6) → `TcpSegment::parse` → `TcpConnection::on_segment`
     (handshake, data, FIN, RST, retransmission via `on_tick`).

Outbound: a socket builds the payload, wraps it in TCP/UDP → IPv4
(checksum filled in) → Ethernet (dst MAC from the ARP cache, or
`NoRoute` if unknown — the kernel ARPs first, then retries) →
`NetworkDevice::send`.

## Modules

| Module | Contents |
|---|---|
| `ethernet` | `MacAddr`, `EtherType`, `EthernetFrame` parse/build (+ padding) |
| `arp` | `ArpPacket`, `ArpCache` (TTL expiry, pending queue) |
| `ipv4` | `Ipv4Addr`, `Ipv4Header`/`Ipv4Packet`, checksum, `FragmentReassembler` |
| `icmp` | `IcmpPacket` echo request/reply |
| `udp` | `UdpPacket`, pseudo-header checksum, `UdpSocketTable` |
| `tcp` | `TcpSegment`, `TcpConnection` state machine, retransmit timer |
| `socket` | `NetworkDevice` trait, `MockDevice`, `TcpSocket`, `UdpSocket` |

## Build / test

```sh
cargo test
```

## Wiring into the kernel (sketch)

```rust
// In the NIC IRQ handler (vector 42/43):
while let Some(frame) = nic.receive() {
    net_stack.handle_frame(&frame); // Ethernet -> IP -> TCP/UDP
}
// In the timer tick (100 Hz, vector 32):
tcp_conn.on_tick(10); // retransmit if a segment went unacked
arp_cache.tick(1);    // once a second
```

## Limitations (honest)

- **No IPv6** — IPv4 only; EtherType `0x86dd` is recognised but not parsed.
- **No TCP congestion control, SACK, or window scaling** — one
  retransmission timer (`TCP_RTO_MS = 1000`, 5 retries, then the
  connection is reset). No Nagle, no delayed ACK.
- **Fragmentation is limited** — at most 4 concurrent datagrams, 8
  fragments each, 30 s timeout; fragments are dropped, not ICMP'd,
  when the table is full. IPv4 options are skipped, not honoured.
- **No DNS, no DHCP** — addresses are configured statically; a
  future `rustos-netapps` crate can add DHCP/DNS clients on top of
  the UDP socket API.
- **No real NIC driver yet** — `NetworkDevice` is a trait; there is
  no e1000/virtio-net implementation in this repo. The stack is
  verified against `MockDevice` only.
- **Not live-tested** — QEMU is not installed on this VM and there
  is no real NIC hardware here, so no frame has ever travelled over
  a real wire. The handshake, checksums, ARP cache and retransmit
  logic are all unit-tested against mocks.
