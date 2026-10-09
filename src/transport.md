# Transport

The transport layer is parsed from `Internet::payload`, and the internet layer says what to expect through `payload_protocol`.

## The `Transport` struct

```rust
pub struct Transport<'a> {
    pub protocol: TransportProtocol,
    pub source_port: Option<u16>,
    pub destination_port: Option<u16>,
    /// TCP and UDP: the bytes after the header, possibly empty. `None` for every other protocol.
    pub payload: Option<&'a [u8]>,
    /// Full parsed header: TcpPacket, UdpPacket, IcmpPacket or Icmpv6Packet.
    /// `None` for the other protocols, and for an unreadable ICMP message.
    pub details: Option<TransportDetails<'a>>,
}
```

`Transport` and `TransportDetails` are both `#[non_exhaustive]`. The identity of the layer is `protocol` plus the two ports: `PartialEq`, `Hash` and serialization ignore `payload` and `details`, and `protocol` is serialized under the key `protocol_transport` as its `Display` name (`"TCP"`, `"ICMPv6"`, `"Unknown (150)"`), the same string `TransportOwned` carries ([#22](https://github.com/Akmot9/Packet-parser/issues/22)).

`TransportProtocol` has a named variant for **every protocol number IANA has assigned** (0 to 147 and 253 to 255: `Tcp`, `Udp`, `Icmp`, `Ipv6Icmp`, `Gre`, `Sctp`, `Ospfigp`...) and `Unknown(u8)` for the unassigned range 148 to 252, so a packet carrying a protocol without a dedicated parser still gets a correct `protocol` label. Only TCP, UDP, ICMPv4 and ICMPv6 are decoded further.

## Dispatch on the IP protocol number

```rust
pub fn try_from_parts(payload_protocol: Option<TransportProtocol>, payload: &'a [u8])
    -> Result<Self, TransportError>
{
    match payload_protocol {
        Some(TransportProtocol::Tcp) => { let tcp = TcpPacket::try_from(payload)?; /* ports, payload, details */ }
        Some(TransportProtocol::Udp) => { let udp = UdpPacket::try_from(payload)?; /* ... */ }
        Some(TransportProtocol::Icmp) => Ok(Transport { /* no ports, payload: None,
            details: IcmpPacket::try_from(payload).ok().map(TransportDetails::Icmp) */ }),
        Some(TransportProtocol::Ipv6Icmp) => Ok(Transport { /* same with Icmpv6Packet */ }),
        Some(other) => Ok(Transport { protocol: other, source_port: None, destination_port: None, payload: None, details: None }),
        None => Err(TransportError::UnsupportedProtocol),
    }
}
```

Same philosophy as the internet layer: the protocol number decides, there is no probing. `Transport` has no `TryFrom<&[u8]>` at all: the one that existed until 10.x guessed TCP, then UDP, blindly, and 11.0.0 removed it.

`UnsupportedProtocol` (which `PacketFlow` maps to `transport: None, corrupted: None`) is distinct from a TCP or UDP parse error, which reaches the caller wrapped in `TransportError::TcpError` or `TransportError::UdpError` and becomes `transport: None, corrupted: Transport`, with the error's `Display` as text. Despite its name, `UnsupportedProtocol` does not mean an unknown L4 protocol (those take the `Some(other)` arm): it means the internet layer announced nothing to parse. ARP and PROFINET carry no transport; an IPv4 or IPv6 fragment, the first one included, cannot be parsed safely without reassembly, which the crate does not do; an IPv6 extension chain can end in No Next Header (59). `TransportError` also declares `PacketTooShort` and `InvalidTcpPacket(String)`, which `try_from_parts` never returns.

## The protocols

TCP, UDP, ICMPv4 and ICMPv6 are decoded further, each on its page: [TCP](./tcp.md), [UDP](./udp.md), [ICMPv4 and ICMPv6](./icmp.md).

## Checksums

TCP and UDP checksums are never verified during parsing, for the same offloading reason as IPv4 (`UdpError::InvalidChecksum` exists, but the parser never returns it). They need the IP pseudo-header, so the opt-in functions `verify_tcp_checksum` and `verify_udp_checksum` take the addresses:

```rust
use packet_parser::checksum::verify_tcp_checksum;

// Some(true): present and correct; Some(false): present and wrong;
// None: not verifiable (too short, UDP checksum field at 0,
// or an IPv4 address mixed with an IPv6 one).
let ok = verify_tcp_checksum(internet.source?, internet.destination?, internet.payload);
```

ICMP and ICMPv6 checksums have no verifier: the `checksum` module covers the IPv4 header, TCP and UDP only.
