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

## TCP validations

```text
packet-beta
0-15: "Source port"
16-31: "Destination port"
32-63: "Sequence number"
64-95: "Acknowledgment number"
96-99: "Data offset"
100-102: "Reserved"
103-111: "Flags (NS CWR ECE URG ACK PSH RST SYN FIN)"
112-127: "Window size"
128-143: "Checksum"
144-159: "Urgent pointer"
160-191: "Options (if data offset > 5)"
```

`TcpPacket` holds the decoded `header: TcpHeader` and the `payload`, everything after `data_offset × 4` bytes. The header exposes every field: `data_offset` in 32-bit words, `reserved` as the three raw bits, one `bool` per flag from `ns` to `fin`. Options are not decoded: `options` is the raw slice between byte 20 and the end of the header.

Structural checks (an `Err` means "not a readable TCP header"):

✅ **Minimum length** – at least **20 bytes** (`TcpError::PacketTooShort`).  
✅ **Data offset** – between **5 and 15** words, 20 to 60 bytes (`TcpError::InvalidDataOffset`, carrying the value read).  
✅ **Header available** – the buffer holds the whole header, options included (`TcpError::PacketTooShort`).  

Semantic checks (the header is readable, `TryFrom` returns `Ok`, and the anomaly is exposed by `TcpPacket::anomaly()`):

⚠️ **SYN + FIN both set** – no conforming stack opens and closes a connection in the same segment. This is a classic scan and firewall-evasion signature (`TcpError::InvalidFlags { flags }`, with the whole flags byte).  
⚠️ **Reserved bits set** – the three bits between the data offset and NS. RFC 9293 §3.1 says they must be zero (`TcpError::ReservedBitsSet { bits }`). NS is decoded into `ns` and not checked.  

`anomaly()` names one anomaly: when both are present it returns `ReservedBitsSet`, which it checks first. `TcpPacket::is_anomalous()` gives the same verdict as a plain `bool`.

The pipeline **keeps** an anomalous transport, with its ports, and reports it in `corrupted` (`layer: Transport`, `error: "TCP error: Invalid TCP flags 0x03: SYN and FIN are both set"`). Before 11.0.0 such a segment lost its transport layer, which deprived the caller of the ports, so of any flow correlation, at the precise moment the packet is interesting ([#24](https://github.com/Akmot9/Packet-parser/issues/24)). Its payload stays in `transport.payload` but is *not* handed to the application probes nor to tunnel detection (`application` and `inner` are `None`): bytes that did not come from a conforming stack are not worth classifying. This case runs in a cold function outside the common pipeline: weaving it into the L4 and L7 stages cost about 10 ns on every TCP segment, for a case that almost never occurs.

```rust
if let Some(corrupted) = &flow.corrupted
    && corrupted.layer == CorruptedLayerKind::Transport
{
    match &flow.transport {
        None => { /* structural: unreadable header */ }
        Some(transport) => { /* semantic: ports usable, packet suspicious */ }
    }
}
```

## UDP validations

✅ **Minimum length** – at least **8 bytes** (`UdpError::PacketTooShort { expected, actual }`).  
✅ **Length field** – equal to the buffer length (`UdpError::InvalidLength { length, actual }`). UDP is the one header whose declared length must match exactly: the internet layer already trimmed the Ethernet padding (IPv4 to its total length, IPv6 to its payload length), so a mismatch is a corrupt datagram.  

`payload` is everything after the 8-byte header. UDP has no semantic anomaly: a datagram either parses or corrupts the layer.

## ICMPv4 and ICMPv6

ICMP has neither ports nor sessions. It is reached through the IP protocol number (1, or next header 58 for ICMPv6), **never through probing**, and the two versions have separate parsers: their type numbering is disjoint (128 is an echo request in ICMPv6, 8 is undefined there).

Two deliberate choices:

- `payload` stays **`None`**: nothing stacks above ICMP, and exposing its bytes would hand them to the application probes, which would mislabel them. The decoded message is in `details` (`TransportDetails::Icmp` / `Icmpv6`).
- an **unreadable ICMP message does not corrupt the flow**: the protocol is correctly identified by the IP header, so `protocol` is set and only `details` falls back to `None`. The `IcmpError` / `Icmpv6Error` is discarded; to know why, run `IcmpPacket::try_from` or `Icmpv6Packet::try_from` on `internet.payload`.

Decoded messages, in `IcmpPacket::body` (`IcmpBody`) and `Icmpv6Packet::body` (`Icmpv6Body`), after the common `message_type`, `code` and `checksum`:

- **Echo** request/reply (ICMPv4 8/0, ICMPv6 128/129): identifier, sequence number, data.
- **Error reports**, which quote the datagram that caused them: ICMPv4 destination unreachable (3), redirect (5), time exceeded (11) and parameter problem (12); ICMPv6 destination unreachable (1), packet too big (2), time exceeded (3) and parameter problem (4). The four type-dependent bytes stay raw in `rest_of_header` (next-hop MTU, parameter-problem pointer..., to read according to type and code), and the quoted bytes are exposed zero-copy as `original_datagram` / `invoking_packet`, not parsed.
- **Neighbor discovery** (ICMPv6 only, RFC 4861): router solicitation (133), router advertisement (134: current hop limit, M/O flags, router lifetime, reachable time, retransmit timer), neighbor solicitation (135: target address) and neighbor advertisement (136: R/S/O flags, target address), each with its NDP options as raw bytes. Redirect (137) is not interpreted.
- any other type: `Other`, the raw bytes after the common header.

What makes a message unreadable:

| Check (error variant) | ICMPv4 (`IcmpError`) | ICMPv6 (`Icmpv6Error`) |
| --- | --- | --- |
| Common header: type, code, checksum (`InvalidLength`) | 4 bytes | 4 bytes |
| Code defined for the type (`InvalidCodeForType`) | echo: 0; destination unreachable: 0–15; redirect: 0–3; time exceeded: 0–1; parameter problem: 0–2 | destination unreachable: 0–7; packet too big: 0; time exceeded: 0–1; parameter problem: 0–2; echo and the four ND messages: 0 |
| Echo: identifier and sequence (`InvalidEchoLength`) | 8 bytes | 8 bytes |
| Error report (`InvalidErrorPayloadLength`) | 8 + 28 bytes: an option-less IPv4 header and the first 8 data bytes, as RFC 792 requires | 8 + 40 bytes: the fixed IPv6 header (RFC 4443 §3) |
| Neighbor solicitation/advertisement: target address (`InvalidNeighborLength`) | – | 24 bytes |
| Router solicitation / advertisement: fixed fields (`InvalidRouterLength`) | – | 8 / 16 bytes |

An error report quoting less than that minimum is refused rather than exposed: routers sometimes truncate below it, and the consumer would read a partial IP header. A type the crate does not interpret has no code constraint: it parses as `Other` and never fails.

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
