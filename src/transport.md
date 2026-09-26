# Transport

The transport layer is parsed from `Internet::payload`, and the internet layer says what to expect through `payload_protocol`.

## The `Transport` struct

```rust
pub struct Transport<'a> {
    pub protocol: TransportProtocol,
    pub source_port: Option<u16>,
    pub destination_port: Option<u16>,
    /// The bytes handed to the application layer. `None` when nothing stacks above.
    pub payload: Option<&'a [u8]>,
    /// Full parsed header: TcpPacket, UdpPacket, IcmpPacket or Icmpv6Packet.
    pub details: Option<TransportDetails<'a>>,
}
```

`TransportProtocol` maps **every IANA protocol number** (`Tcp`, `Udp`, `Icmp`, `Ipv6Icmp`, `Gre`, `Sctp`, `Ospf`...), so a packet carrying a protocol without a dedicated parser still gets a correct `protocol` label. Only TCP, UDP, ICMPv4 and ICMPv6 are decoded further.

## Dispatch on the IP protocol number

```rust
pub fn try_from_parts(payload_protocol: Option<TransportProtocol>, payload: &'a [u8])
    -> Result<Self, TransportError>
{
    match payload_protocol {
        Some(TransportProtocol::Tcp) => { let tcp = TcpPacket::try_from(payload)?; /* ports, payload, details */ }
        Some(TransportProtocol::Udp) => { let udp = UdpPacket::try_from(payload)?; /* ... */ }
        Some(TransportProtocol::Icmp) => Ok(Transport { /* no ports, payload: None, details: IcmpPacket::try_from(payload).ok() */ }),
        Some(TransportProtocol::Ipv6Icmp) => Ok(Transport { /* same with Icmpv6Packet */ }),
        Some(other) => Ok(Transport { protocol: other, source_port: None, destination_port: None, payload: None, details: None }),
        None => Err(TransportError::UnsupportedProtocol),
    }
}
```

Same philosophy as the internet layer: the protocol number decides, there is no probing, and `UnsupportedProtocol` (which `PacketFlow` maps to `transport: None, corrupted: None`) is distinct from a TCP or UDP parse error (`corrupted: Transport`).

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

Structural checks (an `Err` means "not a readable TCP header"):

✅ **Minimum length** – at least **20 bytes**.  
✅ **Data offset** – between **5 and 15** words (20 to 60 bytes).  
✅ **Header available** – the buffer holds the whole header, options included.  

Semantic checks (the header is readable, `TryFrom` returns `Ok`, and the anomaly is exposed by `TcpPacket::anomaly()`):

⚠️ **SYN + FIN both set** – no conforming stack opens and closes a connection in the same segment. This is a classic scan and firewall-evasion signature (`TcpError::InvalidFlags`).  
⚠️ **Reserved bits set** – RFC 9293 says they must be zero (`TcpError::ReservedBitsSet`).  

The pipeline **keeps** an anomalous transport, with its ports, and reports it in `corrupted`. Its payload is *not* handed to the application probes: bytes that did not come from a conforming stack are not worth classifying.

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

✅ **Minimum length** – at least **8 bytes**.  
✅ **Length field** – equal to the buffer length. UDP is the one header whose declared length must match exactly: the internet layer already trimmed the Ethernet padding, so a mismatch is a corrupt datagram.  

## ICMPv4 and ICMPv6

ICMP has neither ports nor sessions. It is reached through the IP protocol number (1, or next header 58 for ICMPv6), **never through probing**, and the two versions have separate parsers: their type numbering is disjoint (128 is an echo request in ICMPv6, 8 is undefined there).

Two deliberate choices:

- `payload` stays **`None`**: nothing stacks above ICMP, and exposing its bytes would hand them to the application probes, which would mislabel them. The decoded message is in `details` (`TransportDetails::Icmp` / `Icmpv6`).
- an **unreadable ICMP message does not corrupt the flow**: the protocol is correctly identified by the IP header, so `protocol` is set and only `details` falls back to `None`.

Decoded messages: echo request/reply, the error reports that quote the original datagram (destination unreachable, redirect, time exceeded, parameter problem), and for ICMPv6 the neighbor discovery messages of RFC 4861 (router/neighbor solicitation and advertisement with their flags, lifetimes and target address).

## Checksums

TCP and UDP checksums are never verified during parsing, for the same offloading reason as IPv4. They need the IP pseudo-header, so the opt-in functions take the addresses:

```rust
use packet_parser::checksum::verify_tcp_checksum;

// Some(true): present and correct; Some(false): present and wrong;
// None: not verifiable (too short, or UDP checksum absent).
let ok = verify_tcp_checksum(internet.source?, internet.destination?, internet.payload);
```
