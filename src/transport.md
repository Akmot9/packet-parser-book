# Transport

The transport layer (L4) is parsed from the internet layer's `payload`,
dispatching on its `payload_protocol`.

## The `Transport` structure

```rust
pub struct Transport<'a> {
    pub protocol: TransportProtocol,
    pub source_port: Option<u16>,
    pub destination_port: Option<u16>,
    pub payload: Option<&'a [u8]>,
    pub details: Option<TransportDetails<'a>>,
}
```

Same split as L3: the flattened fields are the flow identity, and the full
decoded header lives in `details`:

```rust
pub enum TransportDetails<'a> {
    Tcp(TcpPacket<'a>),
    Udp(UdpPacket<'a>),
    Icmp(IcmpPacket<'a>),
    Icmpv6(Icmpv6Packet<'a>),
}
```

The enum is `#[non_exhaustive]`, so adding a decoded protocol stays a minor
version bump. Match with a `_` arm.

Ports are `Option` because `TransportProtocol` covers the whole IANA protocol
number space, and most of those protocols have no ports at all.

## What is decoded

### TCP

```rust
pub struct TcpHeader<'a> {
    pub source_port: u16,
    pub destination_port: u16,
    pub sequence_number: u32,
    pub acknowledgment_number: u32,
    pub data_offset: u8,
    pub reserved: u8,
    pub ns: bool, pub cwr: bool, pub ece: bool, pub urg: bool,
    pub ack: bool, pub psh: bool, pub rst: bool, pub syn: bool, pub fin: bool,
    pub window_size: u16,
    pub checksum: u16,
    pub urgent_pointer: u16,
    pub options: &'a [u8],
}
```

Every flag is a named `bool` rather than a bitfield the caller has to mask
themselves. The data offset is validated before it is used to slice options and
payload — an unchecked one is an out-of-bounds read waiting to happen.

**No TCP reassembly.** Each segment is parsed on its own. An application message
split across segments is not reconstructed, which is what keeps the crate
stateless and per-packet.

### UDP

```rust
pub struct UdpPacket<'a> {
    pub source_port: u16,
    pub destination_port: u16,
    pub length: u16,
    pub checksum: u16,
    pub payload: &'a [u8],
}
```

### ICMPv4

Reached through **IP protocol number 1, never through probing**. Decoded
messages:

- Echo request / reply — identifier, sequence, and the echoed data.
- The error reports that quote the original datagram: destination unreachable,
  redirect, time exceeded, parameter problem — with their four type-dependent
  bytes and the quoted datagram.

### ICMPv6

Reached through **IPv6 next header 58**. Type numbering is *disjoint* from
ICMPv4 — 128 is an echo request there, 8 is undefined — so the two have separate
parsers rather than a shared one with special cases. Decoded messages:

- Echo request / reply.
- The error reports that quote the invoking packet.
- Neighbor discovery (RFC 4861): router solicitation and advertisement — the
  latter with its hop limit, M/O flags, router lifetime, reachable time and
  retransmit timer — plus neighbor solicitation and advertisement with their
  target address and R/S/O flags.

### Why ICMP keeps `payload: None`

Neither ICMP version carries an application layer. Their decoded content is
exposed through `TransportDetails::Icmp` / `Icmpv6`, and `payload` stays
deliberately `None`.

The reason is defensive: if ICMP bytes were exposed as a transport payload, they
would be submitted to application detection, which would happily label a quoted
datagram as some application protocol. Withholding the payload makes that
impossible by construction rather than by a special case in the detector.

## Beyond TCP/UDP/ICMP

`TransportProtocol::from_u8` maps the IANA protocol numbers, so a flow carrying
GRE, ESP or SCTP is **named** even though it is not decoded. In that case
`details` is `None`, ports are `None`, and the layer still tells you what the IP
header announced.

## Parsing L4 on its own

```rust
// Dispatching: the protocol number is known.
let transport = Transport::try_from_parts(payload_protocol, payload)?;

// Probing: no context.
let transport = Transport::try_from(payload)?;
```

As at L3, prefer `try_from_parts`: it is what allows a malformed TCP header to be
reported as `corrupted: Transport` instead of vanishing into an indistinguishable
`None`.
