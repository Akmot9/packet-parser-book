# Internet

The internet layer (L3) is parsed from the link layer's `network_payload()`,
dispatching on the `NetworkProtocol` the link layer announced.

## The `Internet` structure

```rust
pub struct Internet<'a> {
    pub source: Option<IpAddr>,
    pub source_type: Option<IpType>,
    pub destination: Option<IpAddr>,
    pub destination_type: Option<IpType>,
    pub protocol_name: &'static str,
    pub payload_protocol: Option<TransportProtocol>,
    pub payload: &'a [u8],
    pub details: Option<InternetDetails<'a>>,
}
```

Two design points deserve attention.

**Addresses are optional.** Not because IP addresses are optional, but because
not every L3 protocol has them in the IP sense. The flattened fields above are
the *common denominator* of the layer — what a flow matrix needs.

**`details` holds the full header.** Everything protocol-specific — TTL, flags,
options, the ARP operation — lives there:

```rust
pub enum InternetDetails<'a> {
    Ipv4(Ipv4Packet<'a>),
    Ipv6(Ipv6Packet<'a>),
    Arp(ArpPacket),
}
```

`details` is ignored by `PartialEq`, `Hash` and serialization. Two packets of the
same conversation differ in TTL and identification; treating those as part of the
flow identity would give every packet its own bucket.

## Supported protocols

| Protocol | Notes |
| --- | --- |
| IPv4 | Full header, options, fragmentation flags |
| IPv6 | Fixed header plus the extension-header chain |
| ARP | Hardware/protocol types, operation, sender and target addresses |
| Profinet | Industrial traffic reached by its own EtherType |

### IPv4

```rust
pub struct Ipv4Packet<'a> {
    pub version_ihl: u8,
    pub dscp_ecn: u8,
    pub total_length: u16,
    pub identification: u16,
    pub flags_fragment: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub header_checksum: u16,
    pub source_addr: Ipv4Addr,
    pub dest_addr: Ipv4Addr,
    pub options: &'a [u8],
    pub payload: &'a [u8],
}
```

The packed fields keep their wire form and are read through accessors
(`version()`, `ihl()`, `header_length()`), so the structure stays a faithful
image of the header. `dscp_ecn` is decoded separately into the `Dscp` and `Ecn`
types exported at the crate root.

### IPv6

IPv6 is not "IPv4 with longer addresses": the upper-layer protocol is at the end
of an **extension header chain**, not in a fixed field. So `next_header` keeps
what the fixed header said, while `transport_protocol` holds what the chain
actually resolves to — and `payload` starts past the extension headers.

`transport_protocol` is `None` when the chain ends with No Next Header (59), or
when a Fragment extension header is present.

### ARP

ARP has no IP payload and no transport layer. Its addresses are exposed in the
common `source`/`destination` fields when they are IP addresses, and the full
frame — hardware type, protocol type, operation, sender and target hardware
addresses — sits in `InternetDetails::Arp`.

## Address classification

Both endpoints are classified into an `IpType`:

```rust
pub enum IpType {
    Private, Multicast, Loopback, Apipa,
    LinkLocal, Ula, Public, Documentation, Unknown,
}
```

This is cheap at parse time and expensive to redo later, which is why it is done
here rather than left to callers. It is also what lets you separate
"machine talking to the internet" from "machine talking to its own subnet"
without a second pass.

## Fragmentation: the deliberate `None`

The crate does **not** perform IP reassembly. For a fragmented IPv4 packet — and
for an IPv6 packet carrying a Fragment extension header — `payload_protocol` is
set to `None`.

This is not an omission, it is the point. The first fragment of a TCP segment
looks like a parseable TCP header, and parsing it yields ports read from a
datagram that is not complete. Reporting the L3 layer honestly and refusing to
guess above it is the correct answer for a stateless parser.

`protocol` in the IPv4 details still shows what the header claimed, so the
information is not lost — it just does not drive L4 parsing.

## Beyond TCP and UDP

`payload_protocol` is a `TransportProtocol`, an enum covering the IANA IP
protocol numbers, not just 6 and 17. Many of those variants have no ports and no
application payload; they are represented so the layer can be *named* even when
it cannot be decoded. Which ones are actually parsed is covered in
[the transport chapter](./transport.md).

## Parsing L3 on its own

```rust
// Dispatching: the caller knows what was announced.
let internet = Internet::try_from_parts(ethertype, payload)?;

// Probing: no context, tries each supported protocol.
let internet = Internet::try_from(payload)?;
```

Prefer the first when you have the EtherType. It is the version that can tell a
corrupt IPv4 header from an unsupported protocol — see
[Data validation](./data_validation.md).
