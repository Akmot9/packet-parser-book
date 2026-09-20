# Parsing the data link layer

This chapter follows `packet_parser` 10.5.0 at revision
[85728b6](https://github.com/Akmot9/Packet-parser/tree/85728b6424c478366607f6c8ce703fe650e82004).

The capture format determines how packet bytes begin. Ethernet starts with MAC
addresses, Linux cooked captures start with a capture header, and RAW IP starts
directly with an IP header. Pass that format explicitly to
`parse(link_type, bytes)`. The result's `data_link` field is a `LinkLayer<'a>`:
a common interface with a format-specific view and a borrowed network payload.

## Selecting the link format

`LinkType(pub u32)` stores a canonical `LINKTYPE_*` identifier. It preserves unknown
numeric values, so callers can report unsupported formats without losing the
original identifier. Obtain the value from the capture metadata and pass only the
packet bytes, excluding PCAP or PCAPNG record headers. If a live capture uses
platform-specific `DLT_*` values, the caller must map them to canonical `LINKTYPE_*`
values first.

The top-level dispatcher supports the following formats in this revision:

| `LinkType` constant | Value | Decoding behavior |
| --- | ---: | --- |
| `ETHERNET` | 1 | Ethernet header, including stacked VLAN tags. |
| `RAW` | 101 | Headerless IPv4 or IPv6, selected by the first version nibble. |
| `LINUX_SLL` | 113 | A 16-byte Linux cooked capture v1 header. |
| `IPV4` | 228 | Headerless IP; the version nibble must be 4. |
| `IPV6` | 229 | Headerless IP; the version nibble must be 6. |
| `IEEE802_3BR` | 274 | Complete express mPackets; removes preamble, SMD and trailing mCRC before decoding Ethernet. |
| `LINUX_SLL2` | 276 | A 20-byte Linux cooked capture v2 header. |

Call `is_supported(link_type)` to check decoder availability. This does not validate
the packet bytes or promise support for every frame within that format. In
particular, IEEE 802.3br preemptible fragments need reassembly and are rejected;
the express-frame decoder removes the mCRC without verifying it.

The existence of a constant or a result variant does not imply top-level support.
`IEEE802_11` and `BLUETOOTH_HCI_H4_WITH_PHDR` have constants but no top-level decoder
in this revision. An `Ieee80211` view can still appear inside a decoded CAPWAP
tunnel. The authoritative list is the
[link decoder dispatcher](https://github.com/Akmot9/Packet-parser/blob/85728b6424c478366607f6c8ce703fe650e82004/src/parse/link/mod.rs).

## Reading the common and specific views

Use the common accessors when the capture may contain different link formats:

| Accessor | Information returned |
| --- | --- |
| `link_type()` | The declared canonical format, retained even when several formats share a decoder. |
| `network_protocol()` | `Ipv4`, `Ipv6`, `Arp`, `Profinet`, or `Other(u16)`. |
| `network_payload()` | The borrowed bytes passed to the network-layer parser. |
| `kind()` | A reference to the format-specific `LinkLayerKind` variant. |

`as_ethernet()`, `as_raw_ip()`, `as_linux_sll()`, `as_linux_sll2()` and
`as_ieee80211()` return `Some(&details)` for the corresponding view and `None`
otherwise. `as_ethernet()` also succeeds for an express mPacket, whose declared
`link_type()` remains `IEEE802_3BR`.

`DataLink<'a>` is the Ethernet-specific view. It exposes `destination_mac`,
`source_mac`, `vlan`, `vlan_stack`, `ethertype` and `payload`. RAW IP has an
`ip_version` and payload, with no MAC addresses or EtherType. Linux cooked views
expose packet direction, hardware type, declared address length, available source
address bytes and protocol; SLL2 also exposes the interface index and reserved
field. These capture addresses are not necessarily Ethernet MAC addresses.

For SLL and SLL2, an address length greater than the eight-byte wire slot is
preserved, with `address_is_truncated()` reporting the discrepancy. SLL2 preserves
a nonzero reserved field and exposes `reserved_is_zero()` for inspection. These
metadata conditions do not themselves cause a parsing error.

## Ethernet fields and validation

An untagged Ethernet header is laid out as follows. Byte offsets start at zero:

| Bytes | Field |
| --- | --- |
| 0–5 | Destination MAC address |
| 6–11 | Source MAC address |
| 12–13 | EtherType, read in big-endian order |
| 14 onward | Payload |

The Ethernet parser checks for at least 14 bytes before reading those fields.
`MacAddress::try_from` requires **exactly six bytes**. It stores the address as
`[u8; 6]`; display formatting and optional OUI lookup are separate from parsing.
An unknown OUI does not invalidate an address.

When the EtherType field is a VLAN TPID (`0x8100`, `0x88A8` or `0x9100`), the
parser consumes the tag's two-byte TCI and the next two-byte type field. It repeats
this for stacked tags, checking for `14 + 4 × tag_count` bytes at each step.
`vlan_stack` exposes all tags from outermost to innermost; `vlan` contains the
innermost tag. After the tags, `ethertype` and `payload` describe the encapsulated
protocol and its bytes.

These are header and bounds checks. `DataLink::try_from` does not establish that
arbitrary input is Ethernet, verify a frame checksum, or require a nonempty IPv4
or IPv6 payload. Prefer the top-level `parse` API for captured packets: it selects
the decoder from `LinkType` and validates recognized higher layers separately.
For example, a complete Ethernet header announcing IPv4 with an empty payload
preserves the link layer and records an Internet-layer corruption in `PacketFlow`.

In IEEE 802.3 frames the type/length field may instead carry a length. This
revision has a specific STP path: it checks the bridge group destination,
the length-delimited LLC `42 42 03` header and a valid BPDU. It does not generally
decode Ethernet LLC/SNAP payloads into IP. LLC/SNAP handling for encapsulated
IEEE 802.11 frames belongs to the CAPWAP tunnel path.

## Unknown protocols and errors

An unknown EtherType is retained as its numeric value and mapped to
`NetworkProtocol::Other(value)`. A successfully decoded link layer with an
unsupported network protocol remains available: `internet` is `None` and the
unsupported protocol alone does not set `corrupted`. STP classification is a
separate link-layer case, so an absent Internet layer does not always mean an
absent application label.

```rust
# extern crate packet_parser;
use packet_parser::{is_supported, parse, LinkLayerError, LinkType, NetworkProtocol, ParseError};

// A complete Ethernet header carrying an unknown EtherType.
let bytes = [
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
    0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
    0xab, 0xcd,
];
assert!(is_supported(LinkType::ETHERNET));
let flow = parse(LinkType::ETHERNET, &bytes).unwrap();
assert_eq!(flow.data_link.network_protocol(), NetworkProtocol::Other(0xabcd));
assert_eq!(flow.data_link.as_ethernet().unwrap().ethertype.0, 0xabcd);
assert!(flow.internet.is_none());
assert!(flow.corrupted.is_none());

assert!(matches!(
    parse(LinkType::ETHERNET, &bytes[..13]),
    Err(ParseError::InvalidLinkLayer(LinkLayerError::Truncated {
        link_type: LinkType::ETHERNET, required: 14, actual: 13,
    }))
));

let unsupported = LinkType(0xdead);
assert!(!is_supported(unsupported));
assert!(matches!(
    parse(unsupported, &bytes),
    Err(ParseError::UnsupportedLinkType(value)) if value == unsupported
));
```

At the top level, unsupported capture formats produce
`ParseError::UnsupportedLinkType`. Link decoding failures produce
`ParseError::InvalidLinkLayer`, including Ethernet failures. Its `LinkLayerError`
distinguishes `Truncated { link_type, required, actual }`, `InvalidIpVersion`,
`InvalidPreamble`, `InvalidSmd` and `PreemptibleFragment`. RAW requires a first byte
with a valid version nibble; full IP-header validation happens in the Internet
layer. For mPackets, truncation lengths account for the whole packet, including
the framing bytes.

The low-level `DataLink::try_from` API instead returns `DataLinkError`, such as
`DataLinkTooShort`; it has no capture `LinkType` context. Both error contracts are
distinct from the recoverable higher-layer failures described in
[the PacketFlow chapter](packet.md).
