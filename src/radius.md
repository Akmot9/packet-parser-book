# RADIUS

Remote Authentication Dial In User Service, RFC 2865, with accounting (RFC 2866) and dynamic authorization, Disconnect and CoA (RFC 5176): who connects, through which equipment, with what result. Decoded since 11.6.0 ([#101](https://github.com/Akmot9/Packet-parser/issues/101), [#156](https://github.com/Akmot9/Packet-parser/pull/156)). The module is `packet_parser::parse::application::protocols::radius`: the header, then the list of attributes, each one borrowed from the datagram and, when the crate knows its type, named after the IANA registry, with accessors for the integers, IPv4 addresses and texts of the RFC and for the vendor id of a Vendor-Specific. Passwords stay encrypted: nothing in the crate knows the shared secret.

## Detection: five ports, then any UDP port

Two rules of the [dispatch table](./application.md#reading-the-table), 26 and 44, share one probe, `ProbeId::Radius`:

```rust
// among the port rules, after DIS
port_rule("RADIUS", Guard::Udp, is_radius_udp_port, ProbeId::Radius), // 1812, 1813, 1645, 1646, 3799
// in the blind cascade, after DNP3, before BACnet/IP
rule("RADIUS", Guard::Udp, ProbeId::Radius),
```

`is_radius_udp_port` matches, on either side, 1812 and 1813, the IANA ports, 1645 and 1646, their historical numbers (the switch of `radius.pcap` still sends from 1645), and 3799, the port of RFC 5176. On UDP 1700, which tshark also dissects as RADIUS, the crate relies on the blind rule. The probe is `RadiusPacket::try_from(full_payload).is_ok()`, run on the whole payload and not on its first `PROBE_CAP` bytes, because the declared length is compared with the real datagram. It accepts a datagram only if:

- the code is one of the fourteen of RFC 2865, 2866 and 5176;
- the declared length is between 20 and 4096 and equals the datagram;
- the attributes tile the rest exactly: none shorter than its 2-byte header, none past the end, no byte left over.

RFC 2865 §3 tells a receiver to treat the bytes after `Length` as padding and ignore them. The crate requires the length to be the datagram's instead, its reason being that a decoder tolerating trailing bytes would make a poor blind probe. With that, the same probe runs blind on any UDP datagram that no earlier rule has claimed, and there is no `DecodeAsProtocol` variant for RADIUS: a server on another port is recognized anyway. Both rules are `Guard::Udp`; RADIUS over TCP or TLS is not probed.

Since the two rules share the probe, a datagram on 1812 that fails it is not probed again by the blind rule: it goes on down the table, usually to `"Unknown"`. A refusal never fills `corrupted`: on UDP a port is a hint, not an announcement, as for [PTP](./ptp.md). Every packet of the corpus has 1812 on one side; the blind route is checked by moving frame 1 of `radius.pcap` to other ports, and the test shows what the probe looks at and what it does not (*tested*):

```rust
{{#include ../examples/src/building_aaa.rs:radius_blind_probe}}
```

## The packet

```rust
pub struct RadiusPacket<'a> {
    pub code: u8,
    pub kind: RadiusCode,                      // always known: the decoder refuses other codes
    pub identifier: u8,                        // pairs a request and its response
    pub length: u16,                           // equal to the datagram
    pub authenticator: [u8; 16],               // as on the wire
    pub attributes: Vec<RadiusAttribute<'a>>,
}
```

| Bytes | Field | Note |
| --- | --- | --- |
| 0 | `code`, `kind` | one of the fourteen codes below |
| 1 | `identifier` | |
| 2–3 | `length` | 20 to 4096 (RFC 2865 §3), header included |
| 4–19 | `authenticator` | the Request Authenticator, or a Response Authenticator computed with the shared secret: copied, not verified |
| 20– | `attributes` | type, length, value, up to `length` |

| Code | `RadiusCode` | RFC |
| --- | --- | --- |
| 1 | `AccessRequest` | 2865 |
| 2 | `AccessAccept` | 2865 |
| 3 | `AccessReject` | 2865 |
| 4 | `AccountingRequest` | 2866 |
| 5 | `AccountingResponse` | 2866 |
| 11 | `AccessChallenge` | 2865 |
| 12 | `StatusServer` | 2865 |
| 13 | `StatusClient` | 2865 |
| 40 | `DisconnectRequest` | 5176 |
| 41 | `DisconnectAck` | 5176 |
| 42 | `DisconnectNak` | 5176 |
| 43 | `CoaRequest` | 5176 |
| 44 | `CoaAck` | 5176 |
| 45 | `CoaNak` | 5176 |

The structs and enums of the module are `#[non_exhaustive]`, and `RadiusCode::from_code` is public. The attribute list is the only part that allocates: a `Vec` whose initial capacity is at most 16, and never more than the bytes left could hold; past 16 attributes it grows like any `Vec`. An Access-Request from a switch, decoded attribute by attribute (*tested*):

```rust
{{#include ../examples/src/building_aaa.rs:radius_access_request}}
```

The header alone is a valid packet: the Access-Reject of a capture taken on the loopback interface, read from a [BSD loopback](./null_loopback.md) frame (*tested*):

```rust
{{#include ../examples/src/building_aaa.rs:radius_loopback_reject}}
```

## Attributes

```rust
pub struct RadiusAttribute<'a> {
    pub attribute_type: u8,
    pub kind: Option<AttributeType>,   // None for a type the crate does not name
    pub length: u8,                    // declared, header included
    pub value: &'a [u8],               // length - 2 bytes, borrowed
}
```

`AttributeType` names 127 types of the IANA registry *RADIUS Attribute Types*: 1 to 125 except 17, 21, 54 and 93, and the extended types 241 to 246 (`ExtendedType1` to `ExtendedType4`, `LongExtendedType1`, `LongExtendedType2`). Two names do not follow the registry: 124 and 125, MIP6-Feature-Vector and MIP6-Home-Link-Prefix for IANA (RFC 5447), are `MipHomeAgentAddress` and `MipHomeAgentHost` in the crate. Any other type is kept, with `kind: None` and its value. `AttributeType::from_code` is public. Four accessors read a value:

| Method | Returns | `Some` when |
| --- | --- | --- |
| `as_u32()` | `Option<u32>` | the value is 4 bytes: NAS-Port, Service-Type, Acct-Status-Type… |
| `as_ipv4()` | `Option<Ipv4Addr>` | the value is 4 bytes: NAS-IP-Address, Framed-IP-Address… |
| `as_text()` | `Option<&'a str>` | the value is UTF-8: User-Name, NAS-Identifier, Reply-Message… |
| `vendor()` | `Option<(u32, &'a [u8])>` | the attribute is a Vendor-Specific (26) whose value has at least 4 bytes: the vendor id, an IANA Private Enterprise Number, then the bytes the vendor defines |

The first three do not look at the type: `as_u32` reads any 4-byte value, and choosing the accessor the RFC gives an attribute is the caller's job. `RadiusPacket::attribute(kind)` returns the first attribute of a type. An attribute holds at most 253 bytes of value, its length being one byte, so a longer EAP packet is spread over several EAP-Message attributes, which the caller reads by walking `attributes`: frame 36722 of the Ultimate PCAP, an Access-Challenge of 1 068 bytes, carries four of them, 255, 255, 255 and 247 bytes long with their 2-byte headers. An Access-Accept over IPv6 with three Microsoft attributes (*tested*):

```rust
{{#include ../examples/src/building_aaa.rs:radius_vendor_specific}}
```

## Validations

All of them are `RadiusParseError`, in `packet_parser::errors::application::radius`:

| Error | When |
| --- | --- |
| `Truncated { expected, actual }` | fewer than the 20 bytes of the header |
| `UnknownCode(u8)` | a code outside the fourteen above |
| `InvalidLength(u16)` | a declared length below 20 or above 4096 |
| `LengthMismatch { declared, actual }` | a declared length other than the datagram's |
| `AttributeTooShort { attribute_type, length }` | an attribute length of 0 or 1, shorter than its own header |
| `AttributeOverflow { attribute_type, needed, available }` | an attribute that runs past the end, or a single byte left after the last attribute |

In the pipeline, every one of them means the same thing: the label is not given, as the detection section shows.

## Oracle: 95 packets, attribute by attribute

The golden test `tests/radius_golden.rs` runs the two captures of `pcaps_exemple/protocols/radius/` and `The-Ultimate-PCAP.pcapng`, read in place, and compares every packet with tshark 4.6.6, frozen in `tests/data/radius_tshark_oracle.tsv` by `tools/radius_oracle.sh`: ports, code, identifier, length, authenticator, the types and lengths of the attributes, the vendor ids of the Vendor-Specific.

| Capture | Packets | Content | Origin |
| --- | --- | --- | --- |
| `protocols/radius/radius.pcap` | 4 | a Cisco switch, from port 1645, authenticates `John.McGuirk` in EAP: Access-Request, Access-Challenge, Access-Request, Access-Accept | Zeek test corpus, BSD 3-clause |
| `protocols/radius/radius_localhost.pcap` | 19 | on the loopback interface, LINKTYPE_NULL: Access-Requests to port 1812 carrying EAP-Message, User-Password or CHAP-Password, and their Access-Challenge, Access-Accept and Access-Reject | Zeek test corpus, BSD 3-clause |
| `The-Ultimate-PCAP.pcapng` | 72 of 51 328 frames | December 2022, a switch and VMware machines over IPv4 and IPv6: EAP-PEAP and EAP-TTLS exchanges, Microsoft Vendor-Specific attributes | Johannes Weber, *The Ultimate PCAP* |

Over the 95: 49 Access-Request, 26 Access-Challenge, 18 Access-Accept and 2 Access-Reject, carrying 28 Vendor-Specific attributes, all of Microsoft (311). None of the other 51 256 frames of the Ultimate PCAP is labelled RADIUS. A second test moves frame 1 of `radius.pcap` to ports 40000 and 40001, then alters the code (to 6, outside the fourteen), the length and the length of the first attribute (twice): each is refused and loses the label, while an altered authenticator and an altered attribute value keep it.

A run of the 11.6.0 pipeline over the 386 403 frames that the crate's test reader gets from the captures tracked under `pcaps_exemple/` gives the label `"RADIUS"` to exactly the 265 packets tshark dissects as RADIUS: these 95, and 170 more on port 1812 that the golden test does not cover, in `vlan0--packet-capture CAPWAP…cap`, a 2016 test-network capture at the root of `pcaps_exemple/` whose origin is not documented. The 170 and the 72 of the Ultimate PCAP are the 242 RADIUS packets that, according to the CHANGELOG, leave `"Unknown"` on the 11.5.0 corpus. The fuzz target `parse_radius` runs nightly, on its input and on mutations of three real packets: whatever it decodes must have the input's length, between 20 and 4096, and attributes that tile it exactly, each value `length - 2` bytes inside the input, `vendor()` answering only on a Vendor-Specific.

## What is left out

- **The shared secret**: neither authenticator nor the Message-Authenticator is verified, and User-Password, Tunnel-Password or the keys a vendor attribute carries stay the bytes of the wire.
- **EAP** is not decoded: an EAP-Message value is raw bytes, and an EAP packet spread over several attributes is not reassembled.
- **Vendor attributes**: `vendor()` gives the vendor id and the vendor's bytes; their sub-attributes are not split.
- **Other value types**: no accessor for IPv6 addresses (NAS-IPv6-Address, in the Ultimate PCAP), and the extended types 241 to 246 are named but not unpacked.
- **No state**: a response is not matched with its request, and the three identical Access-Requests of `radius_localhost.pcap`, a retransmission, are three packets. One datagram at a time, as in the rest of the crate.
- **Codes no capture exercises**: none of the 265 RADIUS packets of the repository's captures is an accounting, Status-Server, Status-Client, Disconnect or CoA packet; codes 4, 5, 12, 13 and 40 to 45 follow the RFCs.
