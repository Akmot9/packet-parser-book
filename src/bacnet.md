# BACnet/IP

BACnet (ASHRAE 135, *A Data Communication Protocol for Building Automation and Control Networks*) is the protocol of building automation, and annex J carries it over UDP as BACnet/IP. Decoded since 11.6.0 ([#159](https://github.com/Akmot9/Packet-parser/pull/159)), as part of epic [#102](https://github.com/Akmot9/Packet-parser/issues/102) with [IEC 60870-5-104](./iec104.md) and [GOOSE](./goose.md). The module is `packet_parser::parse::application::protocols::bacnet`: it reads the three layers of a datagram, the BVLC, the NPDU and the APDU, and stops at the service data, which stays tag-encoded bytes.

## Detection: its ports, then any UDP port

Two rules of the [dispatch table](./application.md) share one probe, `ProbeId::Bacnet`:

```rust
// among the port rules, right after RADIUS
port_rule("BACnet/IP", Guard::Udp, is_bacnet_udp_port, ProbeId::Bacnet), // 47808..=47823
// in the blind cascade, after DNP3 and RADIUS, before Bitcoin
rule("BACnet/IP", Guard::Udp, ProbeId::Bacnet),
```

`is_bacnet_udp_port` matches 47808 to 47823, `0xBAC0` to `0xBACF`, on either side: 47808 is the IANA `bacnet` port, and the crate's source ties the fifteen others to the multiple networks of annex J (tshark registers BVLC on 47808 alone). The probe is `BacnetPacket::try_from(payload).is_ok()`, run on the whole payload and not on the first `PROBE_CAP` bytes, because the BVLC length is compared with the real datagram. It accepts a datagram only if:

- the first byte, the BVLC type, is `0x81`;
- the function is one of the thirteen of annex J, `0x00` to `0x0C`;
- the BVLC length is the length of the datagram, to the byte;
- for the four functions that carry an NPDU, the NPDU has version 1, the addresses and the hop count its control byte announces, and then either a network message or an APDU of type 0 to 7 with the fixed fields of its type.

The crate considers this constrained enough to do without the port, so the same probe runs blind on every UDP datagram, and there is no `DecodeAsProtocol` variant for BACnet: a device on another port is recognized anyway. Both rules are `Guard::Udp`; the same bytes in a TCP segment never get the label.

Since the two rules share the probe, a datagram on 47808 that fails it is not probed again by the blind rule: it goes on down the table, usually to `"Unknown"`. A refusal never fills `corrupted`: on UDP a port is a hint, not an announcement, as for [PTP](./ptp.md). Every datagram of the corpus has 47808 on one side; the blind route is checked by moving frame 3 of `iti_bacnet_test.pcap` to other ports (*tested*):

```rust
{{#include ../examples/src/building_aaa.rs:bacnet_blind_probe}}
```

## The datagram

```rust
pub struct BacnetPacket<'a> {
    pub bvlc: BvlcHeader,
    pub forwarded_from: Option<(Ipv4Addr, u16)>, // Forwarded-NPDU: the original sender
    pub npdu: Option<Npdu<'a>>,                   // for the functions that carry one
    pub body: &'a [u8],                           // after the header (and the origin)
}

pub struct BvlcHeader {
    pub function: u8,
    pub kind: BvlcFunction,
    pub length: u16,                              // the whole datagram
}
```

Every struct and enum of the module is `#[non_exhaustive]`, and every byte field borrows the datagram: decoding allocates nothing.

| Bytes | Field | Note |
| --- | --- | --- |
| 0 | type | `0x81`; checked, not kept |
| 1 | `function`, `kind` | the code and its `BvlcFunction` |
| 2–3 | `length` | big-endian, header included: must equal the datagram |
| 4–9 | `forwarded_from` | Forwarded-NPDU only: IPv4 address and UDP port of the original sender |
| then | `body` | the rest: the NPDU, or the data of the function |

| Code | `BvlcFunction` | NPDU |
| --- | --- | --- |
| `0x00` | `Result` | — |
| `0x01` | `WriteBroadcastDistributionTable` | — |
| `0x02` | `ReadBroadcastDistributionTable` | — |
| `0x03` | `ReadBroadcastDistributionTableAck` | — |
| `0x04` | `ForwardedNpdu` | after the 6-byte origin |
| `0x05` | `RegisterForeignDevice` | — |
| `0x06` | `ReadForeignDeviceTable` | — |
| `0x07` | `ReadForeignDeviceTableAck` | — |
| `0x08` | `DeleteForeignDeviceTableEntry` | — |
| `0x09` | `DistributeBroadcastToNetwork` | yes |
| `0x0A` | `OriginalUnicastNpdu` | yes |
| `0x0B` | `OriginalBroadcastNpdu` | yes |
| `0x0C` | `SecureBvll` | — |

For the four functions that carry an NPDU, `body` holds the bytes `npdu` decodes. For the nine others `npdu` is `None` and `body` is their data, undecoded: a result code, a time-to-live, a table; a Secure-BVLL is recognized and left whole in `body`. `BvlcFunction::from_code` is public. A registration and its answer (*tested*):

```rust
{{#include ../examples/src/building_aaa.rs:bacnet_bvlc_only}}
```

### The NPDU

```rust
pub struct Npdu<'a> {
    pub version: u8,                               // 1
    pub control: u8,                               // the raw byte
    pub destination: Option<NetworkAddress<'a>>,   // DNET, DLEN, DADR
    pub source: Option<NetworkAddress<'a>>,        // SNET, SLEN, SADR
    pub hop_count: Option<u8>,                     // present with a destination
    pub message: NpduMessage<'a>,
}

pub struct NetworkAddress<'a> {
    pub network: u16,
    pub address: &'a [u8],                         // MAC address, empty for a broadcast
}

pub enum NpduMessage<'a> {
    Network { message_type: u8, vendor_id: Option<u16>, data: &'a [u8] },
    Apdu(Apdu<'a>),
}
```

The NPDU is the network layer of BACnet, the one that routes between BACnet networks. After its two fixed bytes, what follows depends on the control byte, so the fields have sizes, not offsets:

| Field | Bytes | Present when |
| --- | --- | --- |
| `version` | 1 | always; must be 1 |
| `control` | 1 | always |
| `destination` | 2 + 1 + DLEN | control bit `0x20` |
| `source` | 2 + 1 + SLEN | control bit `0x08` |
| `hop_count` | 1 | a destination is present |
| `message_type` | 1 | control bit `0x80`, then a 2-byte `vendor_id` for types `0x80` and above |
| the rest | | the network message `data`, or the APDU |

| Control bit | Meaning | Read through |
| --- | --- | --- |
| `0x80` | a network-layer message, not an APDU | `NpduMessage::Network` |
| `0x40` | reserved | not checked |
| `0x20` | destination specifier | `destination`, `hop_count` |
| `0x10` | reserved | not checked |
| `0x08` | source specifier | `source` |
| `0x04` | expecting reply | `expecting_reply()` |
| `0x03` | priority | `priority()`: 0 normal, 1 urgent, 2 critical equipment, 3 life safety |

A destination network of 65535 is a global broadcast, and an empty `address` a broadcast on the destination network. Network messages are typed by number only: `message_type`, the `vendor_id` of a proprietary type, and the `data`, raw. `NpduMessage` is `#[non_exhaustive]`: a `match` on it needs a `_` arm. A Who-Is broadcast to every network, then a network message of the same segment (*tested*):

```rust
{{#include ../examples/src/building_aaa.rs:bacnet_broadcast}}
```

### The APDU

```rust
pub struct Apdu<'a> {
    pub apdu_type: u8,                      // high nibble of the first byte
    pub kind: ApduType,
    pub flags: u8,                          // low nibble, as is
    pub invoke_id: Option<u8>,              // absent from an unconfirmed request
    pub max_segments_and_apdu: Option<u8>,  // confirmed request: the raw byte
    pub segment: Option<(u8, u8)>,          // sequence number, window size
    pub service: Option<u8>,                // service choice
    pub reason: Option<u8>,                 // reject or abort reason
    pub data: &'a [u8],                     // the service data, tag-encoded
}
```

The type says which fixed fields follow the first byte; whatever comes after them is `data`:

| Type | `ApduType` | Fields, in wire order |
| --- | --- | --- |
| 0 | `ConfirmedRequest` | `max_segments_and_apdu`, `invoke_id`, `segment` if SEG, `service` |
| 1 | `UnconfirmedRequest` | `service` |
| 2 | `SimpleAck` | `invoke_id`, `service` |
| 3 | `ComplexAck` | `invoke_id`, `segment` if SEG, `service` |
| 4 | `SegmentAck` | `invoke_id`, `segment` |
| 5 | `Error` | `invoke_id`, `service` |
| 6 | `Reject` | `invoke_id`, `reason` |
| 7 | `Abort` | `invoke_id`, `reason` |

`flags` is the low nibble of the first byte: SEG `0x08` and MOR `0x04` in a ConfirmedRequest or a ComplexACK, SA `0x02` in a ConfirmedRequest, NAK `0x02` and SRV `0x01` in a SegmentACK, SRV `0x01` in an Abort. The decoder itself reads only SEG, which says whether a sequence number and a window follow; the other bits are left to the caller.

`confirmed_service()` names the service of a ConfirmedRequest, SimpleAck, ComplexAck or Error among the 34 of `ConfirmedService` (0 `AcknowledgeAlarm` to 33 `AuditLogQuery`), and `unconfirmed_service()` that of an UnconfirmedRequest among the 15 of `UnconfirmedService` (0 `IAm` to 14 `YouAre`). An unknown code is not an error: `service` keeps the byte and the method returns `None`. Both enums have a public `from_code`. A readProperty and the ComplexACK that answers it (*tested*):

```rust
{{#include ../examples/src/building_aaa.rs:bacnet_read_property}}
```

## Validations

All of them are `BacnetParseError`, in `packet_parser::errors::application::bacnet`:

| Error | When |
| --- | --- |
| `Truncated { expected, actual }` | a part is shorter than its fixed fields: the 4-byte BVLC header, the origin of a Forwarded-NPDU, the NPDU header, a network address, the hop count, a network message, the fields of an APDU type; the two numbers count the bytes of that part, not of the datagram |
| `InvalidBvlcType(u8)` | the first byte is not `0x81`; BACnet/IPv6 (annex U), type `0x82` for tshark, ends here |
| `UnknownBvlcFunction(u8)` | a function above `0x0C` |
| `LengthMismatch { declared, actual }` | a BVLC length other than the datagram's, trailing bytes included |
| `UnsupportedNpduVersion(u8)` | an NPDU version other than 1 |
| `UnknownApduType(u8)` | an APDU type above 7 |

In the pipeline, every one of them means the same thing: the label is not given, as the detection section shows.

## Oracle: 45 datagrams, field by field

The golden test `tests/bacnet_golden.rs` runs the two captures of `pcaps_exemple/protocols/bacnet/` and compares every datagram with tshark 4.6.6, frozen in `tests/data/bacnet_tshark_oracle.tsv` by `tools/bacnet_oracle.sh`: ports and payload length, BVLC function and length, NPDU version, control, destination and source networks and address lengths, hop count, network message type, APDU type, invoke id, confirmed or unconfirmed service. The 45 datagrams that carry a BVLC are all labelled `"BACnet/IP"`; the four empty UDP datagrams of the ITI capture stay without application.

| Capture | Datagrams | Content | Origin |
| --- | --- | --- | --- |
| `iti_bacnet_test.pcap` | 22 of 26 frames | two controllers: nine readProperty of the device object and their ComplexACK, a Read-Broadcast-Distribution-Table and a Register-Foreign-Device, both answered by a BVLC-Result | ITI ICS-Security-Tools, CC-BY-4.0 |
| `ndpi_bacnet.pcap` | 23 | nine readProperty that Internet scanners send to an exposed device, then a local network: Who-Is, I-Am, an Error, two network messages | nDPI test corpus, LGPL-3.0 |

Over the 45: 27 Original-Unicast-NPDU, 14 Original-Broadcast-NPDU, two BVLC-Results, one Read-Broadcast-Distribution-Table and one Register-Foreign-Device; 18 ConfirmedRequest, 11 UnconfirmedRequest, 9 ComplexACK and one Error APDU, plus two network messages. One column is compared after a translation: tshark's `bvlc.length` is the size of the BVLC header it consumed (4, or 10 with the origin of a Forwarded-NPDU) when an NPDU follows, and the whole message otherwise; the test rebuilds that value, while the wire field is checked against the datagram by the decoder itself. A second test moves frame 3 of the ITI capture to ports 40000 and 40001, where only the blind rule can label it, then alters one byte at a time (BVLC type, function, length, NPDU version, APDU type): the decoder refuses each of the five, and the label goes.

A run of the 11.6.0 pipeline over the captures the repository tracks, 386 403 frames, gives the label `"BACnet/IP"` to these 45 datagrams and to nothing else: the very frames tshark dissects as BVLC. The fuzz target `parse_bacnet` runs nightly, on its input and on mutations of four real datagrams: whatever it decodes must have the input's length as BVLC length, a hop count exactly when it has a destination, a vendor id exactly on network message types `0x80` and above, and its body and data inside the input.

## What is left out

- **Service data** stays tag-encoded bytes in `Apdu::data`: object identifiers, property values, the device range of a Who-Is, the content of an I-Am. The crate decodes the envelope, not the application tags.
- **Network messages and BVLC control functions** are typed, not decoded: `message_type` and `data`, the result codes, times-to-live and tables in `body`. A Secure-BVLL is recognized and left whole.
- **No state**: no reassembly of segmented messages, no pairing of a request with its acknowledgement by invoke id. One datagram at a time, as in the rest of the crate.
- **Annex J only**: BACnet/IPv6 is refused as `InvalidBvlcType`, and the other data links of the standard reach no decoder.
- **The two reserved bits** of the NPDU control, `0x40` and `0x10`, are not checked: a datagram with one of them set is decoded and labelled like any other.
- **Paths no capture exercises**: the corpus has no segmented message, no SimpleACK, SegmentACK, Reject or Abort, no source address, no Forwarded-NPDU and no proprietary network message. These follow the standard; the last two are checked by unit tests on built bytes, the Forwarded-NPDU wrapped around frame 3.
