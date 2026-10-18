# STANAG 5066 SIS

STANAG 5066 SIS, the Subnetwork Interface Sublayer of annex A (Edition 4, draft v1.6 published by Isode), added in 11.6.0 ([#122](https://github.com/Akmot9/Packet-parser/issues/122)) as part of the defense lot ([#125](https://github.com/Akmot9/Packet-parser/issues/125)): the layer that connects applications to an HF radio node, for links beyond the horizon, over TCP 5066. It carries notably ACP 142 (P_MUL) and the military messaging of STANAG 4406 annex E. The module is `packet_parser::parse::application::protocols::stanag5066`.

The unit is the S_PDU: the preamble `90 EB`, a version byte, two bytes of primitive size and the type of the primitive, one of 27, each decoded into typed values. The decoder is stateless, like [GIOP](./giop.md#stateless-on-a-protocol-that-ignores-segment-boundaries): it decodes the first S_PDU of a TCP segment, accepts one that overflows the segment, and says where the next one starts.

## Detection: TCP 5066 only

```rust
// among the port rules, after IKE, ESP and NAT-keepalive: TCP 5066 on either side
port_rule("STANAG 5066", Guard::Tcp, is_stanag5066_tcp_port, ProbeId::Stanag5066),
```

with the probe

```rust
ProbeId::Stanag5066 => SisPdu::try_from(payload).is_ok(),
```

TCP 5066 is the IANA port (`stanag-5066`) and the one Wireshark registers. There is no blind rule: the preamble `90 EB 00`, a type and a size are three fixed bytes and two constraints, too little to probe every TCP segment with. A node on another port is declared with `ParseConfig::decode_as(port, DecodeAsProtocol::Stanag5066)`, which maps to the same probe behind the same TCP guard, `("STANAG 5066", Guard::Tcp, ProbeId::Stanag5066)`, evaluated before the table like every [Decode As](./application.md#decode-as) port. `Application::try_from`, which has no ports, never answers STANAG 5066. The probe sees only the first 18 KiB of the payload (`PROBE_CAP`), like most probes: a first S_PDU that runs past that bound is judged as a truncated one.

The guard on a real S_PDU moved to port 5067 (*tested*):

```rust
{{#include ../examples/src/defense_a.rs:sis_port_guard}}
```

## The S_PDU

![The S_BIND_REQUEST of frame 25 of S5066-HFChat-1.pcap, 32 bits per row: the sync preamble 90 EB, version 0, a primitive size of 4, the PDU type 1, then the primitive itself, SAP 5 (HF Chat) and rank 1 in one byte, the service type byte 0x14 (ARQ, node delivery confirmation) and an unused byte; SisPdu keeps the SisHeader, the named type and the typed primitive.](images/application/stanag5066_struct.svg)

```rust
#[non_exhaustive]
pub struct SisHeader {
    pub version: u8,
    /// Size of the primitive, type included.
    pub primitive_size: u16,
    pub pdu_type: u8,
}

#[non_exhaustive]
pub struct SisPdu<'a> {
    pub header: SisHeader,
    pub pdu_type: PduType,          // the named type
    pub primitive: SisPrimitive<'a>,
    /// The segment does not hold the whole announced primitive: the S_PDU
    /// goes on in the next segment.
    pub truncated: bool,
    // bytes of this S_PDU present in the buffer, read with consumed()
}
```

| Bytes | Field | Note |
| --- | --- | --- |
| 0–1 | preamble | `90 EB`, not kept |
| 2 | `version` | 0, the only one defined |
| 3–4 | `primitive_size` | type included: the S_PDU is 5 + `primitive_size` bytes |
| 5 | `pdu_type` | 1 to 27; `SisPdu::pdu_type` is the `PduType` |
| 6– | the primitive | `primitive_size` − 1 bytes, decoded into `SisPrimitive` |

A bind, as an HF Chat client and its node exchange it (*tested*):

```rust
{{#include ../examples/src/defense_a.rs:sis_bind}}
```

## Twenty-seven primitives, eight variants

Neighbouring primitives share a variant: the hard links (6 to 13), the management messages (18, 19), the data primitives and their confirmations (20 to 27).

```rust
#[non_exhaustive]
pub enum SisPrimitive<'a> {
    /// S_BIND_REQUEST.
    Bind { sap_id: u8, rank: u8, service_type: ServiceType },
    /// S_BIND_ACCEPTED.
    BindAccepted { sap_id: u8, mtu: u16 },
    /// S_BIND_REJECTED and S_UNBIND_INDICATION.
    Rejected { reason: u8 },
    /// S_HARD_LINK_*: `reason` for REJECTED, TERMINATED and REJECT,
    /// `remote_status` for ESTABLISHED and INDICATION; TERMINATE only
    /// carries the address.
    HardLink {
        reason: Option<u8>,
        remote_status: Option<u8>,
        link_type: Option<u8>,      // two bits
        priority: Option<u8>,       // two bits
        remote_sap_id: Option<u8>,
        remote_node: NodeAddress,
    },
    /// S_SUBNET_AVAILABILITY.
    SubnetAvailability { status: u8, reason: u8 },
    /// S_MANAGEMENT_MESSAGE_REQUEST and INDICATION.
    Management { message_type: u8, body: &'a [u8] },
    /// S_UNIDATA_* and S_EXPEDITED_UNIDATA_*: `priority` for the requests and
    /// indications that are not expedited, `reason` for the rejections,
    /// `service_type`, `minimum_retransmissions` and `time_to_live` for the
    /// requests, `transmission_mode`, `source_sap_id` and `source` for the
    /// indications.
    Unidata {
        priority: Option<u8>,
        reason: Option<u8>,
        destination_sap_id: u8,
        destination: NodeAddress,
        service_type: Option<ServiceType>,
        minimum_retransmissions: Option<u8>,
        /// Twenty bits, LSB 2 s.
        time_to_live: Option<u32>,
        transmission_mode: Option<u8>,
        source_sap_id: Option<u8>,
        source: Option<NodeAddress>,
        /// Announced size of the U_PDU.
        u_pdu_size: u16,
        /// The U_PDU present in the segment: shorter than `u_pdu_size`
        /// when the S_PDU is truncated.
        u_pdu: &'a [u8],
    },
    /// S_UNBIND_REQUEST, S_DATAFLOW_ON, S_DATAFLOW_OFF, S_KEEP_ALIVE.
    Empty,
}
```

The fixed fields of each type must be present, within the announced size and within the segment, or the S_PDU is `PrimitiveTooShort`; the minimum counts the bytes after the type byte.

| Code | `PduType` | `SisPrimitive` | Fixed bytes |
| --- | --- | --- | --- |
| 1 | `BindRequest` | `Bind` | 3 |
| 2 | `UnbindRequest` | `Empty` | 0 |
| 3 | `BindAccepted` | `BindAccepted` | 3 |
| 4, 5 | `BindRejected`, `UnbindIndication` | `Rejected` | 1 |
| 6, 12 | `HardLinkEstablish`, `HardLinkAccept` | `HardLink`: type, priority, remote SAP, node | 5 |
| 7 | `HardLinkTerminate` | `HardLink`: node only | 4 |
| 8, 11 | `HardLinkEstablished`, `HardLinkIndication` | `HardLink`: `remote_status` first | 6 |
| 9, 10, 13 | `HardLinkRejected`, `HardLinkTerminated`, `HardLinkReject` | `HardLink`: `reason` first | 6 |
| 14 | `SubnetAvailability` | `SubnetAvailability` | 2 |
| 15, 16, 17 | `DataflowOn`, `DataflowOff`, `KeepAlive` | `Empty` | 0 |
| 18, 19 | `ManagementMessageRequest`, `ManagementMessageIndication` | `Management` | 1 |
| 20, 24 | `UnidataRequest`, `ExpeditedUnidataRequest` | `Unidata` | 11 |
| 21, 25 | `UnidataIndication`, `ExpeditedUnidataIndication` | `Unidata` | 12 |
| 22, 26 | `UnidataRequestConfirm`, `ExpeditedUnidataRequestConfirm` | `Unidata` | 7 |
| 23, 27 | `UnidataRequestRejected`, `ExpeditedUnidataRequestRejected` | `Unidata` | 7 |

A bind request puts the SAP, the service access point the client binds to, in the high nibble of byte 6 and the rank in the low one, then the service type in byte 7; an acceptance puts the SAP in the high nibble of byte 6 and the MTU in bytes 7–8. The hard links other than S_HARD_LINK_TERMINATE pack their link type (two bits), priority (two bits) and remote SAP (four bits) in one byte, preceded by the status or the reason when the type has one, and followed by the node address; S_HARD_LINK_TERMINATE carries the node address alone.

### Data primitives (20 to 27)

The data primitives are the traffic itself. Their layout, in bytes of the S_PDU:

| Field | Requests 20, 24 | Indications 21, 25 | Confirmations, rejections 22, 23, 26, 27 |
| --- | --- | --- | --- |
| `priority`, high nibble | 6 (20 only) | 6 (21 only) | — |
| `reason`, high nibble | — | — | 6 (23, 27 only) |
| `destination_sap_id`, low nibble | 6 | 6 | 6 |
| `destination` | 7–10 | 7–10 | 7–10 |
| `service_type` | 11 | — | — |
| `minimum_retransmissions`, high nibble | 12 | — | — |
| `time_to_live`, 20 bits | 12–14 | — | — |
| `transmission_mode` (high nibble), `source_sap_id` (low) | — | 11 | — |
| `source` | — | 12–15 | — |
| `u_pdu_size` | 15–16 | 16–17 | 11–12 |
| `u_pdu` | 17– | 18– | 13– |

The `time_to_live` is raw, in units of two seconds (tshark labels it "x2 seconds"). Two records recur:

```rust
#[non_exhaustive]
pub struct NodeAddress {
    /// Announced size, in half-bytes.
    pub size: u8,
    pub group: bool,
    /// The 28 address bits, 0x0a324202 for 10.50.66.2.
    pub address: u32,
    /// The four bytes, as they are.
    pub raw: [u8; 4],
}

#[non_exhaustive]
pub struct ServiceType {
    /// Four bits: 1 ARQ, 2 non-ARQ (broadcast), 3 non-ARQ with errors.
    pub transmission_mode: u8,
    /// Two bits: 0 none, 1 confirmation by the node, 2 by the client.
    pub delivery_confirmation: u8,
    /// The delivery-order bit is zero: in-order delivery.
    pub in_order_delivery: bool,
    /// An extended field follows.
    pub extended: bool,
    pub raw: u8,
}
```

A node address is read on four bytes, like tshark does: three bits of size, one group bit, 28 bits of address. Its `Display` is tshark's dotted notation, the 29 low bits of the four bytes, group bit included, written like an IPv4 address.

The U_PDU of a complete S_PDU must be exactly `u_pdu_size` bytes, with one tolerance: an indication (21, 25) may carry four more, the counters a Rockwell Collins node (v2.1 and earlier) inserts before the U_PDU, which the decoder skips like tshark. Any other size is `PrimitiveTooShort`, even a longer U_PDU: `expected` is then the announced size and `actual` the bytes found. An indication in transmission mode 3, non-ARQ with errors, puts two lists before its U_PDU, the errored blocks then the missing ones, each a two-byte count followed by four bytes per block; the decoder skips them to reach the U_PDU.

An S_UNIDATA_REQUEST carrying ACP 142 (*tested*):

```rust
{{#include ../examples/src/defense_a.rs:sis_unidata_request}}
```

## Stateless: one S_PDU at a time

An S_PDU and a TCP segment have no reason to coincide: one S_PDU may be split over several segments, and one segment may hold several S_PDUs. The HF Chat client and node of the corpus send every data primitive in two segments, its header and fixed fields then its U_PDU, even when the whole S_PDU is only 29 bytes; the ACP 142 capture packs three S_PDUs of 2 065 bytes into one segment. With no reassembly, the decoder follows four rules:

1. **An S_PDU that overflows its segment is accepted and flagged** `truncated`. Its fixed fields are decoded, and `u_pdu` is what the segment holds, possibly nothing. The fixed fields must all be there: a segment that cuts them is `PrimitiveTooShort`, truncated or not.
2. **A continuation segment is not SIS.** It does not start with the preamble, so `try_from` refuses it (`InvalidPreamble`, or `Truncated` below six bytes), and the segment is labelled by whatever else matches: `"Unknown"`, for the five of the corpus.
3. **What follows a complete S_PDU must start another one**: nothing, or as many bytes of `90 EB 00` as remain, up to three. Anything else is `UnexpectedTrailingBytes`, and the segment is not labelled STANAG 5066.
4. **`consumed()` says where the next S_PDU starts**: the bytes of this S_PDU present in the buffer, header included, which for a truncated S_PDU is the whole buffer. A caller reads the next S_PDU at `&payload[pdu.consumed()..]`.

An S_UNIDATA_INDICATION split over two segments (*tested*):

```rust
{{#include ../examples/src/defense_a.rs:sis_split_pdu}}
```

and the only segment of the corpus that holds several S_PDUs, three S_UNIDATA_REQUESTs walked with `consumed` (*tested*):

```rust
{{#include ../examples/src/defense_a.rs:sis_consumed}}
```

## Validations

All of them are `Stanag5066ParseError`, in `packet_parser::errors::application::stanag5066`:

| Error | When |
| --- | --- |
| `Truncated { expected, actual }` | fewer than 6 bytes, the header and the type |
| `InvalidPreamble([u8; 2])` | the first two bytes are not `90 EB` |
| `UnsupportedVersion(u8)` | a version other than 0 |
| `EmptyPrimitive` | a `primitive_size` of 0, which cannot hold the type |
| `ReservedPduType(u8)` | a type other than 1 to 27 |
| `PrimitiveTooShort { pdu_type, expected, actual }` | the fixed fields of the type are missing, or a complete S_PDU holds a U_PDU of another size than announced |
| `UnexpectedTrailingBytes { trailing }` | after a complete S_PDU, bytes that do not start `90 EB 00` |

Like every application decoder, a failure is not a corruption: the segment goes on to the next rules of the table, and nothing goes to `corrupted`.

## Oracle: 34 segments, without reassembly

The golden test `tests/stanag5066_golden.rs` runs the four captures of `pcaps_exemple/protocols/stanag5066/` and compares every segment with tshark 4.6.6 **without TCP reassembly** (`tcp.desegment_tcp_streams:FALSE`), the view of a stateless parser, frozen in `tests/data/stanag5066_tshark_oracle.tsv` by `tools/stanag5066_oracle.sh`: S_PDU types, primitive sizes, node addresses, SAPs, U_PDU sizes, transmission modes, TTLs, ranks, MTUs and reasons. The 34 segments where tshark sees SIS are labelled `"STANAG 5066"` and decoded alike, 36 S_PDUs of 13 of the 27 types; the 5 continuation segments, where tshark sees no SIS without reassembly, come out `"Unknown"`; 5 S_PDUs split between two segments are decoded on their first one and flagged `truncated`, three in `S5066-HFChat-1.pcap` (an indication, a request, a confirmation) and two in `S5066-HFChat-Rejected.pcap` (a request, a rejection). The other 47 frames are TCP segments without payload.

| Capture | Frames (with an S_PDU) | Content | Origin |
| --- | --- | --- | --- |
| `S5066-HFChat-1.pcap` | 44 (6) | an HF Chat client and its node, the NATO C3 Agency test bench, 2005 | Wireshark wiki |
| `S5066-HFChat-Rejected.pcap` | 19 (5) | the same bench, an S_UNIDATA_REQUEST rejected with reason 3 | Wireshark wiki |
| `S5066-Expedited.pcap` | 13 (13) | expedited data and hard links on the loopback, 2006 | Wireshark wiki |
| `wireshark_10827_sis_acp142.pcap` | 10 (10) | ACP 142 over SIS on the loopback, 2015 | Wireshark issue 10827 |

In the golden histogram of the whole corpus, `"STANAG 5066"` went from 0 to 34 with 11.6.0, all taken from `"Unknown"`. The fuzz target `parse_stanag5066` runs nightly: no panic, and every S_PDU it decodes consumes no more than the input, borrows its U_PDU from the input, and, when truncated, consumes the rest of it.

## What is left out

- **No reassembly**: the U_PDU of a split S_PDU is what its first segment holds, and the continuation segments come out `"Unknown"`. A caller that tracks the TCP stream has `u_pdu_size` to rebuild it.
- **The U_PDU stays raw**: the ACP 142 (P_MUL) or STANAG 4406 annex E message it carries, behind its client transport header, is not decoded; neither is the body of a management message.
- **Skipped, not exposed**: the block lists of an indication in mode 3, and the minimum number of retransmissions that follows the service type of an S_BIND_REQUEST (the data requests do expose theirs).
- **Values are numbers**: SAP identifiers, reasons and statuses are not named.
- **The DTS layer** below the SIS is out of scope: the wiki's DTS captures are LINKTYPE 237, which the crate does not read, or DTS encapsulated on TCP 5067 to 5069, which is not SIS.
