# PTP

Precision Time Protocol, IEEE 1588, added in 11.5.0 ([#121](https://github.com/Akmot9/Packet-parser/issues/121)) as the first protocol of the defense lot ([#125](https://github.com/Akmot9/Packet-parser/issues/125)): it synchronizes radars, combat systems and TSN avionics (802.1AS), and on the OT side the electrical substations (C37.238). The module is `packet_parser::parse::application::protocols::ptp`, whichever way the message travels.

## Two carriers, two places in `PacketFlow`

PTP has two transports in the standard, and the crate follows both:

- **UDP 319 and 320** (annex D over IPv4, annex E over IPv6): the datagram gets the application label `"PTP"`, like any other protocol of the [dispatch table](./application.md).
- **Raw Ethernet, EtherType `0x88F7`** (annex F), VLAN-tagged or not: there is no IP and no UDP, so the message *is* the internet layer, `NetworkProtocol::Ptp` on the [internet page](./network.md).

![Two PacketFlow stacks: frame 25, Ethernet, IPv4, UDP 319 to 319 and the application label PTP, decoded by PtpPacket::try_from_udp into a Sync; frame 1, Ethernet with EtherType 0x88F7, an internet layer named PTP holding the decoded Pdelay_Req in InternetDetails::Ptp, transport and application None](images/application/ptp_carriers.svg)

On UDP the rule is **port-guarded**: `port_rule("PTP", Guard::Udp, is_ptp_port, ProbeId::Ptp)`, 319 or 320 on either side. A blind probe is not possible here: the header has no magic, a `messageType` nibble does not tell PTP from arbitrary bytes, and a `Delay_Req` has exactly the shape of an SLPv1 header, which is how 829 of them were once labelled SRVLOC ([#117](https://github.com/Akmot9/Packet-parser/issues/117)). PTP on another UDP port is declared with `ParseConfig::decode_as(port, DecodeAsProtocol::Ptp)`. The probe is `PtpPacket::try_from_udp`, stricter than the plain `TryFrom`: the message must fill the datagram, or all of it but the **two bytes of annex E**, the checksum correction field that UDP over IPv6 appends; anything else is `UnexpectedTrailingBytes`.

On Ethernet the internet dispatch calls `PtpPacket::try_from` and the flow gets an `Internet` with `protocol_name` `"PTP"`, no addresses, `payload_protocol` `None`, and the decoded message in `InternetDetails::Ptp`; `transport` and `application` stay `None`. Ethernet pads short frames, so the bytes after `messageLength` are admitted and exposed in `PtpV2Message::trailing`. A `versionPTP` other than 1 or 2, or a reserved `messageType`, is not a corruption but an `InternetError::UnsupportedProtocol`, the outcome every `0x88F7` frame had before 11.5.0; a truncated or inconsistent message is `InternetError::PtpError`, reported in `corrupted` as `PTP error: …`.

Both carriers, on two frames of the same capture (*tested*):

```rust
{{#include ../examples/src/lib.rs:ptp_two_carriers}}
```

## The message

```rust
pub enum PtpPacket<'a> {
    V2(PtpV2Message<'a>),
    V1(PtpV1Message<'a>),
}
```

The version is the low nibble of byte 1: 2 for IEEE 1588-2008 and 2019, 1 for IEEE 1588-2002, whose 16-bit `versionPTP` happens to put a 1 in that very byte. Any other value is `UnsupportedVersion`. `PtpPacket::version()` and `PtpPacket::sequence_id()` answer without matching on the variant.

![The 44-byte PTPv2 Sync message of frame 25, 32 bits per row: the 34-byte header with messageType 0 and versionPTP 2 in orange, messageLength 44, the clock identity, port 1, sequenceId 115, then the Sync body, an originTimestamp of 1169232217 seconds and 174421797 nanoseconds; on the right, PtpV2Header with message_type 0 Sync, version 2, length 44, sequence 115, and PtpV2Message with the header, the Sync body, empty TLVs and no trailing byte](images/application/ptp_header.svg)

### PTPv2: `PtpV2Message`

```rust
pub struct PtpV2Message<'a> {
    pub header: PtpV2Header,
    pub body: PtpV2Body,
    pub tlvs: PtpTlvs<'a>,    // between the body and messageLength
    pub trailing: &'a [u8],   // after messageLength: Ethernet padding, annex E bytes
}
```

`PtpV2Header` is the 34-byte common header of §13.3, decoded field by field:

| Bytes | Field | Note |
| --- | --- | --- |
| 0 | `major_sdo_id` (high nibble), `message_type` (low nibble) | `majorSdoId` is `transportSpecific` in 1588-2008: 1 for 802.1AS |
| 1 | `minor_version_ptp` (high), `version_ptp` (low) | 2 |
| 2–3 | `message_length` | header, body and TLVs; what follows is `trailing` |
| 4 | `domain_number` | |
| 5 | `minor_sdo_id` | reserved in 1588-2008 |
| 6–7 | `flags` | two-step, unicast, timescale, leap flags… left as bits |
| 8–15 | `correction_field` | `i64`, nanoseconds × 2¹⁶ |
| 16–19 | `message_type_specific` | |
| 20–29 | `source_port_identity` | `PortIdentity { clock_identity: [u8; 8], port_number: u16 }` |
| 30–31 | `sequence_id` | |
| 32 | `control_field` | PTPv1 heritage, kept for compatibility |
| 33 | `log_message_interval` | `i8` |

The body depends on `message_type`, and so does the **minimum `messageLength`** (§13.5 to §13.13): a declared length below it, or beyond the bytes received, is `InvalidMessageLength { message_type, declared, minimum, available }`.

| `messageType` | `PtpV2Body` | Minimum | Fields |
| --- | --- | --- | --- |
| `0x0` | `Sync` | 44 | `origin_timestamp` |
| `0x1` | `DelayReq` | 44 | `origin_timestamp` |
| `0x2` | `PdelayReq` | 54 | `origin_timestamp` (then 10 reserved bytes) |
| `0x3` | `PdelayResp` | 54 | `request_receipt_timestamp`, `requesting_port_identity` |
| `0x8` | `FollowUp` | 44 | `precise_origin_timestamp` |
| `0x9` | `DelayResp` | 54 | `receive_timestamp`, `requesting_port_identity` |
| `0xA` | `PdelayRespFollowUp` | 54 | `response_origin_timestamp`, `requesting_port_identity` |
| `0xB` | `Announce(PtpAnnounce)` | 64 | `origin_timestamp`, `current_utc_offset`, `grandmaster_priority1`, `grandmaster_clock_quality`, `grandmaster_priority2`, `grandmaster_identity`, `steps_removed`, `time_source` |
| `0xC` | `Signaling` | 44 | `target_port_identity` |
| `0xD` | `Management` | 48 | `target_port_identity`, `starting_boundary_hops`, `boundary_hops`, `action` |
| `0x4`–`0x7`, `0xE`, `0xF` | — | — | `ReservedMessageType` |

A `PtpTimestamp` is `seconds: u64` (48 bits on the wire) and `nanoseconds: u32`; a `ClockQuality` is `clock_class`, `clock_accuracy` and `offset_scaled_log_variance`. The values are decoded, not interpreted: the crate computes no offset and keeps no clock state, as everywhere else it is stateless, one message at a time.

### TLVs: a view, read on demand

Between the body and `messageLength` come the TLVs of §14.1, where the profiles put what makes them different (the organization extensions of C37.238, the path trace of 802.1AS, the management payload of ST 2059-2). `PtpTlvs` is a **stateless view** over those bytes: `tlvs.iter()` (or `for tlv in message.tlvs`) walks them from the start and yields `Result<PtpTlv, PtpPacketParseError>`, each `PtpTlv { tlv_type: u16, value: &[u8] }` borrowing the packet, the value raw. A truncated TLV comes out as `TruncatedTlv { tlv_type, offset, needed, available }` and the iterator stops there. The message decode never depends on the TLVs being valid: a message with a broken TLV area is still a message, which is what the oracle below does too. `tlvs.as_bytes()` gives the area whole.

### PTPv1: `PtpV1Message`

IEEE 1588-2002 is recognized by its 40-byte header and left otherwise raw:

```rust
pub struct PtpV1Message<'a> {
    pub header: PtpV1Header<'a>,  // versionPTP, versionNetwork, subdomain, messageType,
                                  // sourceCommunicationTechnology, sourceUuid, sourcePortId,
                                  // sequenceId, control, flags
    pub body: &'a [u8],
}
```

The validations are the ones of the 2002 text: `versionPTP` must be exactly 1 (`InvalidV1VersionPtp`), `versionNetwork` 1 (`UnsupportedNetworkVersion`), `control` one of Sync 0, Delay_Req 1, Follow_Up 2, Delay_Resp 3, Management 4 (`ReservedControl`), `messageType` consistent with it, 1 for the two event messages and 2 for the general ones (`InconsistentMessageType`), and the length fixed by `control`: 124 bytes for Sync and Delay_Req, 52 for Follow_Up, 60 for Delay_Resp, at least 40 for Management (`InvalidV1Length { control, expected, actual }`).

## Validations

All of them are `PtpPacketParseError`, in `packet_parser::errors::application::ptp`:

| Error | When |
| --- | --- |
| `Truncated { expected, actual }` | fewer bytes than the header, or than the body of the type, needs |
| `UnsupportedVersion(u8)` | `versionPTP` is neither 1 nor 2 |
| `ReservedMessageType(u8)` | PTPv2 `messageType` `0x4`–`0x7`, `0xE` or `0xF` |
| `InvalidMessageLength { message_type, declared, minimum, available }` | `messageLength` below the minimum of the type, or beyond the bytes received |
| `UnexpectedTrailingBytes { trailing }` | `try_from_udp` only: bytes after `messageLength` other than the two of annex E |
| `TruncatedTlv { tlv_type, offset, needed, available }` | from the TLV iterator, never from the message decode |
| `InvalidV1VersionPtp`, `UnsupportedNetworkVersion`, `ReservedControl`, `InconsistentMessageType`, `InvalidV1Length` | PTPv1, see above |

What a failure means depends on the carrier. On UDP, the label is simply not given: the datagram is probed by the next rules and ends `"Unknown"`, with nothing in `corrupted`, because a port is a hint and the payload may belong to something else. On `0x88F7` the EtherType has announced PTP, so the failure is a verdict: `UnsupportedProtocol` for an unknown version or type, a corrupted internet layer for the rest, exactly the distinction the [internet page](./network.md#dispatch-on-the-announced-protocol-not-probing) draws for every announced protocol.

## Oracle: 3 328 messages, frame by frame

The golden test `tests/ptp_golden.rs` runs the eight captures of `pcaps_exemple/protocols/ptp/` and compares every message with tshark 4.6.6, frozen in `tests/data/ptp_tshark_oracle.tsv`: version, type, length, domain, `sequenceId`, source identity and the list of TLV types. 3 217 PTPv2 and 4 PTPv1 messages on UDP, 107 PTPv2 at layer 2, one of them VLAN-tagged; the two ICMP messages that quote a PTP datagram are ICMP and excluded; no frame of the other corpus folders comes out PTP. The fuzz target `parse_ptp` runs nightly on the same parser.

| Capture | Messages | Equipment, profile | Origin |
| --- | --- | --- | --- |
| `ptpv2.pcap` | 39 | Hirschmann, PTPv2, UDP and layer 2 | Wireshark wiki |
| `PTP_sync.pcap` | 4 | Fujitsu Siemens, **PTPv1** | Wireshark wiki |
| `ndpi_ptpv2.pcap` | 14 | Symmetricom, PTPv2 over **IPv6** | nDPI test corpus |
| `wireshark_6126_nodeb_startup.pcap` | 3 179 | a 3G NodeB, telecom profile | Wireshark issue 6126 |
| `wireshark_14578_white_rabbit.pcap` | 85 | Seven Solutions, White Rabbit, layer 2 | Wireshark issue 14578 |
| `wireshark_7694_c37_238.pcap` | 1 | SEL, power profile IEEE C37.238, layer 2 | Wireshark issue 7694 |
| `wireshark_12264_st2059_mgt.pcap` | 1 | Meinberg, SMPTE ST 2059-2 management | Wireshark issue 12264 |
| `wireshark_4761_802_1as.pcap` | 7 | Marvell, IEEE 802.1AS (gPTP), layer 2 | Wireshark issue 4761 |

The NodeB capture is the one that taught the SRVLOC probe its language check: its 829 `Delay_Req` are the frames of [#117](https://github.com/Akmot9/Packet-parser/issues/117).

## What is left out

- **TLV values** are not decoded: type and raw bytes only. The profiles (802.1AS, C37.238, ST 2059-2, telecom) are visible through `flags`, `major_sdo_id` and the TLV types, not interpreted.
- **PTPv1 bodies** stay raw; only the header is decoded.
- **No clock state**: no offset, no best-master decision, no pairing of a `Follow_Up` with its `Sync`. One message at a time, like the rest of the crate.
- **Other carriers** of the annexes (DeviceNet, ControlNet, PROFINET) are not recognized; UDP 319/320 and `0x88F7` are.
- **Security** (annex K of 2008, clause 16 of 2019) is not checked; a secured message decodes like any other, its authentication TLV listed with the rest.
