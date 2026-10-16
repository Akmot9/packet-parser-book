# RTPS

Real-Time Publish-Subscribe, the wire protocol of DDS (OMG DDSI-RTPS 2.x), added in 11.6.0 ([#120](https://github.com/Akmot9/Packet-parser/issues/120)) with the defense lot ([#125](https://github.com/Akmot9/Packet-parser/issues/125)). DDS is the middleware of recent combat system architectures (NGVA, GVA, naval systems) and of ROS 2, and RTPS succeeds GIOP/MIOP in that role. The module is `packet_parser::parse::application::protocols::rtps`.

## Detection: a magic, then an exact tiling

An RTPS message fills one UDP datagram. As for [PTP](./ptp.md) on UDP, the pipeline gives the datagram a label, `"RTPS"`, and nothing more: the decode is `RtpsPacket::try_from` on the transport payload.

The rule is a **blind probe**, `rule("RTPS", Guard::Udp, ProbeId::Rtps)`, in the blind cascade of the [dispatch table](./application.md#reading-the-table), right after the blind NTP rule and before ASTERIX. There is no port guard: Cyclone DDS and Connext Micro send between random unicast ports, which is why the dispatch probes blind (frame 9 below goes from 54020 to 58584, the Connext Micro capture of the corpus to 21914). What identifies RTPS is its first four bytes, then its structure:

```rust
ProbeId::Rtps => {
    (full_payload.starts_with(b"RTPS") || full_payload.starts_with(b"RTPX"))
        && RtpsPacket::try_from(full_payload).is_ok()
}
```

- the magic is a **constant-cost guard**, as for GIOP: the decoder only runs on a datagram that starts with `RTPS`, or with `RTPX`, a variant RTI Connext emits;
- the decoder reads the **whole payload**, not only the first `PROBE_CAP` = 18 KiB that most probes, ASTERIX's among them, see: a 60 KB `DATA_FRAG` is still RTPS, and the six of `wireshark_15227_reassembly_one_each.pcapng`, up to 65 064 bytes of payload, are labelled;
- the submessages must **tile the datagram exactly**; a reserved `submessageId` or a body too short for its kind refuses the message.

A refused message is not a corruption: the label is not given, the datagram goes on down the table and usually comes out `"Unknown"`, with nothing in `corrupted`. RTPS is probed on UDP only, and there is no `DecodeAsProtocol` variant for it: a rule without a port guard has no port to extend.

Cyclone DDS on the macOS loopback, between two random ports (*tested*):

```rust
{{#include ../examples/src/defense_b.rs:rtps_random_port}}
```

## The message

```rust
pub enum RtpsPacket<'a> {
    Message(RtpsMessage<'a>),
    Ping(RtpsPing),
}

pub struct RtpsMessage<'a> {
    pub header: RtpsHeader,
    pub submessages: Vec<RtpsSubmessage<'a>>,   // in wire order
}

pub struct RtpsHeader {
    pub magic: [u8; 4],          // RTPS, or RTPX (RTI Connext)
    pub version_major: u8,
    pub version_minor: u8,
    pub vendor_id: u16,          // 0x0101 RTI Connext, 0x0110 Cyclone DDS...
    pub guid_prefix: [u8; 12],
}
```

Every type of the module is `#[non_exhaustive]`. `RtpsPacket::version()` returns `(major, minor)`, `vendor_id()` the vendor, and `message()` the message, `None` for a ping.

The header is the 20 bytes of DDSI-RTPS 2.5 §9.4.4:

| Bytes | Field | Note |
| --- | --- | --- |
| 0–3 | `magic` | `RTPS` or `RTPX`; anything else is `InvalidMagic` |
| 4 | `version_major` | 2; anything else is `UnsupportedVersion`: RTPS 1.x, another format, is not decoded |
| 5 | `version_minor` | not checked: 1 in 230 frames of the corpus, 2 in the CoreDX one |
| 6–7 | `vendor_id` | big-endian |
| 8–19 | `guid_prefix` | the twelve bytes, as they are |

### The RTI ping

RTI Connext also sends sixteen-byte "pings" to probe a participant: the magic, the version, the vendorId and the text `NDDSPING`, with neither guidPrefix nor submessage. They are outside the specification, but tshark counts them as RTPS, and so does the crate:

```rust
pub struct RtpsPing {
    pub magic: [u8; 4],
    pub version_major: u8,
    pub version_minor: u8,
    pub vendor_id: u16,
    pub text: [u8; 8],   // NDDSPING
}
```

A payload of exactly 16 bytes ending with `NDDSPING` is an `RtpsPacket::Ping`, its magic and version still checked; sixteen bytes without the text are a truncated header, `Truncated { expected: 20, actual: 16 }`. The corpus has eight pings, seven in `RTPS_Discovery.pcapng` and one in `rtps.pcap`, all counted by the golden test; the one of `rtps.pcap` (*tested*):

```rust
{{#include ../examples/src/defense_b.rs:rtps_ping}}
```

## Submessages

After the header, the message is a run of submessages, each introduced by four bytes (§9.4.5.1):

| Bytes | Field | Note |
| --- | --- | --- |
| 0 | `submessageId` | gives `kind`; a reserved value is `ReservedSubmessageId` |
| 1 | `flags` | bit `0x01` is E, the byte order; the other bits depend on the kind |
| 2–3 | `octetsToNextHeader` | the length of the body, in the byte order of E |

```rust
pub struct RtpsSubmessage<'a> {
    pub kind: SubmessageKind,
    pub id: u8,
    pub flags: u8,
    pub little_endian: bool,          // flag E
    pub octets_to_next_header: u16,   // as carried by the wire
    pub body: &'a [u8],               // after the four header bytes, zero-copy
    pub details: SubmessageDetails,
}
```

### Byte order: one flag per submessage

`little_endian` is flag E, `flags & 0x01`. Each submessage chooses its own byte order, and the crate reads in it every number of the submessage: `octetsToNextHeader`, sequence numbers, counts, fragment numbers and sizes, `numBits`, timestamps. A `SequenceNumber_t` is a signed high half then an unsigned low half, each in that order, returned as an `i64`. Two fields do not follow E: the entity ids, kept as the four octets of the `EntityId_t` read big-endian (`0x000003c2` for the built-in publications writer, for instance), and the vendorId, big-endian in `INFO_SRC` as in the header. All 544 submessages of the corpus set E: only the crate's unit tests, on synthetic bytes, read big-endian ones.

### `octetsToNextHeader`: a length, or zero

The body is `octetsToNextHeader` bytes long. Zero means that the submessage runs **to the end of the message**, which only the last one can do, except for PAD and INFO_TS, where zero is an empty body. `octets_to_next_header` keeps what the wire carries, `body` what it covers; a length beyond the end of the datagram is `SubmessageOverflow`. The thirteen zeros of the corpus are the final DATA of the thirteen OpenDDS messages; the first of them (*tested*):

```rust
{{#include ../examples/src/defense_b.rs:rtps_to_the_end}}
```

The sequence number of that DATA has a high half of −1, like those of frames 12 and 13, the two other DATA of the capture that carry a key and no data: −4 294 967 296 as an `i64`, which is also what `tshark -T fields` prints, where `tshark -V` shows the unsigned 18 446 744 069 414 584 320.

### Kinds and their fields

`SubmessageKind` names the identifiers of the specification up to RTPS 2.4, of DDS Security 1.1 and of the vendor range; the HeaderExtension that RTPS 2.5 adds at `0x00` is not among them. `SubmessageDetails` decodes, for the kinds of the specification, the entity ids, sequence numbers, counters, timestamps and fragmentation fields, once the body has been checked to be long enough for them:

| `submessageId` | `SubmessageKind` | `SubmessageDetails` | Minimum body |
| --- | --- | --- | --- |
| `0x15` DATA | `Data` | `Data { reader_id, writer_id, writer_sequence_number, inline_qos, serialized_payload, serialized_key }` | 20 |
| `0x16` DATA_FRAG | `DataFrag` | `DataFrag { reader_id, writer_id, writer_sequence_number, fragment_starting_number, fragments_in_submessage, fragment_size, sample_size }` | 32 |
| `0x07` HEARTBEAT | `Heartbeat` | `Heartbeat { reader_id, writer_id, first_sequence_number, last_sequence_number, count }` | 28 |
| `0x06` ACKNACK | `AckNack` | `AckNack { reader_id, writer_id, bitmap_base, num_bits, count, final_flag }` | 24 + bitmap |
| `0x08` GAP | `Gap` | `Gap { reader_id, writer_id, gap_start, gap_list_base, num_bits }` | 28 + bitmap |
| `0x13` HEARTBEAT_FRAG | `HeartbeatFrag` | `HeartbeatFrag { reader_id, writer_id, writer_sequence_number, last_fragment_number, count }` | 24 |
| `0x12` NACK_FRAG | `NackFrag` | `NackFrag { reader_id, writer_id, writer_sequence_number, fragment_number_base, num_bits, count }` | 28 + bitmap |
| `0x09` INFO_TS | `InfoTimestamp` | `InfoTimestamp { timestamp: Option<RtpsTime> }` | 8; nothing with flag I |
| `0x0e` INFO_DST | `InfoDestination` | `InfoDestination { guid_prefix }` | 12 |
| `0x0c` INFO_SRC | `InfoSource` | `InfoSource { version_major, version_minor, vendor_id, guid_prefix }` | 20 |
| `0x0d` INFO_REPLY_IP4 | `InfoReplyIp4` | `Opaque` | 8 |
| `0x0f` INFO_REPLY | `InfoReply` | `Opaque` | 4 |
| `0x01` PAD | `Pad` | `Opaque` | — |
| `0x30`–`0x34` | `SecureBody`, `SecurePrefix`, `SecurePostfix`, `SecureRtpsPrefix`, `SecureRtpsPostfix` | `Opaque` | — |
| `0x80`–`0xff` | `VendorSpecific(id)` | `Opaque` | — |
| `0x00` (HeaderExtension, RTPS 2.5) and any other | — | — | `ReservedSubmessageId` |

The bitmap of a `SequenceNumberSet` or a `FragmentNumberSet` is `numBits` rounded up to 32-bit words, 4 × ⌈`numBits` / 32⌉ bytes, and the count of an ACKNACK or a NACK_FRAG comes after it: the crate checks that the bitmap fits before reading the count. An `RtpsTime` is `seconds: u32` and `fraction: u32`, in 2⁻³² s. Of the flags, `details` exposes Q, D and K of a DATA (`inline_qos`, `serialized_payload`, `serialized_key`), F of an ACKNACK (`final_flag`) and I of an INFO_TS (`timestamp: None`); the others stay in `flags`. What follows the fixed fields, the serialized data, the inline QoS, the locator lists, stays in `body`, as raw bytes.

Nine kinds occur in the corpus, a list the golden test checks; over its 223 messages, INFO_TS appears 159 times, DATA 153, INFO_DST 96, HEARTBEAT 64, ACKNACK 61, DATA_FRAG 6, GAP 3, INFO_SRC once and the vendor submessage `0x80` of CoreDX once. HEARTBEAT_FRAG, NACK_FRAG, PAD, the two INFO_REPLY and the security submessages occur in no capture.

## Validations

All of them are `RtpsParseError`, in `packet_parser::errors::application::rtps`:

| Error | When |
| --- | --- |
| `Truncated { expected, actual }` | fewer than the 20 bytes of the header, or fewer than the four bytes of a submessage header where one must start (`expected` counts from the start of the message) |
| `InvalidMagic([u8; 4])` | the first four bytes are neither `RTPS` nor `RTPX` |
| `UnsupportedVersion { major, minor }` | the major version is not 2 |
| `NoSubmessage` | a header and nothing after it |
| `ReservedSubmessageId { id, offset }` | an identifier that is neither one of the specification up to RTPS 2.4, nor `0x30`–`0x34` (DDS Security), nor `0x80`–`0xff`; `0x00`, the HeaderExtension of RTPS 2.5, is refused too |
| `SubmessageOverflow { id, offset, declared, available }` | `octetsToNextHeader` beyond the end of the message |
| `SubmessageTooShort { id, offset, expected, actual }` | a body shorter than its kind requires (entity ids, sequence numbers, bitmap) |

The probe only asks whether the decode succeeds, so any of them means "not RTPS". Each one on the bytes of frame 9, one modification at a time (*tested*):

```rust
{{#include ../examples/src/defense_b.rs:rtps_refusals}}
```

## Oracle: 231 frames, six implementations

The golden test `tests/rtps_golden.rs` runs the eight captures of `pcaps_exemple/protocols/rtps/` and compares every frame with tshark 4.6.6 without IP reassembly, frozen by `tools/rtps_oracle.sh` in `tests/data/rtps_tshark_oracle.tsv`: version, vendorId, guidPrefix, the sequence of submessages with their `octetsToNextHeader`, the entity ids and the sequence numbers. Every frame of the oracle must come out `"RTPS"` and decode identically, every other frame of the folder must not: 231 frames, the 8 pings and the 4 `RTPX` messages among them. The other 16 frames of the folder are IPv4 fragments of `RTPS_Discovery.pcapng`, which tshark reassembles and a stateless parser never sees whole. In the golden histogram of `pcaps_exemple/protocols/` (`tests/golden_pcaps.rs`), `"RTPS"` went from 0 to 231 and `"Unknown"` from 9 409 to 9 178: no frame of another folder comes out RTPS. The fuzz target `parse_rtps` runs nightly on the same decoder.

| Capture | RTPS frames | Implementation (vendorId) | Origin |
| --- | --- | --- | --- |
| `talker-listener-rtps.pcapng` | 87 | Eclipse Cyclone DDS (`0x0110`), ROS 2 talker and listener, LINKTYPE_NULL | foxglove/rtps |
| `RTPS_Discovery.pcapng` | 93 | RTI Connext (`0x0101`), discovery, pings, the `RTPX` messages | Wireshark wiki |
| `rtps.pcap` | 29 | RTI Connext (`0x0101`) | nDPI test corpus |
| `wireshark_15227_reassembly_one_each.pcapng` | 6 | RTI Connext (`0x0101`), DATA_FRAG datagrams of 55 to 65 KB | Wireshark issue 15227 |
| `wireshark_15868_micro_2_4_11.pcapng` | 1 | RTI Connext Micro (`0x010a`), port 21914 | Wireshark issue 15868 |
| `wireshark_6449_opendds_messenger.pcap` | 13 | OpenDDS (`0x0103`) | Wireshark issue 6449 |
| `wireshark_9378_ddsi.pcapng` | 1 | OpenSplice (`0x0102`) | Wireshark issue 9378 |
| `wireshark_17630_default_multicast_locator.pcapng` | 1 | CoreDX (`0x0106`), RTPS 2.2, a vendor submessage | Wireshark issue 17630 |

Two oracle details: tshark lists the identifier of a vendor submessage but not its `octetsToNextHeader`, so the comparison skips that length; and it prints a sequence number signed with `-T fields`, which is the form the oracle keeps.

## What is left out

- **User data**: the serialized payload (CDR), the inline QoS parameter lists and the locator lists stay raw in `body`; no topic, type or QoS policy is decoded, and the `extraFlags` and `octetsToInlineQos` of a DATA are not exposed.
- **Names**: entity ids and GUID prefixes are numbers and bytes; tshark calls `0x000200c2` `ENTITYID_P2P_BUILTIN_PARTICIPANT_MESSAGE_WRITER`, the crate does not.
- **DDS Security**: the secure submessages are recognized by their identifier, their bodies stay opaque.
- **HeaderExtension**: RTPS 2.5 adds this submessage, `0x00`, right after the header. The crate does not know it: a message that carries one is `ReservedSubmessageId` and is not labelled. No capture of the corpus has one.
- **Reassembly**: `DATA_FRAG` fragments are not put back together, nor are the IPv4 fragments of a datagram. One message at a time, as everywhere in the crate.
- **RTPS 1.x** is `UnsupportedVersion`, and RTPS is only looked for on UDP.
