# RTPS

Real-Time Publish-Subscribe, the wire protocol of DDS (OMG DDSI-RTPS 2.x), added in 11.6.0 ([#120](https://github.com/Akmot9/Packet-parser/issues/120)) with the defense lot ([#125](https://github.com/Akmot9/Packet-parser/issues/125)). DDS is the middleware of recent combat system architectures (NGVA, GVA, naval systems) and of ROS 2, and RTPS succeeds GIOP/MIOP in that role. The module is `packet_parser::parse::application::protocols::rtps`. Since 13.0.0 its submodule `dds` also reads the DDS layer of a DATA: inline QoS, serialized data and discovery ([#317](https://github.com/Akmot9/Packet-parser/issues/317), [below](#the-dds-layer)).

## Detection: a magic, then an exact tiling

An RTPS message fills one UDP datagram. As for [PTP](./ptp.md) on UDP, the pipeline gives the datagram a label, `"RTPS"`, and nothing more: the decode is `RtpsPacket::try_from` on the transport payload.

The rule is a **blind probe**, `rule(ApplicationProtocol::Rtps, Guard::Udp, ProbeId::Rtps)`, in the blind cascade of the [dispatch table](./application.md#reading-the-table), right after the blind NTP rule and, since 11.8.0, before the blind [Valmet DNA](./valmet_dna.md) rule, then ASTERIX. There is no port guard: Cyclone DDS and Connext Micro send between random unicast ports, which is why the dispatch probes blind (frame 9 below goes from 54020 to 58584, the Connext Micro capture of the corpus to 21914). What identifies RTPS is its first four bytes, then its structure:

```rust
ProbeId::Rtps => {
    (payload.starts_with(b"RTPS") || payload.starts_with(b"RTPX"))
        && RtpsPacket::try_from(payload).is_ok()
}
```

- the magic is a **constant-cost guard**, as for GIOP: the decoder only runs on a datagram that starts with `RTPS`, or with `RTPX`, a variant RTI Connext emits;
- the decoder reads the **whole payload**, never a `PROBE_CAP` prefix of 18 KiB, which since 11.7.0 only the probes of the four text protocols keep: a 60 KB `DATA_FRAG` is still RTPS, and the six of `wireshark_15227_reassembly_one_each.pcapng`, up to 65 064 bytes of payload, are labelled;
- the submessages must **tile the datagram exactly**; a reserved `submessageId`, a body too short for its kind, or a HEADER_EXTENSION out of place or with a wrong `messageLength` refuses the message.

A refused message is not a corruption: the label is not given, the datagram goes on down the table and usually comes out `"Unknown"`, with nothing in `corrupted`. RTPS is probed on UDP only, and there is no `DecodeAsProtocol` variant for it: a rule without a port guard has no port to extend.

Cyclone DDS on the macOS loopback, between two random ports (*tested*):

```rust
{{#include ../examples/src/defense_b.rs:rtps_random_port}}
```

## The message

![The RTPS message of frame 9 of talker-listener-rtps.pcapng, 32 bits per row: the magic RTPS, protocol version 2.1, vendorId 0x0110 (Cyclone DDS) and the 12-byte guidPrefix, then four submessages each introduced by its id, its flags and octetsToNextHeader in the byte order the E flag announces: INFO_DST (12 bytes), INFO_TS (8), DATA (48) and HEARTBEAT (28); RtpsMessage keeps the RtpsHeader and a Vec of RtpsSubmessage with their typed details.](images/application/rtps_struct.svg)

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

`little_endian` is flag E, `flags & 0x01`. Each submessage chooses its own byte order, and the crate reads in it every number of the submessage: `octetsToNextHeader`, sequence numbers, counts, fragment numbers and sizes, `numBits`, timestamps. A `SequenceNumber_t` is a signed high half then an unsigned low half, each in that order, returned as an `i64`. Three fields do not follow E: the entity ids, kept as the four octets of the `EntityId_t` read big-endian (`0x000003c2` for the built-in publications writer, for instance), the vendorId, big-endian in `INFO_SRC` as in the header, and the checksum of a [HEADER_EXTENSION](#the-header-extension), big-endian too. All 544 submessages of the corpus set E: only the crate's unit tests, on synthetic bytes, read big-endian ones.

### `octetsToNextHeader`: a length, or zero

The body is `octetsToNextHeader` bytes long. Zero means that the submessage runs **to the end of the message**, which only the last one can do, except for PAD and INFO_TS, where zero is an empty body. `octets_to_next_header` keeps what the wire carries, `body` what it covers; a length beyond the end of the datagram is `SubmessageOverflow`. The thirteen zeros of the corpus are the final DATA of the thirteen OpenDDS messages; the first of them (*tested*):

```rust
{{#include ../examples/src/defense_b.rs:rtps_to_the_end}}
```

The sequence number of that DATA has a high half of −1, like those of frames 12 and 13, the two other DATA of the capture that carry a key and no data: −4 294 967 296 as an `i64`, which is also what `tshark -T fields` prints, where `tshark -V` shows the unsigned 18 446 744 069 414 584 320.

### Kinds and their fields

`SubmessageKind` names the identifiers of DDSI-RTPS 2.5, of DDS Security 1.1 and of the vendor range; the HEADER_EXTENSION that RTPS 2.5 adds at `0x00` has been among them since 11.7.0 ([#186](https://github.com/Akmot9/Packet-parser/issues/186)), and has [its own section](#the-header-extension). `SubmessageDetails` decodes, for the kinds of the specification, the entity ids, sequence numbers, counters, timestamps and fragmentation fields, once the body has been checked to be long enough for them:

| `submessageId` | `SubmessageKind` | `SubmessageDetails` | Minimum body |
| --- | --- | --- | --- |
| `0x00` HEADER_EXTENSION | `HeaderExtension` | `HeaderExtension(RtpsHeaderExtension)` | the fields its flags announce, 0 to 40 |
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
| any other | — | — | `ReservedSubmessageId` |

The bitmap of a `SequenceNumberSet` or a `FragmentNumberSet` is `numBits` rounded up to 32-bit words, 4 × ⌈`numBits` / 32⌉ bytes, and the count of an ACKNACK or a NACK_FRAG comes after it: the crate checks that the bitmap fits before reading the count. An `RtpsTime` is `seconds: u32` and `fraction: u32`, in 2⁻³² s. Of the flags, `details` exposes Q, D and K of a DATA (`inline_qos`, `serialized_payload`, `serialized_key`), F of an ACKNACK (`final_flag`) and I of an INFO_TS (`timestamp: None`); the others stay in `flags`. What follows the fixed fields stays in `body`, as raw bytes. For a DATA and a DATA_FRAG, [the DDS layer](#the-dds-layer) reads the inline QoS and the serialized data from there, on demand.

Nine kinds occur in the corpus, a list the golden test checks; over its 223 messages, INFO_TS appears 159 times, DATA 153, INFO_DST 96, HEARTBEAT 64, ACKNACK 61, DATA_FRAG 6, GAP 3, INFO_SRC once and the vendor submessage `0x80` of CoreDX once. HEADER_EXTENSION, HEARTBEAT_FRAG, NACK_FRAG, PAD, the two INFO_REPLY and the security submessages occur in no capture.

### The header extension

RTPS 2.5 adds a submessage that extends the header (§8.3.3.2, §8.3.7 and §9.4.5.2): the length of the message, a send timestamp, two extension fields of 4 and 8 bytes, a checksum and parameters. In 11.6.0 the crate refused it as `ReservedSubmessageId { id: 0, offset: 20 }`, and the datagram came out `"Unknown"`. Since 11.7.0 its fields are in `SubmessageDetails::HeaderExtension`:

```rust
pub struct RtpsHeaderExtension {
    pub message_length: Option<u32>,      // L
    pub send_timestamp: Option<RtpsTime>, // T
    pub u_extension: Option<[u8; 4]>,     // U
    pub w_extension: Option<[u8; 8]>,     // W
    pub checksum: Option<RtpsChecksum>,   // C1, C2
    pub parameters: bool,                 // P
}

pub enum RtpsChecksum {
    Crc32c(u32),   // C2 alone
    Crc64Xz(u64),  // C1 alone
    Md5([u8; 16]), // C1 and C2
}
```

Each field is present when its flag is set, in this order on the wire:

| Flag | Bit | Field | Bytes | Read as |
| --- | --- | --- | --- | --- |
| E | `0x01` | — | — | the byte order of the submessage |
| L | `0x02` | `message_length` | 4 | `u32`, in the order of E |
| T | `0x04` | `send_timestamp` | 8 | `RtpsTime`, in the order of E |
| U | `0x08` | `u_extension` | 4 | raw bytes |
| W | `0x10` | `w_extension` | 8 | raw bytes |
| C2, C1 | `0x20`, `0x40` | `checksum` | 4, 8 or 16 | big-endian whatever E (Table 9.8): CRC-32C, CRC-64/XZ or MD5 |
| P | `0x80` | `parameters` | the rest of the body | a ParameterList, raw: `header_extension_parameters()` |

A body shorter than the fields its flags announce is `SubmessageTooShort`. Bytes after them, without P, are accepted and stay in `body`. `RtpsSubmessage::header_extension_parameters()` returns the ParameterList of a HEADER_EXTENSION whose P flag is set, as raw bytes: its parameters, the final PID_SENTINEL included, are neither decoded nor checked. Any other submessage, or no P flag, gives `None`.

**The checksum is not verified**: the decoder reads it and keeps it, it does not compute a CRC or an MD5 over the message. Two other things are checked, which tshark 4.6.6 does not check:

- the **position**: a HEADER_EXTENSION comes right after the header, at offset 20, or not at all (§8.3.3.2, §8.3.7.3); anywhere else it is `MisplacedHeaderExtension { offset }`;
- the **`messageLength`**, when L is set: one message per UDP datagram (§9.5), so it must equal the length of the datagram, else `HeaderExtensionLengthMismatch { declared, actual }`.

No capture of the corpus carries a HEADER_EXTENSION (`rtps.sm.id == 0x00`: no frame), so the golden test and the histogram did not move. One, put by hand into frame 9 (*tested*):

```rust
{{#include ../examples/src/defense_b.rs:rtps_header_extension}}
```

## Validations

The decoder of the message returns nine variants of `RtpsParseError`, in `packet_parser::errors::application::rtps`. The five others, added in 13.0.0, come from [the DDS layer](#refusals-of-the-dds-layer) and never refuse a message.

| Error | When |
| --- | --- |
| `Truncated { expected, actual }` | fewer than the 20 bytes of the header, or fewer than the four bytes of a submessage header where one must start (`expected` counts from the start of the message) |
| `InvalidMagic([u8; 4])` | the first four bytes are neither `RTPS` nor `RTPX` |
| `UnsupportedVersion { major, minor }` | the major version is not 2 |
| `NoSubmessage` | a header and nothing after it |
| `ReservedSubmessageId { id, offset }` | an identifier that is neither one of DDSI-RTPS 2.5, HEADER_EXTENSION included, nor `0x30`–`0x34` (DDS Security), nor `0x80`–`0xff` |
| `SubmessageOverflow { id, offset, declared, available }` | `octetsToNextHeader` beyond the end of the message |
| `SubmessageTooShort { id, offset, expected, actual }` | a body shorter than its kind requires (entity ids, sequence numbers, bitmap, the fields of a HEADER_EXTENSION) |
| `MisplacedHeaderExtension { offset }` | a HEADER_EXTENSION that is not the first submessage (added in 11.7.0) |
| `HeaderExtensionLengthMismatch { declared, actual }` | a HEADER_EXTENSION whose `messageLength` is not the length of the datagram (added in 11.7.0) |

The refusal of an unknown identifier departs from the specification: rule 3 of DDSI-RTPS 2.5 §8.3.4.1 asks a receiver to ignore a submessage whose `submessageId` it does not know and to go on with the next one. The crate refuses the message instead, because the closed table of identifiers is part of the signature its blind probe relies on.

The probe only asks whether the decode succeeds, so any of them means "not RTPS". Each one on the bytes of frame 9, one modification at a time (*tested*):

```rust
{{#include ../examples/src/defense_b.rs:rtps_refusals}}
```

## The DDS layer

RTPS carries DDS. A DATA holds a sample of a topic, sometimes with inline QoS. The DATA of the discovery writers say what a participant announces of itself and of its endpoints. Since 13.0.0 the module `rtps::dds` reads them ([#317](https://github.com/Akmot9/Packet-parser/issues/317)).

Detection does not change. The probe and `RtpsPacket::try_from` stop at the submessages, as above. The DDS layer is decoded on demand, from an `RtpsSubmessage`, by three methods:

| Method | Gives | `None` for |
| --- | --- | --- |
| `inline_qos()` | the ParameterList of a DATA or a DATA_FRAG with flag Q | any other submessage; no flag Q |
| `serialized_payload()` | the encapsulation header and the data of a DATA with flag D or K, or of a DATA_FRAG that starts at fragment 1 | any other submessage; a DATA with neither D nor K; a later fragment |
| `discovery()` | the built-in topic and the ParameterList of a DATA from an SPDP or SEDP writer | another writer; a DATA_FRAG; a DATA with neither data nor key |

Each one returns `Option<Result<_, RtpsParseError>>`. `None` means that the submessage carries nothing of the kind. `Err` means that what it carries is malformed: the message stays RTPS, and its frame keeps its label. Every slice they return borrows from `body`. The types of `rtps::dds` are `#[non_exhaustive]`, like the others.

![The DATA submessage of frame 3 of talker-listener-rtps.pcapng, 32 bits per row: its id 0x15, flags E and D, octetsToNextHeader 248, then extraFlags, octetsToInlineQos 16, readerId, the SPDP writerId 0x000100c2 and writerSN 1; then the encapsulation header, PL_CDR_LE read big-endian, and options 0; then the ParameterList, little-endian: PID_USER_DATA, PID_PROTOCOL_VERSION, PID_VENDORID with the two octets 01 10, eight more parameters and the PID_SENTINEL. The card shows what inline_qos() and discovery() make of them.](images/application/rtps_dds_data.svg)

### Where the data starts

A DATA, like a DATA_FRAG, starts with `extraFlags` and `octetsToInlineQos`, two bytes each, before its entity ids and its sequence number. `octetsToInlineQos` counts from the byte after it. The crate checks that it points between the end of the fixed fields and the end of the body:

| Submessage | Fixed fields | `octetsToInlineQos` accepted |
| --- | --- | --- |
| DATA | 20 bytes | 16 to `body.len()` − 4 |
| DATA_FRAG | 32 bytes | 28 to `body.len()` − 4 |

Any other value is `InvalidOctetsToInlineQos`. With flag Q, the inline QoS start there, and the data follow their PID_SENTINEL. Without it, the data start there. Frame 3 above carries 16: its data start right after the 20 fixed bytes. `SubmessageDetails` exposes neither `extraFlags` nor `octetsToInlineQos`.

### Inline QoS

`inline_qos()` reads the ParameterList of flag Q, an [`RtpsParameterList`](#the-parameterlist) like the data of discovery. Its headers and values are in the byte order of the submessage, flag E. tshark finds inline QoS in 17 frames of the corpus, with two PIDs only:

| PID | Accessor | Frames |
| --- | --- | --- |
| `0x0070` PID_KEY_HASH | `key_hash()` | 14 |
| `0x0071` PID_STATUS_INFO | `status_info()` | 4 |

[The example of the refusals](#refusals-of-the-dds-layer) starts with one of them: an RTI Connext participant that leaves.

### The serialized payload

`serialized_payload()` decodes the four-byte encapsulation header, then keeps what follows:

```rust
pub struct RtpsSerializedPayload<'a> {
    pub encapsulation: RtpsEncapsulation, // the representation identifier, bytes 0-1
    pub options: u16,                     // the representation options, bytes 2-3
    pub data: &'a [u8],                   // the rest
}
```

- The header is big-endian, whatever flag E.
- `options` is kept as carried.
- `data` runs to the end of the submessage, padding included. For a DATA_FRAG, it stops at the end of the first fragment.
- `RtpsSerializedPayload::parse` does the same on any bytes.

`RtpsEncapsulation` names the representation identifiers of DDS-XTypes 1.3 (Table 60):

| Identifier | `RtpsEncapsulation` | `name()` | Data |
| --- | --- | --- | --- |
| `0x0000`, `0x0001` | `CdrBe`, `CdrLe` | `CDR_BE`, `CDR_LE` | classic CDR |
| `0x0002`, `0x0003` | `PlCdrBe`, `PlCdrLe` | `PL_CDR_BE`, `PL_CDR_LE` | a ParameterList, which `parameters()` decodes |
| `0x0004` | `Xml` | `XML` | XML |
| `0x0010`, `0x0011` | `Cdr2Be`, `Cdr2Le` | `CDR2_BE`, `CDR2_LE` | XCDR2 |
| `0x0012`, `0x0013` | `PlCdr2Be`, `PlCdr2Le` | `PL_CDR2_BE`, `PL_CDR2_LE` | XCDR2 of a mutable type: EMHEADERs, not a ParameterList |
| `0x0014`, `0x0015` | `DCdr2Be`, `DCdr2Le` | `D_CDR2_BE`, `D_CDR2_LE` | XCDR2 of an appendable type: a DHEADER first |
| any other | `Other(code)` | `None` | unknown |

`code()` gives the identifier back. `little_endian()` gives the byte order of the data: `Some(false)` for the `Be` forms, `Some(true)` for the `Le` ones, `None` for XML and `Other`. `is_parameter_list()` is true for the two PL_CDR only, and `parameters()` is `None` for any other encapsulation.

The [DDS oracle](#the-dds-layer-137-frames-101-announcements) of the corpus holds 155 encapsulation headers:

| Encapsulation | Headers |
| --- | --- |
| PL_CDR_LE (`0x0003`) | 101, the discovery announcements |
| CDR_LE (`0x0001`) | 54 |
| any other | 0 |

### Discovery: SPDP and SEDP

`discovery()` recognizes the writer of a DATA by its entity id (DDSI-RTPS 2.5 §9.3.1.4, and DDS Security 1.1 for the secure writers):

| Writer entity id | `RtpsBuiltinTopic` | `name()` |
| --- | --- | --- |
| `0x000100c2`; secure `0xff0101c2` | `Participant` (SPDP) | `DCPSParticipant` |
| `0x000002c2` | `Topic` (SEDP) | `DCPSTopic` |
| `0x000003c2`; secure `0xff0003c2` | `Publication` (SEDP) | `DCPSPublication` |
| `0x000004c2`; secure `0xff0004c2` | `Subscription` (SEDP) | `DCPSSubscription` |

Any other writer gives `None`, the participant message writer `0x000200c2` of frame 9 among them. `RtpsBuiltinTopic::from_writer` is the same table, on its own.

```rust
pub struct RtpsDiscovery<'a> {
    pub topic: RtpsBuiltinTopic,
    pub secure: bool,                     // a DDS Security writer, 0xff......
    pub key_only: bool,                   // flag K without flag D
    pub encapsulation: RtpsEncapsulation, // PL_CDR, big- or little-endian
    pub parameters: RtpsParameterList<'a>,
}
```

- The data must be PL_CDR. Any other encapsulation is `NotAParameterList`.
- The list is read in the byte order of the encapsulation, not of the submessage.
- `key_only` marks a key alone: a participant or an endpoint that leaves.

### The ParameterList

Inline QoS and discovery data are both an `RtpsParameterList` (§9.4.2.11):

```rust
pub struct RtpsParameterList<'a> {
    pub bytes: &'a [u8],      // the parameters, without the PID_SENTINEL
    pub little_endian: bool,
}

pub struct RtpsParameter<'a> {
    pub id: u16,
    pub value: &'a [u8],      // the length the header announces
    pub little_endian: bool,  // the order of the list
}
```

The list is checked once, when it is decoded:

- every parameter fits in the list, its header and the value its length announces;
- a PID_SENTINEL ends it;
- the length of the sentinel is ignored, and so is what follows it.

`RtpsParameterList::parse` does the same on any bytes, and also returns the bytes it consumed, sentinel included. `iter()` gives the parameters in wire order, without the sentinel. `get(id)` gives the first one with that id. Two bits of its id are flags (§9.6.2.2.1), and `name()` names it:

| Method | Bit | Meaning |
| --- | --- | --- |
| `is_vendor_specific()` | 15, `0x8000` | a PID of the implementation that the vendorId names |
| `must_understand()` | 14, `0x4000` | a receiver that does not understand it must ignore the whole submessage |
| `name()` | — | its name in the specification, `PID_TOPIC_NAME` for instance, one of the 64 it knows; `None` for a vendor PID or an unknown one |

The crate reports the must-understand bit. It does not act on it.

A parameter reads its own value with `string()`, `u32_value()`, `guid()`, `duration()` and `locator()`. The list has fifteen typed accessors. Each one reads the first parameter of its PID, and gives `None` when it is absent or its value too short:

| Accessor | PID | Returns |
| --- | --- | --- |
| `topic_name()` | `0x0005` PID_TOPIC_NAME | `&[u8]`, a CDR string without its NUL |
| `type_name()` | `0x0007` PID_TYPE_NAME | `&[u8]` |
| `entity_name()` | `0x0062` PID_ENTITY_NAME | `&[u8]` |
| `participant_guid()` | `0x0050` PID_PARTICIPANT_GUID | `[u8; 16]`: guidPrefix, then entity id |
| `endpoint_guid()` | `0x005a` PID_ENDPOINT_GUID | `[u8; 16]` |
| `key_hash()` | `0x0070` PID_KEY_HASH | `[u8; 16]`, the GUID itself for a built-in topic |
| `status_info()` | `0x0071` PID_STATUS_INFO | `RtpsStatusInfo`, read big-endian: `disposed()`, `unregistered()`, `filtered()` |
| `domain_id()` | `0x000f` PID_DOMAIN_ID | `u32` |
| `protocol_version()` | `0x0015` PID_PROTOCOL_VERSION | `(u8, u8)` |
| `vendor_id()` | `0x0016` PID_VENDORID | `u16`, read big-endian, like the header's |
| `builtin_endpoint_set()` | `0x0058` PID_BUILTIN_ENDPOINT_SET | `u32`, one bit per built-in endpoint |
| `participant_lease_duration()` | `0x0002` PID_PARTICIPANT_LEASE_DURATION | `RtpsDuration` |
| `reliability()` | `0x001a` PID_RELIABILITY | `RtpsReliability { kind, max_blocking_time }` |
| `durability()` | `0x001d` PID_DURABILITY | `RtpsDurabilityKind` |
| `locators()` | the six locator PIDs below | an iterator of `(RtpsLocatorRole, RtpsLocator)`, in wire order |

Strings are bytes: nothing checks that they are UTF-8. The other value types:

- `RtpsDuration` is `seconds: i32` and `fraction: u32`, in 2⁻³² s. `is_infinite()` tests DURATION_INFINITE: `0x7fffffff` seconds and a fraction of `0xffffffff`.
- `RtpsLocator` is `kind: i32`, `port: u32` and `address: [u8; 16]`. `ipv4()` reads the last four bytes of a kind 1 locator, `ipv6()` the sixteen of a kind 2 one. Other kinds keep their bytes.
- `RtpsReliabilityKind` keeps the values of the wire: `BestEffort` is 1, `Reliable` 2. `max_blocking_time` is `None` for a four-byte value.
- `RtpsDurabilityKind` is `Volatile`, `TransientLocal`, `Transient` or `Persistent`, 0 to 3.
- Both kinds have an `Other(u32)` for any other value.

The PID of a locator gives its role:

| PID | `RtpsLocatorRole` | Reaches |
| --- | --- | --- |
| `0x002f`, `0x0030` | `Unicast`, `Multicast` | the data of an endpoint |
| `0x0031`, `0x0048` | `DefaultUnicast`, `DefaultMulticast` | the data of the participant's endpoints, by default |
| `0x0032`, `0x0033` | `MetatrafficUnicast`, `MetatrafficMulticast` | the metatraffic of the participant: discovery, heartbeats, acknowledgements |

Frame 3 of `talker-listener-rtps.pcapng` is the SPDP announcement of the participant of frame 9, to 239.255.0.1:7400. It names no entity. Two of its eleven parameters, `0x8007` and `0x8019`, belong to Cyclone DDS (*tested*):

```rust
{{#include ../examples/src/defense_b.rs:rtps_spdp}}
```

### A publication, then its first sample

Frame 57 of the same capture is SEDP. The participant announces a writer of the topic `rt/chatter`, the one of the ROS 2 talker. Its endpoint GUID ends with the entity id `0x00001503`. Frame 70 is a DATA of that writer, its first sample. A user writer is not a discovery one: `discovery()` is `None` (*tested*):

```rust
{{#include ../examples/src/defense_b.rs:rtps_sedp}}
```

### User data stays bytes

The crate stops at the encapsulation header of a user type. Its data is `&[u8]`: without the IDL of the type, nothing says how to read it. The example above reads its `std_msgs/String` by hand, a CDR string, `Hello World: 1`. The key of a user instance, flag K, stays bytes too. So do the XCDR2 and XML forms, which are named and not decoded.

### Refusals of the DDS layer

Five variants were added at the end of `RtpsParseError` in 13.0.0. Only the DDS layer returns them, never `RtpsPacket::try_from`:

| Error | When | Returned by |
| --- | --- | --- |
| `InvalidOctetsToInlineQos { octets_to_inline_qos, body }` | `octetsToInlineQos` points into the fixed fields, or beyond the body | the three methods |
| `ParameterTruncated { offset, expected, actual }` | a parameter header, or the value its length announces, overflows the list; `offset` counts from the start of the list | the three methods, `RtpsParameterList::parse` |
| `ParameterListUnterminated { length }` | a list without PID_SENTINEL | the three methods, `RtpsParameterList::parse` |
| `SerializedPayloadTooShort { actual }` | serialized data shorter than the four bytes of the encapsulation header | `serialized_payload()`, `discovery()`, `RtpsSerializedPayload::parse` |
| `NotAParameterList { encapsulation }` | the data of a discovery writer are not PL_CDR | `discovery()` |

`serialized_payload()` and `discovery()` return the errors of a list too: they read the inline QoS to find where the data start. A refusal here refuses nothing else. The message still decodes, the probe still says RTPS, and the frame is not corrupted.

Frame 29 of `rtps.pcap` first, an RTI Connext participant that leaves: a DATA of the SPDP writer with inline QoS only. Then each refusal on its bytes, and `NotAParameterList` on those of frame 70 (*tested*):

```rust
{{#include ../examples/src/defense_b.rs:rtps_dds_refusals}}
```

## Oracle: 231 frames, six implementations

The golden test `tests/rtps_golden.rs` runs the eight captures of `pcaps_exemple/protocols/rtps/` and compares every frame with tshark 4.6.6 without IP reassembly, frozen by `tools/rtps_oracle.sh` in `tests/data/rtps_tshark_oracle.tsv`: version, vendorId, guidPrefix, the sequence of submessages with their `octetsToNextHeader`, the entity ids and the sequence numbers. Every frame of the oracle must come out `"RTPS"` and decode identically, every other frame of the folder must not: 231 frames, the 8 pings and the 4 `RTPX` messages among them. The other 16 frames of the folder are IPv4 fragments of `RTPS_Discovery.pcapng`, which tshark reassembles and a stateless parser never sees whole. In the golden histogram of `pcaps_exemple/protocols/` (`tests/golden_pcaps.rs`), `"RTPS"` went from 0 to 231 and `"Unknown"` from 9 409 to 9 178: no frame of another folder comes out RTPS. The fuzz target `parse_rtps` runs nightly on the same decoder, and since 13.0.0 on [its DDS layer](#the-dds-layer-137-frames-101-announcements) too.

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

### The DDS layer: 137 frames, 101 announcements

The golden test `tests/rtps_dds_golden.rs` replays the same eight captures against a second oracle: tshark 4.6.9, frozen by `tools/rtps_dds_oracle.sh` in `tests/data/rtps_dds_tshark_oracle.tsv`. It holds a row for each frame that carries a parameter or an encapsulation header: 137 frames. Each row lists, in wire order:

- the encapsulation identifiers;
- the PIDs, PID_SENTINEL included;
- the topic, type and entity names;
- the participant and endpoint GUIDs, and the key hashes;
- the kind, port and IPv4 address of the locators;
- the status info, the reliability, the durability and the built-in endpoint set.

The crate rebuilds the same row from `inline_qos()`, `serialized_payload()` and `discovery()`. Every RTPS message of the folder must match its row, or have none.

| Capture | Frames in the DDS oracle |
| --- | --- |
| `talker-listener-rtps.pcapng` | 57 |
| `RTPS_Discovery.pcapng` | 33 |
| `rtps.pcap` | 28 |
| `wireshark_6449_opendds_messenger.pcap` | 13 |
| `wireshark_15227_reassembly_one_each.pcapng` | 3, the DATA_FRAG of fragment 1 |
| `wireshark_15868_micro_2_4_11.pcapng` | 1 |
| `wireshark_9378_ddsi.pcapng` | 1 |
| `wireshark_17630_default_multicast_locator.pcapng` | 1 |
| total | 137 |

Three oracle details:

- no IP reassembly, as for the first oracle;
- `rtps.enable_topic_info` is off: otherwise tshark adds to user data the topic and type it remembers from discovery, which are not on the wire;
- no domain column: the `rtps.domain_id` of tshark comes from the port, not from PID_DOMAIN_ID.

A second test checks what tshark does not, on the 101 SPDP and SEDP announcements of five implementations:

| Check | Result |
| --- | --- |
| built-in topics | 61 `DCPSParticipant`, 19 `DCPSPublication`, 21 `DCPSSubscription`; no `DCPSTopic`, no secure writer, no key alone |
| PID_VENDORID of the 61 SPDP | RTI Connext 46, Cyclone DDS 11, OpenSplice 2, CoreDX 1, Connext Micro 1 |
| participant GUID | the guidPrefix of the sender, then ENTITYID_PARTICIPANT, `0x000001c1` |
| endpoint GUID | the guidPrefix of the sender, with a topic and a type name: 29 distinct topics |
| lease duration | in all 61 SPDP |
| PID_DOMAIN_ID | from Cyclone DDS only, 11 times, domain 0 |
| key hash of a built-in instance disposed or unregistered | the GUID of the sender, in frame 29 of `rtps.pcap` |

The sender is the guidPrefix of the header, or that of the last INFO_SRC. The OpenDDS capture carries no discovery.

The fuzz target `parse_rtps` calls the three methods on every submessage it decodes. When they succeed, every list, value and data slice points into the body of the submessage. The parameters tile their list, and every typed accessor reads without a panic. Three real frames seed its mutations, besides frames 8 and 9 of Cyclone DDS: the SPDP DATA of Connext Micro, frame 29 of `rtps.pcap` and frame 12 of the OpenDDS capture.

## What is left out

The limits every protocol shares, reassembly and checksums among them, are on the [Limits](./limits.md) page. The ones below are this protocol's own.

- **User data**: the data of a user type stays bytes after its encapsulation header, and so does its key. XCDR2, its mutable and appendable forms, and XML are named, not decoded. The `extraFlags` and `octetsToInlineQos` of a DATA are not exposed.
- **The ParameterList**: fifteen PIDs have a typed accessor; the others give their value as bytes, through `get` and `iter`. The must-understand bit is reported, not acted on.
- **Discovery** is read from a DATA only, not from an announcement cut into DATA_FRAG.
- **Names**: entity ids and GUID prefixes are numbers and bytes; tshark calls `0x000200c2` `ENTITYID_P2P_BUILTIN_PARTICIPANT_MESSAGE_WRITER`, the crate does not. Only the discovery writers get a name, that of their built-in topic.
- **DDS Security**: the secure submessages are recognized by their identifier, their bodies stay opaque. `discovery()` recognizes the secure discovery writers; no capture has one.
- **The HEADER_EXTENSION checksum** is read, not verified, and its ParameterList stays raw and unchecked.
- **Unknown submessages** refuse the message, where rule 3 of §8.3.4.1 asks to skip them.
- **Reassembly**: `DATA_FRAG` fragments are not put back together, nor are the IPv4 fragments of a datagram. `serialized_payload()` of a DATA_FRAG gives the start of the data, from fragment 1 only. One message at a time, as everywhere in the crate.
- **RTPS 1.x** is `UnsupportedVersion`, and RTPS is only looked for on UDP.
