# DNP3

DNP3, the Distributed Network Protocol of IEEE 1815, is the SCADA protocol of the North American electric sector, spoken between a master and its outstations. It was added in 11.6.0 ([#99](https://github.com/Akmot9/Packet-parser/issues/99)), and its European counterpart, [IEC 60870-5-104](./iec104.md), came in the same release. The module is `packet_parser::parse::application::protocols::dnp3`, the errors are in `packet_parser::errors::application::dnp3`, and the label is `"DNP3"`.

A DNP3 message has three layers, and the crate reads all three, one payload at a time and without state: the **link frame**, protected by CRCs; the **transport** header, one byte per frame that marks the pieces of an application fragment spread over several frames; and the **application** layer, a header and a chain of object headers.

## Detection: the CRC is the signature

DNP3 runs on TCP or UDP, usually on port 20000, and the crate looks at neither the port nor the transport: the rule is a [blind probe](./application.md#three-detection-routes) without a transport guard, `rule("DNP3", Guard::Any, ProbeId::Dnp3)`, rule 43 of the [table](./application.md#reading-the-table), in the blind cascade after DIS and before RADIUS. Port 20000 appears in no rule. What makes a blind probe safe here is the link layer itself: every frame starts with `05 64`, and its header and each block of sixteen bytes of user data carry a CRC-16/DNP that the decoder checks. A payload that is not DNP3 has to get every one of those CRCs right.

The probe is `Dnp3Packet::try_from` on the **whole payload**, not on its first `PROBE_CAP` bytes: the link frames, each checked by its CRCs, must tile the segment or the datagram to the last byte. There is no `DecodeAsProtocol` variant for DNP3: Decode As extends port guards, and this rule has none. The portless `Application::try_from` tries DNP3 at the same place in its own cascade.

The corpus shows both directions of the rule. `dnp3_read_p20001.pcap` is `dnp3_read.pcap` with its port rewritten to 20001: tshark 4.6.6 shows its two segments with a payload as `data` until its DNP3 dissector is forced on that port (`-d tcp.port==20001,dnp3`, as the oracle does), while the crate labels them `"DNP3"` like any other. And on port 20000 itself, two segments of `dnp3.pcap` (frames 19 and 21) start with `05 05`: tshark shows them as `data`, the crate as `"Unknown"`.

The read request of `dnp3_read.pcap` on a port no rule knows, then a read of the same four classes over UDP (*tested*):

```rust
{{#include ../examples/src/scada.rs:dnp3_blind_probe}}
```

## The link frame

```rust
pub struct Dnp3Packet<'a> {
    pub frames: Vec<LinkFrame<'a>>,    // one or more, tiling the payload
}

pub struct LinkFrame<'a> {
    pub header: LinkHeader,
    pub raw: &'a [u8],                 // the frame as on the wire, CRCs included
    pub user_data: Vec<u8>,            // CRCs removed: at most 250 bytes
    pub transport: Option<TransportHeader>,       // None without user data
    pub application: Option<ApplicationFragment>, // first segment of a fragment only
}

pub struct LinkHeader {
    pub length: u8,       // the bytes after LENGTH, CRCs excluded: 5 plus the user data
    pub control: u8,      // raw: DIR, PRM, FCB, FCV, function code
    pub destination: u16,
    pub source: u16,
    pub crc: u16,         // as transmitted, checked by the decoder
}
```

Like every public type of the module, they are `#[non_exhaustive]`. The 10-byte header (IEEE 1815-2012 §9.2.4):

| Bytes | Field | Note |
| --- | --- | --- |
| 0–1 | start | `05 64`, otherwise `InvalidStartBytes` |
| 2 | `length` | control, destination and source (5), plus the user data, CRCs not counted: below 5 is `InvalidLength`, and 255 allows 250 bytes of user data |
| 3 | `control` | DIR `0x80` `direction_from_master()`, PRM `0x40` `primary()`, FCB `0x20` `frame_count_bit()`, FCV `0x10` `frame_count_valid()` (DFC in a secondary frame), function code in the low nibble, `function_code()` |
| 4–5 | `destination` | little-endian |
| 6–7 | `source` | little-endian |
| 8–9 | `crc` | CRC of bytes 0 to 7, little-endian; a mismatch is `HeaderCrcMismatch { expected, actual }` |
| 10… | user data | blocks of 16 bytes, the last one possibly shorter, each followed by its own CRC; a mismatch is `BlockCrcMismatch { block, expected, actual }`, `block` counted from 0 |

A frame with *n* bytes of user data is 10 + *n* + 2 × ⌈*n* / 16⌉ bytes long on the wire: 27 bytes for the 15 bytes of a read request, 292 for a full frame of 250. A buffer shorter than the 10-byte header, or than the frame its `length` announces, is `Truncated { expected, actual }`. The CRC is CRC-16/DNP (§9.2.4.3 and annex E): polynomial `0x3D65`, reflected, complemented, transmitted least significant byte first; its implementation is internal to the crate.

`function()` names the code according to PRM, as `LinkFunction`:

| PRM | Code | `LinkFunction` |
| --- | --- | --- |
| 1 (primary) | 0, 2, 3, 4, 9 | `ResetLinkStates`, `TestLinkStates`, `ConfirmedUserData`, `UnconfirmedUserData`, `RequestLinkStatus` |
| 0 (secondary) | 0, 1, 11, 15 | `Ack`, `Nack`, `LinkStatus`, `NotSupported` |

Any other combination is `None`, which does not fail the decode.

`user_data` is the only part of the payload the decoder copies: the CRCs interrupt the data every sixteen bytes, so a slice of the payload would not be contiguous. `raw` still borrows the frame as received.

`Dnp3Packet::try_from` reads frames back to back until the payload is consumed, and every one of them must be complete and valid. Bytes left after the last frame are read as the start of another frame and fail like one, as `Truncated` or `InvalidStartBytes` for instance: `UnexpectedTrailingBytes` is declared but never returned. In the corpus, every segment and datagram holds exactly one frame.

## The transport header

```rust
pub struct TransportHeader {
    pub raw: u8,          // FIN 0x80, FIR 0x40, sequence on six bits
}
```

It is the first byte of the user data: `is_final()` (FIN), `is_first()` (FIR) and `sequence()`. A frame without user data, a link function such as `RequestLinkStatus`, has `transport: None` and no application.

An application fragment longer than one frame can carry is cut into transport segments, one per frame, from a FIR segment to a FIN segment. The decoder reads the application header and the object headers on the **FIR segment only**, as far as that frame goes; the following segments get their link and transport headers and `application: None`. Nothing is reassembled: tshark does reassemble, and shows the application layer on the *last* segment of the fragment. In `dnp3_udp_read.pcap`, the first fragment of a response spans frames 6 to 14, transport sequence 32 to 40: on frame 6 the crate reads the application header that tshark shows on frame 14, control `0x87`, a `Response`, IIN `90 00`, and the first two of the three object headers tshark lists, g1v1 and g10v2.

The application header has its own FIR bit, which marks the first *fragment* of a message made of several: control `0x87` is FIR without FIN, and frames 15 to 21 carry the second and last fragment of that response, whose control on frame 15 is `0x48`, FIN without FIR. `dnp3_link_only.pcap` has the same shape: its frame 22 is a transport FIR segment whose application control is `0x48`, the second and last fragment of the response that frame 9 began.

A link frame without data, then the first two segments of the `dnp3_udp_read.pcap` response (*tested*):

```rust
{{#include ../examples/src/scada.rs:dnp3_transport}}
```

## The application layer

```rust
pub struct ApplicationFragment {
    pub header: ApplicationHeader,
    pub objects: Vec<ObjectHeader>,
    pub undecoded: Range<usize>,  // in user_data; empty when everything was read
}

pub struct ApplicationHeader {
    pub control: u8,      // raw: FIR 0x80, FIN 0x40, CON 0x20, UNS 0x10, sequence on four bits
    pub function_code: u8,
    pub internal_indications: Option<[u8; 2]>,  // IIN1 then IIN2, responses only
}
```

The control byte has its accessors, `is_first()`, `is_final()`, `confirm_requested()`, `unsolicited()` and `sequence()`. A response, function `0x81` `Response`, `0x82` `UnsolicitedResponse` or `0x83` `AuthenticationResponse` (`is_response()`), adds the two bytes of internal indications. `function()` names the code as one of the 37 variants of `ApplicationFunction`, codes 0 to 33 and `0x81` to `0x83`; an unknown code is `None` and the decode goes on. A FIR segment whose application header is shorter than 2 bytes, 4 for a response, is `ApplicationHeaderTooShort { actual }`.

Then come the object headers, one after the other to the end of the user data:

```rust
pub struct ObjectHeader {
    pub group: u8,
    pub variation: u8,
    pub qualifier: u8,          // raw
    pub prefix: PrefixCode,
    pub range: RangeSpecifier,
    pub data: Range<usize>,     // the objects, prefixes included, in user_data
}

pub enum PrefixCode {
    None,
    Index { octets: u8 },       // each object preceded by its index, 1, 2 or 4 bytes
    Size { octets: u8 },        // each object preceded by its size, 1, 2 or 4 bytes
    Reserved(u8),
}

pub enum RangeSpecifier {
    StartStop { start: u32, stop: u32, octets: u8 },  // codes 0 to 2
    Absolute { start: u32, stop: u32, octets: u8 },   // codes 3 to 5
    All,                                              // code 6: no range field, no data
    Count { count: u32, octets: u8 },                 // codes 7 to 9
    VariableCount { count: u8 },                      // code 11
    Reserved(u8),                                     // codes 10, 12 to 15
}
```

The qualifier is two codes (§4.2.2.7.1). Its low nibble is the range code, and the range fields that follow the header are 1, 2 or 4 bytes wide according to it. Bits 4 to 6 are the prefix code: 1 to 3 an index, 4 to 6 a size, each on 1, 2 or 4 bytes, and 7 is reserved; bit 7 of the qualifier is reserved too and is not read. `range.object_count()` gives the number of objects the range announces: stop − start + 1, or the count. It is `None` for `All` and `Reserved`, and for a range whose stop is below its start, which the decoder then treats like `All`: the header is listed with an empty `data`, and the chain goes on.

Whether data follows a header depends on the function. Confirm, Read, the immediate freezes and freeze-and-clears (codes 7 to 10), the cold and warm restarts, enable and disable unsolicited, assign class, delay measurement and record current time carry headers only, unless the objects are prefixed by their size: a file block read (g70v5, qualifier `0x5b`) carries the file handle and the block number. For the other functions, the size of the objects comes from a table of IEEE 1815-2012 annex A in the crate: a fixed size in bytes, packed bits (one bit per point for g1v1, g10v1, g12v3 and g80v1, among them the binary inputs, binary outputs and internal indications, two bits for g3v1), or a size carried by the prefix, for files, device profiles, data sets and authentication among others. `data` is then the range of the objects in `user_data`, and `LinkFrame::object_data(&header)` the bytes.

The chain stops at a header whose prefix or range code is reserved, and, when the function carries data, at a group and variation the table does not know, at a variable-size object without a size prefix, or at data that goes beyond the frame. That header is still listed, with an empty `data`, and what follows it is `undecoded`; a header cut before its last range field is not listed at all. Frames 154 and 156 of `dnp3.pcap` show a real case: a Disable Unsolicited whose third header, g60v4, has the qualifier byte `0xed`, prefix code 6 and range code 13 once bit 7 is set aside. Range code 13 is not defined by the standard: the crate lists the header with `PrefixCode::Size { octets: 4 }` and `RangeSpecifier::Reserved(13)` and would read nothing past it (nothing follows it here), and tshark shows an "Unknown Range Type".

The values themselves are not decoded: the crate says where each object is, the caller reads it. A response with three object headers (*tested*):

```rust
{{#include ../examples/src/scada.rs:dnp3_response_objects}}
```

## Validations

All of them are `Dnp3ParseError`:

| Error | When |
| --- | --- |
| `Truncated { expected, actual }` | fewer than the 10 bytes of a link header, or than the frame its `length` announces |
| `InvalidStartBytes([u8; 2])` | a frame that does not start with `05 64` |
| `InvalidLength(u8)` | `length` below 5 |
| `HeaderCrcMismatch { expected, actual }` | the CRC of the 8 header bytes does not match |
| `BlockCrcMismatch { block, expected, actual }` | the CRC of a block of user data does not match |
| `ApplicationHeaderTooShort { actual }` | a FIR segment with less than 2 bytes of application header, 4 for a response |
| `UnexpectedTrailingBytes { trailing }` | declared, never returned (see above) |

A refused payload is not labelled DNP3: it goes on to the next rules of the table and usually comes out `"Unknown"`, with nothing in `corrupted`, since no layer announced DNP3. One altered bit is enough (*tested*):

```rust
{{#include ../examples/src/scada.rs:dnp3_crc}}
```

## Oracle: 218 frames against tshark

The golden test `tests/dnp3_golden.rs` runs the sixteen captures of `pcaps_exemple/protocols/dnp3/`, taken from the test corpus of Zeek (BSD 3-clause, see the folder's `SOURCE.md`), and compares every segment and datagram that has a payload with tshark 4.6.6 without TCP reassembly, the view of a stateless parser (`tools/dnp3_oracle.sh`, frozen in `tests/data/dnp3_tshark_oracle.tsv`). Of 220 payloads, 218 are DNP3 frames, 179 on TCP and 39 on UDP, all labelled by the blind probe; the other two are the `05 05` segments of `dnp3.pcap`. On the 218 frames the link and transport headers match field by field: length, control, function, addresses, header CRC, FIR, FIN and sequence. 16 frames carry no user data; 159 application fragments fit in one frame, and their application header and 160 object headers, group, variation and the prefix and range codes of the qualifier, match too, except the objects of the four STOP_APPL of `dnp3.pcap`, which tshark does not dissect for that function; 7 first segments and 36 continuations belong to fragments spread over several frames.

A second test alters, one at a time, ten bytes of frame 4 of `dnp3_read.pcap`, from the second start byte to the block CRC: every altered frame is refused, by the decoder and by the probe, while the intact frame, moved to port 40000, stays DNP3. The fuzz target `parse_dnp3` runs nightly on the same parser: the frames must tile the input, the user data have the length `length` announces, every object lies within the user data, and a single altered byte in any of four real frames must be refused.

| Capture | Frames | Content |
| --- | --- | --- |
| `dnp3.pcap` | 214 | nine TCP sessions between three pairs of hosts, eight in 2004 and one in 2007: class reads, writes, selects, restarts, stop application, enable and disable unsolicited, confirmations, solicited and unsolicited responses |
| `dnp3_read.pcap` | 10 | read of classes 1, 2, 3 and 0, response with binary inputs, binary outputs and analog inputs |
| `dnp3_read_p20001.pcap` | 10 | the same bytes, port rewritten to 20001 |
| `dnp3_write.pcap` | 10 | write of the time and date (g50v1) |
| `dnp3_select_operate.pcap` | 13 | select then operate of a binary command (g12v1, CROB) |
| `dnp3_en_spon.pcap` | 10 | enable unsolicited (g60v2 to g60v4) |
| `dnp3_del_measure.pcap` | 10 | delay measurement, response g52v2 |
| `dnp3_rec_time.pcap` | 10 | record current time |
| `dnp3_file_read.pcap` | 30 | open, read of its single block (g70v5, prefixed by its size), close |
| `dnp3_file_write.pcap` | 22 | write of a file |
| `dnp3_file_del.pcap` | 10 | deletion of a file |
| `dnp3_link_only.pcap` | 35 | link status requests and replies, then a read whose response spans two application fragments over sixteen link frames |
| `dnp3_udp_read.pcap` | 23 | a read over UDP 20000, whose response spans two application fragments over sixteen link frames |
| `dnp3_udp_write.pcap` | 2 | write of g80v1 over UDP, clearing the restart indication |
| `dnp3_udp_select_operate.pcap` | 10 | select then operate over UDP, then a read whose response spans three link frames |
| `dnp3_udp_en_spon.pcap` | 4 | enable unsolicited over UDP (g60v2 to g60v4) |

One capture of the same Zeek folder is left out, `dnp3-flowbuffer-overflow-assert.pcap`: a scapy script generated it, and the corpus admits only real traffic.

## What is left out

- **Object values** are not decoded: no point value, flag, counter or time stamp, only where each object lies in `user_data`.
- **No reassembly**, at any level: neither the transport segments of a fragment, nor the fragments of a message, nor a link frame split over two TCP segments, which is labelled DNP3 in neither.
- **Groups outside the table** of annex A stop the object chain of a function that carries data; the header is kept, the rest is `undecoded`.
- **Secure Authentication** is named, not checked: functions 32, 33 and `0x83`, and group 120, whose objects are sized by their prefix.
