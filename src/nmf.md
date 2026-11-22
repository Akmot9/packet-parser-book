# NMF

NMF, the .NET Message Framing protocol ([MC-NMF]), is what a WCF service speaks on a `net.tcp://` binding: it cuts a TCP stream into SOAP messages. Each end opens with a short preamble, then sends its messages as *envelopes*. The decoder was added in 13.3.0 ([#351](https://github.com/Akmot9/Packet-parser/issues/351), [#352](https://github.com/Akmot9/Packet-parser/issues/352), PR [#359](https://github.com/Akmot9/Packet-parser/pull/359)). The module is `packet_parser::parse::application::protocols::nmf`, the errors are `NmfError`, in `packet_parser::errors::application::nmf`, and the label is `"NMF"`.

![The preamble of frame 4 of terrain_nmf_censure.pcap, 32 bits per row, five records one after the other, each opened by its type byte: a Version record, type 0x00, major 1 and minor 0; a Mode record, type 0x01, mode 2 for Duplex; a Via record, type 0x02, a size of 41 on one byte and a 41-byte URI that starts with net.tcp://host/, censored; a Known Encoding record, type 0x03, encoding 8; and a Preamble End record, the single byte 0x0C; on the right NmfSegment, which gives the five records in wire order, the URI as a borrowed string](images/application/nmf_preamble.svg)

```rust
pub struct NmfSegment<'a> { /* the TCP segment, validated */ }

pub enum NmfRecord<'a> {
    Version { major: u8, minor: u8 },    // 0x00: always 1.0
    Mode(NmfMode),                       // 0x01
    Via(&'a str),                        // 0x02: the URI the messages are bound to
    KnownEncoding(u8),                   // 0x03: a well-known encoding, by number
    ExtensibleEncoding(&'a str),         // 0x04: an encoding named by its MIME type
    UnsizedEnvelope { chunks: &'a [u8] },// 0x05: a message sent as chunks
    SizedEnvelope { declared_length: u32, payload: &'a [u8] }, // 0x06
    End,                                 // 0x07: end of the session
    Fault(&'a str),                      // 0x08: a fault, named by a URI
    UpgradeRequest(&'a str),             // 0x09: TLS or Negotiate, by name
    UpgradeResponse,                     // 0x0A
    PreambleAck,                         // 0x0B
    PreambleEnd,                         // 0x0C
}

pub enum NmfMode { SingletonUnsized, Duplex, Simplex, SingletonSized } // 1 to 4
```

A segment is a run of records, and a record is a type byte followed by nothing, by one byte, or by a size and that many bytes. `NmfSegment::try_from` validates the whole segment once; `records()` then gives the records in wire order without allocating, and `as_bytes()` the segment. The types are `#[non_exhaustive]`, and the strings and payloads borrow from the segment. `record_type()` gives the type byte of a record.

A **size** ([MC-NMF] §2.2.2) is written on one to five bytes, seven bits in each, the low bits first; the high bit of a byte says that another follows. 41 is `29`; 1 106 is `D2 08`.

The preamble a client sends first (*tested*):

```rust
{{#include ../examples/src/nmf.rs:nmf_preamble}}
```

The message itself is not decoded. The payload of an envelope is a SOAP message, most often in the binary XML of [MC-NBFSE], and it is returned as bytes.

## Detection: any TCP port

| Where | Rule | Probe | Accepts |
| --- | --- | --- | --- |
| any TCP port | blind rule 76 | `ProbeId::NmfBlind` | a segment `NmfSegment::try_from` accepts and that opens with a preamble or with a sized envelope in binary XML |
| a TCP port declared with `ParseConfig::decode_as(port, DecodeAsProtocol::Nmf)` | tried [before the table](./application.md#decode-as) | `ProbeId::Nmf` | any segment `NmfSegment::try_from` accepts |

NMF has no registered port: 808 is the default of the Net.TCP port sharing service, and a service listens where its configuration says. Rule 76 sits near the end of the blind cascade of the [table](./application.md#reading-the-table), before DCE/RPC and MQTT. A decoder alone would be far too weak a probe: a record may be one byte long, and `0x07` proves nothing. The blind rule therefore accepts two openings only, each with a signature of several bytes:

- **a preamble**: a Version record, 1.0, a Mode record, then a Via record whose text holds `://`. That is `00 01 00 01`, a mode from 1 to 4, `02`, a size and a URI in UTF-8;
- **a sized envelope in binary XML**: the payload starts with the string table of [MC-NBFSE], a size followed by length-prefixed UTF-8 strings that fill it exactly, then `56 02 0B 01 73`. Those five bytes are the element `s:Envelope` of the static dictionary of [MC-NBFS] and the declaration of its prefix: the first bytes of every SOAP message in that encoding.

Everything else needs a declared port: the acknowledgement of the preamble and the end of the session, one byte each, an envelope in another encoding, a fault. `DecodeAsProtocol::Nmf` resolves to the label `NMF`, the guard `Tcp` and the probe `Nmf`, the decoder alone (*tested*):

```rust
{{#include ../examples/src/nmf.rs:nmf_one_byte}}
```

## Validations

| Part | Check | Error |
| --- | --- | --- |
| Segment | not empty | `NmfError::Empty` |
| Record type | `0x00` to `0x0C` | `UnknownRecordType` |
| Version | three bytes, and 1.0 | `TruncatedRecord`, `UnsupportedVersion { major, minor }` |
| Mode | two bytes, and 1 to 4 | `TruncatedRecord`, `InvalidMode` |
| Known encoding | two bytes | `TruncatedRecord` |
| Size | at most five bytes, and a value that fits in 32 bits | `MalformedSize` |
| Via, extensible encoding, fault, upgrade request | the string is whole in the segment | `TruncatedRecord { record_type, expected, actual }` |
| The same four | valid UTF-8 | `InvalidString { record_type }` |

The records are read one after the other until the end of the segment, and the first failure is the error. Two records are allowed to run past it, because a message is often longer than a segment:

- a **sized envelope** keeps the size it announces in `declared_length` and, in `payload`, the bytes the segment holds. `is_truncated()` says that the message goes on in the next segment;
- an **unsized envelope** takes everything up to the end of the segment as its chunks, without splitting them.

A record after a truncated envelope cannot exist: the envelope ends the segment. What the decoder refuses, on the bytes of the preamble (*tested*):

```rust
{{#include ../examples/src/nmf.rs:nmf_refusals}}
```

## What is not NMF

Each row was checked against the crate, on a TCP port without a rule of its own, then on the same port declared `Nmf`:

| Payload | Blind | Declared | Why |
| --- | --- | --- | --- |
| the preamble of the example | `"NMF"` | `"NMF"` | |
| the preamble without its last two records | `"NMF"` | `"NMF"` | Version, Mode and Via are the signature |
| its Version and Mode records alone | `"Unknown"` | `"NMF"` | five bytes, no Via |
| the acknowledgement, `0B` | `"Unknown"` | `"NMF"` | one byte is no signature |
| the start of a sized envelope in binary XML | `"NMF"` | `"NMF"` | truncated, and named by its opening |
| a sized envelope of three bytes, `abc` | `"Unknown"` | `"NMF"` | its payload does not open as [MC-NBFSE] |
| forty null bytes | `"Unknown"` | `"Unknown"` | `UnsupportedVersion`: a Version record of 0.0 |
| the preamble, on UDP | `"Unknown"` | `"Unknown"` | the guard is TCP |
| a DCE/RPC Bind | `"DCE/RPC"` | `"NMF"` | its first byte, `05`, opens an unsized envelope |

The last row is a warning about declared ports. An unsized envelope has no size to check, so on a port declared `Nmf` any segment that starts with `05` is NMF. Declare the port of a service you know to be WCF, not a range.

## Oracle: 23 segments

No public NMF capture was found: the Wireshark tracker has fuzz files only. `pcaps_exemple/protocols/nmf/terrain_nmf_censure.pcap` is 32 frames of a field capture of the maintainer, censored by `tools/censor_capture.py` before they were published. Addresses, ports, the URI of the Via record, the strings of the string tables and the bodies of the messages were rewritten; record types, sizes, the mode, the encoding and the segmentation are the original ones. Its `SOURCE.md` lists each rewritten field, and tshark reads the same records before and after.

The golden test `tests/nmf_golden.rs` compares the crate with tshark 4.6.9, which is told the two service ports. `tools/nmf_oracle.sh` freezes, in `tests/data/nmf_tshark_oracle.tsv`, one line per segment with a payload: its record types, the size of its envelope, the mode, the encoding and the length of the Via.

| Segments | What | Without Decode As | Ports declared |
| --- | --- | --- | --- |
| 1 | the preamble | `"NMF"` | `"NMF"` |
| 5 | sized envelopes: four whole messages, and the first segment of a message of 50 253 bytes | `"NMF"` | `"NMF"` |
| 2 | the acknowledgement and the end of the session, one byte each | `"Unknown"` | `"NMF"` |
| 15 | continuation segments, in the middle of a message | `"Unknown"` | `"Unknown"` |

The test checks that the eight segments of the first three rows split into the records tshark reads, field by field, and that the long envelope is cut by its segment with `is_truncated()`. tshark does not reassemble here either, and reads the fifteen continuation segments as records; the crate does not. In the golden histogram `"NMF"` went from 0 to 6.

## What is left out

The limits every protocol shares are on the [Limits](./limits.md) page. The ones below are this protocol's own.

- **Continuation segments.** A message of 50 KiB is one labelled segment followed by some thirty-four that are `"Unknown"`. On a real WCF flow most segments are in that case: the label of a flow is the label of its first segments ([Limits](./limits.md#what-a-stateless-parser-cannot-see)).
- **Text SOAP and binary XML without a session dictionary.** No real frame of the corpus carries them, so the blind rule does not know them: they are named on a declared port only.
- **Unsized envelopes** are not split into chunks, and their end is not looked for.
- **After an upgrade**, the stream is TLS or Negotiate: it is no longer readable NMF, and TLS is labelled TLS.
- **The message.** Neither the string table nor the binary XML is decoded.
