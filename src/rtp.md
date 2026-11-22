# RTP

RTP, the Real-time Transport Protocol (RFC 3550), carries sound and video: each datagram is a slice of a stream, with a sequence number and a timestamp to put the slices back in order. The decoder was added in 13.3.0 ([#353](https://github.com/Akmot9/Packet-parser/issues/353), PR [#358](https://github.com/Akmot9/Packet-parser/pull/358)). The module is `packet_parser::parse::application::protocols::rtp`, the errors are `RtpError`, in `packet_parser::errors::application::rtp`, and the label is `"RTP"`.

RTP is the one protocol of the crate with a decoder, a label and **no rule in the dispatch table**: `parse` gives the label on a port the caller declares, and nowhere else. The [reason](#why-there-is-no-blind-rule) is below.

![The RTP packet of frame 624 of wireshark_aaa.pcap, 32 bits per row: a first byte 0x80 for version 2, no padding, no extension and no CSRC, a second byte 0x08 for a clear marker bit and payload type 8, sequence number 28590, timestamp 1240, the SSRC 0x3796cb71, then 160 bytes of payload; on the right the RtpPacket struct, with the version, the marker, the payload type, the sequence number, the timestamp, the SSRC, an empty CSRC list, no extension, the payload as bytes and a padding length of 0](images/application/rtp_struct.svg)

```rust
pub struct RtpPacket<'a> {
    pub version: u8,                 // always 2
    pub marker: bool,                // the end of a video frame, the start of a talkspurt
    pub payload_type: u8,            // seven bits
    pub sequence_number: u16,
    pub timestamp: u32,              // in units of the payload clock
    pub ssrc: u32,                   // the synchronization source
    pub csrc: CsrcList<'a>,          // zero to fifteen contributing sources
    pub extension: Option<RtpHeaderExtension<'a>>,
    pub payload: &'a [u8],           // without the padding
    pub padding_length: u8,          // count byte included; 0 without the P bit
}

pub struct RtpHeaderExtension<'a> {
    pub profile: u16,                // 0xBEDE: the one-byte elements of RFC 8285
    pub data: &'a [u8],              // a multiple of four bytes
}
```

`RtpPacket` and `RtpHeaderExtension` are `#[non_exhaustive]`, and everything borrows from the datagram. `CsrcList` is a view over the list a mixer fills: `len()`, `is_empty()`, `iter()` for the identifiers in wire order, `as_bytes()`. `static_payload_name()` names the static payload types of RFC 3551, `PCMU` for 0, `PCMA` for 8, `MP2T` for 33; it is `None` for a dynamic type, 96 to 127, whose meaning is in the signalling of the call. Two constants are public: `RTP_VERSION` and `RTP_FIXED_HEADER_LENGTH`, 12.

The header, the CSRC list, the extension, the payload and the padding tile the datagram: nothing is left over, and nothing is guessed. The payload itself, the sound or the picture, is not decoded.

## Detection: a declared port, and nothing else

| Where | Rule | Probe | Accepts |
| --- | --- | --- | --- |
| a UDP port declared with `ParseConfig::decode_as(port, DecodeAsProtocol::Rtp)` | tried [before the table](./application.md#decode-as) | `ProbeId::Rtp` | any packet `RtpPacket::try_from` accepts |
| any other port | none | none | nothing: the packet is `"Unknown"` |

A phone call says where its media goes: the SDP body of the [SIP](./sip.md) INVITE and of its answer name the UDP ports. A caller that reads them, or that knows the ports of its cameras, declares them. One packet of a G.711 call, before and after (*tested*):

```rust
{{#include ../examples/src/rtp.rs:rtp_declared_port}}
```

`DecodeAsProtocol::Rtp` resolves to the label `RTP`, the guard `Udp` and the probe `Rtp`. The guard is UDP alone: RTP over TCP (RFC 4571) prefixes each packet with its length, which the crate does not read.

### Why there is no blind rule

A blind rule stands on a signature, and RTP has none: no magic, no length field, no checksum. Of the 96 bits of its header, two are fixed, the version. Any datagram whose first byte is `0x80` to `0xBF` and that is long enough has a well-formed RTP header, whatever it carries.

13.3.0 was developed with a blind rule, the last of the UDP cascade, with three more demands: no CSRC, a payload type outside 64 to 95, a payload that is not empty. It named the 15 011 RTP frames of the oracle. It also named eight frames that are not RTP:

| Frames | What they are |
| --- | --- |
| 3, in `The-Ultimate-PCAP.pcapng` | RDP over UDP, whose header starts with `0x80` |
| 3, in `wireshark_8579_radardata.pcap` | lines of text on UDP 7001 |
| 2, in `ndpi_quic_interop_V.pcapng` | QUIC Version Negotiation off port 443 |

Eight frames is few. But a label of the crate is a statement, and a consumer that builds a flow matrix cannot tell the eight from the others. No tightening of the probe brings the count to zero: the header has too few bits to stand on. The rule was removed before the release ([#364](https://github.com/Akmot9/Packet-parser/issues/364), PR [#365](https://github.com/Akmot9/Packet-parser/pull/365)), and a test of the crate checks that no frame of those three captures is labelled RTP any more.

What proves RTP is a flow, not a packet: several datagrams between the same two ports, with one SSRC and sequence numbers that follow each other. That needs memory, and `parse` has none ([Limits](./limits.md#what-a-stateless-parser-cannot-see)). A consumer that keeps a table of flows can confirm RTP that way, then declare the port, or keep the label itself. `RtpPacket::try_from` gives it the two fields to compare.

## Validations

| Part | Check | Error |
| --- | --- | --- |
| Datagram | at least the 12 bytes of the fixed header | `RtpError::TooShort { expected, actual }` |
| Version | 2 | `InvalidVersion` |
| Payload type | not 72 to 76 | `RtcpPayloadType` |
| CSRC list | CC identifiers of four bytes fit in the datagram | `TruncatedCsrcList { count, expected, actual }` |
| Extension, with the X bit | its four-byte header and the words it announces fit | `TruncatedExtension { expected, actual }` |
| Padding, with the P bit | the last byte counts at least one byte, and at most what follows the header | `InvalidPadding { padding, available }` |

The payload types 72 to 76 are reserved (RFC 3551 §6) because of [RTCP](./rtcp.md): with the marker bit, they give a second byte of 200 to 204, the first five RTCP packet types. A Sender Report read as RTP would be a packet of type 72 with its marker set; the decoder refuses it, and the dispatch then names it for what it is, even on a port declared RTP (*tested*):

```rust
{{#include ../examples/src/rtp.rs:rtp_refuses_rtcp}}
```

A payload may be empty: the twelve bytes of a header alone are a valid packet.

## On a declared port

Each row was checked against the crate, on a port declared `Rtp`:

| Payload | Label | Why |
| --- | --- | --- |
| a packet of the corpus, on UDP | `"RTP"` | |
| the same packet, on TCP | `"Unknown"` | the guard is UDP |
| the same packet, on a port that is not declared | `"Unknown"` | no rule of the table gives the label |
| its first twelve bytes | `"RTP"` | an empty payload is valid |
| its first byte changed to `0x40`, version 1 | `"Unknown"` | `InvalidVersion` |
| its CC field set to 1 | `"RTP"` | four bytes of the payload are read as a CSRC |
| its P bit set, the last byte being 213 | `"Unknown"` | `InvalidPadding`: 213 bytes do not fit |
| an RTCP Sender Report | `"RTCP"` | `RtcpPayloadType`, then the table |

A declared port is a statement of the caller: on it, everything that has the shape of RTP is RTP. The sixth row shows the cost. The decoder cannot know that a packet has no CSRC, only that the header says so.

## Oracle: 15 011 frames

The golden test `tests/rtp_golden.rs` compares the crate with tshark 4.6.9, whose `rtp_udp` heuristic is switched on and whose T.38 dissector is switched off. `tools/rtp_oracle.sh` freezes, in `tests/data/rtp_tshark_oracle.tsv`, one line per frame that tshark dissects as RTP: the payload type, the marker, the sequence number, the timestamp, the SSRC, the number of CSRC, the length of the extension and the padding. No capture was added: the four were already in the corpus.

| Capture | RTP frames | What |
| --- | --- | --- |
| `The-Ultimate-PCAP.pcapng` | 7 907 | SIP calls, video, and 457 SRTP packets |
| `wireshark_FAX-Call-t38-CA-TDM-SIP-FB-1.pcap` | 6 995 | G.711 before and after a fax |
| `ndpi_line.pcap` | 100 | a LINE call, with header extensions and padding |
| `wireshark_aaa.pcap` | 9 | G.711 A-law, the call of the [SIP](./sip.md) page |

The test checks three things:

- without Decode As, no frame of these captures is labelled `"RTP"`;
- with the destination port of each frame of the oracle declared, the 15 011 are labelled `"RTP"`;
- for each one, `RtpPacket::try_from` gives the fields of tshark, and the five parts tile the datagram.

SRTP (RFC 3711) encrypts the payload and leaves the header in clear, so its 457 packets decode like the others. tshark gives T.38 the G.711 packets that follow the fax re-INVITE of the second capture, because it follows the call; the oracle switches that dissector off, and the crate reads them as RTP.

## What is left out

The limits every protocol shares are on the [Limits](./limits.md) page. The ones below are this protocol's own.

- **No label without a declared port.** A consumer that does not know the media ports sees `"Unknown"`, and has to confirm the flow itself.
- **Nothing ties a packet to its session.** The SSRC, the sequence number and the timestamp are read, not followed: a gap, a reordering or a change of source is the consumer's to see.
- **The payload.** No codec is decoded, and a dynamic payload type has no name.
- **The header extension** is returned as bytes: the elements of RFC 8285 are not split.
- **SRTP** decodes as RTP: the header does not say that the payload is encrypted.
- **RTP over TCP** (RFC 4571) and RTP interleaved in RTSP are not read.
