# RTCP

RTCP, the RTP Control Protocol (RFC 3550 §6), travels beside an [RTP](./rtp.md) stream: each end reports what it sent and what it received, names itself, and says goodbye. The decoder was added in 13.3.0 ([#354](https://github.com/Akmot9/Packet-parser/issues/354), PR [#362](https://github.com/Akmot9/Packet-parser/pull/362)). The module is `packet_parser::parse::application::protocols::rtcp`, the errors are `RtcpError`, in `packet_parser::errors::application::rtcp`, and the label is `"RTCP"`.

![The RTCP datagram of frame 633 of wireshark_aaa.pcap, 32 bits per row, three packets one after the other, each opened by a four-byte header: version 2 with a count, a packet type and a length in 32-bit words minus one; the Sender Report, type 200, length 6 for 28 bytes, with the sender SSRC 0x3796cb71, a 64-bit NTP timestamp, the RTP timestamp 9411, 9 packets and 1548 octets sent; the Source Description, type 202, length 11 for 48 bytes; the Goodbye, type 203, length 6 for 28 bytes; on the right RtcpCompound, which gives the three packets in wire order, their bodies as bytes, and the sender information of the report](images/application/rtcp_compound.svg)

```rust
pub struct RtcpCompound<'a> { /* the datagram, validated */ }

pub struct RtcpPacket<'a> {
    pub padding: bool,               // the body ends with padding
    pub count: u8,                   // five bits: what they count depends on the type
    pub packet_type: RtcpPacketType,
    pub body: &'a [u8],              // what follows the four-byte header
}

pub struct RtcpSenderInfo {
    pub ntp_timestamp: u64,          // wallclock time of the report
    pub rtp_timestamp: u32,          // the same instant on the clock of the stream
    pub packet_count: u32,
    pub octet_count: u32,
}
```

A datagram carries one RTCP packet or several, back to back: a *compound* packet (§6.1). `RtcpCompound::try_from` validates the whole datagram once; `packets()` then gives the packets in wire order without allocating, and `as_bytes()` the datagram. The types are `#[non_exhaustive]`, and every body borrows from the datagram.

| Type | `RtcpPacketType` | `count` is | Defined in |
| --- | --- | --- | --- |
| 200 | `SenderReport` | the number of report blocks | RFC 3550 §6.4.1 |
| 201 | `ReceiverReport` | the number of report blocks | RFC 3550 §6.4.2 |
| 202 | `SourceDescription` | the number of chunks | RFC 3550 §6.5 |
| 203 | `Goodbye` | the number of sources | RFC 3550 §6.6 |
| 204 | `ApplicationDefined` | a subtype | RFC 3550 §6.7 |
| 205 | `TransportFeedback` | a feedback message type | RFC 4585 §6.2 |
| 206 | `PayloadFeedback` | a feedback message type | RFC 4585 §6.3 |
| 207 | `ExtendedReport` | reserved | RFC 3611 |

Two methods read what a consumer most often wants. `sender_ssrc()` is the SSRC that opens the body of every packet but a Source Description and a Goodbye, whose body is a list of sources. `sender_info()` is `Some` for a Sender Report: the NTP timestamp, the RTP timestamp and the two counters. The report blocks, the SDES items and the feedback messages stay bytes. Two constants are public: `RTCP_VERSION` and `RTCP_HEADER_LENGTH`, 4.

The last datagram a phone sends at the end of a call (*tested*):

```rust
{{#include ../examples/src/rtp.rs:rtcp_compound}}
```

## Detection: any UDP port

| Where | Rule | Probe | Accepts |
| --- | --- | --- | --- |
| any UDP port | blind rule 75 | `ProbeId::RtcpBlind` | a datagram `RtcpCompound::try_from` accepts, opened by a Sender Report or a Receiver Report, or made of one feedback packet alone |
| a UDP port declared with `ParseConfig::decode_as(port, DecodeAsProtocol::Rtcp)` | tried [before the table](./application.md#decode-as) | `ProbeId::Rtcp` | any datagram `RtcpCompound::try_from` accepts |

RTCP has no port of its own: by convention it takes the port after the one of its RTP stream, and RFC 5761 lets both share one. Rule 75 is the last UDP rule of the [table](./application.md#reading-the-table): every probe with a stronger signature has had the datagram first.

RTCP has what RTP lacks. Each packet says its length, and the lengths must tile the datagram to its last byte. The packet type is one of eight values. Each type has a minimum size, which grows with its count: a Sender Report with two report blocks is at least 76 bytes. On top of the decoder, the blind rule asks for the opening RFC 3550 §6.1 imposes, a Sender Report or a Receiver Report first. It accepts one exception, the reduced-size RTCP of RFC 5506: a single feedback packet, type 205 or 206, alone in its datagram.

`DecodeAsProtocol::Rtcp`, new in 13.3.0 and the last of the 34 variants, resolves to the label `RTCP`, the guard `Udp` and the probe `Rtcp`: on a declared port, any well-formed datagram is RTCP, whatever its first packet.

## Validations

| Part | Check | Error |
| --- | --- | --- |
| Packet | at least the four bytes of its header | `RtcpError::TooShort { expected, actual }` |
| Version | 2 | `InvalidVersion` |
| Packet type | 200 to 207 | `UnknownPacketType` |
| Length | the packet it announces fits in what remains of the datagram | `TruncatedPacket { declared, available }` |
| Padding, with the P bit | the last byte of the body is a multiple of four, not zero, and not longer than the body | `InvalidPadding` |
| Size | the body, without its padding, holds what the type and the count require | `PacketTooShortForType { packet_type, count, expected, actual }` |
| Padding | only on the last packet of the datagram | `InvalidPadding` |

The checks run in this order on each packet, from the first to the last, and the first failure is the error. Nothing may follow the last packet: a byte left over is a packet too short for its header.

| Type | Minimum body |
| --- | --- |
| Sender Report | 24 bytes, the SSRC and the sender information, plus 24 for each report block |
| Receiver Report | 4 bytes, the SSRC, plus 24 for each report block |
| Source Description | 8 bytes for each chunk |
| Goodbye | 4 bytes for each source |
| Application-defined | 8 bytes, the SSRC and a four-character name |
| Feedback, 205 and 206 | 8 bytes, the SSRC of the sender and the SSRC of the media source |
| Extended Report | 4 bytes, the SSRC |

Two refusals on the bytes of the corpus (*tested*):

```rust
{{#include ../examples/src/rtp.rs:rtcp_refusals}}
```

## What is not RTCP

Each row was checked against the crate, on a UDP port without a rule of its own, then on the same port declared `Rtcp`:

| Payload | Blind | Declared | Why |
| --- | --- | --- | --- |
| the Sender Report, SDES and BYE of the example | `"RTCP"` | `"RTCP"` | |
| its Sender Report alone, 28 bytes | `"RTCP"` | `"RTCP"` | a report may come alone |
| its SDES and BYE, without the report | `"Unknown"` | `"RTCP"` | well formed, but a compound packet opens with a report |
| its BYE alone | `"Unknown"` | `"RTCP"` | the same |
| one feedback packet of the LINE call | `"RTCP"` | `"RTCP"` | reduced-size RTCP |
| that feedback packet followed by a BYE | `"Unknown"` | `"RTCP"` | a feedback packet opens no compound packet |
| the example with one byte more | `"Unknown"` | `"Unknown"` | the lengths no longer tile the datagram |
| an RTP packet of the same call | `"Unknown"` | `"Unknown"` | its second byte, 8, is no packet type |
| the example, on TCP | `"Unknown"` | `"Unknown"` | the guard is UDP |

The seventh row is what makes the rule safe to run blind, and what [RTP](./rtp.md#why-there-is-no-blind-rule) has no equivalent of. A datagram is RTCP only if its first byte is `0x80` to `0xBF`, its second one of two values, or of two others when the packet is alone, and its length field, 16 bits, matches the size of the datagram or leads to another header that passes the same tests.

## Oracle: 52 datagrams

The golden test `tests/rtcp_golden.rs` compares the crate with tshark 4.6.9. `tools/rtcp_oracle.sh` freezes, in `tests/data/rtcp_tshark_oracle.tsv`, one line per datagram that tshark dissects as RTCP: the types and the lengths of its packets, the SSRC of each sender, and the sender information of a Sender Report.

| Capture | RTCP | What |
| --- | --- | --- |
| `sip/wireshark_aaa.pcap` | 1 | the Sender Report, SDES and BYE of the example |
| `ntp/ndpi_line.pcap` | 11 | feedback packets, each alone in its datagram |
| `rtcp/terrain_rtcp_censure.pcap` | 40 | 20 Sender Reports and 20 Receiver Reports, each with one report block and followed by an SDES |

The third capture is new. The corpus had no Receiver Report, and no public capture with one was found, so 40 datagrams were taken from a field capture of the maintainer and censored by `tools/censor_capture.py` before they were published. Addresses, ports, NTP timestamps and the text of the SDES items were rewritten; packet types, lengths, counts and SSRC are the original ones. Its `SOURCE.md` lists each rewritten field.

The crate and tshark give RTCP the same 52 datagrams, and no other frame of the corpus gets the label. In the golden histogram `"RTCP"` went from 0 to 52.

## What is left out

The limits every protocol shares are on the [Limits](./limits.md) page. The ones below are this protocol's own.

- **The bodies.** Report blocks, SDES items, the reason of a Goodbye and feedback messages are returned as bytes.
- **SRTCP** (RFC 3711) encrypts the packets and adds an index and an authentication tag after the last one. The lengths no longer tile the datagram, which stays `"Unknown"`, even on a declared port.
- **A compound packet that opens with another type** than a report is named on a declared port only.
- **RTCP multiplexed with RTP** on one port (RFC 5761) is named packet by packet: the RTCP datagrams get their label, the RTP ones do not, unless the port is declared `Rtp`.
- **RTCP over TCP** is not read.
