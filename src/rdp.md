# RDP

Remote Desktop Protocol, MS-RDPBCGR, added in 11.6.0 ([#100](https://github.com/Akmot9/Packet-parser/issues/100)). It rides on the stack that 10.0.0 tooled for S7comm, TPKT (RFC 1006) and COTP X.224 (RFC 905), with T.125 MCS above it. Segment by segment, the decoder reads what a stateless parser can see of a connection: the **X.224 connection**, where the client sends its cookie and the security protocols it offers and the server selects one or refuses, then the **MCS PDUs** that follow when standard RDP security is kept. Module: `packet_parser::parse::application::protocols::rdp`.

## Detection: port 3389, then TLS

The rule is port-guarded, TCP 3389 (IANA `ms-wbt-server`) on either side:

```rust
port_rule("RDP", Guard::Tcp, is_rdp_tcp_port, ProbeId::Rdp),   // 3389
```

A [blind probe](./application.md#three-detection-routes) is ruled out because none of the three layers is RDP's own: TPKT, COTP and MCS are also the stack of T.120 and of ISO over TCP. A server on another port is declared with `ParseConfig::decode_as(port, DecodeAsProtocol::Rdp)`, which runs the same probe under the same TCP guard ([Decode As](./application.md#decode-as)). The probe is `RdpPacket::try_from`, on the whole segment rather than its first `PROBE_CAP` bytes. `Application::try_from`, which has no port, never answers `"RDP"`.

**After a TLS or CredSSP negotiation, the segments are labelled TLS.** Once the server has selected TLS or CredSSP, the connection carries TLS records. Their first byte is a content type (`0x16` for a handshake) where TPKT wants version 3, so the RDP probe refuses them and the blind TLS rule further down the table takes them. That is the decision of the issue, tested on `rdp-to-ssl.pcap`: a stateless parser sees TLS records and names them, and nothing ties them back to the RDP connection they belong to.

The Connection Request of frame 6 of `rdp-x509.pcap`, on its port, moved to another one, then on that port declared (*tested*):

```rust
{{#include ../examples/src/remote_vpn.rs:rdp_connection_request}}
```

## The segment: TPKTs

```rust
pub struct RdpPacket<'a> {
    pub pdus: Vec<RdpPdu<'a>>,
    /// The last TPKT announces more than the segment holds.
    pub truncated: bool,
}

pub struct RdpPdu<'a> {
    /// Declared TPKT length, header included.
    pub tpkt_length: u16,
    pub cotp: X224Tpdu,
    pub payload: RdpPayload<'a>,
}

pub struct X224Tpdu {
    pub length_indicator: u8,
    pub pdu_type: CotpPduType,
    /// CR and CC only.
    pub dst_ref: Option<u16>,
    pub src_ref: Option<u16>,
    pub class: Option<u8>,
    /// DT only: last TPDU of the TSDU.
    pub end_of_tsdu: Option<bool>,
}
```

Every type of the module is `#[non_exhaustive]`: a `match` on `RdpPayload` or `McsPduType` needs a `_` arm.

`RdpPacket::try_from` reads TPKTs back to back until the end of the segment, and the segment is RDP only if every one of them decodes. The last one may announce more bytes than the segment holds, because TCP cut it: as long as the headers the decoder reads are complete, it is decoded on what is there and `truncated` is set. Its continuation, in the next segment, has no header of its own and is not RDP: the crate does not reassemble, and tshark without reassembly calls those bytes `data`. TCP cuts 16 TPKTs of the corpus in two, and the 12 that start their segment are decoded that way: 11 Send Data Requests of 1 421 bytes whose first segment holds 1 260, and a Connect-Response of 1 405 bytes whose first segment holds 1 398. The other 4 start in the middle of a segment, after the end of the previous TPKT (frames 69, 71, 73 and 74 of `rdp-proprietary-encryption.pcap`): those segments do not start with a TPKT, and none of their bytes is decoded.

The TPKT header and the fixed part of the TPDU, on the Connection Request of frame 6 of `rdp-x509.pcap` (offsets in the TCP payload):

| Bytes | Field | Frame 6 | Check |
| --- | --- | --- | --- |
| 0 | TPKT version | 3 | must be 3, else `InvalidTpkt` |
| 1 | TPKT reserved | 0 | must be 0, else `InvalidTpkt` |
| 2–3 | `tpkt_length`, big-endian, header included | 47 | at least 7, else `TpktTooShort` |
| 4 | `length_indicator` | 42 | |
| 5 | `pdu_type`: high nibble `E` for CR, `D` for CC (the low nibble is the credit), `F0` for DT | `E0`, CR | any other TPDU is `UnexpectedTpdu` |
| 6–7 | `dst_ref` (CR and CC) | 0 | |
| 8–9 | `src_ref` (CR and CC) | 0 | |
| 10 | `class` (CR and CC) | 0 | |
| 11… | X.224 user data, as far as the length indicator goes: the token, then the negotiation | | see below |

In a DT, byte 6 holds the EOT bit (`0x80`), `end_of_tsdu`, and the MCS PDU starts `length_indicator` + 1 bytes into the TPDU, at byte 7 for the usual length indicator of 2.

MS-RDPBCGR counts the token and the negotiation of a CR or a CC in the length indicator, where the crate's generic COTP parser, `copt::CotpHeader`, would read variable-part parameters. The RDP decoder therefore reads the fixed part itself and reuses only `CotpPduType`.

## The connection: Connection Request and Confirm

```rust
pub enum RdpPayload<'a> {
    /// X.224 Connection Request of the client.
    ConnectionRequest {
        /// `Cookie: mstshash=<user>` or a routing token, without its CR LF.
        token: Option<&'a [u8]>,
        negotiation: Option<NegotiationRequest>,
    },
    /// X.224 Connection Confirm of the server.
    ConnectionConfirm {
        negotiation: Option<NegotiationResponse>,
    },
    /// An MCS PDU in a Data TPDU.
    Mcs(McsPdu<'a>),
}

pub struct NegotiationRequest {
    pub flags: u8,
    /// Bits: 1 TLS, 2 CredSSP, 4 RDSTLS, 8 CredSSP with Early User
    /// Authorization Result; zero for standard RDP security only.
    pub requested_protocols: u32,
}

pub enum NegotiationResponse {
    Accepted { flags: u8, selected_protocol: u32 },
    Failure { failure_code: u32 },
}
```

The X.224 user data of a Connection Request is a token, then a negotiation request, both optional. The token is everything before the first CR LF, kept raw: `Cookie: mstshash=<user>` from the usual client, or a routing token. `RdpPayload::cookie_user()` returns the user of a cookie as a `&str`, and `None` for anything else. After the token comes nothing, or an 8-byte negotiation structure; a negotiation structure of another length is `InvalidNegotiation` (see the [validations](#validations)), and anything else `UnexpectedX224Data`. The user data of a Connection Confirm is empty, or the server's response or failure, in the same 8-byte structure:

| Byte | Field | Note |
| --- | --- | --- |
| 0 | type | `0x01` request (in a CR), `0x02` response or `0x03` failure (in a CC) |
| 1 | `flags` | kept raw, not read for a failure |
| 2–3 | length, little-endian | must be 8, else `InvalidNegotiation` |
| 4–7 | `requested_protocols`, `selected_protocol` or `failure_code` | `u32`, little-endian |

The protocols are bits (MS-RDPBCGR §2.2.1.1.1), and `NegotiationRequest` has a method for each but the last:

| Value | Security protocol | Method |
| --- | --- | --- |
| 0 | standard RDP security only | `standard_security_only()` |
| `0x1` | TLS | `tls()` |
| `0x2` | CredSSP | `credssp()` |
| `0x4` | RDSTLS | `rdstls()` |
| `0x8` | CredSSP with Early User Authorization Result | `credssp()` |
| `0x10` | RDS-AAD-Auth | none: the bit stays in `requested_protocols` |

`selected_protocol` holds one of these values; the flags and `failure_code` stay numbers that the crate does not name. The negotiation is where the connection forks: standard security keeps TPKT and MCS on the wire, TLS or CredSSP turns the rest of it into TLS records. A refusal and a CredSSP selection, on real frames of two captures (*tested*):

```rust
{{#include ../examples/src/remote_vpn.rs:rdp_negotiation}}
```

## MCS PDUs

```rust
pub struct McsPdu<'a> {
    pub kind: McsPduType,
    /// The whole PDU, choice or tag included.
    pub raw: &'a [u8],
    /// Decoded for Send Data.
    pub send_data: Option<McsSendData<'a>>,
}

pub enum McsPduType {
    ConnectInitial,
    ConnectResponse,
    ErectDomainRequest,
    DisconnectProviderUltimatum,
    AttachUserRequest,
    AttachUserConfirm,
    ChannelJoinRequest,
    ChannelJoinConfirm,
    SendDataRequest,
    SendDataIndication,
}

pub struct McsSendData<'a> {
    /// User id, from 1001.
    pub initiator: u16,
    pub channel_id: u16,
    /// Priority (two high bits) and segmentation (next two bits).
    pub priority_and_segmentation: u8,
    /// Declared length of the data.
    pub declared_length: Option<u16>,
    /// The data present in this segment.
    pub data: &'a [u8],
}
```

A Data TPDU carries one MCS PDU. The two connect PDUs of T.125 are BER: Connect-Initial is recognized by its tag `7F 65` (`[APPLICATION 101]`), Connect-Response by `7F 66` (`[APPLICATION 102]`), each followed by a readable BER length, short form or long form on one to four bytes, else `InvalidBerLength`. Their content, which tshark dissects further as T.124, stays in `raw`. Every other PDU is a DomainMCSPDU in PER, whose choice is the six high bits of the first byte:

| Choice | `McsPduType` |
| --- | --- |
| 1 | `ErectDomainRequest` |
| 8 | `DisconnectProviderUltimatum` |
| 10 | `AttachUserRequest` |
| 11 | `AttachUserConfirm` |
| 14 | `ChannelJoinRequest` |
| 15 | `ChannelJoinConfirm` |
| 25 | `SendDataRequest` |
| 26 | `SendDataIndication` |

Any other choice is `UnknownMcsPdu(choice)`. The two Send Data PDUs, which carry the RDP traffic itself, are decoded further. On frame 32 of `rdp-proprietary-encryption.pcap`, offsets in the MCS PDU:

| Bytes | Field | Frame 32 |
| --- | --- | --- |
| 0 | the choice, shifted left by 2 | `0x64`: 25, Send Data Request |
| 1–2 | `initiator`, big-endian, plus 1001 | 7, so 1008 |
| 3–4 | `channel_id`, big-endian | 1003 |
| 5 | `priority_and_segmentation` | `0x70` |
| 6 | PER length, `declared_length`: one byte below `0x80`, or two bytes `10xxxxxx xxxxxxxx` (14 bits) | 80 |
| 7… | `data`, from the end of the length to the end of the TPKT, or of the segment if TCP cut it | 80 bytes |

A fragmented length (first byte `11xxxxxx`) leaves `declared_length` at `None`, and `data` then starts right after the priority byte. The data are not decoded: they are the RDP payload as it travels, encrypted or not.

Frame 32, then a TPKT cut by TCP and its continuation (*tested*):

```rust
{{#include ../examples/src/remote_vpn.rs:rdp_mcs}}
```

## Validations

All of them are `RdpParseError`, in `packet_parser::errors::application::rdp`:

| Error | When |
| --- | --- |
| `Truncated { expected, actual }` | fewer than 7 bytes left for a TPKT, a TPDU shorter than its fixed part (3 bytes, 7 for a CR or CC), an empty MCS PDU, a Send Data shorter than 6 bytes, an empty segment |
| `InvalidTpkt { version, reserved }` | a TPKT version other than 3, or a non-zero reserved byte |
| `TpktTooShort(u16)` | a TPKT length below 7: the 4 bytes of its header and a TPDU of 3 |
| `UnexpectedTpdu(u8)` | a TPDU other than CR, CC and DT |
| `InvalidNegotiation { structure_type, length }` | a negotiation structure whose length field is not 8, or which is not 8 bytes long (from four bytes on; shorter, it is `UnexpectedX224Data`) |
| `UnexpectedX224Data(usize)` | user data of a CR or CC that is neither a token nor a negotiation structure |
| `UnknownMcsPdu(u8)` | a DomainMCSPDU choice other than the eight above |
| `InvalidBerLength` | an unreadable BER length after a connect tag |
| `Cotp(CotpParseError)` | declared, never returned by the decoder |

A failure only means no label. On port 3389 or a declared port, the segment goes on down the table and comes out `"Unknown"` unless another rule takes it, TLS after the negotiation. Nothing is reported in `corrupted`: a port is a hint, and the payload may belong to something else.

## Oracle: 861 segments, without reassembly

`tests/rdp_golden.rs` runs the five captures of `pcaps_exemple/protocols/rdp/`, taken from Zeek's test corpus (BSD 3-clause), and compares every segment that has a payload with tshark 4.6.6 run **without TCP reassembly** (`tcp.desegment_tcp_streams:FALSE`, the view of a stateless parser). `tools/rdp_oracle.sh` freezes, in `tests/data/rdp_tshark_oracle.tsv`, the highest layer tshark sees, the TPKT length, the COTP type, the token, the negotiation and the MCS PDU type. Zeek warns that many traces of its corpus are generated; the `SOURCE.md` of the folder settles the question for these five on their bytes, and sets aside `rdp-invalid-length.pcap`, whose bytes are fabricated.

| Segments | tshark | The crate |
| --- | --- | --- |
| 83 | `rdp`, `t125` or `t124` | `"RDP"`, with the same TPKT length, COTP type, token, negotiation and MCS type: 7 Connection Requests, 6 of them with a cookie, 7 Connection Confirms and 69 MCS PDUs |
| 481 | `tls`, or `x509ce` for a certificate | `"TLS"` for the 449 that start with a whole record; `"Unknown"` for the other 32: 27 continuations of a record cut by TCP, and 5 segments of `rdp-to-ssl.pcap` that start an Application Data record longer than themselves, which the TLS probe refuses |
| 287 | `data` for 278 segments that do not start with a TPKT, the 16 continuations of cut TPKTs among them; nothing above `tcp` for 9 segments it flags as out of order | `"Unknown"` |
| 10 | retransmissions, not dissected | not compared |

The 69 MCS PDUs are 3 Connect-Initial, 2 Connect-Response, 1 Erect Domain Request, 1 Attach User Request, 1 Attach User Confirm, 6 Channel Join Requests, 6 Channel Join Confirms, 27 Send Data Requests, 21 Send Data Indications and 1 Disconnect Provider Ultimatum. In the golden histogram of the whole corpus, `"RDP"` counts 89 frames: these 83, and six of the retransmissions, two in each of `rdp-no-cookie-mstshash.pcap`, `rdp-unknown-keyboard.pcap` and `rdp-x509.pcap`, which the stateless parser labels by their bytes. The fuzz target `parse_rdp` runs nightly on the decoder: no panic, and on success the TPKTs tile the segment, the last one possibly cut, and every borrowed slice points into the input.

| Capture | Frames | Content |
| --- | --- | --- |
| `rdp-x509.pcap` | 15 | cookie `mstshash=JOHN-PC`, standard RDP security, Connect-Initial and Connect-Response |
| `rdp-unknown-keyboard.pcap` | 11 | the same hosts and opening, a Connect-Initial with an unknown keyboard layout |
| `rdp-no-cookie-mstshash.pcap` | 20 | no cookie; TLS, CredSSP and CredSSP with Early User Authorization Result offered, the last one selected, then TLS |
| `rdp-to-ssl.pcap` | 658 | cookie `mstshash=AWAKECODI`, CredSSP selected, then the whole session in TLS |
| `rdp-proprietary-encryption.pcap` | 542 | standard RDP security after a refused TLS: the whole MCS session, TPKTs of 1 421 bytes cut across two segments |

## What is left out

- **RDP over UDP** (MS-RDPEUDP) is another transport, which the crate does not decode; the `rdpeudp*` captures of Zeek's corpus were left out.
- **No reassembly**: a TPKT cut by TCP is decoded on its first segment when it starts that segment, and its continuation stays `"Unknown"`, like the continuations of TLS records. A segment that starts with a continuation is refused whole, the complete TPKTs that follow it included: frame 77 of `rdp-proprietary-encryption.pcap` holds two.
- **Fast-path PDUs**, which MS-RDPBCGR sends without the TPKT, X.224 and MCS headers, fail the TPKT check and stay `"Unknown"`; tshark leaves them at `data` as well. Of the 262 `data` segments of the corpus that do not continue a cut TPKT, 241 start with a byte whose two low bits are clear, the mark of a fast-path PDU, where a TPKT has 3.
- **The correlation info** that a client may append to its negotiation request (36 bytes, announced by its flag `0x08`, MS-RDPBCGR §2.2.1.1) is not read: such a Connection Request is `InvalidNegotiation`, and comes out `"Unknown"` even on port 3389.
- **No connection state**: after a TLS or CredSSP negotiation the label is `"TLS"`, and nothing records that those records belong to an RDP connection, nor which protocol it selected.
- **The connect PDUs are not opened**: the T.124 conference data of a Connect-Initial or Connect-Response, where the keyboard layout of `rdp-unknown-keyboard.pcap` sits, stays in `raw`.
- **The Send Data contents are raw**: the RDP PDUs they carry are `data`.
- **Flags and failure codes** are numbers; the crate does not name them.
