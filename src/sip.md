# SIP

SIP, the Session Initiation Protocol (RFC 3261), sets calls up, changes them and ends them: a phone registers with its server, invites another one, hangs up. The voice travels apart, in RTP; SIP carries the signalling only, as text, in a syntax borrowed from HTTP. The decoder was added in 13.2.0 ([#342](https://github.com/Akmot9/Packet-parser/issues/342), PR [#343](https://github.com/Akmot9/Packet-parser/pull/343)). The module is `packet_parser::parse::application::protocols::sip`, the errors are `SipError`, in `packet_parser::errors::application::sip`, and the label is `"SIP"`.

![A SIP response, a 100 Trying, 32 bits per row: the status line, version SIP/2.0, space, the three-digit code 100, space, the reason phrase Trying and CR LF; then the header lines in the order the server sends them, Call-ID first, CSeq: 6 REGISTER, From, To, Via and Content-Length: 0, and the empty line that ends the head; on the right the SipMessage struct, with the start line, the Call-ID, the CSeq split into 6 and REGISTER, the raw From, To and Via, a Content-Length of 0, six headers and an empty body](images/application/sip_response.svg)

```rust
pub struct SipMessage<'a> {
    pub start_line: SipStartLine<'a>,
    pub headers: SipHeaders<'a>,     // every header line, in wire order
    pub via: &'a str,                // the first Via, raw
    pub from: &'a str,               // raw: display name, URI, tag
    pub to: &'a str,
    pub call_id: &'a str,
    pub cseq: SipCseq<'a>,
    pub content_length: Option<u32>, // None when the header is absent
    pub body: &'a [u8],              // cut at Content-Length
}

pub enum SipStartLine<'a> {
    Request { method: &'a str, uri: &'a str },
    Response { status_code: u16, reason: &'a str },
}

pub struct SipCseq<'a> {
    pub sequence: u32,               // below 2^31
    pub method: &'a str,             // for a response, the method of the request it answers
}
```

The three types and both variants are `#[non_exhaustive]`, and everything borrows from the payload. `is_request()` tells the two start lines apart, `status_code()` is `None` for a request, and `method()` gives the method of a request, or for a response the method its CSeq names. The five fields from `via` to `cseq` are the mandatory headers, found whatever their form on the wire, `Call-ID` or `i`. When a header occurs twice, the field holds the first one: for Via, the last hop the message crossed.

`SipHeaders` is the view over the whole header block, validated once while parsing, in the manner of `HttpHeaders`. `iter()` gives the `(name, value)` pairs in wire order, the names as written; `len()` and `is_empty()` count them. `get(name)` returns the first value of a name compared case-insensitively, and it knows the compact forms both ways: `get("Call-ID")` finds an `i:` line and `get("i")` a `Call-ID:` line. None of them allocates. Three constants are public: `SIP_VERSION`, `SIP_METHODS` and `SIP_COMPACT_FORMS`.

## Detection: any port, UDP and TCP

| Where | Rule | Probe | Accepts |
| --- | --- | --- | --- |
| any TCP or UDP port | blind rule 63 | `ProbeId::Sip` | a head that `SipMessage::try_from` accepts, within the first `PROBE_CAP` bytes |
| a port declared with `ParseConfig::decode_as(port, DecodeAsProtocol::Sip)` | tried [before the table](./application.md#decode-as) | `ProbeId::Sip` | the same |

Rule 63 sits in the blind cascade of the [table](./application.md#reading-the-table), after the first SSH rule and just before HTTP. It has no transport guard: RFC 3261 §18 runs SIP over UDP and TCP alike. It has no port either. 5060 is the registered port, but a server may listen anywhere, and the content proves more than a port would. 5061 carries SIP inside TLS, which is labelled TLS: the crate does not decrypt.

A rule without a port and without a transport can only stand on a strong signature, and SIP has one:

- the version `SIP/2.0`, compared case-insensitively (§7.1);
- for a request, one of the 14 methods of the IANA registry, in upper case: methods are case-sensitive (§7.1);
- the five headers every request and every response carries (§8.1.1): Via, From, To, Call-ID and CSeq;
- a CSeq whose number is below 2<sup>31</sup> and whose method, for a request, is the method of the request line.

Before any of that, `may_start_sip` looks at the first bytes alone: a status line, or one of the 14 methods followed by a space. Almost every other payload stops there, at a constant cost. The two rules on either side cannot take a SIP message: the HTTP probe wants the version `HTTP/`, and SSDP, on UDP 1900, speaks HTTP too (`NOTIFY * HTTP/1.1`).

`DecodeAsProtocol::Sip`, new in 13.2.0 and the last of the 31 variants, resolves to the label `SIP`, the guard `Any` and the probe of rule 63. A declared port is tried before the table, so it wins over a port rule that would accept the payload first. Like every declared port, it does not lift a terminal port such as mDNS on UDP 5353.

A server's `100 Trying` to a REGISTER, with its headers in the order that server sends them (*tested*):

```rust
{{#include ../examples/src/sip.rs:sip_response}}
```

## The start line

| Start line | Example | `SipStartLine` | Checked |
| --- | --- | --- | --- |
| `Method SP Request-URI SP SIP-Version` | `REGISTER sip:sip.cybercity.dk SIP/2.0` | `Request { method, uri }` | the method is one of the 14; the URI is a scheme, a colon, then visible ASCII without a space; the version is `SIP/2.0` |
| `SIP-Version SP Status-Code SP Reason-Phrase` | `SIP/2.0 100 Trying` | `Response { status_code, reason }` | three digits, from 100 to 699; the reason may be empty |

The scheme follows `absoluteURI` in RFC 2396: a letter, then letters, digits, `+`, `-` or `.`. So `sip:`, `sips:`, `tel:` and `urn:` all pass. The 14 methods are those of the IANA registry of SIP methods:

| Method | Defined in |
| --- | --- |
| `INVITE`, `ACK`, `BYE`, `CANCEL`, `OPTIONS`, `REGISTER` | RFC 3261 |
| `PRACK` | RFC 3262 |
| `SUBSCRIBE`, `NOTIFY` | RFC 6665 |
| `PUBLISH` | RFC 3903 |
| `INFO` | RFC 6086 |
| `REFER` | RFC 3515 |
| `MESSAGE` | RFC 3428 |
| `UPDATE` | RFC 3311 |

## Header lines

Each line of the head is a name, a colon and a value (§7.3.1). The name is a `token` (§25.1): letters, digits and ten marks, `- . ! % * _ + ' ~` and the backquote, possibly followed by blanks before the colon. The blanks around the value are trimmed. A line that starts with a space or a tab continues the previous one: RFC 3261 still allows this folding, which HTTP gave up. The value is then returned raw, the CR LF and the blanks of the fold included.

A header may come in its long form or in a compact form of one letter (§7.3.3). `SIP_COMPACT_FORMS` holds the 20 pairs of the IANA registry, and the decoder accepts both forms of the five mandatory headers:

| Compact | Long | Compact | Long |
| --- | --- | --- | --- |
| `a` | Accept-Contact | `m` | Contact |
| `b` | Referred-By | `n` | Identity-Info |
| `c` | Content-Type | `o` | Event |
| `d` | Request-Disposition | `r` | Refer-To |
| `e` | Content-Encoding | `s` | Subject |
| `f` | **From** | `t` | **To** |
| `i` | **Call-ID** | `u` | Allow-Events |
| `j` | Reject-Contact | `v` | **Via** |
| `k` | Supported | `x` | Session-Expires |
| `l` | Content-Length | `y` | Identity |

The values are not decoded further. From, To and Via keep their display names, URIs and parameters as one string, and the body, SDP most of the time, is bytes.

The body is what follows the empty line, cut at `Content-Length` when the header is present. Over UDP, a datagram carries one whole message (§18.3), and every frame of the corpus has a body of exactly the announced length. Over TCP, the cut keeps a second message of the same segment out of the body of the first one; that second message is not decoded.

## Validations

| Part | Check | Error |
| --- | --- | --- |
| Head | ends with an empty line, CR LF CR LF | `SipError::MissingHeaderTerminator` |
| Head | valid UTF-8 | `InvalidUtf8` |
| Request line | a method among the 14 | `UnknownMethod` |
| Request-URI | a scheme, a colon, visible ASCII | `InvalidRequestUri` |
| Version | `SIP/2.0`, in any case | `InvalidVersion` |
| Status code | three digits, from 100 to 699 | `InvalidStatusCode` |
| Header line | a token, a colon, a value, or the continuation of a fold | `InvalidHeader` |
| Mandatory headers | Via, From, To, Call-ID and CSeq, long or compact | `MissingHeader`, with the long name |
| CSeq | a number below 2<sup>31</sup>, blanks, one of the 14 methods, nothing after | `InvalidCseq` |
| CSeq of a request | the method of the request line | `CseqMethodMismatch { request, cseq }` |
| Content-Length | decimal digits | `InvalidContentLength` |

The checks run in this order, and the first failure is the error. A status line is recognized by its version, so `SIP/3.0 200 OK` is read as a request line, and fails with `UnknownMethod`.

## What is not SIP

The rule has no port and no transport, so the head is all that keeps other payloads out. Each row was checked against the crate, on UDP and on TCP, on port 5060 and on port 12345:

| Payload | Label | Why |
| --- | --- | --- |
| `invite sip:… SIP/2.0`, the five headers | `"Unknown"` | methods are case-sensitive |
| `INVITE sip:… sip/2.0`, the five headers | `"SIP"` | the version is not |
| `FOO sip:… SIP/2.0`, a method outside the registry | `"Unknown"` | `UnknownMethod` |
| `INVITE bob@biloxi.com SIP/2.0` | `"Unknown"` | the URI has no scheme |
| `INVITE sip:… SIP/3.0` | `"Unknown"` | `InvalidVersion` |
| `SIP/2.0 700 …` | `"Unknown"` | the code goes up to 699 |
| an INVITE without CSeq | `"Unknown"` | `MissingHeader("CSeq")` |
| an INVITE with `CSeq: 1 ACK` | `"Unknown"` | `CseqMethodMismatch` |
| a CSeq of 2 147 483 648 | `"Unknown"` | the number must be below 2<sup>31</sup> |
| a head without its empty line, or with LF line ends | `"Unknown"` | `MissingHeaderTerminator` |
| `OPTIONS / HTTP/1.1` | `"HTTP"` on TCP, `"Unknown"` on UDP | the version is HTTP's |
| `NOTIFY * HTTP/1.1` | `"SSDP"` on UDP 1900, `"Unknown"` elsewhere | the version is HTTP's |
| `OPTIONS rtsp://… RTSP/1.0` | `"Unknown"` | the version is RTSP's |
| a keep-alive: CR LF CR LF, spaces, `hello` | `"Unknown"` | no start line |

Unlike the HTTP probe, the SIP probe does not accept line ends that are `LF` alone: RFC 3261 §7 asks for CR LF, and every message of the corpus has them.

Phones and servers keep their NAT bindings open with small datagrams on the SIP port. RFC 5626 uses CR LF pairs, or STUN; others send what they like. The two captures of the corpus that carry them (*tested*):

```rust
{{#include ../examples/src/sip.rs:sip_keepalives}}
```

## Oracle: 201 frames

The golden test `tests/sip_golden.rs` compares the crate with tshark 4.6.9, without IP defragmentation or TCP reassembly, the view of a stateless parser. `tools/sip_oracle.sh` freezes, in `tests/data/sip_tshark_oracle.tsv`, one line per frame that tshark dissects as SIP. Each line holds the method or the status code, the number and the method of the CSeq, and the Content-Length. It keeps no Call-ID and no phone number. The captures are in `pcaps_exemple/protocols/sip/`, each with its provenance and its licence in `SOURCE.md`, and in the Ultimate PCAP:

| Capture | Frames | SIP | What |
| --- | --- | --- | --- |
| `wireshark_aaa.pcap` | 691 | 81 | a soft phone behind a home router in 2005: REGISTER, 401 and 407, INVITE, CANCEL, 100, 183, 200, 403, 408, 480; around them, DNS, NetBIOS, DHCP, FTP and RTP |
| `wireshark_FAX-Call-t38-CA-TDM-SIP-FB-1.pcap` | 7 217 | 92 | a fax call through a media gateway in 2008: INVITE, OPTIONS, BYE, 100, 180, 200, 488; around them, MEGACO, RTP and T.38 |
| `ndpi_sip_hello.pcapng` | 30 | 8 | REGISTER, 401 and 200 with a Huawei SoftX3000 in 2022, and 22 `hello` keep-alives |
| `ndpi_http_on_sip_port.pcap` | 4 | 0 | the negative: an HTTP GET and its 403, on TCP 5060 |
| `The-Ultimate-PCAP.pcapng` | 51 328 | 20 | three calls in 2019: INVITE, 100, 180, 200, ACK, BYE |

The first two come from the Wireshark wiki, under the GPL; the two others from the test corpus of nDPI, under the LGPL 3.0. The test checks four things:

- the crate labels `"SIP"` exactly the 201 frames of the oracle, and no other frame of these captures;
- for each one, `SipMessage::try_from` gives the start line, the CSeq and the Content-Length of tshark;
- the body has exactly the announced length;
- the first Via names UDP, as every message of the corpus travels over UDP.

The HTTP of the negative stays HTTP. tshark dissects one more frame as SIP: frame 15114 of the Ultimate PCAP, the first IPv4 fragment of a 2 017-byte INVITE. The crate does not reassemble IP ([#105](https://github.com/Akmot9/Packet-parser/issues/105)) and gives a fragment no application layer, so the oracle leaves it out, and a third test checks that it stays without one.

In the golden histogram `"SIP"` went from 0 to 181. Most of the other frames of these captures came in as `"Unknown"`: the RTP, T.38 and MEGACO of the fax call, the keep-alives, the NetBIOS datagrams.

## What is left out

The limits every protocol shares, reassembly among them, are on the [Limits](./limits.md) page. The ones below are this protocol's own.

- **SIP over TCP.** The corpus has no real TCP capture: the TCP path is covered by the crate's unit tests, on synthetic messages.
- **A message over several segments.** A head cut between two TCP segments is `"Unknown"`, because its empty line is in the next one. So are the segments that carry the rest of a message, and a head longer than `PROBE_CAP`, 18 KiB.
- **IPv4 fragments.** An INVITE whose SDP pushes the datagram beyond the MTU is fragmented, and no fragment is read.
- **Keep-alives.** CR LF pairs, STUN, spaces and `hello` on port 5060 stay `"Unknown"`.
- **SIP inside TLS** is labelled TLS, and **SIP over WebSocket** (RFC 7118) is not decoded.
- **Extension methods** outside the IANA registry are not recognized.
- **The values.** No URI, Via parameter or SDP body is decoded, and a folded value is returned with its fold.
