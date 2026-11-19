# HTTP

HTTP/1.x (RFC 9112), as it fits in one TCP segment: the crate reassembles nothing. The module is `packet_parser::parse::application::protocols::http`, and its errors are `HttpParseError`, in `packet_parser::errors::application::http`. Since 11.7.0 it has two decoders, `HttpRequest` and `HttpResponse` ([#176](https://github.com/Akmot9/Packet-parser/issues/176)), and both borrow everything from the payload:

![An HTTP/1.1 response, a 204 No Content, 32 bits per row: the status line, version, space, three-digit code, space, reason phrase and CR LF, then the header line Content-Length: 0, six more header lines and the empty line that ends the head; on the right the HttpResponse struct, with the version, the status code 204, the reason, seven headers and an empty body](images/application/http_response.svg)

```rust
pub struct HttpRequest<'a> {
    pub method: &'a str,
    pub uri: &'a str,
    pub version: &'a str,           // "HTTP/1.1", "HTTP/1.0"...
    pub headers: HttpHeaders<'a>,
    pub body: &'a str,              // the body as text, empty when it is not UTF-8
    pub body_bytes: &'a [u8],       // the body as carried, since 11.7.0
}

pub struct HttpResponse<'a> {
    pub version: &'a str,
    pub status_code: u16,           // three digits
    pub reason: &'a str,            // possibly empty
    pub headers: HttpHeaders<'a>,
    pub body: &'a [u8],
}
```

Both are `#[non_exhaustive]`. `HttpHeaders` is the view over the header block that both share, validated once while parsing: `iter()` gives the `(name, value)` pairs in wire order, `get(name)` the first value of a name compared case-insensitively, and neither allocates.

## Detection: requests and responses

The rule is a blind probe on TCP, `rule(ApplicationProtocol::Http, Guard::Tcp, ProbeId::Http)`, rule 63 of the table, between the two SSH rules and before GIOP; no port is involved. The SSH rule after it, added in 13.1.0, reads a banner behind other lines, so that an HTTP response whose body quotes a banner stays HTTP. Before 11.7.0 the probe was `HttpRequest::try_from` alone: a response came out `"Unknown"` while the request that caused it came out `"HTTP"`, and since the whole payload had to be valid UTF-8, so did a request whose binary body fitted in the same segment. The probe now accepts either of two start lines:

- a request line: a method among GET, HEAD, POST, PUT, DELETE, CONNECT, OPTIONS, TRACE and PATCH, a URI, and a version, `HTTP/` then one digit, or two separated by a dot;
- a status line (RFC 9112 §4): the same version, a code of exactly three digits, and a reason phrase, possibly empty.

Header lines follow, each with a colon, up to the first `CRLF CRLF`. Only this head must be valid UTF-8, for requests as for responses; the body is taken as it is, an image, gzip or a piece of a `chunked` transfer. The probe reads the first `PROBE_CAP` bytes of the payload (invariant 3), and without a `CRLF CRLF` in them, all of them are the head.

The body is not decoded: no chunk is reassembled, nothing is decompressed, and nothing checks it against `Content-Length`, so a body cut by the segment is what follows the head in this one. HTTP/2 and HTTP/3 have no decoder, and HTTP inside TLS is labelled TLS: the crate does not decrypt.

Frame 30 of `pcaps_exemple/protocols/arp/arppoison.pcapng`, a server's `204 No Content`, came out `"Unknown"` in 11.6.0 (*tested*):

```rust
{{#include ../examples/src/shared.rs:http_response}}
```

Frame 21178 of `pcaps_exemple/The-Ultimate-PCAP.pcapng` is an OCSP request to Let's Encrypt over IPv6, whose 85-byte DER body is in the same segment; because of that body, it came out `"Unknown"` in 11.6.0 (*tested*):

```rust
{{#include ../examples/src/shared.rs:http_binary_body}}
```

## What is not HTTP

The rule has no port, so its start line is all that keeps other text protocols out. Each row was checked against the crate, on TCP:

| Payload starts with | Label | Why |
|---|---|---|
| `get / HTTP/1.1` | `"Unknown"` | methods are upper case |
| `PROPFIND / HTTP/1.1`, `NOTIFY * HTTP/1.1` | `"Unknown"` | the method is not one of the nine |
| `PRI * HTTP/2.0`, the HTTP/2 preface | `"Unknown"` | `PRI` is not one of the nine |
| `OPTIONS rtsp://… RTSP/1.0` | `"Unknown"` | the version does not start with `HTTP/` |
| `INVITE sip:… SIP/2.0` | `"Unknown"` | neither the method nor the version |
| `ICY 200 OK` | `"Unknown"` | a status line starts with `HTTP/` |
| `HTTP/1.1 20 OK` | `"Unknown"` | the code is not three digits |
| a header line without a colon | `"Unknown"` | `HttpParseError::InvalidHeader` |
| a head that is not UTF-8 | `"Unknown"` | `HttpParseError::InvalidUtf8` |

On UDP nothing is HTTP: the rule has a TCP guard. `NOTIFY` and `M-SEARCH` on UDP 1900 are SSDP, rule 16.

Three shapes are accepted that a strict reader would refuse: a start line with no header after it, line ends that are `LF` alone, and a status line with no reason phrase. `HTTP/2 200` is accepted too, since the version is one digit or two; it is a line no HTTP/2 connection carries in clear.

## Validations

The head is text, so the table counts lines, not bytes.

| Part | Check | Error |
|---|---|---|
| Head | valid UTF-8, up to the first empty line or the end of what the probe reads | `HttpParseError::InvalidUtf8` |
| Request line | three parts: method, URI, version | `MissingMethod`, `MissingUri`, `MissingVersion` |
| Method | GET, HEAD, POST, PUT, DELETE, CONNECT, OPTIONS, TRACE or PATCH | `InvalidMethod`, with the text |
| Version | `HTTP/`, then one digit, or two separated by a dot | `InvalidVersion`, with the text |
| Status line | a version, then a code | `MissingVersion`, `MissingStatusCode` |
| Status code | exactly three digits | `InvalidStatusCode`, with the text |
| Header line | a colon | `InvalidHeader` |

## Oracle: 296 frames

`tests/http_golden.rs` compares the crate with tshark 4.6.6 without TCP reassembly, the view of a stateless parser (`tools/http_oracle.sh`, frozen in `tests/data/http_tshark_oracle.tsv`). For each frame it checks the kind, the version, and the method and URI or the code and phrase. It runs on every capture of `pcaps_exemple/protocols/` and on `The-Ultimate-PCAP.pcapng`: 144 requests and 152 responses match.

The crate labels no other frame of these captures `"HTTP"`, retransmissions apart. tshark does not dissect a retransmission; the crate labels six of them like the segments they repeat, and they are left out of the comparison. The two responses that tshark decrypts in `tls12-dsb.pcapng`, with the key the capture carries, stay TLS.

With 11.7.0 the golden histogram went from 72 to 146 HTTP labels: 72 responses more, and 2 retransmissions of responses. `"Unknown"` went from 9 579 to 9 505.

## What is left out

The limits every protocol shares, reassembly and checksums among them, are on the [Limits](./limits.md) page. The ones below are this protocol's own.

- **The body.** No chunk is reassembled, nothing is decompressed, and nothing checks the body against `Content-Length`: a body cut by the segment is what follows the head in this one.
- **A message over several segments.** The crate reassembles nothing. A head cut between two header lines, or after the colon of one, is read as far as it goes; cut before the colon of a header line, the segment is `"Unknown"`. So are the segments that carry the rest of the message, which start with no request or status line.
- **Other methods.** A WebDAV `PROPFIND` or any extension method is not recognized. The response to it still is: a response is recognized on its own status line.
- **HTTP/2 and HTTP/3.** They have no decoder.
- **HTTP inside TLS.** It is labelled TLS: the crate does not decrypt.
- **Retransmissions.** A retransmitted segment is labelled like the one it repeats, and counted again.
