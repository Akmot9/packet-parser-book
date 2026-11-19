# TLS

Transport Layer Security, as far as its record layer: the five bytes that precede every record, from TLS 1.0 to TLS 1.3. The module is `packet_parser::parse::application::protocols::tls`, with `TlsPacket` for one record and `parse_tls_records` for the records of a segment. Its errors are `TlsError`, in `packet_parser::errors::application::tls`.

The crate reads the envelope and nothing inside it. It does not decode the handshake, so it extracts no server name and no cipher suite, and it decrypts nothing.

![A TLS record, 32 bits per row: the five-byte record header with content type 22, version 3.1 and length 224, then the first bytes of the record, a Client Hello handshake of 220 bytes that offers version 3.3; on the right the TlsPacket struct, with the content type Handshake, the version, the length and the 224 payload bytes borrowed raw](images/application/tls_record.svg)

## Detection: one blind rule on TCP

Rule 61 of the [dispatch table](./application.md#reading-the-table) has a TCP guard, no port, and `TlsPacket::try_from` as its probe. A segment is `"TLS"` when it starts with a record header and holds the whole record:

- the first byte is a content type, 20 to 24;
- the next two are a version, 3.1 to 3.4;
- the length that follows fits in what is left of the segment.

The probe looks at the first record only. What follows it in the segment is not checked, so the label says "this segment starts with a TLS record".

Port 443 plays no part. TLS is where its handshake is: on 443, on 8443, on a mail port after STARTTLS, on a database port after an `SSLRequest`. The rule comes late in the table, after every port rule and most blind ones, because five bytes are thin evidence next to a decoder that checks a whole message.

That order explains a label that surprises at first. On port 3389, the [RDP](./rdp.md#detection-port-3389-then-tls) rule is tried first; once the server has selected TLS or CredSSP, the segments no longer start with a TPKT header, the RDP probe refuses them, and rule 61 labels them `"TLS"`. The same happens to [PostgreSQL](./postgresql.md) after an accepted `SSLRequest`. The label follows the bytes of each segment, not the history of the connection.

A Client Hello, on port 443 and off it (*tested*):

```rust
{{#include ../examples/src/tls.rs:tls_client_hello}}
```

## The record

```rust
#[non_exhaustive]
pub struct TlsPacket<'a> {
    pub content_type: TlsContentType, // ChangeCipherSpec, Alert, Handshake,
                                      // ApplicationData, Heartbeat
    pub version: TlsVersion,          // major and minor, displayed as "TLS 1.2"
    pub length: u16,                  // the length the header declares
    pub payload: &'a [u8],            // that many bytes, borrowed
}
```

The version of the record header is not the version of the session. A TLS 1.2 client writes 3.1 in its first record, for the middleboxes that refuse anything newer, and TLS 1.3 writes 3.3 in every record: the negotiated version is in the handshake, which the crate does not read. `TlsVersion` displays what the header says.

The record version may be 3.0 since 13.1.0, displayed `SSL 3.0`. RFC 5246 (appendix E.1) lets a client send its Client Hello in a 3.0 record to reach an old server, and SSL 3.0 uses it itself. Until then such records came out `"Unknown"`, even on TCP 443 [#300](https://github.com/Akmot9/Packet-parser/issues/300).

`payload` is the record as it is on the wire. For a handshake before the keys are set, it is cleartext: the Client Hello of the example carries the name `example.com` in its bytes. After the Change Cipher Spec, or in every TLS 1.3 record after the Server Hello, it is ciphertext.

`parse_tls_records` walks a segment and returns the records that are whole. It stops without an error at the first record that is cut, or at the first bytes that are not a record header.

## A record cut by the segment

A record can be up to 16 KiB of data, and a certificate chain rarely fits in one segment. The first segment holds the record header and declares more bytes than it carries; the following ones start in the middle of the record.

Since the probe wants the first record whole, the outcome depends on where the cut falls:

| The segment starts with | Label |
|---|---|
| a whole record, whatever follows | `"TLS"` |
| a record header whose record is cut | `"Unknown"` |
| the middle of a record | `"Unknown"`, unless the bytes happen to form a record header |

Frames 2 and 3 of `tls12-dsb.pcapng` show the first and the third row (*tested*):

```rust
{{#include ../examples/src/tls.rs:tls_record_cut}}
```

A record of TLS 1.2 can reach 18 437 bytes with its header, more than the 18 432 bytes the probes used to read. Since 11.7.0 the TLS probe reads the whole segment, so a record of that size in one large segment is recognized ([#185](https://github.com/Akmot9/Packet-parser/issues/185)).

## Validations

| Bytes | Field | Check | Error |
|---|---|---|---|
| 0–4 | Record header | the buffer holds at least 5 bytes | `TlsError::TooShort` |
| 0 | Content type | 20 to 24 | `InvalidContentType`, with the byte |
| 1–2 | Version | 3.1, 3.2, 3.3 or 3.4 | `InvalidVersion { major, minor }` |
| 3–4 | Length | the buffer holds that many bytes after the header | `InconsistentLength { declared, available }` |

The length is not compared with the maximum a TLS version allows.

## Oracle: counts and digests

TLS has no field-by-field oracle. `tests/tshark_regression.rs` compares, for the seven captures of `pcaps_exemple/protocols/tls/`, the frames the crate labels `"TLS"` with the frames of `tshark -Y tls`: 587 frames, a count and a digest of the frame numbers per capture. The differences are named:

| Capture | Frames tshark reports and the crate does not | Why |
|---|---|---|
| `tls1.3-ech.pcapng` | 20, 30, 45, 67, 74 | records over two to four segments |
| `tls12-dsb.pcapng` | 3 | the second segment of a record, the example above |
| `dump.pcapng` | 964, 1069, 1084 | Client Hellos in the SSLv2-compatible format, which is not a TLS record |

`tls12-dsb.pcapng` carries its own keys, and tshark decrypts the HTTP exchange in it. The crate labels those frames `"TLS"`. The golden histogram counts 1 294 TLS labels.

## What is left out

The limits every protocol shares, reassembly and checksums among them, are on the [Limits](./limits.md) page. The ones below are this protocol's own.

- **The handshake.** No message is decoded: no server name, no ALPN, no cipher suite, no certificate. A consumer that wants the SNI reads it in `payload`.
- **The negotiated version.** The label does not tell TLS 1.2 from TLS 1.3, and the record version does not either.
- **The SSLv2-compatible Client Hello.** It has no record header.
- **DTLS.** The rule has a TCP guard, and the DTLS record header is not the TLS one.
- **A record over several segments.** Only a segment that starts with a whole record is labelled.
- **Decryption.** Never, even when the capture holds the keys.
