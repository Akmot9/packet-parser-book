# Focus: GIOP

GIOP (General Inter-ORB Protocol) is the wire protocol of CORBA. It is the most complete application decoder of the crate, and the one whose development taught the most about parsing real traffic: two bugs were only found when the parser met genuine captures, and the final shape of the decoder — accept truncated messages, walk consecutive messages in a segment, resynchronize in the middle of a stream — comes straight from what an ORB actually puts on the wire. This chapter walks through it as a worked example of the method described in the previous chapters.

Module: `packet_parser::parse::application::protocols::giop`. Specification: CORBA formal/04-03-12, chapter 15. Supported: GIOP 1.0, 1.1 and 1.2, the eight message types, both endiannesses.

## The message

```text
packet-beta
0-31:   "Magic 'GIOP' (4 bytes)"
32-39:  "Major version u8 (1)"
40-47:  "Minor version u8 (0, 1, 2)"
48-55:  "Flags u8: bit 0 endianness, bit 1 more fragments (1.1+)"
56-63:  "Message type u8 (0..7)"
64-95:  "Message size u32 (body only, in the message's endianness)"
96-..:  "Body (CDR-encoded, layout depends on type and version)"
```

```rust
pub struct GiopPacket<'a> {
    pub header: GiopHeader,
    pub payload: GiopMessage<'a>,
    /// The buffer does not hold the whole body announced by `message_length`.
    pub truncated: bool,
    // bytes of the buffer covered by this message, header included
}

pub enum GiopMessage<'a> {
    Request(GiopRequest<'a>),
    Reply(GiopReply<'a>),
    CancelRequest(GiopCancelRequest),
    LocateRequest(GiopLocateRequest<'a>),
    LocateReply(GiopLocateReply<'a>),
    CloseConnection,        // header only
    MessageError,           // header only
    Fragment(GiopFragment<'a>),
    /// Valid type, unreadable body: the header stays reliable.
    Other,
}
```

## Reading it

```rust
use packet_parser::parse::application::protocols::giop::{GiopMessage, GiopPacket, TargetAddress};

let packet = GiopPacket::try_from(tcp_payload)?;
let h = &packet.header;
println!("GIOP 1.{} {:?} little_endian={} size={} truncated={}",
    h.minor_version, h.message_type, h.is_little_endian(), h.message_length, packet.truncated);

if let GiopMessage::Request(request) = &packet.payload {
    println!("Request id={} op={} contexts={} stub={} bytes",
        request.request_id, request.operation,
        request.service_contexts.len(), request.stub_data.len());
    if let TargetAddress::KeyAddr(key) = &request.target {
        println!("target object key: {} bytes", key.len());
    }
}
```

On frame 4 of `pcaps_exemple/protocols/giop/corba.pcap` (the nDPI test corpus), this prints:

```text
GIOP 1.2 Request little_endian=false size=216 truncated=false
Request id=0 op=echo contexts=1 stub=76 bytes
target object key: 60 bytes
```

and `flow.application` is labelled `"GIOP"` by the pipeline, through a blind TCP probe: the literal magic, a version in 1.0..1.2 and a known message type make a strong enough signature.

The book's example crate checks every one of these values on that frame — this is the test that pins down the difference between the pipeline's *classification* and the protocol parser's *decode* (*tested*):

```rust
{{#include ../examples/src/lib.rs:classification_vs_decode}}
```

## The header: a `TryFrom` like the others

```rust
impl TryFrom<&[u8]> for GiopHeader {
    type Error = GiopParseError;

    fn try_from(payload: &[u8]) -> Result<Self, Self::Error> {
        ensure_min_len(payload)?;                                   // 12 bytes
        let magic = parse_magic(payload)?;                          // "GIOP"
        let (major_version, minor_version) = extract_version(&payload[4..6])?; // 1.0..1.2
        let flags = extract_flags(&payload[6])?;
        let message_type = GiopMessageType::try_from(payload[7])?;  // 0..7
        validate_message_type_in_version(payload[7], minor_version)?; // Fragment needs 1.1+
        let message_length = extract_message_size(&payload[8..12], flags & 0x01 != 0)?;
        Ok(GiopHeader { magic, major_version, minor_version, flags, message_type, message_length })
    }
}
```

Two details in this sequence are lessons from real frames:

- **`message_size` follows the endianness announced by the flags.** The first version of the parser read it big-endian unconditionally. Frame 19 of `corba.pcap`, a little-endian Request carried inside a MIOP datagram, announced a size of `0xD8000000` and was rejected. GIOP 1.0 calls that byte `byte_order`, a boolean; GIOP 1.1+ calls it `flags` with the same bit at the same place.
- **The domain of a field depends on the version.** Message type 7 (Fragment) does not exist in GIOP 1.0; reply status 4 and 5 (`LOCATION_FORWARD_PERM`, `NEEDS_ADDRESSING_MODE`) and locate status 3..5 only exist in 1.2. Accepting them on an older header would produce a "valid" struct that contradicts itself, so `validate_reply_status(value, minor_version)` and friends take the version.

## The body is CDR: a cursor, not indexes

The header is fixed; the body is **CDR** (Common Data Representation), CORBA's serialization. Its rule: every primitive is aligned on its natural size, counted from the start of the CDR stream. A `ulong` after a 2-byte `short` is preceded by 2 bytes of padding. Strings and `sequence<octet>` are length-prefixed. The layout of a Request also changed between GIOP 1.1 and 1.2 (service contexts moved from the front to after the operation name, `object_key` became a `TargetAddress` union, `requesting_principal` was removed, and the stub data became aligned on 8).

Indexing into the body with fixed offsets is therefore impossible. The module uses a small crate-internal **cursor**:

```rust
pub(super) struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
    base: usize,          // 12 for a message body: alignment counts from the header
    little_endian: bool,
}

impl<'a> Cursor<'a> {
    fn align(&mut self, boundary: usize);          // CDR padding, bounded by the buffer
    fn align_body_1_2(&mut self);                  // Request/Reply 1.2 body aligned on 8
    fn read_u8(&mut self)  -> Result<u8, GiopParseError>;
    fn read_u16(&mut self) -> Result<u16, GiopParseError>;   // align(2) first
    fn read_u32(&mut self) -> Result<u32, GiopParseError>;   // align(4) first
    fn read_bytes(&mut self, len: usize) -> Result<&'a [u8], GiopParseError>;
    fn read_octet_sequence(&mut self) -> Result<&'a [u8], GiopParseError>;  // ulong len + bytes
    fn read_str(&mut self) -> Result<&'a str, GiopParseError>;              // + UTF-8, trailing NUL dropped
    fn rest(&self) -> &'a [u8];
}
```

Every read checks `ensure_available` first and returns `UnexpectedEof` otherwise: the cursor is the one place where bounds are enforced, and the parsers above it never index the buffer. It stays zero-copy: `read_bytes`, `read_octet_sequence` and `read_str` return slices of the original buffer, and `rest()` is how `stub_data` and `body` are obtained.

The second bug found on real frames lives here. The `TargetAddress` discriminant is a CDR `short` (2 bytes, followed by 2 bytes of padding before the next `ulong`), not an octet. Read as one byte, no real GIOP 1.2 Request decoded. The golden tests on `corba.pcap` lock these paddings in: without them, the operation name and service contexts of every real Request come out shifted.

The `base` field handles a subtlety: the alignment of a message body counts from the start of the message, header included (offset 0 is the magic), while an **encapsulation** — the opaque `profile_data` of an IOR profile — is its own CDR stream, starting at its own endianness byte. `Cursor::encapsulation()` restarts at base 0 and reads that byte.

A Request in GIOP 1.2 then reads as:

```rust
pub fn parse(body: &'a [u8], little_endian: bool) -> Result<Self, GiopParseError> {
    let mut cur = Cursor::new(body, little_endian);
    let request_id = cur.read_u32()?;
    let response_flags = cur.read_u8()?;
    let _reserved = cur.read_bytes(3)?;
    let target = parse_target_address(&mut cur)?;     // short discriminant + KeyAddr / ProfileAddr / ReferenceAddr
    let operation = cur.read_str()?;
    let service_contexts = parse_service_context_list(&mut cur)?;
    cur.align_body_1_2();                             // padding to 8, only if a body follows
    Ok(GiopRequest { request_id, response_flags, target, operation, service_contexts,
                     requesting_principal: None, stub_data: cur.rest() })
}
```

and the 1.0/1.1 layout is a separate function with the historical order, mapped onto the same struct (`response_expected` lands in `response_flags`, `object_key` becomes `TargetAddress::KeyAddr`).

## Sender-controlled counters are bounded before allocation

A service context list and an IOR profile list are `ulong count` followed by `count` entries, and each entry is at least 8 bytes. A hostile count of `0xFFFFFFFF` must not drive a `Vec::with_capacity`. The checks module bounds every counter against the bytes remaining before the loop:

```rust
pub fn validate_service_context_count(count: usize, remaining: usize) -> Result<(), GiopParseError> {
    if count > remaining / SERVICE_CONTEXT_MIN_LEN {
        return Err(GiopParseError::InvalidServiceContextCount { count, available: remaining });
    }
    Ok(())
}
```

## Typed replies, degraded gracefully

A Reply carries a `reply_status`, and the meaning of its body depends on it. The decoder types that:

```rust
pub enum GiopReplyDetail<'a> {
    Results,                                              // NO_EXCEPTION: IDL-typed, opaque
    UserException { exception_id: &'a str, members: &'a [u8] },
    SystemException(GiopSystemException<'a>),             // repository id, minor code, completion status
    LocationForward(Ior<'a>),                             // the reference to retry against
    NeedsAddressingMode(u16),
    Undecoded,                                            // body unreadable, raw bytes kept in `body`
}
```

`LocationForward` is the interesting one for an analyst: the IOR says **which host and port** the client is being redirected to. `Ior::iiop()` returns the first readable IIOP profile — host, port, object key — decoded from its encapsulation:

```rust
if let GiopMessage::Reply(reply) = &packet.payload
    && let GiopReplyDetail::LocationForward(ior) = &reply.detail
    && let Some(iiop) = ior.iiop()
{
    println!("redirected to {}:{} ({})", iiop.host, iiop.port, ior.type_id);
}
```

Every level degrades on its own. An unreadable IIOP profile does not fail the IOR (`iiop()` returns `None`); an unreadable body does not fail the Reply (`detail` becomes `Undecoded`, the header and status are already reliable); an unreadable Request body does not fail the packet (`payload` becomes `GiopMessage::Other`). The reason is the pipeline: the blind probe calls `GiopPacket::try_from` on arbitrary TCP traffic, and the decode depth of the body must not change the **classification**, which only the header earns.

## Stateless, on a protocol that ignores segment boundaries

GIOP messages routinely exceed the TCP MSS: an 8 KiB `push` Request on a 1460-byte segment is four segments. The parser is stateless — no TCP reassembly, no Fragment reassembly — so three behaviours were chosen deliberately:

1. **A message that overflows its segment is accepted and flagged**, not rejected. The first segment carries the complete header and usually the complete Request header (request id, operation, object key), which is exactly what an analyst wants. `truncated` is set, `wire_len()` is bounded by the buffer, and the body is decoded on the bytes present. Before this choice, the first segment of every large message came out `Unknown` from the pipeline.
2. **A segment may hold several messages.** An ORB happily chains short messages (a LocateRequest and a Request) in one segment. `giop_messages(payload)` iterates over them, stopping at the first byte that does not open a valid message or after a truncated one.
3. **A message may start in the middle of a continuation segment.** After a large message, the next one begins at offset 952 of a segment that does not start with the magic, and the stateless pipeline cannot label that segment. A caller that tracks flows and *already knows* the stream is GIOP can resynchronize with `find_giop_message(payload)`, which returns the offset of the first valid header (magic, version, type, reserved flag bits at zero), then read with `giop_messages`. It is also how the GIOP message inside a MIOP multicast datagram is reached. It is **not** for classifying unknown traffic: four magic bytes in the middle of application data prove nothing.

## Verified against tshark, message by message

The unit tests build synthetic bodies for the cases no ORB at hand emits (CancelRequest, `OBJECT_FORWARD_PERM`, `ReferenceAddr`...). Everything else is verified on real captures under `pcaps_exemple/protocols/giop/`, each with its provenance in `SOURCE.md`:

- `corba.pcap` from the nDPI test corpus: GIOP 1.2 over TCP and over MIOP, both endiannesses, plus a ZIOP (compressed) message;
- three captures attached to public Wireshark bug reports: LocateRequest/LocateReply, a fragmented 8 KiB Request whose Fragments start mid-segment, a GIOP 1.0 `LOCATION_FORWARD` with an IIOP profile, a `USER_EXCEPTION` from CosNaming;
- seven `lab_*.pcap` produced by `tools/capture_giop.sh`: a real omniORB 4.3.3 server and clients in a throwaway container, scripted to emit the same scenario in GIOP 1.0, 1.1 and 1.2, plus system exceptions, CloseConnection, MessageError and a client timeout. The recipe is replayable.

`tests/giop_tshark_regression.rs` replays every capture and compares each message, column by column, with an oracle produced by `tools/giop_oracle.sh` — tshark 4.6.6 with TCP reassembly **disabled**, i.e. the view of a stateless parser: type, version, flags, size, request id, reply and locate status, operation, exception id, IIOP host and port, object key and stub data lengths. The known divergences (tshark reports no request id on a 1.1 Fragment, and no operation on any Fragment) are named in `tshark_only_columns`, not hidden. A larger corpus (1 641 messages from other Wireshark issues), too big to redistribute, is replayed by an `#[ignore]` test.

The fuzz target `parse_giop` runs `find_giop_message`, then `giop_messages`, then dereferences every IOR it finds, asserting that no message ever covers more bytes than the buffer holds and that the iteration always progresses.

## What is left out

- Stub data and user-exception members are IDL-typed: without the IDL they are opaque, and kept as raw slices.
- IIOP 1.1+ tagged components in a profile are not decoded.
- ZIOP (compressed GIOP) and MIOP framing are recognized as such but not decoded: the ZIOP body needs decompression, and MIOP is reached through `find_giop_message`.
- No reassembly, by design. Fragments are decoded individually (`GiopFragment` carries the request id from 1.2 on); reassembling them belongs to a stateful layer above the parser.
