# DCE/RPC

DCE/RPC (DCE 1.1: Remote Procedure Call, Open Group C706) is the remote procedure call of Windows: MSRPC and DCOM run on it. A client binds to an interface, then calls its operations by number. The decoder reads the connection-oriented form, the one that runs over TCP. It was added in 13.3.0 ([#356](https://github.com/Akmot9/Packet-parser/issues/356), PR [#361](https://github.com/Akmot9/Packet-parser/pull/361)). The module is `packet_parser::parse::application::protocols::dcerpc`, the errors are `DceRpcError`, in `packet_parser::errors::application::dcerpc`, and the label is `"DCE/RPC"`.

![The Request of frame 40263 of The-Ultimate-PCAP.pcapng, 32 bits per row: the 16-byte common header, version 5.0, PDU type 0, flags 0x03, the data representation label 10 00 00 00 for little-endian, ASCII and IEEE, a fragment length of 168 and an authentication length of 0, both little-endian, and call identifier 2; then the three fields of a Request, an allocation hint of 144, presentation context 1 and operation number 3, and 144 bytes of stub data; on the right the DceRpcPdu struct, with the header fields, the byte order, the three request fields on demand and the body as bytes](images/application/dcerpc_request.svg)

```rust
pub struct DceRpcPdu<'a> {
    pub version_minor: u8,           // 0 or 1; the major version is 5
    pub pdu_type: DceRpcPduType,
    pub flags: u8,                   // pfc_flags
    pub little_endian: bool,         // from the data representation label
    pub data_representation: [u8; 4],
    pub frag_length: u16,            // the whole fragment, header included
    pub auth_length: u16,            // the authentication value that ends it
    pub call_id: u32,
    pub body: &'a [u8],              // what follows the 16-byte header
    // private: the bytes of the segment after the fragment
}

pub struct DceRpcRequest {
    pub alloc_hint: u32,
    pub context_id: u16,             // presentation context, set by the Bind
    pub opnum: u16,                  // operation number within the interface
}
```

Both structs are `#[non_exhaustive]`, and `body` borrows from the segment. The header says in which byte order its own integers are written: the first byte of the data representation label is `0x10` for little-endian, what Windows sends, `0x00` for big-endian. The decoder reads `frag_length`, `auth_length`, `call_id` and the request fields in that order, and `little_endian` keeps it for the caller.

| Method | Gives |
| --- | --- |
| `is_first_fragment()`, `is_last_fragment()` | bits `0x01` and `0x02` of `flags`: a call that fits in one fragment has both |
| `is_truncated()` | `true` when the fragment goes on in the next TCP segment |
| `rest()` | the bytes of the segment after the fragment: another PDU, or nothing |
| `request()` | the three fields of a Request; `None` for another type, or when the segment stops before them |

`DceRpcPduType` names the twelve connection-oriented types, and `as_u8()` gives the byte back:

| Code | Variant | Code | Variant |
| --- | --- | --- | --- |
| 0 | `Request` | 14 | `AlterContext` |
| 2 | `Response` | 15 | `AlterContextResponse` |
| 3 | `Fault` | 16 | `Auth3` |
| 11 | `Bind` | 17 | `Shutdown` |
| 12 | `BindAck` | 18 | `CoCancel` |
| 13 | `BindNak` | 19 | `Orphaned` |

A client that asks the endpoint mapper of a server where a service listens starts with a Bind (*tested*):

```rust
{{#include ../examples/src/dcerpc.rs:dcerpc_bind}}
```

The Request follows, with the number of the operation (*tested*):

```rust
{{#include ../examples/src/dcerpc.rs:dcerpc_request}}
```

The body is not decoded: the presentation contexts of a Bind, the stub data of a call, in NDR, and the authentication verifier are returned as bytes. An operation number means something only with the interface the Bind chose, and the crate keeps no state to remember it.

## Detection: any TCP port

| Where | Rule | Probe | Accepts |
| --- | --- | --- | --- |
| any TCP port | blind rule 77 | `ProbeId::DceRpc` | a PDU `DceRpcPdu::try_from` accepts, followed by nothing or by a second PDU it accepts |

DCE/RPC has no fixed port. TCP 135 is the endpoint mapper, a directory: it answers with the port of the service, drawn from a dynamic range, and the calls go there. A port rule would see the directory and miss the calls. Rule 77 sits at the end of the blind cascade of the [table](./application.md#reading-the-table), after NMF and before MQTT.

The common header is enough to stand on, because sixteen bytes leave little freedom:

- the version, `05 00` or `05 01`;
- a PDU type among twelve values;
- a data representation label whose four bytes take few values: two byte orders, two character sets, four floating-point formats, and two reserved bytes that are null;
- a fragment length, read in the byte order the label announced, that covers at least the header of its type;
- an authentication length that fits in the fragment.

When the fragment ends before the segment does, what follows must be a PDU too: one segment may hold two. A fragment longer than its segment is accepted, the rest being in the next one.

There is no `DecodeAsProtocol` variant: the rule has no port guard, so it already runs on every TCP port.

## Validations

| Part | Check | Error |
| --- | --- | --- |
| Segment | at least the 16 bytes of the common header | `DceRpcError::TooShort { expected, actual }` |
| Version | 5.0 or 5.1 | `UnsupportedVersion { major, minor }` |
| PDU type | one of the twelve | `UnknownPduType` |
| Data representation | a byte order of 0 or 1, a character set of 0 or 1, a floating-point format of 0 to 3, two null bytes | `InvalidDataRepresentation` |
| Fragment length | at least the header and the fixed fields of the type | `FragmentTooShort { frag_length, minimum }` |
| Authentication length | when not zero, the value and its eight-byte trailer fit after those fields | `InvalidAuthLength { auth_length, frag_length }` |

The checks run in this order, and the first failure is the error. The fixed fields are 8 bytes for a Request, a Response, a Bind, a Bind Ack and both Alter Context PDUs, 16 for a Fault, and none for the five others. What the decoder refuses, and the one cut it accepts (*tested*):

```rust
{{#include ../examples/src/dcerpc.rs:dcerpc_refusals}}
```

## What is not DCE/RPC

Each row was checked against the crate, on a TCP port without a rule of its own:

| Payload | Label | Why |
| --- | --- | --- |
| the Bind of the example | `"DCE/RPC"` | |
| its first 100 bytes | `"DCE/RPC"` | a fragment cut by its segment |
| its first 10 bytes | `"Unknown"` | `TooShort` |
| the Bind twice in one segment | `"DCE/RPC"` | two PDUs |
| the Bind followed by `hello` | `"Unknown"` | what follows a fragment must be a PDU |
| its version changed to 4 | `"Unknown"` | `UnsupportedVersion`: 4 is the connectionless form |
| its type changed to 1 | `"Unknown"` | `UnknownPduType`: a connectionless type |
| a reserved byte of its label set to 1 | `"Unknown"` | `InvalidDataRepresentation` |
| its fragment length changed to 10 | `"Unknown"` | `FragmentTooShort` |
| its authentication length changed to 255 | `"Unknown"` | `InvalidAuthLength` |
| the Bind, on UDP | `"Unknown"` | the guard is TCP |

## Oracle: 385 segments

The golden test `tests/dcerpc_golden.rs` compares the crate with tshark 4.6.9, its TCP and DCE/RPC reassembly switched off. `tools/dcerpc_oracle.sh` freezes, in `tests/data/dcerpc_tshark_oracle.tsv`, one line per segment that tshark dissects as DCE/RPC over TCP: the minor version, the PDU type, the flags, the data representation, the two lengths, the call identifier and the operation number. No capture was added: the 385 segments are in `The-Ultimate-PCAP.pcapng`, calls between Windows machines, with and without authentication.

| PDU | Segments |
| --- | --- |
| Request | 135 |
| Response | 134 |
| Alter Context and its response | 31 and 31 |
| Bind and Bind Ack | 27 and 27 |

The test checks, for each segment, every field of the oracle, and that `request()` gives the operation number of the 135 Requests. Sixteen fragments are longer than their segment, and `is_truncated()` says so for exactly those.

The crate labels fourteen segments more than tshark. They are TCP retransmissions: tshark recognizes them from the sequence numbers and does not hand them to its dissector, and a stateless parser reads them like any other segment ([Limits](./limits.md#what-a-stateless-parser-cannot-see)). The test names them one by one. No other frame of the capture gets the label, the DCE/RPC that travels inside SMB included, and no frame of the captures under `pcaps_exemple/protocols/` does.

## What is left out

The limits every protocol shares are on the [Limits](./limits.md) page. The ones below are this protocol's own.

- **Continuation segments.** The segments that carry the rest of a truncated fragment are `"Unknown"`.
- **The second PDU of a segment** is checked by the probe and not decoded: `rest()` gives its bytes, and `DceRpcPdu::try_from` reads them.
- **Fragments are not reassembled.** A call split over several fragments is several PDUs with the same `call_id`.
- **The interface.** The crate reads no UUID from a Bind and keeps no association between a context and an interface: an operation number has no name.
- **The body.** NDR, the authentication trailer and the object UUID that `pfc_flags` may announce are not decoded.
- **Connectionless DCE/RPC**, version 4, over UDP, and **DCE/RPC inside SMB** named pipes or HTTP are not read.
