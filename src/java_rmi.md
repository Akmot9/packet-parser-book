# Java RMI

Java RMI lets a JVM call a method of an object that lives in another JVM. Its wire protocol is JRMP, chapter 10 of the *Java RMI Specification*, "RMI Wire Protocol". It runs over TCP. The decoder was added in 13.0.0 ([#313](https://github.com/Akmot9/Packet-parser/issues/313), PR [#314](https://github.com/Akmot9/Packet-parser/pull/314)). The module is `packet_parser::parse::application::protocols::java_rmi`, the errors are in `packet_parser::errors::application::java_rmi`, and the label is `"Java RMI"`.

A client opens a connection with a stream header: `JRMI`, a version, a protocol. Then each message starts with a type byte. The client sends Calls, the server answers with Returns. Ping and PingAck check an idle connection. A DgcAck acknowledges the remote references that a Return carried. A Call and a Return carry a Java serialization stream: the decoder reads the call header and the return header, and leaves the arguments and the value as bytes.

## Detection: TCP 1099, then any TCP port

The registry listens on TCP 1099, the IANA port `rmiregistry`. The objects it hands out, and the JMX connectors, listen on a port the application picks. So Java RMI has two rules and a Decode As variant:

| Where | Rule | Probe | Accepts |
| --- | --- | --- | --- |
| TCP 1099, on either side | port rule 35 | `ProbeId::JavaRmi` | any message that `JavaRmiPacket::try_from` accepts |
| a port declared with `ParseConfig::decode_as(port, DecodeAsProtocol::JavaRmi)` | tried [before the table](./application.md#decode-as) | `ProbeId::JavaRmi` | the same |
| any other TCP port | blind rule 67 | `ProbeId::JavaRmiBlind` | a stream header, a Call or a Return |

Rule 35 sits among the port rules of the [table](./application.md#reading-the-table), after IEC 104 and before PostgreSQL. Rule 67 sits in the blind cascade, after GIOP and before DHCP. Both probes read the whole payload. All three routes keep the TCP guard: the same bytes over UDP are never `"Java RMI"`.

Why two probes: three messages carry a signature, the others do not.

- The **stream header** is `JRMI`, then one of two versions and one of three protocols.
- A **Call** or a **Return** is its type byte, then `AC ED 00 05`, the magic and the version of a Java serialization stream, then a block marker and a block long enough for its header. The source counts at least 48 fixed bits.
- **Ping**, **PingAck** and **ProtocolNotSupported** are one byte.
- A **DgcAck** is a type byte and fourteen free bytes, a UID.
- A **ProtocolAck** is a type byte, a length, a hostname and a port.

`JavaRmiPacket::is_self_identifying()` is true for the stream header, the Call and the Return, and the blind probe asks for it. The other five messages need TCP 1099 or a declared port. `DecodeAsProtocol::JavaRmi`, new in 13.0.0 and the 30th of the 31 variants, resolves to the label `Java RMI`, the guard `Tcp` and the probe of rule 35.

A Ping on 1099 and off it, then a declared port (*tested*):

```rust
{{#include ../examples/src/java_rmi.rs:java_rmi_port_and_blind}}
```

On the capture of the corpus, a registry on 1099, an exported object on 50050 and a JMX connector on 50051, the routes give:

| Server port | Segments with a payload | `parse`: `"Java RMI"` | `parse_with`, 50050 and 50051 declared |
| --- | --- | --- | --- |
| 1099, the registry | 33 | 29 | 29 |
| 50050, the `Station` object | 43 | 23 | 40 |
| 50051, the JMX connector | 160 | 91 | 157 |
| total | 236 | 143 | 226 |

Off 1099, `parse` labels the 114 stream headers, Calls and Returns, and leaves the Pings, PingAcks, DgcAck and ProtocolAcks `"Unknown"`. Ten segments stay `"Unknown"` on every route: the nine EndpointIdentifiers and one refused header ([below](#validations)).

## The messages

| First byte | Message | Sent by | Size in the segment | `JavaRmiPacket` | `Display` |
| --- | --- | --- | --- | --- | --- |
| `0x4a`, the `J` of `JRMI` | stream header | client | 7 bytes, then `messages` | `Header(JavaRmiHeader)` | `JRMI, Version: 2, StreamProtocol` |
| `0x4e` | ProtocolAck | server | exactly 7 + the hostname | `ProtocolAck(JavaRmiEndpoint)` | `ProtocolAck 127.0.0.1:36556` |
| `0x4f` | ProtocolNotSupported | server | exactly 1 | `ProtocolNotSupported` | `ProtocolNotSupported` |
| `0x50` | Call | client | at least 41 | `Call(JavaRmiCall)` | `Call Registry.list` |
| `0x51` | Return | server | at least 22 | `Return(JavaRmiReturn)` | `ReturnData` |
| `0x52` | Ping | client | exactly 1 | `Ping` | `Ping` |
| `0x53` | PingAck | server | exactly 1 | `PingAck` | `PingAck` |
| `0x54` | DgcAck | client | exactly 15 | `DgcAck(JavaRmiUid)` | `DgcAck` |

`message_type()` gives the first byte back. The decoder reads one message per segment, and the fixed-size ones must fill it exactly.

```rust
pub enum JavaRmiPacket<'a> {
    Header(JavaRmiHeader<'a>),
    ProtocolAck(JavaRmiEndpoint<'a>),
    ProtocolNotSupported,
    Call(JavaRmiCall<'a>),
    Return(JavaRmiReturn<'a>),
    Ping,
    PingAck,
    DgcAck(JavaRmiUid),     // the UID of the Return it acknowledges
}

pub struct JavaRmiHeader<'a> {
    pub version: u16,               // 1 or 2; every JDK since 1.2 sends 2
    pub protocol: JavaRmiProtocol,  // Stream, SingleOp or Multiplex
    pub messages: &'a [u8],         // what follows the 7 bytes in the segment
}

pub struct JavaRmiEndpoint<'a> {
    pub hostname: &'a [u8],         // modified UTF-8, written by writeUTF
    pub port: u16,
}

pub struct JavaRmiCall<'a> {
    pub object: JavaRmiObjId,       // the remote object called
    pub operation: i32,             // the method number of a 1.1 stub, or -1
    pub hash: i64,                  // the interface hash (1.1 stub) or the method hash
    pub arguments: &'a [u8],        // the rest of the segment, serialized
}

pub struct JavaRmiReturn<'a> {
    pub return_type: JavaRmiReturnType,  // Normal or Exceptional
    pub ack_id: JavaRmiUid,              // repeated by a DgcAck
    pub value: &'a [u8],                 // the rest of the segment, serialized
}

pub struct JavaRmiObjId {
    pub object_number: i64,
    pub space: JavaRmiUid,
}

pub struct JavaRmiUid {
    pub unique: i32,
    pub time: i64,                  // milliseconds since the Unix epoch
    pub count: i16,
}
```

All of them are `#[non_exhaustive]`, as are `JavaRmiProtocol`, `JavaRmiReturnType`, `JavaRmiWellKnownObject` and the error. A `match` on `JavaRmiPacket` needs a `_` arm.

### A session

One connection of the capture, the client on TCP 36568, the registry on 1099:

| Frame | From | Message |
| --- | --- | --- |
| 28 | client | stream header, `StreamProtocol` |
| 30 | registry | ProtocolAck, `127.0.0.1:36568`: the client as the server sees it |
| 32 | client | its EndpointIdentifier: no type byte, not decoded |
| 33 | client | Call `Registry.list()` |
| 35 | registry | Return: the names `station` and `jmxrmi` |
| 36, 37 | client, registry | Ping, PingAck: the client probes the connection before it reuses it |
| 38 | client | Call `Registry.lookup("station")` |
| 39 | registry | Return: a dynamic proxy, the remote reference to the `Station` object |
| 51, 52 | client, registry | Ping, PingAck |
| 53 | client | DgcAck: the UID of the Return of frame 39 |

### The stream header

| Bytes | Field | Note |
| --- | --- | --- |
| 0–3 | magic | `JRMI`, `0x4a524d49`; otherwise `InvalidHeaderMagic` |
| 4–5 | `version` | 1 or 2; otherwise `InvalidVersion` |
| 6 | `protocol` | one of the three below; otherwise `UnknownProtocol` |
| 7… | `messages` | the rest of the segment |

| `JavaRmiProtocol` | Byte | `name()` | What follows |
| --- | --- | --- | --- |
| `Stream` | `0x4b` | `StreamProtocol` | nothing in the segment; the server answers with a ProtocolAck, and the connection can be reused |
| `SingleOp` | `0x4c` | `SingleOpProtocol` | the Call, in the same segment; no ProtocolAck, one call per connection |
| `Multiplex` | `0x4d` | `MultiplexProtocol` | streams multiplexed on one connection (JDK 1.1); only the header is read |

`code()` gives the byte back. `JavaRmiHeader::message()` decodes `messages` on demand, and returns `None` when it is empty. Frame 319 of the capture is a SingleOp header followed by `Registry.list()`, 48 bytes in one segment.

### ProtocolAck, DgcAck and the one-byte messages

The ProtocolAck carries the client's address as the server sees it: a type byte, a two-byte length, the hostname, then the port on four bytes. It must fill the segment exactly, otherwise `UnexpectedLength`. A port above 65 535 is `InvalidPort`. `hostname_str()` returns the hostname when it is valid UTF-8.

The DgcAck is the type byte and a UID, 15 bytes. The client sends it after a Return that carried remote references, and repeats that Return's `ack_id`. Ping, PingAck and ProtocolNotSupported are their type byte alone.

## The Call

![The Call of frame 38 of jdk11-loopback.pcap, 32 bits per row: the type byte 0x50, the magic AC ED and the version 5 of a Java serialization stream, the block marker 0x77 and a block length of 34, then the call header, an ObjID of 22 zero bytes summarised after its first byte (object 0 in the null space, the registry), operation 2 and the interface hash 0x44154dc9d4e63bdf, then the argument, still serialized, TC_STRING, a length of 7 and the bytes of station; JavaRmiCall keeps the object, the operation, the hash and the ten bytes of arguments, and names the method Registry.lookup.](images/application/java_rmi_call.svg)

| Bytes | Field | Note |
| --- | --- | --- |
| 0 | type | `0x50` |
| 1–2 | stream magic | `AC ED`; otherwise `InvalidStreamMagic` |
| 3–4 | stream version | 5; otherwise `InvalidStreamVersion` |
| 5 | block marker | `TC_BLOCKDATA` `0x77`, or `TC_BLOCKDATALONG` `0x7a`; otherwise `ExpectedBlockData` |
| 6 | block length | at least 34, otherwise `BlockTooShort`; after `0x7a`, four bytes, 6–9 |
| 7–14 | `object.object_number` | `i64` |
| 15–28 | `object.space` | a UID: `unique` (`i32`), `time` (`i64`), `count` (`i16`) |
| 29–32 | `operation` | `i32` |
| 33–40 | `hash` | `i64` |
| 41… | `arguments` | the rest of the segment |

After `TC_BLOCKDATALONG`, the call header starts three bytes later, at byte 10. The block may run past the segment: only the 34 bytes of the header must be there.

### Methods with a name

Three objects have a fixed number in the null space, the UID whose three fields are zero. `JavaRmiObjId::well_known()` names them. `well_known_method()` also names the method, when the call goes through the 1.1 stub of the object: the hash is then the interface hash, and the operation indexes the methods.

| Object | `object_number` | Interface hash | Operations, by number |
| --- | --- | --- | --- |
| `Registry` | 0 | `JAVA_RMI_REGISTRY_INTERFACE_HASH`, `0x44154dc9d4e63bdf` | 0 `bind`, 1 `list`, 2 `lookup`, 3 `rebind`, 4 `unbind` |
| `Activator` | 1 | none in the crate | not named |
| `Dgc` | 2 | `JAVA_RMI_DGC_INTERFACE_HASH`, `0xf6b6898d8bf28643` | 0 `clean`, 1 `dirty` |

`Dgc` is the distributed garbage collector: a client calls `dirty` to lease the references it holds, and `clean` to release them. `Display` writes the named method, `Call Registry.lookup`.

A call to the registry, its Return, then a lookup (*tested*):

```rust
{{#include ../examples/src/java_rmi.rs:java_rmi_registry_call}}
```

An exported object has a random number in the space of its JVM. Its 1.2 stub, or its dynamic proxy, sends operation -1, and the hash names the method. The crate keeps that hash as a number: `well_known_method()` is `None`, and `Display` writes `Call object … operation -1 hash 0x…`. A call to the `Station` object of the capture, off 1099 (*tested*):

```rust
{{#include ../examples/src/java_rmi.rs:java_rmi_method_call}}
```

## The Return

| Bytes | Field | Note |
| --- | --- | --- |
| 0 | type | `0x51` |
| 1–6 | stream header and block | as in a Call; the block is at least 15 bytes |
| 7 | `return_type` | 1 `Normal`, 2 `Exceptional`; otherwise `InvalidReturnType` |
| 8–21 | `ack_id` | a UID |
| 22… | `value` | the rest of the segment: the value, or the exception |

`Display` writes `ReturnData`, and `ReturnData (exception)` for an exceptional Return.

## Validations

All of them are `JavaRmiError`:

| Error | When |
| --- | --- |
| `TooShort { expected, actual }` | an empty segment; a stream header under 7 bytes; a ProtocolAck under 3; a Call or a Return that stops before the end of its serialization header, its block marker and length, or its call or return header |
| `UnknownMessageType(u8)` | a first byte other than `0x4a` and `0x4e` to `0x54` |
| `InvalidHeaderMagic(u32)` | a `J` that does not open `JRMI` |
| `InvalidVersion(u16)` | a stream header version other than 1 or 2 |
| `UnknownProtocol(u8)` | a protocol other than `0x4b`, `0x4c`, `0x4d` |
| `UnexpectedLength { message, expected, actual }` | a Ping, PingAck or ProtocolNotSupported that is not 1 byte, a DgcAck that is not 15, a ProtocolAck that is not 7 plus its hostname |
| `InvalidPort(u32)` | a ProtocolAck port above 65 535 |
| `InvalidStreamMagic(u16)` | a Call or a Return without `AC ED` |
| `InvalidStreamVersion(u16)` | a serialization stream version other than 5 |
| `ExpectedBlockData(u8)` | a byte 5 that is neither `0x77` nor `0x7a` |
| `BlockTooShort { expected, actual }` | a block shorter than the call header, 34 bytes, or the return header, 15 |
| `InvalidReturnType(u8)` | a return type other than 1 or 2 |

A refused segment is not labelled, even on 1099. It goes on down the table and usually comes out `"Unknown"`. The flow keeps no error: call `JavaRmiPacket::try_from` to see it. Three frames of the capture (*tested*):

```rust
{{#include ../examples/src/java_rmi.rs:java_rmi_errors}}
```

## Oracle: 236 segments against tshark

The golden test `tests/java_rmi_golden.rs` reads the 394 frames of `pcaps_exemple/protocols/java_rmi/jdk11-loopback.pcap`. It compares every segment that has a payload with tshark 4.6.9. tshark dissects RMI on TCP 1099 only: `tools/java_rmi_oracle.sh` declares 50050 and 50051 with `-d tcp.port==…,rmi`, and freezes its output in `tests/data/java_rmi_tshark_oracle.tsv`. Compared: the type of each message, the version and protocol of each stream header, the hostname and port of each ProtocolAck.

| Message | Segments |
| --- | --- |
| Return, one of them exceptional (frame 69) | 60 |
| Call | 59 |
| Ping | 42 |
| PingAck | 42 |
| stream header: 9 `StreamProtocol`, 1 `SingleOpProtocol` with its call | 10 |
| ProtocolAck | 9 |
| EndpointIdentifier of the client, refused: no type byte | 9 |
| DgcAck | 3 |
| stream header with the unknown protocol `0x4e`, refused | 1 |
| ProtocolNotSupported | 1 |
| total | 236 |

tshark reads neither the call header nor the return header. The test checks what the crate reads there against the structure of the session:

| What the crate reads | Number |
| --- | --- |
| registry calls, to TCP 1099, with the registry's interface hash: `bind` 1, `list` 2, `lookup` 2, `unbind` 1 | 6 |
| DGC calls, to ObjID 2, with the DGC's interface hash: `dirty` 20, `clean` 2 | 22 |
| application calls: operation -1, no well-known object | 32 |
| exceptional Returns, whose value holds the message of the exception | 1 |
| DgcAcks whose UID is the one of a Return seen before | 3 |

Every Return has a UID of its own. The test also checks each label: `"Java RMI"` on 1099, or off it for a stream header, a Call or a Return; `"Java RMI"` everywhere with 50050 and 50051 declared.

| Capture | Frames | Content | Origin |
| --- | --- | --- | --- |
| `jdk11-loopback.pcap` | 394 | two OpenJDK 11.0.33 JVMs on the loopback, 20.4 s, 11 TCP connections; a registry on 1099, a `Station` object on 50050, a JMX connector on 50051; two connections written by hand, the SingleOp call and the unknown protocol | the maintainer's capture, MIT |

`tools/java_rmi_capture.sh` reproduces it: it compiles `tools/java_rmi_capture/JrmpCapture.java`, runs the two JVMs and captures the three ports with dumpcap. The JVMs draw UIDs, object numbers and ephemeral ports at random, so each run differs: the tests cite the frames of the committed file. Its `SOURCE.md` lists what the payloads contain: `127.0.0.1`, class names, the strings of the program and the JDK version, nothing of the machine.

A unit test of `dispatch/tests.rs` replays frames of the same capture through the table. A stream header, a Call and a Return are `"Java RMI"` on 1099 and on 50050, never on UDP. A Ping, a PingAck and a DgcAck are `"Java RMI"` on 1099, `"Unknown"` on 50050, `"Java RMI"` on 50050 declared, never on UDP even declared.

The fuzz target `parse_java_rmi` runs nightly. Its seeds are seven frames of the capture, 4, 6, 33, 53, 60, 61 and 319. It decodes the input, then each seed altered by XOR masks that the input chooses. It must neither panic nor loop. On success, the type is the first byte and every field is the one of the wire. The messages after a stream header, the arguments and the value end the input, and the hostname points into it. `is_self_identifying()` is true exactly for a stream header, a Call or a Return. Decoding the message after a header, `Display` and the accessors must not panic.

## What is left out

The limits every protocol shares, reassembly and checksums among them, are on the [Limits](./limits.md) page. The ones below are this protocol's own.

- **Serialized values**: the arguments and the return value stay bytes, borrowed from the segment. No object, class descriptor or exception is read. The exceptional Return of frame 69, 2 588 bytes, gives its type and its UID; the exception stays in `value`.
- **No reassembly**: a Call or a Return longer than its segment is read from its first segment. Its header is read, and `arguments` or `value` stop at the end of the segment. The next segments start in the middle of the serialized bytes, and nothing ties them to the message. The capture has none: its largest message, frame 69, fits in one segment.
- **One message per segment**: after a Call or a Return, whatever follows goes into `arguments` or `value`. Only a SingleOp header carries a message after it, through `message()`.
- **The EndpointIdentifier** that the client sends after the ProtocolAck has no type byte. It starts with the high byte of the hostname length, 0 for any name under 256 bytes, and is `UnknownMessageType(0)`. tshark shows it as "Continuation".
- **MultiplexProtocol**: only the header is recognized, not the multiplexed operations.
- **Method names** exist only for the registry and the DGC. Activator calls and application calls keep their hash.
- **No session state**: nothing ties a Return to its Call, or a DgcAck to its Return. The golden test does it; the crate does not.
