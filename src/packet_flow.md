# The `PacketFlow` structure

`PacketFlow` is what a parse returns. It is the structure this book used to call
`ParsedPacket`, redesigned around one observation: **real captures are partial**.
A packet whose EtherType is unknown to us is not an invalid packet, and refusing
to return anything for it throws away the perfectly valid MAC addresses we did
read.

## The shape

```rust
pub struct PacketFlow<'a> {
    /// Link layer (mandatory), tagged with its canonical LINKTYPE.
    pub data_link: LinkLayer<'a>,

    /// Internet layer (optional).
    pub internet: Option<Internet<'a>>,

    /// Transport layer (optional).
    pub transport: Option<Transport<'a>>,

    /// Application layer (optional, best-effort).
    pub application: Option<Application>,

    /// Packet carried inside a tunnel, recursively.
    pub inner: Option<Box<PacketFlow<'a>>>,

    /// Set when a recognized layer carried invalid bytes.
    pub corrupted: Option<CorruptedLayer>,
}
```

Read as a tree:

```text
PacketFlow<'a>
├── data_link:   LinkLayer<'a>              (mandatory — Ethernet, SLL, SLL2, RAW)
├── internet:    Option<Internet<'a>>       source / destination / protocol_name
│                                           / payload_protocol / payload / details
├── transport:   Option<Transport<'a>>      protocol / source_port / destination_port
│                                           / payload / details
├── application: Option<Application>        application_protocol: &'static str
├── inner:       Option<Box<PacketFlow<'a>>>  packet carried inside a tunnel
└── corrupted:   Option<CorruptedLayer>     set when a recognized layer held
                                            invalid bytes
```

Only `data_link` is mandatory. That asymmetry is the whole design.

## Fail-closed below, fail-soft above

There is exactly **one** thing that can fail a parse: the link layer.

- The LINKTYPE has no decoder in this build → `Err(ParseError::UnsupportedLinkType)`.
- The link header itself is unreadable → `Err(ParseError::InvalidLinkLayer(..))`.

Above the link layer, nothing fails. An unknown IP protocol number, a truncated
TCP header, an application payload we cannot classify — none of these produce an
`Err`. They produce a `None` on that layer, and the layers *below* stay filled.

## Three outcomes, and why you must not confuse them

For every optional layer there are three distinct states, and collapsing them is
the most common way to misread a capture:

| `internet` | `corrupted` | Meaning |
| --- | --- | --- |
| `Some(..)` | `None` | The layer was recognized and decoded. |
| `None` | `None` | The protocol is **not supported**; nothing above it could be reached. |
| `None` | `Some(..)` | The layer **was recognized** but carried invalid bytes. |

`CorruptedLayer` names which layer broke and carries a human-readable message:

```rust
pub struct CorruptedLayer {
    pub layer: CorruptedLayerKind, // Internet | Transport
    pub error: String,
}
```

The distinction matters operationally. "We do not decode LLDP" and "this IPv4
header is malformed" are the same `internet: None` to a careless reader, but the
first is a gap in the crate and the second is a finding about the traffic.

This is also why the internal parsing path dispatches on the announced protocol
instead of probing. `Internet::try_from(&[u8])` probes every supported protocol
and therefore *cannot* tell a corrupt packet from an unknown one;
`Internet::try_from_parts(ethertype, payload)` knows the EtherType said "IPv4"
and can report the parse error. See
[the data validation chapter](./data_validation.md).

## Flow identity: equality and hashing

`PartialEq`, `Eq` and `Hash` compare **flow identity** — addresses, protocols,
ports — and deliberately ignore raw payloads and the per-layer `details`. Two
packets from the same conversation with different content compare equal and hash
to the same value, so a `HashMap<PacketFlow, Counter>` builds a conversation
matrix directly.

## Lifetimes

`PacketFlow<'a>` borrows the buffer you passed to `parse`. It cannot outlive it,
cannot cross a thread boundary that outlives it, and cannot be stored in a
long-lived cache. When you need any of that, call
[`to_owned()`](./owned.md) — an explicit, visible copy rather than a silent one
on every packet.
