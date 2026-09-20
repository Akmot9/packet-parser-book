# PacketFlow and the parsing pipeline

This chapter follows `packet_parser` 10.5.0 at revision
[`85728b6`](https://github.com/Akmot9/Packet-parser/tree/85728b6424c478366607f6c8ce703fe650e82004).

## From bytes to a flow

A captured packet is a sequence of bytes. The caller passes one packet to
`parse(link_type, bytes)`, where `bytes` is a borrowed slice, `&[u8]`. PCAP or
PCAPNG record headers are not part of that slice. The capture's LINKTYPE tells
the parser how to read the first bytes; see the [data link chapter](./data_link.md).

A typical Ethernet / IPv4 / TCP packet has nested headers and payloads:

```text
Ethernet frame
├── Ethernet header
└── IPv4 packet
    ├── IPv4 header
    └── TCP segment
        ├── TCP header
        └── Application bytes
```

Each parser checks its header and exposes the relevant payload to the next
stage. This is a common path, not a requirement that every packet contain all
four layers. ARP has no transport layer; RAW IP has no Ethernet header; a
tunnel can carry another packet. The crate parses individual packets and does
not reassemble IP fragments or TCP streams.

## What PacketFlow contains

`parse` returns `Result<PacketFlow<'a>, ParseError>`. The public structure is:

```text
PacketFlow<'a>
├── data_link:   LinkLayer<'a>
├── internet:    Option<Internet<'a>>
├── transport:   Option<Transport<'a>>
├── application: Option<Application>
├── inner:       Option<Box<PacketFlow<'a>>>
└── corrupted:   Option<CorruptedLayer>
```

| Field | Meaning |
| --- | --- |
| `data_link` | The mandatory link view: the declared LINKTYPE, the protocol and bytes passed to the internet parser, and format-specific metadata. It can represent Ethernet, a cooked capture or RAW IP, among other supported formats. |
| `internet` | The internet-layer summary: `protocol_name`, optional `source` and `destination` IP addresses and their classifications, `payload_protocol`, borrowed `payload`, and optional protocol-specific `details`. |
| `transport` | The transport summary: `protocol`, optional `source_port` and `destination_port`, optional borrowed `payload`, and optional protocol-specific `details`. Ports are absent for protocols such as ICMP. |
| `application` | A classification whose only field is `application_protocol: &'static str`, such as `"HTTP"`, `"TLS"` or `"Unknown"`. It does not contain a decoded application message. |
| `inner` | A recursively parsed packet inside a recognized tunnel. The enclosing flow keeps the outer headers; the nested flow contains the inner headers. |
| `corrupted` | A reported internet or transport parsing problem, with `layer: CorruptedLayerKind` and a human-readable `error: String`. |

The `details` fields give access to parsed headers without repeating the parse.
For example, `InternetDetails::Ipv4` holds an `Ipv4Packet`, and
`TransportDetails::Tcp` holds a `TcpPacket`. A present layer does not guarantee
that it has detailed decoding: even an unknown IP protocol number can produce
a transport summary with `TransportProtocol::Unknown(value)` and no ports,
payload or details.

To decode an application message, call its protocol parser separately, such
as `TlsPacket::try_from` on an appropriate transport payload. Account for that
protocol's framing and for messages split across packets: the flow classifier
does not reconstruct a TCP stream. Calling `Application::try_from` directly
also gives a classification, but has no transport or port context.

## Reading partial results

An unsupported LINKTYPE or an unreadable link header returns `Err(ParseError)`.
Once the link layer has been decoded, the pipeline preserves the information
it can read. These cases have different meanings:

| Situation | Result |
| --- | --- |
| Unknown link payload protocol | `internet` and `transport` are `None`, without an internet corruption report. |
| Recognized but structurally invalid IPv4 header | `internet` and `transport` are `None`; `corrupted.layer` is `Internet`. The link view remains available. |
| Valid IP header, structurally invalid TCP header | `internet` is retained, `transport` is `None`, and `corrupted.layer` is `Transport`. |
| Readable TCP header with a reported semantic anomaly, such as SYN and FIN both set | `transport` and its ports are retained, `corrupted.layer` is `Transport`, and application probing is suppressed. |
| No transport payload to classify, or an empty payload | Ordinary transport-based application classification returns `None`. |
| Nonempty payload with no matching application probe | Classification normally returns `Some(Application)` with the label `"Unknown"`. |

There are deliberate exceptions to the ordinary application path. A rejected
probe on the reserved mDNS or LLMNR ports returns `None` instead of falling
through to other protocols. STP can be classified directly from the link layer,
and IP tunnels can be recognized without a TCP or UDP payload.

`corrupted` is not a complete packet-validity certificate. In this version it
reports internet/transport failures handled by the flow pipeline and detected
TCP semantic anomalies. For example, failed ICMP detailed decoding can leave
`transport` present with `details: None` and no corruption report. Application
classification failures do not have their own `CorruptedLayerKind` variant.

## Borrowing the packet buffer

The lifetime `'a` ties the borrowed payloads in `PacketFlow<'a>` to the input
slice. Keep the input buffer alive while using those views. In a capture loop,
finish using a borrowed flow before overwriting or reusing its packet buffer.
Cloning the flow preserves these references; it does not make an independent
copy of the captured bytes.

This avoids copying the packet payloads retained by the link, internet and
transport views. It does not mean parsing never allocates: application probes
may allocate temporary structures, corruption reports own strings, and nested
flows use `Box`.

When metadata must outlive the buffer, use `flow.to_owned_flow()`. It returns
`owned::PacketFlowOwned`, which can be stored independently of the input.

| Preserved by the owned conversion | Omitted by the owned conversion |
| --- | --- |
| LINKTYPE and format-specific link metadata, including addresses and VLAN tags | Packet payload bytes |
| Internet addresses and address classifications, protocol labels, transport ports | Internet and transport `details`, including detailed header fields |
| Nested flows and corruption reports | The internet view's `payload_protocol` field |

The conversion allocates owned metadata as needed and applies recursively to
`inner`. It is a lossy summary, so keep the original packet bytes separately if
you will need to inspect payloads or decode detailed headers later. Serialization
of the borrowed flow also omits payloads and detailed headers.

## Encapsulated packets

For a successfully decoded tunnel, `inner` keeps the nested conversation
separate from its carrier:

```text
Outer PacketFlow: Ethernet / IPv4 / UDP / VXLAN
└── inner: PacketFlow: Ethernet / IPv4 / TCP / HTTP
```

`flow.flatten()` returns a vector of references to the outer flow followed by
each nested flow, ending at the innermost packet. It does not merge their
addresses or discard the outer flow. Without a decoded tunnel, the vector
contains only the original flow.

## How protocols are selected

The stages use both the bytes and the context established by earlier stages:

1. **Link:** the caller supplies the LINKTYPE. The parser never guesses the
   capture format from the packet bytes.
2. **Internet:** `LinkLayer::network_protocol()` selects the internet parser.
   For Ethernet this comes from the effective EtherType; RAW IP has no EtherType.
3. **Transport:** the internet parser supplies `payload_protocol` and the
   bounded payload. Fragment handling can prevent transport decoding when
   reassembly would be needed.
4. **Application:** after tunnel detection, the ordinary classifier evaluates
   an ordered table of rules. Each rule has a transport constraint, an optional
   source/destination port condition, and a content probe. The first matching
   rule supplies the label; some rules explicitly stop fallback probing.

**A port alone never identifies an application protocol.** Port conditions
give a content probe a chance to run, but the bytes must still satisfy it.
For example, sending arbitrary bytes to TCP port 80 does not establish HTTP.
Conversely, the HTTP rule accepts validated HTTP content over TCP without
requiring port 80. Other rules need ports to disambiguate weaker signatures:
the COTP fallback requires TCP port 102 as well as a valid TPKT/COTP payload.

For a service on a custom port, `parse_with` accepts a `ParseConfig` built with
`decode_as(port, protocol)`. These hints are considered before the ordinary
table, while retaining the selected protocol's transport and content checks.
They do not bypass the terminal rules for reserved mDNS/LLMNR ports.

Classification is best effort on the bytes available in this packet. The
ordinary probes use a bounded prefix of the payload (18 KiB in this revision),
with framing checks also using the full payload where needed. Neither a label
nor its absence proves what a complete, reassembled session contains.

The implementation references are the
[`PacketFlow` pipeline](https://github.com/Akmot9/Packet-parser/blob/85728b6424c478366607f6c8ce703fe650e82004/src/parse/mod.rs),
the [application dispatch table](https://github.com/Akmot9/Packet-parser/blob/85728b6424c478366607f6c8ce703fe650e82004/src/parse/dispatch.rs)
and the [owned conversion](https://github.com/Akmot9/Packet-parser/blob/85728b6424c478366607f6c8ce703fe650e82004/src/owned/mod.rs).
