# Getting started

This chapter is the "how do I use it" part. The rest of the book is the "how is it built" part.

> **Reference version: `packet_parser` 11.2.0.** Every code snippet marked *tested* below is included verbatim from the book's `examples/` crate, which compiles and runs against that exact version (`cd examples && cargo test`). Older versions differ: see `MIGRATION-11.md` in the crate repository.

## Installation

```toml
[dependencies]
packet_parser = "11.2.0"
hex = "0.4" # only for the examples below, to decode hex dumps
```

## Parse one packet

`parse` is the entry point. It takes two things:

1. the **LINKTYPE** of the capture: the value stored in the PCAP/PCAPNG file (`LinkType::ETHERNET`, `LinkType::LINUX_SLL`, ...);
2. **exactly one packet**, without any PCAP record header.

```rust
use packet_parser::{LinkType, parse};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let raw = hex::decode(
        "feaa81e86d1efeaa818ec864080045500034000000003d06206b36e6700d\
         ac140a0201bbc1087d7f02aa4e2b998e80100081748300000101080a9373\
         c9c207ef14e3",
    )?;

    // Always pass the LINKTYPE the capture declares.
    let flow = parse(LinkType::ETHERNET, &raw)?;

    println!("L2: {}", flow.data_link);

    if let Some(internet) = &flow.internet {
        println!("L3: {} {:?} -> {:?}",
            internet.protocol_name, internet.source, internet.destination);
    }
    if let Some(transport) = &flow.transport {
        println!("L4: {:?} {:?} -> {:?}",
            transport.protocol, transport.source_port, transport.destination_port);
    }
    if let Some(application) = &flow.application {
        println!("L7: {}", application.application_protocol);
    }
    Ok(())
}
```

Output:

```text
L2:
    Destination MAC: fe:aa:81:e8:6d:1e,
    Source MAC: fe:aa:81:8e:c8:64,
    Ethertype: IPv4,
    VLAN: None,
    Payload Length: 52

L3: IPv4 Some(54.230.112.13) -> Some(172.20.10.2)
L4: Tcp Some(443) -> Some(49416)
```

No `L7` line: this segment is a pure ACK with an empty payload, so there is nothing to classify and `application` stays `None`.

The same frame, as the book's example crate checks it (*tested*):

```rust
{{#include ../examples/src/lib.rs:parse_valid_frame}}
```

## Never guess the LINKTYPE

`parse` is **fail-closed on the link layer**: the LINKTYPE comes from the caller and is never guessed from the bytes. Check it up front to reject a whole capture before reading a single packet:

```rust
use packet_parser::{LinkType, is_supported, parse};

let link_type = LinkType::ETHERNET;
if !is_supported(link_type) {
    return Err(format!("unsupported LINKTYPE {}", link_type).into());
}
let flow = parse(link_type, packet_bytes)?;
```

| LINKTYPE | Value | Decoder status |
| --- | ---: | --- |
| BSD loopback (NULL) | 0 | Supported: four address-family bytes, then the IP packet (11.2.0) |
| Ethernet | 1 | Supported (802.1Q and 802.1ad/QinQ tags included) |
| RAW IP | 101 | Supported for IPv4 and IPv6 |
| Native IEEE 802.11 | 105 | Modelled for CAPWAP inner flows; top-level decoder not yet supported |
| Linux SLL v1 | 113 | Supported |
| Bluetooth H4 with pseudo-header | 201 | Identified, explicitly unsupported |
| IPv4 raw | 228 | Supported |
| IPv6 raw | 229 | Supported |
| IEEE 802.3br mPacket | 274 | Supported for express mPackets (SMD-E); preemptible fragments are refused |
| Linux SLL v2 | 276 | Supported |
| Any other value | Preserved as-is | `ParseError::UnsupportedLinkType` |

`PacketFlow::try_from(&[u8])` and `DataLink::try_from(&[u8])` still exist. They take a bare byte slice and **assume Ethernet**. Feeding them a Linux `any` capture (`LINKTYPE_LINUX_SLL`) does not fail: the 16 cooked-header bytes are read as MAC addresses and an EtherType, and you get `Ok` with fabricated addresses. Use them only when the capture is known to be Ethernet.

## Reading the outcome

Only the link layer can fail the parse. Above it, three outcomes are distinct and must not be confused:

| `flow.internet` / `transport` | `flow.corrupted` | Meaning |
| --- | --- | --- |
| `Some(..)` | `None` | The layer was recognized and decoded. |
| `None` | `None` | The protocol is **not supported** (e.g. LLDP EtherType), nothing above it can be reached. |
| `None` | `Some(..)` | The layer **was recognized** (by its EtherType or IP protocol number) but its bytes are invalid. `CorruptedLayer::layer` says which one, `error` says why. |
| `Some(..)` | `Some(..)` | Semantic anomaly: the header is readable but no conforming stack emits it (TCP SYN+FIN, reserved bits set). The layer is **kept** so its ports remain available for flow correlation; nothing is parsed above it. |

A recognized layer with invalid bytes (*tested*):

```rust
{{#include ../examples/src/lib.rs:corrupted_upper_layer}}
```

An unsupported protocol above the link layer, which is not corruption (*tested*):

```rust
{{#include ../examples/src/lib.rs:unsupported_upper_layer}}
```

And the two link-layer failures, the only ones that return `Err` (*tested*):

```rust
{{#include ../examples/src/lib.rs:unsupported_linktype}}
```

```rust
{{#include ../examples/src/lib.rs:truncated_link_layer}}
```

## Main API

| Need | API |
| --- | --- |
| Check whether a link decoder exists | `is_supported(LinkType)` |
| **Parse a packet (canonical)** | `parse(LinkType, &[u8])` |
| Parse with caller-declared ports ("Decode As") | `parse_with(LinkType, &[u8], &ParseConfig)` |
| Parse Ethernet, compat shortcut (assumes Ethernet) | `PacketFlow::try_from(&[u8])` |
| Parse only Ethernet/VLAN (assumes Ethernet) | `DataLink::try_from(&[u8])` |
| Parse only L3 | `Internet::try_from_network_parts(NetworkProtocol, &[u8])` |
| Parse only L4 | `Transport::try_from_parts(Option<TransportProtocol>, &[u8])` |
| Parse one application protocol in detail | `packet_parser::parse::application::protocols::<proto>::XxxPacket::try_from(&[u8])` |
| Detach the result from the original buffer | `flow.to_owned_flow()` |
| Iterate over encapsulated flows | `flow.flatten()` |
| Verify a checksum (opt-in) | `packet_parser::checksum::verify_{ipv4_header,tcp,udp}_checksum` |
| Measure the time spent per layer | `parse_timed(...)` with the `parse_timing` feature |

## "Decode As": my FTP runs on port 2121

Some protocols are only detected when the port **and** the content agree (see the [application chapter](./application.md)). `ParseConfig` lets the caller declare extra ports. The port never replaces the content check: it only gives the probe its chance before the rest of the table.

```rust
use packet_parser::{DecodeAsProtocol, LinkType, ParseConfig, parse_with};

let config = ParseConfig::new().decode_as(2121, DecodeAsProtocol::Ftp);
let flow = parse_with(LinkType::ETHERNET, &raw, &config)?;
```

## Owned flows and serialization

`PacketFlow<'a>` borrows the input buffer: it cannot outlive it. To store a flow, send it across threads or keep it after the capture buffer is reused, convert it with `to_owned_flow()`. The conversion is **lossy** on purpose: the owned form drops the payloads and the per-layer `details`, and keeps the flow identity (addresses, protocols, ports).

`PacketFlow` and `PacketFlowOwned` both implement `serde::Serialize` and produce the **same JSON**: the link layer is nested and tagged, the upper layers are flattened, payloads and `details` are not serialized.

```json
{
  "data_link": {
    "link_type": 1,
    "network_protocol": { "kind": "ipv4" },
    "link_kind": "ethernet",
    "link_details": {
      "destination_mac": "fe:aa:81:e8:6d:1e",
      "source_mac": "fe:aa:81:8e:c8:64",
      "ethertype": "IPv4"
    }
  },
  "source_ip": "54.230.112.13",
  "ip_source_type": "Public",
  "destination_ip": "172.20.10.2",
  "ip_destination_type": "Private",
  "protocol_internet": "IPv4",
  "protocol_transport": "TCP",
  "source_port": 443,
  "destination_port": 49416
}
```

The owned form is what you keep once the capture buffer is gone (*tested*):

```rust
{{#include ../examples/src/lib.rs:owned_and_json}}
```

## Timing (benchmarks)

`parse_timed` runs the exact same pipeline as `parse` and reports the nanoseconds spent in each layer. The API is always there; without the `parse_timing` feature nothing is measured and `ParseTiming` stays zeroed, so enabling the feature anywhere in a dependency graph never changes a signature.

```rust
use packet_parser::{LinkType, parse_timed, timing::ParseTiming};

let mut timing = ParseTiming::default();
let flow = parse_timed(LinkType::ETHERNET, &raw, &mut timing)?;
println!("L2={}ns L3={}ns L4={}ns L7={}ns total={}ns",
    timing.l2_ns, timing.l3_ns, timing.l4_ns, timing.l7_ns, timing.total_ns);
```

```bash
cargo test --features parse_timing
```

## Known limitations

- No TCP reassembly, no IP reassembly: the parser is **stateless** and sees one packet at a time.
- The application layer is a **classification**, not a decode (see the [application chapter](./application.md) and the [GIOP focus](./giop.md) for the tested example).
- Checksums are never validated during parsing (hardware offloading leaves them uncomputed on sender-side captures). Use the `checksum` module when your context allows it.
