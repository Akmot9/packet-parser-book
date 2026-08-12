# Getting started

## Installation

```toml
[dependencies]
packet_parser = "10.0.0"
```

The examples in this book decode hexadecimal dumps, so they also use `hex`:

```toml
[dependencies]
hex = "0.4"
packet_parser = "10.0.0"
```

## Parsing one packet

`parse` is the entry point. It takes two things: the **LINKTYPE the capture
declares**, and **exactly one packet**, without any PCAP or PCAPNG record
header.

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
        println!(
            "L3: {} {:?} -> {:?}",
            internet.protocol_name, internet.source, internet.destination
        );
    }

    if let Some(transport) = &flow.transport {
        println!(
            "L4: {:?} {:?} -> {:?}",
            transport.protocol, transport.source_port, transport.destination_port
        );
    }

    if let Some(application) = &flow.application {
        println!("L7: {}", application.application_protocol);
    }

    Ok(())
}
```

Note the shape of the code: the link layer is read directly, everything above it
is an `Option`. That is not defensive style — it is the actual contract, and
[the `PacketFlow` chapter](./packet_flow.md) explains why.

## Rejecting a capture before reading it

`is_supported` answers whether this build has a decoder for a LINKTYPE. Ask
before iterating over thousands of packets, not once per packet:

```rust
use packet_parser::{LinkType, is_supported, parse};

let link_type = LinkType::ETHERNET;
if !is_supported(link_type) {
    return Err(format!("unsupported LINKTYPE {}", link_type).into());
}

let flow = parse(link_type, packet_bytes)?;
```

## The main API in one table

| Need | API |
| --- | --- |
| Check whether a link decoder exists | `is_supported(LinkType)` |
| **Parse a packet (canonical)** | `parse(LinkType, &[u8])` |
| Parse Ethernet, compat shortcut — assumes Ethernet, [see the warning](./link_types.md#the-ethernet-shortcut-is-a-trap) | `PacketFlow::try_from(&[u8])` |
| Parse only Ethernet/VLAN — assumes Ethernet | `DataLink::try_from(&[u8])` |
| Parse only L3 | `Internet::try_from(&[u8])` |
| Parse only L4 | `Transport::try_from(&[u8])` or `Transport::try_from_parts(...)` |
| Detach the result from the original buffer | `flow.to_owned()` |
| Iterate over encapsulated flows | `flow.flatten()` |
| Measure an explicit LINKTYPE | `parse_timed(...)`, feature `parse_timing` |
| Measure Ethernet through the compat API | `PacketFlow::try_from_timed(...)`, feature `parse_timing` |

## Runnable examples

The crate repository ships several entry points under `examples/`:

```bash
cargo run --example parse_tcp
cargo run --example parse_hex_dump
cargo run --example pars_quic
cargo run --example parse_pgadm
```

The binaries that read PCAP files through the `pcap` crate need the system
libpcap development package (`sudo apt-get install libpcap-dev` on
Debian/Ubuntu).

## Checks before a commit

```bash
cargo fmt -- --check
cargo clippy --all-targets -- -D warnings
cargo test --all-features
cargo build --release
```
