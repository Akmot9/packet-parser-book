# Introduction


<p align="center"><img src="images/packet_parser.png" alt="The crate Logo" /></p>

**Packet Parser** is a Rust library designed for parsing network frames.  
This book explains how I developed it and its internal architecture, so you can contribute.

## Key Features

- **Multi-layer support**: parses the data link, internet, transport and application layers.
- **Zero-copy**: the result, `PacketFlow`, borrows the input buffer. No payload is copied.
- **Fail-closed on the link layer**: the LINKTYPE is given by the caller, never guessed from the bytes. An unsupported LINKTYPE is an error.
- **Fail-soft above it**: an unknown or malformed upper layer does not fail the whole parse. The layer stays `None`, and a recognized-but-invalid layer is reported in `corrupted`.
- **Data validation**: every protocol struct is built through `TryFrom`, with its checks in a dedicated module.
- **Precise error management**: each layer and each protocol has its own error type, built with `thiserror`.
- **Designed not to panic on hostile bytes**: every index follows an explicit length check, `unwrap`/`expect`/`panic!` are flagged by clippy lints that the CI turns into errors, and the parsers are fuzzed continuously. This is a discipline backed by tooling, not a proof: see the [validation chapter](./data_validation.md#no-panic-on-hostile-bytes) for what is and is not guaranteed.
- **Tunnels**: CAPWAP, GRE, IP-in-IP, VXLAN, Geneve and GTP-U are peeled, and the inner packet is parsed recursively.
- **Extensibility**: a modular architecture that makes adding a protocol a mechanical job.

## Reference version

This book describes **`packet_parser` 11.2.0** ([crates.io](https://crates.io/crates/packet_parser/11.2.0), tag `v11.2.0` in the [repository](https://github.com/Akmot9/Packet-parser)). Code excerpts of the crate's internals are quoted from that revision; the user-facing snippets marked *tested* are compiled and run against it by the book's `examples/` crate. When the crate moves, the book is updated with it and this line changes.

## Purpose of this crate

The goal of this crate is to provide a function that transforms a packet, or a list of bytes to be more precise, into a typed structure, or into an error if you are getting fooled and receive incoherent bytes.

- You can provide a **full network packet** with its LINKTYPE, and `parse` returns a `PacketFlow`: a structured representation containing the **data link, internet, transport and application layers**.
- It is **not restricted to a specific layer**: every protocol struct implements `TryFrom<&[u8]>`. You can pass a TCP payload to `TlsPacket::try_from`, `DnsPacket::try_from`, `NtpPacket::try_from`... and get the detailed structure of that protocol.

To explain how I made this crate, let's dive into packet parsing, my passion.

1. First we [get started](./getting_started.md) with the public API.
2. Then we have to know what I call a packet, because that is what we are starting from, and what the [`PacketFlow` struct](./packet.md) looks like once the packet is parsed.
3. Then we'll see the [data validation procedure](./data_validation.md) I use for every struct in this crate: `TryFrom`.
4. Then we go down layer by layer: [data link](./data_link.md), [internet](./network.md), [transport](./transport.md), [application](./application.md) and [tunnels](./tunnels.md).
5. And finally, how to [add a new protocol](./adding_a_protocol.md).
