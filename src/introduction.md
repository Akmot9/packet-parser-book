# Introduction

<p align="center"><img src="images/packet_parser.png" alt="The logo of the packet_parser crate" /></p>

`packet_parser` is a Rust library that turns the bytes of a captured frame into a typed structure, layer by layer, or into a typed error when the bytes are not coherent. This book describes what the crate decodes, how it decides, and what it leaves out.

## What the crate does

- **Four layers.** `parse` takes a frame and its LINKTYPE and returns a `PacketFlow`: the data link, internet, transport and application layers.
- **Zero-copy.** `PacketFlow` borrows the input buffer. No payload is copied.
- **Fail-closed on the link layer.** The LINKTYPE is given by the caller, never guessed from the bytes. An unsupported LINKTYPE is an error.
- **Fail-soft above it.** An unknown or malformed upper layer does not fail the parse. The layer stays `None`, and a recognized but invalid layer is reported in `corrupted`.
- **One protocol at a time.** Every protocol struct implements `TryFrom<&[u8]>`: a transport payload can go straight to `TlsPacket::try_from`, `DnsPacket::try_from` or `NtpPacket::try_from`.
- **Typed errors.** Each layer and each protocol has its own error type, built with `thiserror`.
- **Designed not to panic on hostile bytes.** Every index follows an explicit length check, clippy lints flag `unwrap`, `expect` and `panic!`, and the parsers are fuzzed every night. This is a discipline backed by tooling, not a proof: the [validation chapter](./data_validation.md#no-panic-on-hostile-bytes) says what is and is not guaranteed.
- **Tunnels.** CAPWAP, GRE, IP-in-IP, VXLAN, Geneve and GTP-U are peeled, and the inner packet is parsed recursively.

## Who this book is for

| Reader | Question | Where to start |
|---|---|---|
| Someone who integrates the crate | What does `parse` return, and what can be built on it? | [Getting started](./getting_started.md), then the [`PacketFlow` struct](./packet.md), the [Protocols](./protocols.md) index and the [Limits](./limits.md) |
| Someone who audits it | How is a label chosen, and how far is each decoder verified? | [Data validation procedure](./data_validation.md), the dispatch table of the [Application](./application.md) chapter, then the "Oracle" and "What is left out" sections of the protocol pages |
| Someone whose protocol the crate does not decode | How can it still get a name, without forking the crate? | [Custom parsers and rules](./custom_parsers.md) |
| Someone who contributes to it | Where does a new protocol go, and what must it prove? | [Adding a new protocol](./adding_a_protocol.md), after the [Data validation procedure](./data_validation.md) |

## What the book guarantees

- **A pinned version.** The book describes `packet_parser` 13.2.0 ([crates.io](https://crates.io/crates/packet_parser/13.2.0), tag `v13.2.0` in the [repository](https://github.com/Akmot9/Packet-parser)). When the crate moves, the book is updated with it and this line changes.
- **Tested examples.** A snippet marked *tested* is compiled and run against that version by the `examples/` crate of the book, on every change.
- **Oracles.** The counts the book quotes come from the golden tests of the crate, many of which compare each decoded field with tshark on real captures. The [Protocols](./protocols.md) index gives the size of each oracle.

The excerpts of the crate's internals are not compiled: they are quoted from the pinned revision.

## How the book is organized

1. [Getting started](./getting_started.md) covers the public API.
2. The [`PacketFlow` struct](./packet.md) shows what a parsed packet looks like, and the [data validation procedure](./data_validation.md) how every struct is built.
3. The layers follow, from the bottom: [data link](./data_link.md), [internet](./network.md), [transport](./transport.md), [application](./application.md), each with one page per protocol.
4. [Protocols](./protocols.md) is the index of every label, and [Tunnels](./tunnels.md) covers encapsulation.
5. [Limits](./limits.md) says what a stateless parser cannot see, [Adding a new protocol](./adding_a_protocol.md) is the contributor's path, and [Custom parsers and rules](./custom_parsers.md) the caller's, for a protocol that stays out of the crate.
6. The [Glossary](./glossary.md) defines the words the book relies on.
