# 📘 `packet-parser` Documentation

Welcome to the documentation book for the [**`packet_parser`**](https://github.com/Akmot9/Packet-parser) Rust crate.

This is not the API reference (that is on [docs.rs](https://docs.rs/packet_parser)). This book explains how the crate is designed: the `PacketFlow` structure, the `TryFrom` validation procedure, each layer's decoders, the application dispatch table, tunnels, and how to add a protocol.

## 🚀 Getting Started

Install `mdBook`, then serve the book locally:

```bash
cargo install mdbook
mdbook serve --open
```

## 🌐 Online Documentation

👉 [https://akmot9.github.io/packet-parser-book/](https://akmot9.github.io/packet-parser-book/)

## 📚 What's Inside

- Getting started with the public API (`parse`, `LinkType`, `PacketFlow`)
- The layered structure and the flow identity
- The data validation procedure (`TryFrom`, `checks`, typed errors, fail-closed / fail-soft)
- Data link, internet, transport and application layers
- Tunnels (CAPWAP, GRE, IP-in-IP, VXLAN, Geneve, GTP-U)
- How to add a new protocol

## 🤝 Contributing

Corrections and improvements to this book are welcome, as are new protocols in the crate itself.

## ⚖️ License

MIT.
