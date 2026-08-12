# 📘 `packet-parser` Documentation

Welcome to the official documentation for the **`packet_parser`** Rust crate.

This book explains how the crate parses network frames: its layered model, the
data validation procedure behind every structure, how each layer is decoded, and
how to add support for a new protocol.

It currently documents **`packet_parser` 10.0.0**.

---

## 🚀 Getting Started

First, install `mdBook` to serve the documentation locally:

```bash
cargo install mdbook
```

Then run the local server:

```bash
mdbook serve --open
```

---

## 🌐 Online Documentation

You can view the latest version of this book online here:
👉 [https://akmot9.github.io/packet-parser-book/](https://akmot9.github.io/packet-parser-book/)

---

## 🧩 About the Crate

**`packet_parser`** is a modular Rust crate built for:

* Parsing network frames at all levels (link, internet, transport, application)
* Zero-copy decoding — the parsed flow borrows the input buffer
* Fail-closed link-layer handling: the LINKTYPE is supplied by the caller, never guessed
* Fail-soft handling above it: an unsupported or corrupt upper layer does not lose the layers below
* Easily extending support for new protocols
* Providing typed errors for each network layer

Crate: [crates.io/crates/packet_parser](https://crates.io/crates/packet_parser) ·
API reference: [docs.rs/packet_parser](https://docs.rs/packet_parser) ·
Source: [github.com/Akmot9/Packet-parser](https://github.com/Akmot9/Packet-parser)

---

## 📚 What's Inside

* Getting started with `parse` and LINKTYPEs
* What a packet is, and what a parse returns (`PacketFlow`)
* The data validation procedure (`TryFrom`, checks, typed errors)
* One chapter per layer: data link, internet, transport, application
* Tunnels, owned flows and serialization
* Performance measurement and benchmarks
* The method for adding a new protocol

---

## 🤝 Contributing

This project is community-friendly and welcomes contributions. You can:

* Suggest corrections or improvements to the documentation
* Add support for new network protocols
* Improve performance or test coverage

---

## ⚖️ License

This project is licensed under the MIT License.

---

💬 For feedback, suggestions, or issues, please visit the GitHub repository.
