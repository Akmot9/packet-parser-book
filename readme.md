# 📘 `packet-parser` book

The design documentation of the [**`packet_parser`**](https://github.com/Akmot9/Packet-parser) Rust crate, as an [mdBook](https://rust-lang.github.io/mdBook/).

This is not the API reference (that is on [docs.rs](https://docs.rs/packet_parser)). The book explains how the crate is built: the `PacketFlow` structure, the `TryFrom` validation procedure, each layer's decoders, the application dispatch table, tunnels, a GIOP walkthrough, and how to add a protocol.

- Read it online: **<https://akmot9.github.io/packet-parser-book/>**
- Reference version: `packet_parser` **11.2.0** — [crates.io](https://crates.io/crates/packet_parser) · [docs.rs](https://docs.rs/packet_parser) · [sources](https://github.com/Akmot9/Packet-parser)

## Layout

```text
src/            the chapters (SUMMARY.md is the table of contents)
src/images/     diagrams
examples/       a Cargo crate: every snippet marked "tested" in the book is
                included from examples/src/lib.rs and run against the
                reference version of packet_parser
tools/          check_book.py, the pre-build checks
.github/        CI: validation on pull requests, deployment to Pages on main
```

## Build locally

The book is built with **mdBook 0.4.48**, the same version the CI pins.

```bash
cargo install mdbook --version 0.4.48 --locked
```

Then, from the repository root:

```bash
python3 tools/check_book.py        # SUMMARY.md vs src/, local links, includes
mdbook build                       # -> book/
mdbook serve --open                # live preview
(cd examples && cargo test)        # compile and run the book's examples
```

`tools/check_book.py` runs **before** `mdbook build` on purpose: mdBook creates any chapter that `SUMMARY.md` references but that is missing, and never checks a local link. The script fails on a missing or orphan chapter, a broken local link or image, an unknown heading anchor, and an `{{#include}}` whose file or anchor does not exist. It reads the sources only.

The examples are ordinary `#[test]`s: change one so that it no longer compiles or no longer passes, and `cargo test` fails — the CI runs the same command.

## Contributing

Corrections and improvements to the **book** are welcome here: open an issue or a pull request. The CI validates every pull request (source checks, book build, examples).

Bugs, protocols and features of the **parser** belong to the crate's repository: <https://github.com/Akmot9/Packet-parser/issues>.

## License

The book and its examples are distributed under the MIT license, see [LICENSE](LICENSE). The crate is MIT as well.
