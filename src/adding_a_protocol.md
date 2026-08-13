# Adding a protocol

This chapter is the working method used in the crate itself. The reference
document lives in the repository as
[`METHODE_AJOUT_PROTOCOLE.md`](https://github.com/Akmot9/Packet-parser/blob/main/METHODE_AJOUT_PROTOCOLE.md);
this is its English walkthrough.

## Where the files go

The library is organized **by layer**, and each protocol touches three trees:

```text
src/
  parse/    data_link/  internet/  transport/  application/
  errors/   data_link/  internet/  transport/  application/
  checks/   data_link/             transport/  application/
```

For an application protocol `foo`:

```text
src/parse/application/protocols/foo.rs   # TryFrom + the struct
src/errors/application/foo.rs            # the error enum
src/checks/application/foo.rs            # validation and field extraction
```

If the protocol grows sub-modules, use a directory
(`src/parse/application/protocols/foo/mod.rs`) but keep the same separation.
Errors stay centralized in `src/errors/<layer>/<protocol>.rs`.

## 1. The error type

Errors must be precise and actionable. Do not use `String` as the main error when
a dedicated variant is possible.

```rust
use thiserror::Error;

#[derive(Debug, Error, PartialEq)]
pub enum FooError {
    #[error("Foo packet too short: {0} bytes")]
    TooShort(usize),
    #[error("Invalid Foo magic: {0:#06x}")]
    InvalidMagic(u16),
}
```

`TooShort(3)` and `InvalidMagic(0x4141)` say different things about the traffic.
A single `InvalidPacket` says nothing.

## 2. The checks

Validation and per-field extraction go in `src/checks/`, **not inline in the
parser**. They allocate nothing and decide nothing about structure — they answer
yes/no and hand back field values.

## 3. The parser

`TryFrom<&[u8]>`, in a linear sequence: length pre-check → `extract_*` per field
in wire order → cross-field validations → construction. Borrow (`&'a [u8]`),
don't copy.

## 4. The rustdoc

The main type carries a rustdoc with a Mermaid `packet-beta` diagram of the wire
layout, behind the `doc-diagrams` feature:

```rust
#[cfg_attr(all(doc, feature = "doc-diagrams"), aquamarine::aquamarine)]
```

## 5. Wiring it in — and the semver rule

Export the module from the layer's `mod.rs`. Then stop before the reflex move:

> **Do not add a variant to an exhaustive public enum.** It breaks users'
> exhaustive `match`es, so it requires a major version.

For a minor release, keep the parser reachable through its module and expose its
name through `Application` / `PacketFlow`. When a major version *does* allow the
new variant, add its `Display` arm in `src/displays/` at the same time.

`cargo semver-checks check-release` enforces this, and the publication workflow
runs it before any `cargo publish`.

## Choosing the detection path

This is the decision that matters most, and it has three answers.

**Path 1 — blind probing** (`Application::try_from`). Reserved for protocols
whose bytes identify themselves: a literal marker (`HTTP/`, `GIOP`), a tightly
constrained binary header (DNS, NTP), or an announced length that must match the
remaining bytes exactly (PostgreSQL).

```rust
if FooPacket::try_from(packet).is_ok() {
    return Ok(Application { application_protocol: "Foo" });
}
```

⚠️ **Order matters** in the probing chain. A permissive parser placed early
captures packets belonging to another protocol. The existing ordering constraints
are documented in comments where they apply (DHCP before SRVLOC — issue #3; MQTT
last, because its fixed header is barely discriminant).

**Path 2 — port-guarded detection**
(`PacketFlow::parse_application_from_transport`). For weak or ambiguous
signatures that no amount of checking can separate from another protocol. FTP,
SMTP and NNTP responses are byte-for-byte identical (`2xx text CRLF`); DHCPv6,
AMS, COTP and QUIC short headers have under-constrained headers; mDNS shares the
DNS format with relaxed validation. The standard port is a guard rail **in
addition to** the parser's checks, never in their place.

**Path 3 — strong signature with a transport constraint.** The protocol
identifies itself well enough to be recognized off its standard port, but is only
defined over one transport. S7Comm takes this path: the full TPKT + COTP-DT + S7
envelope allows probing on any TCP port, while the same bytes over UDP must never
produce the S7Comm label. Test the standard port, a non-standard port, and a
forbidden transport explicitly.

**Decision criterion:** if a valid payload of your protocol can also be a valid
payload of an already-detected protocol — or of arbitrary text — blind probing is
forbidden. Use a port guard and document why in a comment. For a text protocol,
also ask whether a seemingly distinctive command can appear in another protocol's
free-form body. Without session state, that case forces a port guard too.

## 6. Tests

Unit tests near the parser and the checks, covering valid **and** invalid cases.

Beyond that, two kinds carry most of the weight:

- **Golden tests on real frames**, with the source pcap cited in a comment. Any
  synthetic fixture is explicitly identified as synthetic.
- **A non-empty negative corpus** for every new detection, pinned by expected
  frame numbers or a deterministic fingerprint — otherwise a false positive can
  hide a false negative.

Fuzz targets for the protocol need at least one structured valid seed and must
assert the transport and classification invariants.

## 7. Checklist before commit

- `TryFrom<&[u8]>` follows the linear sequence: length pre-check, `extract_*` per
  field in wire order, cross-field validations, construction.
- Errors are in a dedicated file and use `thiserror::Error`.
- Validation and extraction live under `src/checks` — no inline validation in the
  parser.
- The main type has a rustdoc with a Mermaid `packet-beta` diagram.
- The relevant `mod.rs` files export the new module.
- Public-API semver compatibility is preserved; a variant is added to an
  exhaustive public enum only in a major version, with its `Display` arm.
- The detection path is chosen **and justified**.
- Tests cover valid and invalid cases.
- At least one golden test on a real frame exists, with its source pcap cited.
- Every new detection is verified against a non-empty negative corpus.
- The affected fuzz targets have a structured seed and check their invariants.
- The protocol lists in `README.md` and `README-fr.md` are updated — and, if this
  book documents the layer, its chapter too.

## Useful commands

```bash
cargo fmt --all -- --check
cargo test --workspace --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo +nightly fuzz build
cargo audit
cargo deny check --hide-inclusion-graph
cargo semver-checks check-release   # compares the public API to the last published version
```
