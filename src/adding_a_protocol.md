# Adding a new protocol

The crate is built so that adding a protocol is a mechanical job with the same shape every time. The reference document in the repository is `METHODE_AJOUT_PROTOCOLE.md` (in French); this chapter is its summary.

## Mandatory principles

- The parser implements **`TryFrom<&[u8]>`**, as a linear sequence: length pre-check, one `extract_*` per constrained field in wire order, cross-field validations, then construction. The canonical model is `ntp.rs`.
- **Zero-copy**: `&'a [u8]` for payloads and variable fields, scalars for fixed fields, `from_be_bytes` for numbers. No `Vec`, `String`, `to_vec()` or `clone()` in a parsing struct. A `&'a str` only when the protocol mandates UTF-8 and it was validated.
- Any pre-allocation sized by a field of the packet goes through `bounded_capacity`: a sender-controlled counter never drives a `Vec::with_capacity` unbounded.
- **Errors** in a dedicated file, with `thiserror`, carrying the offending values. Never a bare `String`.
- **Checks** in a separate file under `src/checks`, not inline in the parser.
- The main struct's rustdoc documents the wire format with a Mermaid `packet-beta` diagram.
- No `unwrap()` in a parser. The CI runs clippy with `-D warnings` and the `unwrap_used`/`expect_used`/`panic` lints.
- Golden tests use **real frames** from a capture under `pcaps_exemple/`, with the pcap file and frame number cited in a comment. Synthetic bytes are for targeted unit tests (truncation, invalid value, limits) and are labelled as such.

## Files to create

For an application protocol `foo`:

```text
src/parse/application/protocols/foo.rs   the struct and its TryFrom
src/errors/application/foo.rs            enum FooError
src/checks/application/foo.rs            validate_* / extract_*
pcaps_exemple/protocols/foo/             a real capture + SOURCE.md
```

and one `pub mod foo;` in each layer's `mod.rs`.

## 1. The error type

```rust
use thiserror::Error;

#[derive(Debug, Error, PartialEq)]
#[non_exhaustive]
pub enum FooError {
    #[error("Packet too short: expected at least {expected} bytes, got {actual} bytes")]
    InvalidLength { expected: usize, actual: usize },
    #[error("Invalid Foo version: {0}")]
    InvalidVersion(u8),
    #[error("Invalid Foo message type: {0}")]
    InvalidMessageType(u8),
}
```

## 2. The checks

```rust
const FOO_MIN_LENGTH: usize = 8;

pub fn validate_foo_min_length(packet: &[u8]) -> Result<(), FooError> {
    if packet.len() < FOO_MIN_LENGTH {
        return Err(FooError::InvalidLength { expected: FOO_MIN_LENGTH, actual: packet.len() });
    }
    Ok(())
}

pub fn extract_foo_version(byte: u8) -> Result<u8, FooError> {
    let version = byte >> 4;
    if version != 1 {
        return Err(FooError::InvalidVersion(version));
    }
    Ok(version)
}
```

## 3. The parser

```rust
/// Foo Protocol Packet
///
/// ```mermaid
/// packet-beta
/// 0-3: "Version u4"
/// 4-7: "Flags u4"
/// 8-15: "Message Type u8"
/// 16-31: "Length u16"
/// 32-63: "Payload variable"
/// ```
#[derive(Debug, PartialEq)]
#[non_exhaustive]
pub struct FooPacket<'a> {
    pub version: u8,
    pub message_type: u8,
    pub length: u16,
    pub payload: &'a [u8],
}

impl<'a> TryFrom<&'a [u8]> for FooPacket<'a> {
    type Error = FooError;

    fn try_from(packet: &'a [u8]) -> Result<Self, Self::Error> {
        validate_foo_min_length(packet)?;

        let version = extract_foo_version(packet[0])?;
        let message_type = packet[1];
        let length = u16::from_be_bytes([packet[2], packet[3]]);
        validate_foo_announced_length(packet, length)?;

        Ok(FooPacket { version, message_type, length, payload: &packet[4..length as usize] })
    }
}
```

## 4. Plugging it into the dispatch table

Add a `ProbeId::Foo` and its `run_probe` arm in `src/parse/dispatch.rs`, then one line in `RULES`, choosing the route described in the [application chapter](./application.md#three-detection-routes):

- **blind** `rule("Foo", Guard::Tcp, ProbeId::Foo)` only if a valid Foo payload cannot also be a valid payload of another detected protocol, or arbitrary text;
- **port-guarded** `port_rule(..)` otherwise, with a comment explaining why;
- always with the transport guard the RFC imposes.

The position in the table matters: put the line where its priority belongs and say why in a comment. Then update the protocol lists of `README.md` and `README-fr.md`.

Do **not** add a variant to an exhaustive public enum in a minor version: that breaks users' `match`. The types the parser builds are `#[non_exhaustive]` so that new fields and variants stay additive.

## 5. Tests

Minimum for the unit tests: a valid packet, a too-short packet, an invalid version, an invalid announced length, an invalid type or flag.

Then, at `PacketFlow` level:

- at least one golden test on a **real frame** (Ethernet + IP + transport + Foo) checking that the label comes out;
- for a port-guarded protocol, the non-detection of the same bytes off the standard port;
- for a blind probe, a scan of the other protocols' corpus with a **non-empty negative oracle**, keyed by expected frame numbers so that a false positive and a false negative cannot cancel each other out;
- a structured valid seed in the relevant fuzz target: random bytes rarely get through Ethernet + IP + transport + Foo.

Extract a payload from a capture with:

```bash
tshark -r capture.pcap -Y "frame.number==5" -T fields -e tcp.payload
```

## 6. Checklist before commit

```bash
cargo fmt --all -- --check
cargo test --workspace --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo +nightly fuzz build
cargo audit
cargo deny check --hide-inclusion-graph
cargo semver-checks check-release   # public API vs the last published version
```
