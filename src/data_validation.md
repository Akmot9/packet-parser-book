# Data validation procedure

![data_validation](images/TryFrom_algo.png)

When we receive a packet, we use `TryFrom` to apply several validation steps to it.  
If the validations succeed, the function returns a structured representation of the packet or a part of it.  
If the validations fail, it returns a custom error, implemented using the [thiserror crate](https://crates.io/crates/thiserror).

> In the diagram the error is called `ParsedPacketError`. It is now `ParseError` for the top-level API, and each layer and each protocol has its own error type (`DataLinkError`, `Ipv4Error`, `TcpError`, `NtpPacketParseError`...).

## Every struct is a `TryFrom<&[u8]>`

This is the one rule of the crate. `DataLink`, `Ipv4Packet`, `TcpPacket`, `DnsPacket`, `TlsPacket`... all of them are built the same way:

```rust
impl<'a> TryFrom<&'a [u8]> for Ipv4Packet<'a> {
    type Error = Ipv4Error;

    fn try_from(data: &'a [u8]) -> Result<Self, Self::Error> {
        validate_ipv4_min_length(data)?;

        let version_ihl = data[0];
        validate_ipv4_version(version_ihl >> 4)?;

        let header_len = ((version_ihl & 0x0F) as usize) * 4;
        validate_ipv4_header_length(header_len)?;
        validate_ipv4_header_available(data.len(), header_len)?;

        let total_length = u16::from_be_bytes([data[2], data[3]]);
        validate_ipv4_total_length(total_length, header_len, data.len())?;

        // ... every remaining field is read with from_be_bytes ...

        Ok(Ipv4Packet { /* ... */, payload: &data[header_len..total_length as usize] })
    }
}
```

The `TryFrom` is a **linear sequence**, in wire order:

1. a pre-check on the length, so that every index below is proven in-bounds;
2. one check per constrained field, chained with `?`: check the bytes of the field, place the value if it is valid, move on to the next field;
3. cross-field validations between values already extracted;
4. build the struct with the validated values, and split header from payload.

As soon as a check fails, `?` returns the typed error: the bytes are not this protocol.

## Where the checks live

The parser file only *chains* the calls. The checks themselves live in a separate, crate-internal module, one file per protocol:

```text
src/
  parse/     the TryFrom impls and the structs      (public)
  checks/    validate_* and extract_* functions       (crate-internal)
  errors/    one thiserror enum per protocol          (public)
```

Two forms of functions:

- `extract_*`: verifies the bytes of **one field** and returns the typed value, ready to be placed in the struct (`extract_stratum`, `extract_reference_id` on the NTP side);
- `validate_*`: returns `Result<(), Error>` for controls that produce no value: length pre-check, cross-field coherence (`validate_ipv4_total_length`, `validate_datetime_ordering`).

A field without any constraint (a raw counter, a free identifier) is read directly with `from_be_bytes` in the parser.

## Typed errors

Errors carry the values that failed, never a bare string, so a consumer can match on them:

```rust
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum TcpError {
    #[error("Packet too short to be a valid TCP header")]
    PacketTooShort,
    #[error("Invalid data offset: {0}")]
    InvalidDataOffset(u8),
    #[error("Invalid TCP flags {flags:#04x}: SYN and FIN are both set")]
    InvalidFlags { flags: u8 },
    #[error("TCP reserved bits are set: {bits:#05b}")]
    ReservedBitsSet { bits: u8 },
}
```

Errors nest with `#[from]`: `Ipv4Error` converts into `InternetError`, which converts into `ParseError`. Every error enum is `#[non_exhaustive]`, so a new variant can be added in a minor version; a `match` on them needs a `_` arm.

## Structural corruption vs. semantic anomaly

Not every failed check means the same thing:

- **structural**: the bytes cannot be read as this protocol (truncated header, impossible length). The `TryFrom` returns `Err`, and in the pipeline the layer becomes `None` with `corrupted: Some(..)`;
- **semantic**: the header reads fine but says something no conforming stack emits (TCP SYN+FIN, reserved bits set). The `TryFrom` returns `Ok`; the anomaly is exposed by `TcpPacket::anomaly()`, and the pipeline **keeps** the layer while reporting it in `corrupted`. This is a classic scan signature: the ports must stay available for correlation.

## Fail-closed below, fail-soft above

The two error paths of `PacketFlow` are asymmetric on purpose:

- the **link layer is fail-closed**: an unsupported LINKTYPE or a truncated link header returns `Err(ParseError)`. Without a valid link layer there is nothing trustworthy to build on;
- **everything above is fail-soft**: an unsupported protocol leaves the layer `None`, a corrupt one is reported in `corrupted`. Real-world traffic is full of protocols the crate does not decode, and a flow matrix must not lose the L2/L3 information because of an odd L4.

## No panic on hostile bytes

A parser of hostile bytes must never bring its host down. `lib.rs` denies `unwrap`, `expect` and `panic!` in production code with clippy lints that the CI runs with `-D warnings`. Indexing after an explicit length check (`data[0]` after `validate_ipv4_min_length`) is the idiom; its absence of panic is verified by the fuzz targets under `fuzz/` (`parse_packetflow`, `parse_linktype`, `parse_dns`, `parse_giop`, `parse_quic`, `parse_s7comm`, `parse_cotp`, `parse_application`).

Now let's go layer by layer.
