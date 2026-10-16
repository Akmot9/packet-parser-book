# IKE

Internet Key Exchange, in both its versions: IKEv1, the ISAKMP framework of RFC 2408 and RFC 2409, and IKEv2, RFC 7296. Added in 11.6.0 ([#124](https://github.com/Akmot9/Packet-parser/issues/124)) with its companion [ESP](./esp.md), as part of the defense lot ([#125](https://github.com/Akmot9/Packet-parser/issues/125)), which this release completes: on a defense network, the "black" side of the IP encryptors is made of IKE and ESP, and labelling IKE and exposing the SPIs is enough to map who negotiates with whom. The decoder reads the 28-byte header and the chain of top-level payloads without entering them; what is encrypted stays bytes. The module is `packet_parser::parse::application::protocols::ike`, the error type `IkeParseError` is in `packet_parser::errors::application::ike`.

## On UDP 500 and 4500, by port

IKE travels over UDP: port 500 (IANA `isakmp`), and port 4500 (IANA `ipsec-nat-t`) behind a NAT (RFC 3948), or because the implementation chose that port. The rule of the [dispatch table](./application.md) is **port-guarded**, 500 or 4500 on either side:

```rust
port_rule("IKE", Guard::Udp, is_ike_udp_port, ProbeId::Ike),   // 500, 4500
```

There is no blind probe: a 28-byte header with a plausible version and length is not a signature strong enough to try on every datagram. The probe is `IkePacket::from_udp`, run on the whole datagram rather than on the `PROBE_CAP` prefix, since the header's length must cover the message exactly. The rule sits among the port rules, after PostgreSQL's and right before the two other rules of port 4500, ESP and NAT-keepalive; the WireGuard rule of UDP 51820 comes later, so that an IKE packet whose peer drew 51820 as its ephemeral port keeps its label.

One side is enough. In `ipsec_isakmp_esp.pcap`, a client behind a NAT, `192.168.2.100`, talks to nine gateways from ports 10500, 14500 and a few ephemeral ones: only the gateway's side is 500 or 4500. The capture's 279 IKE_SA_INIT messages are on UDP 500, its 240 IKE_AUTH and INFORMATIONAL messages on UDP 4500, with its 315 ESP packets.

IKE on another port is declared with `ParseConfig::decode_as(port, DecodeAsProtocol::Ike)` ([Decode As](./application.md#decode-as)), one of the `DecodeAsProtocol` variants added in 11.6.0: same probe, same transport guard, and the content still decides (*tested*):

```rust
{{#include ../examples/src/ipsec.rs:ike_decode_as}}
```

Being port-guarded, IKE is not among the probes of `Application::try_from`, which has no port to check.

## UDP 4500: three things on one port

RFC 3948 §2 shares port 4500 between three kinds of datagrams, and `UdpEncapsulation::classify` tells them apart:

```rust
#[non_exhaustive]
pub enum UdpEncapsulation<'a> {
    Ike(&'a [u8]),   // the non-ESP marker, then an IKE message: the bytes after the marker
    Esp(&'a [u8]),   // an ESP packet, non-zero SPI first: the whole datagram
    Keepalive,       // NAT-keepalive: a single 0xFF byte
}
```

`classify` reads the UDP payload in this order, and the first matching row decides:

| UDP payload | `classify` |
| --- | --- |
| exactly one byte, `0xFF` (§2.3) | `Keepalive` |
| four zero bytes, the **non-ESP marker** (§2.2), then at least one byte | `Ike(rest)`, the bytes after the marker, not yet decoded |
| the marker alone, or fewer than 8 bytes | `Err(InvalidUdpEncapsulation { length })` |
| anything else: a non-zero SPI and a sequence number (§2.1) | `Esp(payload)`, the whole datagram |

The marker sits where an ESP packet has its SPI, and an SPI of zero is reserved and never sent (RFC 4303 §2.1): no ESP packet starts with it. Port 4500 has three rules, in this order:

```rust
port_rule("IKE",           Guard::Udp, is_ike_udp_port,   ProbeId::Ike),          // 500, 4500
port_rule("ESP",           Guard::Udp, is_nat_t_udp_port, ProbeId::EspNatT),      // 4500
port_rule("NAT-keepalive", Guard::Udp, is_nat_t_udp_port, ProbeId::NatKeepalive), // 4500
```

The IKE probe does not go through `classify`: `IkePacket::from_udp` tries the bare message first, as on port 500, and if that fails while the marker is there with something after it, it decodes what follows the marker. A bare IKE message on 4500 is therefore accepted too. The ESP and keepalive rules, and what they label, are on the [ESP page](./esp.md#in-udp-4500-behind-a-nat); UDP 500 carries neither.

Frame 42 of `ipsec_isakmp_esp.pcap` is an INFORMATIONAL behind the marker. Read bare, the marker becomes the first half of an initiator SPI, every field slides by four bytes, and the length read is 0 (*tested*):

```rust
{{#include ../examples/src/ipsec.rs:ike_nat_t}}
```

## The header

```rust
#[non_exhaustive]
pub struct IkeHeader {
    pub initiator_spi: u64,   // IKEv1: the initiator's cookie
    pub responder_spi: u64,   // zero in the first message of an initial exchange
    pub next_payload: u8,     // type of the first payload
    pub version: u8,          // raw: major version on the high nibble, minor on the low
    pub exchange_type: u8,    // raw; exchange() names it
    pub flags: u8,            // raw; one accessor per flag, by version
    pub message_id: u32,
    pub length: u32,          // the whole message, header included
}
```

ISAKMP and IKEv2 share the layout (RFC 2408 §3.1, RFC 7296 §3.1), big-endian:

| Bytes | Field | Note |
| --- | --- | --- |
| 0–7 | `initiator_spi` | never zero in IKEv2 (`ZeroInitiatorSpi`) |
| 8–15 | `responder_spi` | |
| 16 | `next_payload` | in an IKEv1 message under the E flag, the first payload under the encryption |
| 17 | `version` | `major_version()`, 1 or 2 (`UnsupportedVersion` otherwise), and `minor_version()`, not checked |
| 18 | `exchange_type` | `exchange()` returns an `Option<ExchangeType>` |
| 19 | `flags` | read by the accessors below |
| 20–23 | `message_id` | |
| 24–27 | `length` | must equal the size of the message decoded (`LengthMismatch`) |

The flags byte is the same in both versions, its bits are not. Each accessor returns `false` for the other version: IKEv2 encrypts with a payload, not a flag.

| Accessor | Version | Bit | Meaning |
| --- | --- | --- | --- |
| `encryption_flag()` | IKEv1 | E `0x01` | the payloads are encrypted |
| `commit_flag()` | IKEv1 | C `0x02` | the sender waits for a confirmation before using the SA |
| `authentication_only_flag()` | IKEv1 | A `0x04` | authentication only, no encryption |
| `initiator_flag()` | IKEv2 | I `0x08` | sent by the initiator of the IKE SA |
| `version_flag()` | IKEv2 | V `0x10` | the sender can speak a higher major version |
| `response_flag()` | IKEv2 | R `0x20` | a response |

`ExchangeType` names the code according to the major version (RFC 2408, RFC 7296 and the IANA IKEv2 registry). Any other code is `None`, and the message is decoded all the same.

| `ExchangeType` | IKEv1 | IKEv2 |
| --- | --- | --- |
| `Base` | 1 | — |
| `IdentityProtection` (main mode) | 2 | — |
| `AuthenticationOnly` | 3 | — |
| `Aggressive` | 4 | — |
| `Informational` | 5 | 37 |
| `QuickMode` | 32 | — |
| `NewGroupMode` | 33 | — |
| `IkeSaInit` | — | 34 |
| `IkeAuth` | — | 35 |
| `CreateChildSa` | — | 36 |
| `IkeSessionResume` | — | 38 |
| `GsaAuth`, `GsaRegistration`, `GsaRekey` | — | 39, 40, 41 |
| `IkeIntermediate` | — | 43 |
| `IkeFollowupKe` | — | 44 |

The first message of the site-to-site VPN of the corpus, an IKE_SA_INIT on UDP 500 (*tested*):

```rust
{{#include ../examples/src/ipsec.rs:ike_sa_init}}
```

## The payload chain

After the header come the payloads, each with a 4-byte generic header (RFC 7296 §3.2, RFC 2408 §3.2):

```rust
#[non_exhaustive]
pub struct IkePayload<'a> {
    pub payload_type: u8,           // raw code, as the previous payload (or the header) names it
    pub kind: Option<PayloadType>,  // the code named, by the version of the message
    pub next_payload: u8,           // 0 for the last one
    pub critical: bool,             // IKEv2 only: always false in IKEv1, where the byte is reserved
    pub length: u16,                // declared, generic header included
    pub body: &'a [u8],             // the bytes after the generic header, borrowed
}
```

| Bytes | Field |
| --- | --- |
| 0 | `next_payload` |
| 1 | critical bit `0x80`, then reserved |
| 2–3 | `length` |
| 4 to `length` | `body` |

A payload does not carry its own type: the header's `next_payload` names the first one, and each payload names the next. `IkePacket::payloads` keeps them in message order, and `payload_types()` iterates their raw codes. The walk checks each length, and the chain must end with the message:

- a length below the 4 bytes of the generic header is `InvalidPayloadLength { payload_type, length }`, a length beyond what remains is `PayloadOverflow { payload_type, needed, available }`;
- the chain ends on a `next_payload` of 0, and bytes left after it are `UnexpectedTrailingBytes { trailing }`;
- the chain also ends with the message when the last payload announces another one, as tshark reads it: frame 192 of `ipsec_isakmp_esp.pcap` is an IKE_AUTH whose only payload, of the private type 127 and 784 bytes, announces a 35. One to three bytes left for an announced payload cannot hold its header, though: `PayloadOverflow` with `needed: 4`.

Only the top level is walked: Proposal and Transform live inside a Security Association, and no body is decoded. `payloads` is the decoder's one allocation; the bodies borrow the packet. `PayloadType` names the codes according to the version (RFC 2408, RFC 3947 and the IANA IKEv2 registry); an unknown code, such as the private 127, is `None` and its payload is kept like the others.

| `PayloadType` | IKEv1 | IKEv2 |
| --- | --- | --- |
| `SecurityAssociation` | 1 | 33 |
| `Proposal`, `Transform` | 2, 3 | — |
| `KeyExchange` | 4 | 34 |
| `Identification` | 5 | — |
| `IdentificationInitiator`, `IdentificationResponder` | — | 35, 36 |
| `Certificate`, `CertificateRequest` | 6, 7 | 37, 38 |
| `Hash`, `Signature` | 8, 9 | — |
| `Authentication` | — | 39 |
| `Nonce` | 10 | 40 |
| `Notification` | 11 | 41 |
| `Delete` | 12 | 42 |
| `VendorId` | 13 | 43 |
| `Attributes` | 14 | — |
| `NatDetection` | 20 (RFC 3947); 15 and 130 (drafts) | — |
| `NatOriginalAddress` | 21 (RFC 3947); 16 and 131 (drafts) | — |
| `TrafficSelectorInitiator`, `TrafficSelectorResponder` | — | 44, 45 |
| `Encrypted` (SK) | — | 46 |
| `Configuration` | — | 47 |
| `ExtensibleAuthentication` | — | 48 |
| `GenericSecurePasswordMethod` | — | 49 |
| `GroupIdentification`, `GroupSecurityAssociation`, `KeyDownload` | — | 50, 51, 52 |
| `EncryptedFragment` (SKF, RFC 7383) | — | 53 |
| `PuzzleSolution` | — | 54 |

## What is encrypted

```rust
#[non_exhaustive]
pub struct IkePacket<'a> {
    pub header: IkeHeader,
    pub payloads: Vec<IkePayload<'a>>,    // top level, in message order
    pub encrypted_body: Option<&'a [u8]>, // the encrypted bytes, as they are
}
```

The two versions encrypt differently, and `encrypted_body` covers both:

- **IKEv1** sets the E flag, and everything after the header is encrypted. `payloads` is empty, `encrypted_body` is the rest of the message, and `header.next_payload` names the first payload under the encryption. In the main mode capture of the corpus, the eight messages after the key exchange, frames 5 to 12, are sent that way.
- **IKEv2** encrypts in a payload, SK (46), or SKF (53) for a fragment, which must be the last of the message (RFC 7296 §3.14). The walk stops on it, so a byte after it is `UnexpectedTrailingBytes`. It is the last entry of `payloads` and its body is `encrypted_body`; its `next_payload` names the first payload under the encryption, not a top-level one. In the corpus, 241 IKEv2 messages end with an SK: every IKE_AUTH and every INFORMATIONAL, except frame 192 and its private payload.

The IKE_AUTH response of the VPN, then the first and fifth messages of an IKEv1 main mode (*tested*):

```rust
{{#include ../examples/src/ipsec.rs:ike_encrypted}}
```

## Validations

All of them are `IkeParseError`, checked in this order:

| Error | When |
| --- | --- |
| `Truncated { expected, actual }` | fewer than the 28 bytes of the header |
| `UnsupportedVersion(u8)` | a major version other than 1 or 2 |
| `ZeroInitiatorSpi` | IKEv2 with an initiator SPI of zero |
| `LengthMismatch { declared, actual }` | the header's length is not the size of the message |
| `InvalidPayloadLength { payload_type, length }` | a payload declares less than its 4-byte generic header |
| `PayloadOverflow { payload_type, needed, available }` | a payload runs past the message, or one to three bytes are left for an announced payload |
| `UnexpectedTrailingBytes { trailing }` | bytes after the last payload, or after an IKEv2 SK or SKF |
| `InvalidUdpEncapsulation { length }` | `UdpEncapsulation::classify` only: neither a keepalive, nor the marker with bytes after it, nor 8 bytes for an ESP header |

A failure is not a corruption. The port is a hint: when the probe fails, the datagram goes on to the rules that follow, and nothing is reported in `corrupted`.

## Oracle: 535 messages, field by field

The golden test `tests/ipsec_golden.rs` runs the three captures of `pcaps_exemple/protocols/ipsec/`, 858 frames, and compares every one with tshark 4.6.6, frozen in `tests/data/ipsec_tshark_oracle.tsv` by `tools/ipsec_oracle.sh`. For each IKE message: both SPIs, the version, the exchange type, the flags, the message ID, the length, and the top-level chain with the length of each payload; tshark's Proposal and Transform, nested in a Security Association, are left out. For each ESP packet: the SPI and the sequence number ([ESP](./esp.md#oracle)). No Decode As is needed, every IKE frame has 500 or 4500 on one side. The 535 IKE messages are 12 IKEv1 (6 main mode, 3 quick mode, 3 informational) and 523 IKEv2 (281 IKE_SA_INIT, 224 IKE_AUTH, 18 INFORMATIONAL); 249 carry an encrypted body, 8 IKEv1 and 241 IKEv2. A second test moves frame 42 and frame 11 of the nDPI capture, IKE behind the marker and ESP, to port 4501, where they become `"Unknown"`, and declares them back with Decode As.

| Capture | Frames | Content | Origin |
| --- | --- | --- | --- |
| `attachment_ikev1_main_mode.pcap` | 12 | IKEv1 on UDP 500: main mode, quick mode, informational | Wireshark wiki |
| `ikev2_s2s_ipsec_vpn_aes_gcm.pcapng` | 12 | a site-to-site VPN: IKEv2 on UDP 500 (4), then native ESP (8) | Wireshark wiki |
| `ipsec_isakmp_esp.pcap` | 834 | a client behind a NAT: IKEv2 on UDP 500 (279), IKEv2 (240) and ESP (315) on UDP 4500 | nDPI test corpus |

In the golden histogram, `"IKE"` went from 0 to 535 and `"ESP"` from 0 to 315, and `"Unknown"` lost those 850 frames (8 754 to 7 904). `The-Ultimate-PCAP.pcapng`, at the root of `pcaps_exemple/`, is not read by this test; a run of 11.6.0 over it labels 719 frames `"IKE"`, as many as the ISAKMP frames tshark counts there. The fuzz target `parse_ipsec` runs nightly on `IkePacket`, `UdpEncapsulation::classify` and `EspPacket`.

## What is left out

- **Payload contents**: proposals and transforms, key exchange data, nonces, identities, certificates, notifications and vendor IDs are bytes in `body`. A vendor ID is recognizable by its bytes, the `CISCO-DELETE-REASON` of the example, not named.
- **Decryption**: none, in either version; `encrypted_body` is the ciphertext as it is.
- **No state**: no pairing of a request with its response, no SA table, no link between an IKE SA and the ESP SPIs it negotiates. One message at a time, like the rest of the crate.
- **IKEv2 fragments** (SKF) are decoded one message at a time, never reassembled; an IKE message split by IP fragmentation has no transport layer, as everywhere in the crate.
- **IKE over TCP** is not recognized: the rule is `Guard::Udp`.
