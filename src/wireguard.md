# WireGuard

WireGuard, the VPN tunnel over UDP, added in 11.6.0 as part of epic [#103](https://github.com/Akmot9/Packet-parser/issues/103), in PR [#169](https://github.com/Akmot9/Packet-parser/pull/169). Each datagram carries a single message: the initiation or the response of the Noise IK handshake, the cookie that a responder under load sends back, or the encrypted data of the tunnel. The decoder reads the type, the three reserved bytes, the session indexes, the counter of the data and the fixed-size fields (ephemeral keys, encrypted fields, `mac1` and `mac2`), all borrowed from the datagram. **Nothing is decrypted**: without the keys, the tunnelled packet stays opaque. Module: `packet_parser::parse::application::protocols::wireguard`; references: J. A. Donenfeld's whitepaper and `drivers/net/wireguard/messages.h` in Linux.

## Detection: three rules, no IANA port

WireGuard has no IANA port. 51820 is the port of the examples of `wg(8)` and `wg-quick(8)`; without `ListenPort`, the port is drawn at random, and the corpus shows others: Tailscale on 41641, ProtonVPN on 443, Mullvad on 5060. And a message says little about itself: one type byte from 1 to 4, three reserved bytes, then a fixed size, or for Transport Data a minimum of 32 bytes. The crate therefore has three rules, from the most tolerant to the strictest:

| Where | Probe | Accepts |
| --- | --- | --- |
| a port declared with `ParseConfig::decode_as(port, DecodeAsProtocol::WireGuard)` | `ProbeId::WireGuard` | the shape of any of the four messages, whatever the reserved bytes |
| UDP 51820 | `ProbeId::WireGuardPort` | the shape; for a Cookie Reply or Transport Data, zero reserved bytes as well |
| any other UDP port | `ProbeId::WireGuardBlind` | the shape and zero reserved bytes; for Transport Data, a plausible counter and padding as well |

The shape is what `WireGuardPacket::try_from` checks: a known type, and the exact size of a handshake or a cookie, or at least 32 bytes of Transport Data. All three probes read the whole datagram, not its first `PROBE_CAP` bytes. In the table of `src/parse/dispatch.rs`:

```rust
// UDP 51820, the port of the examples of wg(8): no IANA port. As in tshark's
// heuristic, the shape is enough for an initiation or a response, reserved
// bytes included, and a cookie or data have zero reserved bytes. 51820 is an
// ephemeral port: after the other port rules (#103).
port_rule("WireGuard", Guard::Udp, is_wireguard_udp_port, ProbeId::WireGuardPort),
port_rule("NTP", Guard::Udp, is_ntp_udp_port, ProbeId::Ntp),
// --- blind cascade ---
// ...
rule("QUIC", Guard::Udp, ProbeId::QuicLongHeader),
// Off 51820: zero reserved bytes, a fixed size or, for data, a counter below
// 2^60 and a plaintext padded to sixteen bytes or stopped at the MTU. Last
// UDP probe: Transport Data has only `04 00 00 00` and these constraints.
rule("WireGuard", Guard::Udp, ProbeId::WireGuardBlind),
rule("MQTT", Guard::Tcp, ProbeId::Mqtt),
```

**Decode As** is evaluated before the table ([Decode As](./application.md#decode-as)), and for WireGuard it trusts the caller: the shape is enough, whatever the type and the reserved bytes. It is the one Decode As protocol whose probe is more tolerant than its port rule, on purpose: a declared port is WireGuard on the caller's word, the reserved bytes that Cloudflare uses to spread load included, where 51820 is only an ephemeral port.

**On UDP 51820** the rule follows tshark's heuristic. The shape is enough for an initiation or a response, reserved bytes included, but a Cookie Reply or Transport Data must have zero reserved bytes: otherwise a DCE/RPC datagram (`04 00 28 00`…) or a DNS response whose identifier starts with `0x04` would pass for Transport Data there. It is the last port rule before NTP's, because 51820 falls in the ephemeral port ranges: an ESP, IKE or DNS packet whose peer drew 51820 keeps its label. A unit test of `dispatch.rs` builds two of them: a 148-byte ESP packet whose SPI starts with `0x01`, which has the shape of an initiation, and a 92-byte DNS response whose identifier starts with `0x02`, which has the shape of a response.

**Elsewhere, the blind probe**, the last UDP probe of the cascade, after QUIC, has to make up for a type that is one byte and a Transport Data that has nothing but `04 00 00 00` and its minimum size for it:

- the **reserved bytes are zero**, for every message: Linux reads the header as one four-byte integer;
- the **counter** of Transport Data is below 2^60, `REKEY_AFTER_MESSAGES` (whitepaper §6.2), beyond which a session must be renewed: no real counter gets there;
- the **length** of Transport Data is one that padding explains. The plaintext, the message minus its 16-byte header and its 16-byte tag, is padded with zeros to a multiple of 16 (whitepaper §5.4.6), except when that would exceed the MTU: Linux (`calculate_skb_padding`) and wireguard-go (`calculatePaddingSize`) then stop at the MTU. The probe accepts a plaintext that is a multiple of 16, or at least 552 bytes long, the floor of the IPv4 path MTU of Linux (`DEFAULT_MIN_PMTU`, 512 + 20 + 20). The five 1 452-byte messages of the corpus are of the second kind: 1 420 bytes of plaintext, the MTU of `wg-quick`, which is not a multiple of 16.

The probes and `REKEY_AFTER_MESSAGES` are internal to the crate; the public way to them is `parse`, `parse_with`, and `Application::try_from`, whose cascade, without ports, runs the same blind probe just before MQTT.

Why so strict: tshark's heuristic, which only requires the type, the size and, for a cookie and data, zero reserved bytes, takes 59 datagrams of Zoom, TeamViewer and League of Legends from nDPI's test corpus for WireGuard. They are Transport Data with zero reserved bytes, which only the counter and the padding rule out; the crate takes none of them. 25 are in the crate's corpus, named as tshark's misfires in the golden test.

The three rules on two real messages and their altered copies (*tested*); `02 78 00` is what Cloudflare's WARP client puts in the reserved bytes:

```rust
{{#include ../examples/src/remote_vpn.rs:wireguard_detection}}
```

The blind probe on real traffic: a ProtonVPN keepalive on UDP 443, and a Zoom datagram that tshark's heuristic accepts (*tested*):

```rust
{{#include ../examples/src/remote_vpn.rs:wireguard_blind_probe}}
```

## The message

```rust
pub struct WireGuardPacket<'a> {
    /// 1 to 4.
    pub message_type: u8,
    /// Zero in the protocol; Cloudflare uses them to spread load.
    pub reserved: [u8; 3],
    pub message: WireGuardMessage<'a>,
}

pub enum WireGuardMessage<'a> {
    HandshakeInitiation(HandshakeInitiation<'a>),
    HandshakeResponse(HandshakeResponse<'a>),
    CookieReply(CookieReply<'a>),
    TransportData(TransportData<'a>),
}

pub struct HandshakeInitiation<'a> {
    /// The index the initiator picks for the session.
    pub sender_index: u32,
    /// Curve25519 ephemeral public key.
    pub unencrypted_ephemeral: &'a [u8; 32],
    /// The initiator's static public key, encrypted.
    pub encrypted_static: &'a [u8; 48],
    /// TAI64N timestamp, encrypted (anti-replay).
    pub encrypted_timestamp: &'a [u8; 28],
    pub mac1: &'a [u8; 16],
    /// Zero unless after a Cookie Reply.
    pub mac2: &'a [u8; 16],
}

pub struct HandshakeResponse<'a> {
    /// The index the responder picks for the session.
    pub sender_index: u32,
    /// The index of the initiation it answers.
    pub receiver_index: u32,
    pub unencrypted_ephemeral: &'a [u8; 32],
    /// A Poly1305 tag over an empty plaintext.
    pub encrypted_nothing: &'a [u8; 16],
    pub mac1: &'a [u8; 16],
    pub mac2: &'a [u8; 16],
}

pub struct CookieReply<'a> {
    pub receiver_index: u32,
    /// XChaCha20-Poly1305 nonce.
    pub nonce: &'a [u8; 24],
    pub encrypted_cookie: &'a [u8; 32],
}

pub struct TransportData<'a> {
    /// The session index of the receiver.
    pub receiver_index: u32,
    /// Message counter, also the ChaCha20-Poly1305 nonce.
    pub counter: u64,
    /// The encrypted packet, its 16-byte tag included.
    pub encrypted_packet: &'a [u8],
}
```

All of them are `#[non_exhaustive]`, and a `match` on `WireGuardMessage` needs a `_` arm. `TransportData::is_keepalive()` is true when the encrypted packet is the tag alone, a 32-byte message.

Every message starts with the same four bytes, and every integer is little-endian:

| Bytes | Field |
| --- | --- |
| 0 | `message_type`, 1 to 4 |
| 1–3 | `reserved` |

What follows depends on the type, with a fixed size for three of them:

| Type | `WireGuardMessage` | Size | Fields (offset in the message, size) |
| --- | --- | --- | --- |
| 1 | `HandshakeInitiation` | 148 | 4 `sender_index`, 8 `unencrypted_ephemeral` (32), 40 `encrypted_static` (48), 88 `encrypted_timestamp` (28), 116 `mac1` (16), 132 `mac2` (16) |
| 2 | `HandshakeResponse` | 92 | 4 `sender_index`, 8 `receiver_index`, 12 `unencrypted_ephemeral` (32), 44 `encrypted_nothing` (16), 60 `mac1` (16), 76 `mac2` (16) |
| 3 | `CookieReply` | 64 | 4 `receiver_index`, 8 `nonce` (24), 32 `encrypted_cookie` (32) |
| 4 | `TransportData` | 32 or more | 4 `receiver_index`, 8 `counter` (8), 16 `encrypted_packet`, to the end of the datagram |

The first handshake of `wireshark_wireguard-ping-tcp.pcap`, between two Linux network namespaces (*tested*):

```rust
{{#include ../examples/src/remote_vpn.rs:wireguard_handshake}}
```

and the first data of the same session, then a keepalive (*tested*):

```rust
{{#include ../examples/src/remote_vpn.rs:wireguard_transport_data}}
```

## Validations

All of them are `WireGuardParseError`, in `packet_parser::errors::application::wireguard`:

| Error | When |
| --- | --- |
| `Truncated { expected, actual }` | fewer than 4 bytes, or Transport Data shorter than 32 |
| `UnknownMessageType(u8)` | a type other than 1 to 4, among them `0xC1` to `0xC4` of Cloudflare's WARP client |
| `InvalidLength { message_type, expected, actual }` | an initiation, a response or a cookie that is not exactly 148, 92 or 64 bytes |

These errors never reach `corrupted`: a datagram the probes refuse goes on down the table, and usually comes out `"Unknown"`. On real bytes (*tested*):

```rust
{{#include ../examples/src/remote_vpn.rs:wireguard_errors}}
```

## Oracle: 128 messages, field by field

`tests/wireguard_golden.rs` runs the nine captures of `pcaps_exemple/protocols/wireguard/` and compares every message with tshark 4.6.6, which registers WireGuard on no port: `tools/wireguard_oracle.sh` enables the `wg` heuristic, follows the conversations it pins after a Handshake Initiation, uses an empty Wireshark profile and no key, and freezes in `tests/data/wireguard_tshark_oracle.tsv` the ports, length, type, reserved bytes, indexes, counter, ephemeral key, `mac1`, `mac2`, nonce, cookie and keepalive flag of each message. Of the 153 messages tshark sees, the crate labels and decodes the same 128, field for field: 6 initiations, 6 responses and 116 Transport Data, 5 of them keepalives and 5 of them the 1 452-byte messages stopped at the MTU; no capture carries a Cookie Reply. The other 25 are named, not hidden: the Zoom and League of Legends datagrams that tshark accepts and the blind probe refuses.

| Capture | Messages | Implementation | Server port | Origin |
| --- | --- | --- | --- | --- |
| `wireshark_wireguard-ping-tcp.pcap` | 22 | Linux, two network namespaces: two handshakes, 18 Transport Data | 51820 | Wireshark repository |
| `wireshark_wireguard-psk.pcap` | 4 | the same bench with a pre-shared key: two handshakes | 51820 | Wireshark repository |
| `ndpi_nordvpn.pcap` | 22 | NordVPN (NordLynx) on Windows | 51820 | nDPI test corpus |
| `ndpi_tunnelbear.pcap` | 10 | TunnelBear, Transport Data | 51820 | nDPI test corpus |
| `corelight_tailscale_linux.pcap` | 46 | Tailscale (wireguard-go) on Linux, Transport Data | 41641 | Corelight |
| `ndpi_protonvpn.pcap` | 14 | ProtonVPN: a handshake and Transport Data | 443 | nDPI test corpus |
| `ndpi_mullvad_wireguard.pcap` | 10 | Mullvad, Transport Data | 5060 | nDPI test corpus |
| `ndpi_zoom2.pcap` | 0 | Zoom: 22 datagrams tshark takes for WireGuard | — | nDPI test corpus |
| `ndpi_lol_wild_rift_udp.pcap` | 0 | League of Legends: Wild Rift: 3 such datagrams | — | nDPI test corpus |

The golden test checks the other side too: none of the neighbours of these messages comes out WireGuard, not the 61 "disco" messages of Tailscale on the same port 41641, nor the two extended handshakes of TunnelBear (204 and 100 bytes), nor the 43 obfuscated OpenVPN datagrams of NordVPN on UDP 1198, nor frame 41 of ProtonVPN, retouched by hand in nDPI's corpus. It then replays the 128 messages off their port, from UDP 40000 to 40001, where the blind probe recognizes all of them; with `02 78 00` in their reserved bytes, the blind probe refuses all of them, 51820 keeps only the 12 handshakes, and a port declared by Decode As keeps all 128. No real capture carries WireGuard over IPv6: the keepalive of frame 9 of `wireshark_wireguard-ping-tcp.pcap`, put in a raw IPv6 frame, follows the same rules. In the golden histogram of the whole corpus, `"WireGuard"` counts these 128 frames. The fuzz target `parse_wireguard` runs nightly: no panic, and on success the size is the one of the type, every borrowed field points into the input, a keepalive is exactly 32 bytes, and what the blind cascade labels WireGuard has zero reserved bytes.

## What is left out

- **Decryption**: there are no keys, so the encrypted fields and `encrypted_packet` stay opaque, `mac1` and `mac2` are not checked, and there is no inner flow: the tunnelled packets are not peeled like the encapsulations of the [tunnels chapter](./tunnels.md).
- **Cookie Reply** has no real capture: it is decoded at the offsets of the whitepaper, and a synthetic unit test covers it.
- **boringtun** (Cloudflare) and its derivatives (NordSecurity neptun, Firezone) do not pad their data ("spec requires padding to 16 bytes, but actually works fine without it", `noise/session.rs`): off 51820 and the declared ports, only their handshakes, their keepalives and their packets whose size happens to fit are recognized.
- **A tunnel MTU below 552** and not a multiple of 16: the packets whose padding stops at that MTU are recognized only on 51820 or by Decode As.
- **Cloudflare's official WARP client** also changes the type byte, `0xC1` to `0xC4`: it is not decoded, even by Decode As, which still requires a known type.
- **No session state**: indexes and counters are values. Nothing ties a response to its initiation or checks that a counter grows; one datagram at a time, like the rest of the crate.
