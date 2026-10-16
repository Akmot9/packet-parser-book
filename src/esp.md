# ESP

Encapsulating Security Payload, RFC 4303: the IPsec packet that encrypts and authenticates. Decoded since 11.6.0 ([#124](https://github.com/Akmot9/Packet-parser/issues/124)), with [IKE](./ike.md) and as part of the defense lot ([#125](https://github.com/Akmot9/Packet-parser/issues/125)). Only two fields are in clear, the SPI and the sequence number; everything after them (initialization vector, data, padding, next header, ICV) depends on the algorithm IKE negotiated, and stays bytes. The module is `packet_parser::parse::transport::protocols::esp`, the error type `EspError` is in `packet_parser::errors::transport::esp`.

ESP travels two ways, and the crate follows both:

- **natively**, IP protocol 50 (IPv6 next header 50): the [transport layer](./transport.md) decodes it into `TransportDetails::Esp`, like ICMP, without ports or payload;
- **in UDP 4500** behind a NAT (RFC 3948): the datagram gets the application label `"ESP"`, and `EspPacket::try_from` decodes the UDP payload.

Before 11.6.0, protocol 50 already had its name, `TransportProtocol::Esp`, like every number IANA assigns, and nothing else.

## The packet

```rust
#[non_exhaustive]
pub struct EspPacket<'a> {
    pub spi: u32,          // identifies the security association, with the destination address
    pub sequence: u32,     // anti-replay counter, increasing per association
    pub payload: &'a [u8], // the rest: encrypted data, padding, next header, ICV
}
```

| Bytes | Field | Note |
| --- | --- | --- |
| 0–3 | `spi` | big-endian; 0 is reserved and never sent (RFC 4303 §2.1) |
| 4–7 | `sequence` | big-endian |
| 8 to the end | `payload` | borrowed; its parts cannot be told apart without the key |

Two checks, both `EspError`: fewer than the 8 bytes of SPI and sequence number is `PacketTooShort { expected, actual }`, an SPI of zero is `ReservedSpi`. Eight bytes are enough, `payload` is then empty.

## Native ESP: IP protocol 50

The transport dispatch has an arm for ESP, next to the ICMP ones:

```rust
Some(TransportProtocol::Esp) => Ok(Transport {
    protocol: TransportProtocol::Esp,
    source_port: None,
    destination_port: None,
    payload: None,
    details: EspPacket::try_from(payload).ok().map(TransportDetails::Esp),
}),
```

The consequences are those of [ICMP](./icmp.md):

- `payload` stays `None`: nothing readable stacks above ESP, and handing ciphertext to the application probes would only earn it false labels. `application` is `None`.
- An **unreadable packet does not corrupt the flow**: the IP header named the protocol, so `protocol` is `Esp`, `details` falls back to `None` and `corrupted` stays `None`. `EspPacket::try_from(internet.payload)` gives the reason.
- The **SPI is not part of the identity** of the transport layer, which is the protocol and the ports, both `None` here: `PartialEq`, `Hash` and serialization ignore `details`, and `to_owned_flow` drops it. Two ESP packets of different SAs between the same hosts compare equal at the transport layer.

Over IPv6, next header 50 ends the walk of the extension headers ([IPv6](./ipv6.md)), and the same arm decodes the packet. Frame 5 of the corpus's site-to-site VPN, then an IPv6 packet of `The-Ultimate-PCAP.pcapng` (*tested*):

```rust
{{#include ../examples/src/ipsec.rs:esp_native}}
```

The same frame with its SPI set to zero (*tested*):

```rust
{{#include ../examples/src/ipsec.rs:esp_unreadable}}
```

The corpus has 8 native ESP packets, frames 5 to 12 of `ikev2_s2s_ipsec_vpn_aes_gcm.pcapng`: two SAs, `0x5fbd60dc` and `0xa70bbb39`, sequence numbers 1 to 4 each. `The-Ultimate-PCAP.pcapng` has 1 593, 542 over IPv4 and 1 051 over IPv6, the counts tshark gives; a run of 11.6.0 decodes every one of them into `TransportDetails::Esp`.

## In UDP 4500, behind a NAT

A NAT rewrites ports, and ESP has none. Behind a NAT, ESP rides in UDP 4500 (RFC 3948), sharing the port with IKE and with the keepalives that hold the NAT mapping open. The [IKE page](./ike.md#udp-4500-three-things-on-one-port) explains how `UdpEncapsulation::classify` tells the three apart; two rules of the table, right after the IKE rule, give the other two labels:

```rust
port_rule("ESP",           Guard::Udp, is_nat_t_udp_port, ProbeId::EspNatT),      // 4500
port_rule("NAT-keepalive", Guard::Udp, is_nat_t_udp_port, ProbeId::NatKeepalive), // 4500
```

Both look at UDP 4500 only, on either side; UDP 500 carries neither.

- **`"ESP"`**: `classify` returns `UdpEncapsulation::Esp`, at least 8 bytes that do not start with the four zero bytes of the non-ESP marker, and `EspPacket::try_from` accepts them. The flow keeps its UDP transport, and the ESP packet is `transport.payload`, decoded by `EspPacket::try_from` when needed. It is a label, not a [tunnel](./tunnels.md): what ESP carries is encrypted, and `inner` stays `None`.
- **`"NAT-keepalive"`**: a single `0xFF` byte (RFC 3948 §2.3), `UdpEncapsulation::Keepalive`. There is nothing to decode. The corpus of `protocols/ipsec/` has none; `The-Ultimate-PCAP.pcapng` has three, frames 46989, 47000 and 47009.

Frame 11 of `ipsec_isakmp_esp.pcap`, then the first keepalive of the Ultimate PCAP (*tested*):

```rust
{{#include ../examples/src/ipsec.rs:esp_nat_t}}
```

ESP in UDP on another port is declared with `ParseConfig::decode_as(port, DecodeAsProtocol::Esp)`, a variant added in 11.6.0: the same probe and the same transport guard as the rule of port 4500. The keepalive has no `DecodeAsProtocol` (*tested*):

```rust
{{#include ../examples/src/ipsec.rs:esp_decode_as}}
```

## Oracle

The golden test of the IKE page, `tests/ipsec_golden.rs` ([oracle](./ike.md#oracle-535-messages-field-by-field)), covers ESP too: 323 packets, SPI and sequence number compared with tshark 4.6.6, the 8 native ones and the 315 datagrams of `ipsec_isakmp_esp.pcap`, in UDP 4500. For a native packet it also checks that the transport has no payload and the flow no application; for a datagram, that the label is `"ESP"` and that `classify` returns `Esp`. In the golden histogram `"ESP"` went from 0 to 315, and the native packets stay without application, like ICMP. The fuzz target `parse_ipsec` runs `EspPacket::try_from` nightly: when it accepts, the SPI is not zero and `payload` is everything after the first 8 bytes.

The Ultimate PCAP, which the golden test does not read, adds 7 datagrams labelled `"ESP"` and the 3 keepalives above.

## What is left out

- **Nothing is decrypted**, and the end of the packet is not split: padding, next header and ICV cannot be told apart without the key and the algorithm of the SA, which a stateless parser does not have.
- **No SA state**: `sequence` is read, not checked against an anti-replay window, and no ESP SPI is linked to the IKE exchange that negotiated it.
- **AH** (IP protocol 51) is not decoded: over IPv4 the flow gets `TransportProtocol::Ah` without details; over IPv6, AH is one of the extension headers the internet layer walks, and what follows it is the transport protocol.
- **ESP over TCP** is not recognized: both rules are `Guard::Udp`.
