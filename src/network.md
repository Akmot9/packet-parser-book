# Internet

The internet layer is the first *optional* layer: it is parsed from `LinkLayer::network_payload()`, and the link layer says which protocol to expect through `NetworkProtocol`: `Ipv4` (EtherType `0x0800`), `Ipv6` (`0x86DD`), `Arp` (`0x0806`), `Profinet` (`0x8892`), `Ptp` (`0x88F7`, since 11.5.0), `Goose` (`0x88B8`) and `Lldp` (`0x88CC`), both since 11.6.0, or `Other(u16)` for any other value. The enum is `#[non_exhaustive]`, and its three late variants are declared after `Other(u16)`, at its end. A RAW-IP capture announces `Ipv4` or `Ipv6` directly, without inventing an EtherType.

PTP on `0x88F7`, GOOSE and LLDP travel straight over Ethernet, without IP: for them, the frame itself *is* the internet layer, decoded, without addresses, and nothing is parsed above it.

ICMP and ICMPv6 are not part of this layer: like TCP and UDP, they are selected by `payload_protocol` and decoded by the [transport layer](./transport.md).

## The `Internet` struct

Abridged (doc comments shortened):

```rust
#[derive(Debug, Clone, Serialize)]
#[non_exhaustive]
pub struct Internet<'a> {
    #[serde(rename = "source_ip")]
    pub source: Option<IpAddr>,
    #[serde(rename = "ip_source_type")]
    pub source_type: Option<IpType>,
    #[serde(rename = "destination_ip")]
    pub destination: Option<IpAddr>,
    #[serde(rename = "ip_destination_type")]
    pub destination_type: Option<IpType>,
    /// "IPv4", "IPv6", "ARP", "Profinet", "PTP", "GOOSE" or "LLDP"
    #[serde(rename = "protocol_internet")]
    pub protocol_name: &'static str,
    /// Transport protocol parsable from `payload`. `None` when nothing above
    /// can be parsed: IP fragments, IPv6 No Next Header, ARP, Profinet, PTP,
    /// GOOSE, LLDP.
    #[serde(skip_serializing)]
    pub payload_protocol: Option<TransportProtocol>,
    #[serde(skip_serializing)]
    pub payload: &'a [u8],
    /// Full parsed header: Ipv4Packet, Ipv6Packet, ArpPacket, PtpPacket,
    /// GoosePacket or LldpPacket; None for Profinet.
    #[serde(skip_serializing)]
    pub details: Option<InternetDetails<'a>>,
}
```

The serde renames give the borrowed model and the owned one (`InternetOwned`) a single JSON schema ([#22](https://github.com/Akmot9/Packet-parser/issues/22), 11.0.0): in the flattened flow object, `source_ip` next to `source_port` and `source_mac` is less ambiguous than `source`. `payload_protocol`, `payload` and `details` are not serialized, and `PartialEq`/`Hash` compare the first six fields only. `InternetDetails` (`Ipv4`, `Ipv6`, `Arp`, `Ptp`, and since 11.6.0 `Goose` and `Lldp`) is `#[non_exhaustive]` like `Internet` itself: a `match` on it needs a `_` arm. It has no PROFINET variant: a PROFINET frame is validated, and its `details` is `None`.

Two helpers answer the usual questions about the destination (issue [#9](https://github.com/Akmot9/Packet-parser/issues/9)): `destination_is_multicast()` reads `destination_type`, and `destination_is_limited_broadcast()` reads the address itself and tests it for `255.255.255.255`.

### Address classification: `IpType`

Addresses use the standard `std::net::IpAddr`, and each one is classified by `IpType::from_addr`. An IPv4-mapped IPv6 address, `::ffff:a.b.c.d`, takes the class of the IPv4 it carries (RFC 4291 §2.5.5.2): a dual-stack socket logs its IPv4 clients in that form, and `::ffff:192.168.1.1` is `Private`. For every other address, the first matching row wins:

| `IpType` | IPv4 | IPv6 |
| --- | --- | --- |
| `Broadcast` | `255.255.255.255` only (limited broadcast) | — |
| `Private` | RFC 1918: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` | — |
| `Loopback` | `127.0.0.0/8` | `::1` |
| `Apipa` | `169.254.0.0/16` | — |
| `Multicast` | `224.0.0.0/4` | `ff00::/8` |
| `Documentation` | `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` | `2001:db8::/32`, `3fff::/20` |
| `LinkLocal` | never: `169.254.0.0/16` is already `Apipa` | `fe80::/10` |
| `Ula` | — | `fc00::/7` |
| `Unknown` | `0.0.0.0` | `::` |
| `Public` | anything else | anything else |

`Public` is the fallback, not a proof of global reachability: the shared address space `100.64.0.0/10` (carrier-grade NAT), the benchmarking range `198.18.0.0/15`, and the reserved `240.0.0.0/4` all come out `Public`.

`IpType` is a property of the address alone. It says which range an address belongs to, never where the host sits relative to the capture point: a `Private` peer can be across a VPN or a routed WAN, a `Public` one can be on the same LAN, and the directed broadcast `192.168.1.255` comes out `Private`, because recognizing it needs the subnet mask, which a packet parser does not have. What the enum saves a consumer is re-implementing the RFC 1918 and special-range tables; a filter such as "traffic leaving the site" still needs the site's own prefixes.

`Broadcast` was added in 11.0.0 ([#9](https://github.com/Akmot9/Packet-parser/issues/9)) and is declared last, after `Unknown`: inserted in second position, it would have shifted the discriminant of every following variant (`IpType::Multicast as u8` from 1 to 2), a silent break for anyone storing those values. A test locks the historical discriminants, and the enum is `#[non_exhaustive]`. The JSON form of an `IpType` is the variant name (`"Private"`, `"Public"`); its `Display` prints French labels (`Privée`, `Publique`, `Inconnue`).

Three IPv6 classifications changed in 11.5.0 ([#136](https://github.com/Akmot9/Packet-parser/issues/136)), all visible in the JSON as `ip_source_type` and `ip_destination_type`: link-local is the whole `fe80::/10` (RFC 4291 §2.5.6), where `fe81::` to `febf::` came out `Public`; an IPv4-mapped address takes the class of the IPv4 it carries, where `::ffff:192.168.1.1` came out `Public`; and the documentation prefixes `2001:db8::/32` (RFC 3849) and `3fff::/20` (RFC 9637) are `Documentation` like their IPv4 counterparts, no longer `Public`. The discriminants did not move.

## Dispatch on the announced protocol, not probing

The link layer already told us what the payload is. The internet parser trusts that announcement:

```rust
pub fn try_from_network_parts(
    protocol: NetworkProtocol,
    payload: &'a [u8],
) -> Result<Self, InternetError> {
    match protocol {
        NetworkProtocol::Arp => Ok(Self::from_arp(ArpPacket::try_from(payload)?)),
        NetworkProtocol::Ipv4 => Ok(Self::from_ipv4(ipv4::Ipv4Packet::try_from(payload)?)),
        NetworkProtocol::Ipv6 => Ok(Self::from_ipv6(ipv6::Ipv6Packet::try_from(payload)?)),
        NetworkProtocol::Profinet => {
            // Every RT frame is valid by its Frame ID; only a DCP Frame ID
            // must carry a readable DCP message (#133).
            profinet::validate_frame(payload)?;
            Ok(Self::profinet())
        }
        NetworkProtocol::Ptp => match PtpPacket::try_from(payload) {
            Ok(ptp_packet) => Ok(Self::from_ptp(ptp_packet)),
            // A version or a message type the crate does not know is not a
            // corruption: the frame is not supported, as before 11.5.0.
            Err(
                PtpPacketParseError::UnsupportedVersion(_)
                | PtpPacketParseError::ReservedMessageType(_),
            ) => Err(InternetError::UnsupportedProtocol),
            Err(error) => Err(error.into()),
        },
        NetworkProtocol::Goose => Ok(Self::from_goose(GoosePacket::try_from(payload)?)),
        NetworkProtocol::Lldp => Ok(Self::from_lldp(LldpPacket::try_from(payload)?)),
        NetworkProtocol::Other(_) => Err(InternetError::UnsupportedProtocol),
    }
}
```

`Internet::try_from_parts(Ethertype, &[u8])` is the same call for a caller that holds an Ethernet `Ethertype`.

Why dispatch rather than "try ARP, then IPv4, then IPv6"? Because probing cannot tell a **corrupt packet** from an **unknown protocol**: both just fail every parser. With the EtherType in hand, the two cases are distinct, and the pipeline maps them to the two distinct outcomes (before 5.0.0, a corrupt packet under a known EtherType was silently swallowed):

```rust
match Internet::try_from_network_parts(network_protocol, network_payload) {
    Ok(internet) => (Some(internet), None),
    Err(InternetError::UnsupportedProtocol) => (None, None),   // e.g. MRP, 0x88E3: not our job
    Err(e) => (None, Some(CorruptedLayer {                     // said IPv4, was garbage
        layer: CorruptedLayerKind::Internet,
        error: e.to_string(),
    })),
}
```

`InternetError` wraps one error type per protocol through `#[from]` (`ArpError`, `Ipv4Error`, `Ipv6Error`, `ProfinetPacketError`, since 11.5.0 `PtpPacketParseError`, and since 11.6.0 `GooseParseError` and `LldpParseError`, as `GooseError` and `LldpError` at the end of the enum), and its `Display` is the string stored in `CorruptedLayer::error`, for instance `IPv4 error: Invalid total length: expected 40 bytes (header: 20 + data: 20), but got 20 bytes`, or `GOOSE error: …` and `LLDP error: …` for the two new ones. Some declared variants are never returned by the parsers: `Ipv4Error::InvalidChecksum`, `TtlExpired`, `UnsupportedProtocol`, `InvalidOption`, `FragmentedPacket` and `PacketTooLarge`; `Ipv6Error::HopLimitExpired`, `UnsupportedNextHeader`, `PacketTooLarge` and `InvalidAddress`; `InternetError::InvalidLength`, `InvalidFormat` and `InvalidChecksum`. A wrong checksum, a TTL of zero or a fragment does not fail the parse.

The PTP arm is the one place where the parser's error is read before being wrapped. A `versionPTP` other than 1 or 2, or a reserved `messageType`, is `UnsupportedProtocol`: a revision of IEEE 1588 or a vendor's use the crate does not know, which is how every `0x88F7` frame came out before 11.5.0, not a corruption. A truncated or inconsistent message is `InternetError::PtpError`, and `corrupted` reads `PTP error: …`. The GOOSE and LLDP arms have no such case: every error of their decoders is a corruption.

The PROFINET arm changed in 11.6.0 ([#133](https://github.com/Akmot9/Packet-parser/issues/133)): it called the DCP decoder on every frame, and now calls `profinet::validate_frame`, which accepts any assigned Frame ID and decodes DCP only behind a DCP Frame ID; see the [Profinet page](./profinet.md).

`Internet::try_from(&[u8])` (the probing version) still exists for callers that only have raw L3 bytes, but `PacketFlow` never uses it. It returns `EmptyPacket` for an empty slice, then tries, in this order:

1. ARP, IPv4, IPv6, each with its `TryFrom`;
2. Profinet, but only a complete DCP message: two bytes of a plausible Frame ID are no proof, so a cyclic frame is not recognized;
3. GOOSE (since 11.6.0): a `length` that covers the bytes exactly, and a complete goosePdu with its mandatory fields;
4. LLDP (since 11.6.0): beyond its decode, an LLDPDU that ends with an End of LLDPDU TLV, followed by zero padding only.

When all of them fail, it returns `UnsupportedProtocol`, and the reason each parser gave is lost, which is exactly the ambiguity described above. PTP is not probed. A probe that succeeds is a guess, not a verdict. Measured on the captures of `pcaps_exemple/` at 11.6.0, the GOOSE and LLDP probes fire on GOOSE and LLDP frames only, but the PROFINET one takes 119 IS-IS frames of `The-Ultimate-PCAP.pcapng` for DCP: the LLC header of IS-IS, `FE FE 03`, reads as the Frame ID of a DCP Identify request (*tested*):

```rust
{{#include ../examples/src/internet_layer.rs:blind_probe_is_a_guess}}
```

## The protocols

Each protocol of this layer has its page: [IPv4](./ipv4.md), [IPv6](./ipv6.md), [ARP](./arp.md), [Profinet](./profinet.md), and, since 11.6.0, [GOOSE](./goose.md) and [LLDP](./lldp.md).

| `NetworkProtocol` | EtherType | `protocol_name` | Addresses | `details` |
| --- | --- | --- | --- | --- |
| `Ipv4` | `0x0800` | `"IPv4"` | IPv4 | `Ipv4(Ipv4Packet)` |
| `Ipv6` | `0x86DD` | `"IPv6"` | IPv6 | `Ipv6(Ipv6Packet)` |
| `Arp` | `0x0806` | `"ARP"` | sender and target protocol addresses | `Arp(ArpPacket)` |
| `Profinet` | `0x8892` | `"Profinet"` | none | `None` |
| `Ptp` | `0x88F7` | `"PTP"` | none | `Ptp(PtpPacket)` |
| `Goose` | `0x88B8` | `"GOOSE"` | none | `Goose(GoosePacket)` |
| `Lldp` | `0x88CC` | `"LLDP"` | none | `Lldp(LldpPacket)` |

PTP over raw Ethernet (EtherType `0x88F7`, since 11.5.0) lands here too: `protocol_name` is `"PTP"`, there are no addresses, `payload_protocol` is `None`, and the decoded message is in `InternetDetails::Ptp`. Its page, [PTP](./ptp.md), is under Application, where its module lives and where its UDP form is labelled. GOOSE and LLDP follow the same model, and their modules live with the internet protocols, `parse::internet::protocols::goose` and `::lldp`.

## IP-level tunnels

GRE (protocol 47) and IP-in-IP (protocols 4 and 41) are detected ([#15](https://github.com/Akmot9/Packet-parser/issues/15)) from `Internet::payload_protocol` and `Internet::payload`, not from the transport layer, because they have none: the `Transport` the pipeline builds for them is the catch-all one (protocol only, no ports, no payload). This IP-level check is the first step of the L7 stage, before the UDP-based tunnels and the application probes. Since it reads `payload_protocol`, a tunnel carried in IP fragments is not peeled. See the [tunnels chapter](./tunnels.md).
