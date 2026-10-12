# Internet

The internet layer is the first *optional* layer: it is parsed from `LinkLayer::network_payload()`, and the link layer says which protocol to expect through `NetworkProtocol`: `Ipv4` (EtherType `0x0800`), `Ipv6` (`0x86DD`), `Arp` (`0x0806`), `Profinet` (`0x8892`), `Ptp` (`0x88F7`, since 11.5.0), or `Other(u16)` for any other value. A RAW-IP capture announces `Ipv4` or `Ipv6` directly, without inventing an EtherType.

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
    /// "IPv4", "IPv6", "ARP", "Profinet" or "PTP"
    #[serde(rename = "protocol_internet")]
    pub protocol_name: &'static str,
    /// Transport protocol parsable from `payload`. `None` when nothing above
    /// can be parsed: IP fragments, IPv6 No Next Header, ARP, Profinet, PTP.
    #[serde(skip_serializing)]
    pub payload_protocol: Option<TransportProtocol>,
    #[serde(skip_serializing)]
    pub payload: &'a [u8],
    /// Full parsed header: Ipv4Packet, Ipv6Packet, ArpPacket or PtpPacket.
    #[serde(skip_serializing)]
    pub details: Option<InternetDetails<'a>>,
}
```

The serde renames give the borrowed model and the owned one (`InternetOwned`) a single JSON schema ([#22](https://github.com/Akmot9/Packet-parser/issues/22), 11.0.0): in the flattened flow object, `source_ip` next to `source_port` and `source_mac` is less ambiguous than `source`. `payload_protocol`, `payload` and `details` are not serialized, and `PartialEq`/`Hash` compare the first six fields only. `InternetDetails` (`Ipv4`, `Ipv6`, `Arp`, `Ptp`) is `#[non_exhaustive]` like `Internet` itself: a `match` on it needs a `_` arm.

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
            profinet::ProfinetPacket::try_from(payload)?;
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
        NetworkProtocol::Other(_) => Err(InternetError::UnsupportedProtocol),
    }
}
```

`Internet::try_from_parts(Ethertype, &[u8])` is the same call for a caller that holds an Ethernet `Ethertype`.

Why dispatch rather than "try ARP, then IPv4, then IPv6"? Because probing cannot tell a **corrupt packet** from an **unknown protocol**: both just fail every parser. With the EtherType in hand, the two cases are distinct, and the pipeline maps them to the two distinct outcomes (before 5.0.0, a corrupt packet under a known EtherType was silently swallowed):

```rust
match Internet::try_from_network_parts(network_protocol, network_payload) {
    Ok(internet) => (Some(internet), None),
    Err(InternetError::UnsupportedProtocol) => (None, None),   // e.g. LLDP: not our job
    Err(e) => (None, Some(CorruptedLayer {                     // said IPv4, was garbage
        layer: CorruptedLayerKind::Internet,
        error: e.to_string(),
    })),
}
```

`InternetError` wraps one error type per protocol through `#[from]` (`ArpError`, `Ipv4Error`, `Ipv6Error`, `ProfinetPacketError` and, since 11.5.0, `PtpPacketParseError`), and its `Display` is the string stored in `CorruptedLayer::error`, for instance `IPv4 error: Invalid total length: expected 40 bytes (header: 20 + data: 20), but got 20 bytes`. Some declared variants are never returned by the parsers: `Ipv4Error::InvalidChecksum`, `TtlExpired`, `UnsupportedProtocol`, `InvalidOption`, `FragmentedPacket` and `PacketTooLarge`; `Ipv6Error::HopLimitExpired`, `UnsupportedNextHeader`, `PacketTooLarge` and `InvalidAddress`; `InternetError::InvalidLength`, `InvalidFormat` and `InvalidChecksum`. A wrong checksum, a TTL of zero or a fragment does not fail the parse.

The PTP arm is the one place where the parser's error is read before being wrapped. A `versionPTP` other than 1 or 2, or a reserved `messageType`, is `UnsupportedProtocol`: a revision of IEEE 1588 or a vendor's use the crate does not know, which is how every `0x88F7` frame came out before 11.5.0, not a corruption. A truncated or inconsistent message is `InternetError::PtpError`, and `corrupted` reads `PTP error: …`.

`Internet::try_from(&[u8])` (the probing version) still exists for callers that only have raw L3 bytes, but `PacketFlow` never uses it. It tries ARP, IPv4, IPv6, then Profinet, returns `EmptyPacket` for an empty slice and `UnsupportedProtocol` when all four fail: the reason each parser gave is lost, which is exactly the ambiguity described above.

## The protocols

Each protocol of this layer has its page: [IPv4](./ipv4.md), [IPv6](./ipv6.md), [ARP](./arp.md) and [Profinet](./profinet.md).

PTP over raw Ethernet (EtherType `0x88F7`, since 11.5.0) lands here too: `protocol_name` is `"PTP"`, there are no addresses, `payload_protocol` is `None`, and the decoded message is in `InternetDetails::Ptp`. Its page, [PTP](./ptp.md), is under Application, where its module lives and where its UDP form is labelled.

## IP-level tunnels

GRE (protocol 47) and IP-in-IP (protocols 4 and 41) are detected ([#15](https://github.com/Akmot9/Packet-parser/issues/15)) from `Internet::payload_protocol` and `Internet::payload`, not from the transport layer, because they have none: the `Transport` the pipeline builds for them is the catch-all one (protocol only, no ports, no payload). This IP-level check is the first step of the L7 stage, before the UDP-based tunnels and the application probes. Since it reads `payload_protocol`, a tunnel carried in IP fragments is not peeled. See the [tunnels chapter](./tunnels.md).
