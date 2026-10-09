# Internet

The internet layer is the first *optional* layer: it is parsed from `LinkLayer::network_payload()`, and the link layer says which protocol to expect through `NetworkProtocol`: `Ipv4` (EtherType `0x0800`), `Ipv6` (`0x86DD`), `Arp` (`0x0806`), `Profinet` (`0x8892`), or `Other(u16)` for any other value. A RAW-IP capture announces `Ipv4` or `Ipv6` directly, without inventing an EtherType.

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
    /// "IPv4", "IPv6", "ARP" or "Profinet"
    #[serde(rename = "protocol_internet")]
    pub protocol_name: &'static str,
    /// Transport protocol parsable from `payload`. `None` when nothing above
    /// can be parsed: IP fragments, IPv6 No Next Header, ARP, Profinet.
    #[serde(skip_serializing)]
    pub payload_protocol: Option<TransportProtocol>,
    #[serde(skip_serializing)]
    pub payload: &'a [u8],
    /// Full parsed header: Ipv4Packet, Ipv6Packet or ArpPacket.
    #[serde(skip_serializing)]
    pub details: Option<InternetDetails<'a>>,
}
```

The serde renames give the borrowed model and the owned one (`InternetOwned`) a single JSON schema ([#22](https://github.com/Akmot9/Packet-parser/issues/22), 11.0.0): in the flattened flow object, `source_ip` next to `source_port` and `source_mac` is less ambiguous than `source`. `payload_protocol`, `payload` and `details` are not serialized, and `PartialEq`/`Hash` compare the first six fields only. `InternetDetails` (`Ipv4`, `Ipv6`, `Arp`) is `#[non_exhaustive]` like `Internet` itself: a `match` on it needs a `_` arm.

Two helpers answer the usual questions about the destination (issue [#9](https://github.com/Akmot9/Packet-parser/issues/9)): `destination_is_multicast()` reads `destination_type`, and `destination_is_limited_broadcast()` reads the address itself and tests it for `255.255.255.255`.

### Address classification: `IpType`

Addresses use the standard `std::net::IpAddr`, and each one is classified by `IpType::from_addr`. The first matching row wins:

| `IpType` | IPv4 | IPv6 |
| --- | --- | --- |
| `Broadcast` | `255.255.255.255` only (limited broadcast) | — |
| `Private` | RFC 1918: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` | — |
| `Loopback` | `127.0.0.0/8` | `::1` |
| `Apipa` | `169.254.0.0/16` | — |
| `Multicast` | `224.0.0.0/4` | `ff00::/8` |
| `Documentation` | `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` | — |
| `LinkLocal` | never: `169.254.0.0/16` is already `Apipa` | `fe80::/16` (first segment exactly `fe80`) |
| `Ula` | — | `fc00::/7` |
| `Unknown` | `0.0.0.0` | `::` |
| `Public` | anything else | anything else |

`Public` is the fallback, not a proof of global reachability: the shared address space `100.64.0.0/10` (carrier-grade NAT), the benchmarking range `198.18.0.0/15`, the reserved `240.0.0.0/4`, the IPv6 documentation prefix `2001:db8::/32` and IPv4-mapped addresses (`::ffff:192.168.1.1`) all come out `Public`.

`IpType` is a property of the address alone. It says which range an address belongs to, never where the host sits relative to the capture point: a `Private` peer can be across a VPN or a routed WAN, a `Public` one can be on the same LAN, and the directed broadcast `192.168.1.255` comes out `Private`, because recognizing it needs the subnet mask, which a packet parser does not have. What the enum saves a consumer is re-implementing the RFC 1918 and special-range tables; a filter such as "traffic leaving the site" still needs the site's own prefixes.

`Broadcast` was added in 11.0.0 ([#9](https://github.com/Akmot9/Packet-parser/issues/9)) and is declared last, after `Unknown`: inserted in second position, it would have shifted the discriminant of every following variant (`IpType::Multicast as u8` from 1 to 2), a silent break for anyone storing those values. A test locks the historical discriminants, and the enum is `#[non_exhaustive]`. The JSON form of an `IpType` is the variant name (`"Private"`, `"Public"`); its `Display` prints French labels (`Privée`, `Publique`, `Inconnue`).

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

`InternetError` wraps one error type per protocol through `#[from]` (`ArpError`, `Ipv4Error`, `Ipv6Error`, `ProfinetPacketError`), and its `Display` is the string stored in `CorruptedLayer::error`, for instance `IPv4 error: Invalid total length: expected 40 bytes (header: 20 + data: 20), but got 20 bytes`. Some declared variants are never returned by the parsers: `Ipv4Error::InvalidChecksum`, `TtlExpired`, `UnsupportedProtocol`, `InvalidOption`, `FragmentedPacket` and `PacketTooLarge`; `Ipv6Error::HopLimitExpired`, `UnsupportedNextHeader`, `PacketTooLarge` and `InvalidAddress`; `InternetError::InvalidLength`, `InvalidFormat` and `InvalidChecksum`. A wrong checksum, a TTL of zero or a fragment does not fail the parse.

`Internet::try_from(&[u8])` (the probing version) still exists for callers that only have raw L3 bytes, but `PacketFlow` never uses it. It tries ARP, IPv4, IPv6, then Profinet, returns `EmptyPacket` for an empty slice and `UnsupportedProtocol` when all four fail: the reason each parser gave is lost, which is exactly the ambiguity described above.

## IPv4 validations

```text
packet-beta
0-3: "Version"
4-7: "IHL"
8-15: "DSCP/ECN"
16-31: "Total length"
32-47: "Identification"
48-50: "Flags"
51-63: "Fragment offset"
64-71: "TTL"
72-79: "Protocol"
80-95: "Header checksum"
96-127: "Source address"
128-159: "Destination address"
160-191: "Options (if IHL > 5)"
```

✅ **Minimum length** – at least **20 bytes**, otherwise `Ipv4Error::InvalidLength`.  
✅ **Version** – the high nibble is **4**, otherwise `InvalidVersion`.  
✅ **Header length** – `IHL × 4` is between **20 and 60** bytes (IHL 5..=15), otherwise `InvalidHeaderLength`.  
✅ **Header available** – the buffer holds the whole header, options included, otherwise `InvalidLength`.  
✅ **Total length** – `total_length` is at least the header length and at most the buffer length, otherwise `InvalidTotalLength`. The payload is `data[header_len..total_length]`: Ethernet padding after a short IP packet is *not* handed to the transport layer.  

The upper bound has a consequence: a packet cut by the capture's snapshot length fails it and is reported in `corrupted`, although nothing was wrong on the wire. `parse` receives the captured bytes only, so a truncated capture and a lying header look the same.

Options are neither decoded nor validated: `Ipv4Packet::options` holds their raw bytes, `data[20..header_len]`, empty when IHL is 5.

The header checksum is **not** verified here: on a sender-side capture with hardware offloading it is often uncomputed, and a mandatory check would reject perfectly healthy traffic. `packet_parser::checksum::verify_ipv4_header_checksum(&[u8]) -> Option<bool>` is available when the context allows it: give it the IP packet, it returns `None` when the header itself is unreadable.

The rest of the header is reached through `details` (`InternetDetails::Ipv4`): `ttl`, `identification`, `protocol`, `header_checksum`, and typed accessors. `dscp()` returns a `Dscp` that displays its IANA name when it has one (`EF (46)`, `AF41 (34)`), `ecn()` an `Ecn` (`NotEct`, `Ect1`, `Ect0`, `Ce`, RFC 3168). Both types come from the `dscp_ecn` module that `Ipv6Packet` shares for its Traffic Class.

### Fragments

The crate does no IP reassembly. For a fragmented IPv4 packet (MF flag set or non-zero offset), `payload_protocol` is set to `None` so the transport layer is **not** parsed from incomplete data: a TCP header read from the second fragment of a datagram would be garbage with valid-looking ports. The first fragment is skipped too, although it does start with the L4 header: a UDP length field covers the whole datagram, so UDP's exact-length check would report a healthy fragment as corrupt, and the application probes would see a cut payload. The cost is that a fragmented packet has no `transport` and no ports. `Ipv4Packet::is_fragmented()`, `more_fragments()`, `fragment_offset()` and `is_non_initial_fragment()` expose the flags through `details`.

## IPv6 validations

✅ **Header length** – at least **40 bytes**, otherwise `Ipv6Error::InvalidLength`.  
✅ **Version** – the high nibble is **6**, otherwise `InvalidVersion`.  
✅ **Payload length** – the buffer holds `40 + payload_length` bytes, otherwise `InvalidPayloadLength`. Bytes beyond it (Ethernet padding) are not handed up, as for IPv4.  
✅ **Extension chain** – every extension header walked fits in the payload, otherwise `InvalidExtensionHeader`.  

Extension headers are walked (RFC 8200 §4) to find the real transport protocol: `Ipv6Packet::transport_protocol` is the next header after the extension chain, `extension_headers` keeps the raw bytes of the chain, `payload` starts after it, and `next_header` keeps the fixed header's value, which may name an extension. Five types are walked: Hop-by-Hop (0), Routing (43) and Destination Options (60), whose length counts 8-byte units after the first 8; Fragment (44), a fixed 8 bytes; and AH (51), whose length counts 4-byte units minus 2 (RFC 4302). Any other value ends the walk and becomes `transport_protocol`: ESP (50), whose contents are encrypted, and the Mobility (135), HIP (139) and Shim6 (140) headers included.

As for IPv4, a Fragment extension header (or a `No Next Header` value, 59) sets `transport_protocol` to `None`, so nothing is parsed above an incomplete datagram; `Ipv6Packet::is_fragmented()` tells the two cases apart.

## ARP

ARP carries no transport, but it does carry protocol addresses, and those are worth a flow identity: `source`/`destination` are the sender/target protocol addresses, `payload_protocol` is `None`, `payload` is empty, and `details` holds the full `ArpPacket` (hardware/protocol types and lengths, operation, both hardware addresses as `[u8; 6]`).

✅ Minimum length **28 bytes**, hardware type **1** (Ethernet) with length **6**, protocol type IPv4 (length 4) or IPv6 (length 16), operation request/reply, and the dynamic length `8 + 2×hlen + 2×plen` available. Bytes past it (Ethernet padding) are ignored. A failure is an `ArpError` (`InvalidLength`, `UnsupportedHardwareType`, `UnsupportedProtocolType`, `InvalidHardwareLength`, `InvalidProtocolLength`, `UnsupportedOperation`), and since the EtherType said ARP, it is reported in `corrupted`, not dropped.

## Profinet

Profinet (EtherType `0x8892`) is validated so that a corrupt frame is reported, but the crate keeps no detailed header for it: the `Internet` built by the private `Internet::profinet()` has `protocol_name: "Profinet"`, no addresses, no `payload_protocol`, an empty payload and `details: None`.

The validation is `ProfinetPacket::try_from`, a DCP parser: at least 16 bytes, a Frame ID in `0xC000..=0xF7FF`, `0xF800..=0xFBFF`, `0xFEFD`, `0xFEFE` or `0xFEFF`, and a first block (header at offset 12) whose declared length fits in the buffer and whose bytes are UTF-8, read as the NameOfStation. Its result is discarded; `ProfinetPacket::try_from(flow.data_link.network_payload())` gives the DCP fields to a caller who wants them.

That validator is narrower than Profinet: a frame with any other Frame ID (a DCP Hello `0xFEFC` or an alarm, for instance) fails with `ProfinetPacketError::UnknownFrameId` and is reported in `corrupted` although it is healthy, and a cyclic real-time frame in the accepted ranges passes or fails depending on whether its first data bytes happen to read as a DCP block.

## IP-level tunnels

GRE (protocol 47) and IP-in-IP (protocols 4 and 41) are detected ([#15](https://github.com/Akmot9/Packet-parser/issues/15)) from `Internet::payload_protocol` and `Internet::payload`, not from the transport layer, because they have none: the `Transport` the pipeline builds for them is the catch-all one (protocol only, no ports, no payload). This IP-level check is the first step of the L7 stage, before the UDP-based tunnels and the application probes. Since it reads `payload_protocol`, a tunnel carried in IP fragments is not peeled. See the [tunnels chapter](./tunnels.md).
