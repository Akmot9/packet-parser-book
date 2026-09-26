# Internet

The internet layer is the first *optional* layer: it is parsed from `LinkLayer::network_payload()`, and the link layer says which protocol to expect through `NetworkProtocol`.

## The `Internet` struct

```rust
pub struct Internet<'a> {
    pub source: Option<IpAddr>,
    pub source_type: Option<IpType>,
    pub destination: Option<IpAddr>,
    pub destination_type: Option<IpType>,
    /// "IPv4", "IPv6", "ARP", "Profinet"
    pub protocol_name: &'static str,
    /// Transport protocol parsable from `payload`. `None` for IPv4 fragments.
    pub payload_protocol: Option<TransportProtocol>,
    pub payload: &'a [u8],
    /// Full parsed header: Ipv4Packet, Ipv6Packet or ArpPacket.
    pub details: Option<InternetDetails<'a>>,
}
```

Addresses use the standard `std::net::IpAddr`, and each one is classified by `IpType`: `Private`, `Public`, `Loopback`, `LinkLocal`, `Apipa`, `Ula`, `Multicast`, `Broadcast` (limited broadcast `255.255.255.255`), `Documentation`, `Unknown`. This is what lets a consumer filter "traffic to the Internet" without re-implementing RFC 1918.

## Dispatch on the announced protocol, not probing

The link layer already told us what the payload is. The internet parser trusts that announcement:

```rust
pub fn try_from_network_parts(protocol: NetworkProtocol, payload: &'a [u8])
    -> Result<Self, InternetError>
{
    match protocol {
        NetworkProtocol::Arp => Ok(Self::from_arp(ArpPacket::try_from(payload)?)),
        NetworkProtocol::Ipv4 => Ok(Self::from_ipv4(Ipv4Packet::try_from(payload)?)),
        NetworkProtocol::Ipv6 => Ok(Self::from_ipv6(Ipv6Packet::try_from(payload)?)),
        NetworkProtocol::Profinet => { ProfinetPacket::try_from(payload)?; Ok(Self::profinet()) }
        NetworkProtocol::Other(_) => Err(InternetError::UnsupportedProtocol),
    }
}
```

Why dispatch rather than "try ARP, then IPv4, then IPv6"? Because probing cannot tell a **corrupt packet** from an **unknown protocol**: both just fail every parser. With the EtherType in hand, the two cases are distinct, and the pipeline maps them to the two distinct outcomes:

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

`Internet::try_from(&[u8])` (the probing version) still exists for callers that only have raw L3 bytes, but `PacketFlow` never uses it.

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

✅ **Minimum length** – at least **20 bytes**.  
✅ **Version** – the high nibble is **4**.  
✅ **Header length** – `IHL × 4` is between **20 and 60** bytes (IHL 5..=15).  
✅ **Header available** – the buffer holds the whole header, options included.  
✅ **Total length** – `total_length` is at least the header length and at most the buffer length. The payload is `data[header_len..total_length]`: Ethernet padding after a short IP packet is *not* handed to the transport layer.  

The header checksum is **not** verified here: on a sender-side capture with hardware offloading it is often uncomputed, and a mandatory check would reject perfectly healthy traffic. `packet_parser::checksum::verify_ipv4_header_checksum` is available when the context allows it.

### Fragments

The crate does no IP reassembly. For a fragmented IPv4 packet (MF flag set or non-zero offset), `payload_protocol` is set to `None` so the transport layer is **not** parsed from incomplete data: a TCP header read from the second fragment of a datagram would be garbage with valid-looking ports. `Ipv4Packet::is_fragmented()` and `is_non_initial_fragment()` expose the flags through `details`.

## IPv6 validations

✅ **Header length** – at least **40 bytes**.  
✅ **Version** – the high nibble is **6**.  
✅ **Payload length** – the buffer holds `40 + payload_length` bytes.  

Extension headers are walked to find the real transport protocol: `Ipv6Packet::transport_protocol` is the next header after the extension chain, and `extension_headers` keeps the raw bytes of the chain. As for IPv4, a Fragment extension header (or a `No Next Header` value) sets `transport_protocol` to `None`, so nothing is parsed above an incomplete datagram.

## ARP

ARP carries no transport, but it does carry protocol addresses, and those are worth a flow identity: `source`/`destination` are the sender/target protocol addresses, `payload_protocol` is `None`, and `details` holds the full `ArpPacket` (hardware/protocol types and lengths, operation, both hardware addresses).

✅ Minimum length **28 bytes**, hardware type **1** (Ethernet) with length **6**, protocol type IPv4 (length 4) or IPv6 (length 16), operation request/reply, and the dynamic length `8 + 2×hlen + 2×plen` available.

## Profinet

Profinet (EtherType `0x8892`) is validated so that a corrupt frame is reported, but the crate keeps no detailed header for it: `Internet::profinet()` has no addresses and no payload.

## IP-level tunnels

GRE (protocol 47) and IP-in-IP (protocols 4 and 41) are detected from `payload_protocol` at this level, before any transport parsing, because they have no transport layer. See the [tunnels chapter](./tunnels.md).
