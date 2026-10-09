# Data link

### **Parsing the Data Link Layer from a Raw Packet**
Understanding how to parse the **Data Link Layer** from raw packets is a crucial step in network packet analysis. The Data Link Layer provides essential information such as **MAC addresses, EtherType, and payload extraction**. This part explains how the crate decides which format it reads, then each format has its own page, Ethernet first.

---

## **🌐 The LINKTYPE decides: `LinkType` and `LinkLayer`**

A capture is not always Ethernet. A capture on the Linux `any` interface is *Linux cooked* (SLL), a VPN capture is often *RAW IP*, an industrial capture can be *802.3br*. The bytes of these formats look nothing like an Ethernet header, and nothing in them says which format they are: **only the capture file knows**, through its LINKTYPE.

That is why `parse` takes a `LinkType` and never guesses. `LinkType(pub u32)` uses the canonical `LINKTYPE_*` values stored in PCAP/PCAPNG files, and stays open: an unknown value is preserved, not collapsed into an `Unknown` variant. `parse` never reads a capture file, so mapping the capture source to this namespace is the caller's job: a `DLT_*` value from a live capture must be normalized when it differs from the `LINKTYPE_*` value, and a PCAPNG reader passes the LINKTYPE of the interface each packet references.

```rust
/// Single source of truth for the link types backed by a decoder.
#[inline(always)]
const fn decoder_for(link_type: LinkType) -> Option<DecoderKind> {
    match link_type {
        LinkType::ETHERNET => Some(DecoderKind::Ethernet),
        // BSD loopback: four bytes of address family, then the IP packet.
        LinkType::NULL => Some(DecoderKind::NullLoopback),
        // RAW, IPV4 and IPV6 share the same shape: the bytes start directly
        // at the IP header. RawIpDecoder reads the version from the first
        // nibble, which covers all three without a dedicated decoder.
        LinkType::RAW => Some(DecoderKind::RawIp(LinkType::RAW)),
        LinkType::IPV4 => Some(DecoderKind::RawIp(LinkType::IPV4)),
        LinkType::IPV6 => Some(DecoderKind::RawIp(LinkType::IPV6)),
        LinkType::LINUX_SLL => Some(DecoderKind::LinuxSll),
        LinkType::LINUX_SLL2 => Some(DecoderKind::LinuxSll2),
        LinkType::IEEE802_3BR => Some(DecoderKind::Ieee8023br),
        _ => None,
    }
}
```

This function is the single source of truth: `is_supported` is `decoder_for(..).is_some()`, and `parse` returns `ParseError::UnsupportedLinkType` before reading a single byte when it is `None`. Two constants have no decoder: `LinkType::IEEE802_11` (105) and `LinkType::BLUETOOTH_HCI_H4_WITH_PHDR` (201) are named, and refused like any unknown value.

Every decoder produces the same format-neutral output, consumed by the shared L3/L4/L7 pipeline:

```rust
#[non_exhaustive]
pub struct LinkLayer<'a> {
    link_type: LinkType,               // the LINKTYPE it was decoded as
    network_protocol: NetworkProtocol, // what comes next: Ipv4, Ipv6, Arp, Profinet, Other(u16)
    network_payload: &'a [u8],         // the L3 bytes
    kind: LinkLayerKind<'a>,           // the format-specific view
}

#[non_exhaustive]
pub enum LinkLayerKind<'a> {
    Ethernet(DataLink<'a>),
    RawIp(RawIpLink<'a>),
    LinuxSll(LinuxSllLink<'a>),
    LinuxSll2(LinuxSll2Link<'a>),
    Ieee80211(Ieee80211Link<'a>),
}
```

The fields are private and every constructor is format-specific (`LinkLayer::ethernet` or `From<DataLink>`, `LinkLayer::ieee80211`, crate-internal ones for the other decoders), so `link_type`, `network_protocol` and `kind` cannot disagree. `LinkLayerKind` is `#[non_exhaustive]`: a new link format is a new variant, and a `match` on it needs a wildcard arm.

`NetworkProtocol` is deliberately independent from Ethernet: RAW IP announces `Ipv4` or `Ipv6` without fabricating an EtherType, while Ethernet and SLL map their protocol field to the same value. The common accessors (`link_type()`, `network_protocol()`, `network_payload()`) never assume Ethernet; the format-specific views are explicit (`kind()` to match on, or `as_ethernet()`, `as_raw_ip()`, `as_linux_sll()`, `as_linux_sll2()` and `as_ieee80211()`, which each return an `Option`):

```rust
println!("LINKTYPE={}", flow.data_link.link_type());
println!("next={:?}", flow.data_link.network_protocol());

if let Some(ethernet) = flow.data_link.as_ethernet() {
    println!("{} -> {}", ethernet.source_mac, ethernet.destination_mac);
}
if let Some(sll) = flow.data_link.as_linux_sll() {
    println!("{} type={}", sll.hardware_type, sll.packet_type);
}
```

So a RAW or SLL capture **cannot silently manufacture MAC addresses**, which is what happened before this design when everything was forced through `DataLink`.

### The formats

Each format has its page:

- [Ethernet](./ethernet.md) (LINKTYPE 1), with its MAC addresses, EtherType and VLAN tags;
- [Linux cooked capture](./linux_sll.md), SLL (113) and SLL2 (276);
- [RAW IP](./raw_ip.md) (101, 228, 229);
- [BSD loopback](./null_loopback.md) (NULL, 0);
- [IEEE 802.3br](./ieee802_3br.md) (274);
- and [STP](./stp.md), which lives in Ethernet frames but has no network layer.

IEEE 802.11 is modelled (`Ieee80211Link`) for the inner flows of a CAPWAP tunnel, not yet decodable as a top-level LINKTYPE.

### One error path

Whatever the format, a link failure is reported through the same enum, `LinkLayerError` (`#[non_exhaustive]`), with sizes expressed on the **whole packet**:

```rust
Err(ParseError::InvalidLinkLayer(LinkLayerError::Truncated {
    link_type, required, actual,
}))
```

`Truncated` is the only variant Ethernet produces: its decoder maps `DataLinkError::DataLinkTooShort` onto it, `required` counting the VLAN tags already met. The 802.3br decoder adds its preamble, SMD and mCRC to both sizes and the NULL decoder its four header bytes, so a consumer accounting for link failures never needs to know where a decoder slices the packet. The other variants name what is wrong instead of a size: `InvalidIpVersion`, `InvalidAddressFamily`, `InvalidPreamble`, `InvalidSmd` and `PreemptibleFragment`. An unsupported LINKTYPE is not among them: it is `ParseError::UnsupportedLinkType`.

---

## **🚀 Conclusion**
Parsing the **Data Link Layer** requires **careful validation** and **structured extraction**. By following a modular approach:
- **MAC addresses** are extracted safely.
- **EtherType** is correctly mapped, VLAN stacks are consumed.
- **The LINKTYPE is trusted, the bytes are not**: each format has its own decoder, and none of them can be mistaken for another.
- The structure is **extensible** to new link formats without touching the L3/L4/L7 pipeline.

🚀 **Next Step:** exploring the **internet layer (IPv4/IPv6/ARP)**!
