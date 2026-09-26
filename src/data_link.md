# Data link

### **Parsing the Data Link Layer from a Raw Packet**
Understanding how to parse the **Data Link Layer** from raw packets is a crucial step in network packet analysis. The Data Link Layer provides essential information such as **MAC addresses, EtherType, and payload extraction**. This section explains the approach I took, first for Ethernet, then for the other link formats a capture can contain.

---

## **🧩 Understanding the Ethernet Frame**
The Data Link Layer is responsible for **frame-level communication** between devices on the same network segment. In an **Ethernet frame**, the structure is as follows:

![Packet Parser Overview](images/datalink/packet_parser.png)

The main components are:
1. **Destination MAC Address** (6 bytes) - the unique physical identifier of the receiving network hardware.
2. **Source MAC Address** (6 bytes)
3. **EtherType** (2 bytes) – determines the protocol encapsulated in the payload.
4. **Payload** (variable length) – contains the encapsulated network-layer packet (IPv4, ARP, etc.).

---

### **Breaking Down the MAC Address Structure**
To parse MAC addresses correctly, we need to ensure that:
- They are always **6 bytes long**.
- They are formatted properly for readability.
- We extract **Organizationally Unique Identifiers (OUI)** to identify the manufacturer.

**MAC Address Structure:**
![Mac Struct Overview](images/datalink/mac_struct.png)

```rust
pub struct MacAddress(pub [u8; 6]);

impl MacAddress {
    pub const fn is_broadcast(&self) -> bool;
    pub const fn is_multicast(&self) -> bool;
    pub const fn is_unicast(&self) -> bool;
    /// "2c:fd:a1:3c:4d:5e (ASUSTek)" when the OUI is known.
    pub fn display_with_oui(&self) -> String;
    pub fn get_oui(&self) -> Oui;
}
```

The OUI table is embedded in the crate: no file to load, no network lookup.

---

### **Breaking Down the EtherType Field**
The **EtherType** is a 2-byte field that defines the **type of payload** carried by the frame.

📌 **Key Considerations:**
- Extract the 2-byte **big-endian** value.
- Map **well-known EtherTypes** (IPv4, IPv6, ARP, etc.).
- Allow handling of **unknown protocols** without failure: `Ethertype(pub u16)` is a plain newtype, an unknown value is preserved, and `static_name()` returns `None` for it.

📌 **Example of Well-Known EtherTypes:**

| EtherType (Hex) | Protocol |
|----------------|----------|
| `0x0800` | IPv4 |
| `0x86DD` | IPv6 |
| `0x0806` | ARP |
| `0x8892` | Profinet |
| `0x88CC` | LLDP |
| `0x8100` | VLAN tag (802.1Q) |
| `0x88A8` / `0x9100` | Service tag (802.1ad / legacy QinQ) |

---

### **VLAN tags**

When the EtherType is a **TPID** (`0x8100`, `0x88A8` or `0x9100`), the next 4 bytes are a VLAN tag (TCI + the following EtherType), and that EtherType may itself be a TPID: 802.1ad puts an S-tag in front of the C-tag, and some equipment stacks two `0x8100`. The parser **consumes the whole stack** so that `ethertype` and `payload` always describe the real layer 3:

```rust
pub struct DataLink<'a> {
    pub destination_mac: MacAddress,
    pub source_mac: MacAddress,
    /// The innermost tag (the customer VLAN), if any.
    pub vlan: Option<VlanTag>,
    /// The whole stack, outermost first (S-tag then C-tag).
    pub vlan_stack: VlanStack<'a>,
    /// The real layer-3 EtherType, after the tags.
    pub ethertype: Ethertype,
    pub payload: &'a [u8],
}

pub struct VlanTag {
    pub id: u16,      // VLAN identifier (12 bits)
    pub pcp: u8,      // priority code point (3 bits)
    pub dei: bool,    // drop eligible indicator
    pub inner_ethertype: Ethertype,
}
```

`vlan_stack.outer()` gives the S-VLAN, `vlan_stack.iter()` walks the stack from outer to inner. The untagged case is the hot path and stays a straight line; the stack is unrolled in a separate function.

---

## **📌 Steps Taken to Parse the Ethernet Frame**
To correctly extract this information, I followed these key steps:

![validation](images/datalink/validations.png)

### **Validations**
While parsing, I implemented **validations** to ensure the raw packet is coherent.

📌 **Validations Performed:**

✅ **Frame minimum length** – the packet is at least **14 bytes** (`MAC_DST + MAC_SRC + EtherType`), otherwise `DataLinkError::DataLinkTooShort { required, actual }`.  
✅ **VLAN stack length** – re-checked **at each tag consumed**: `14 + 4 × tags` bytes, so a frame truncated in the middle of the stack reports `DataLinkTooShort` instead of an out-of-bounds access.  
✅ **MAC address length** – exactly **6 bytes**, `MacParseError::InvalidLength` otherwise (unreachable from `DataLink::try_from`, since the frame length is already proven; it protects the direct `MacAddress::try_from`).  

The EtherType is *not* validated: an unknown value is a valid frame carrying a protocol we do not decode, and the internet layer will simply be `None`.

```rust
impl<'a> TryFrom<&'a [u8]> for DataLink<'a> {
    type Error = DataLinkError;

    fn try_from(packets: &'a [u8]) -> Result<Self, Self::Error> {
        validate_data_link_length(packets)?;

        let destination_mac = MacAddress::try_from(&packets[0..6])?;
        let source_mac = MacAddress::try_from(&packets[6..12])?;

        let raw_ethertype = u16::from_be_bytes([packets[12], packets[13]]);
        if VlanTag::is_tpid(raw_ethertype) {
            return Self::parse_tagged(packets, destination_mac, source_mac, raw_ethertype);
        }

        Ok(DataLink {
            destination_mac,
            source_mac,
            vlan: None,
            vlan_stack: VlanStack::default(),
            ethertype: Ethertype::from(raw_ethertype),
            payload: &packets[14..],
        })
    }
}
```

### **Structuring the Parsed Frame**
After extracting all components, I structured the parsed frame in a clear format. This makes it easier to **analyze, debug, and process packets** dynamically.

![Tram Struct Overview](images/datalink/tram_struct.png)

---

## **🌐 Beyond Ethernet: `LinkType` and `LinkLayer`**

A capture is not always Ethernet. A capture on the Linux `any` interface is *Linux cooked* (SLL), a VPN capture is often *RAW IP*, an industrial capture can be *802.3br*. The bytes of these formats look nothing like an Ethernet header, and nothing in them says which format they are: **only the capture file knows**, through its LINKTYPE.

That is why `parse` takes a `LinkType` and never guesses. `LinkType(pub u32)` uses the canonical `LINKTYPE_*` values stored in PCAP/PCAPNG files, and stays open: an unknown value is preserved, not collapsed into an `Unknown` variant.

```rust
const fn decoder_for(link_type: LinkType) -> Option<DecoderKind> {
    match link_type {
        LinkType::NULL => Some(DecoderKind::Null),
        LinkType::ETHERNET => Some(DecoderKind::Ethernet),
        // RAW, IPV4 and IPV6 share one decoder: bytes start at the IP header,
        // and the version nibble says which one.
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

This function is the single source of truth: `is_supported` is `decoder_for(..).is_some()`, and `parse` returns `ParseError::UnsupportedLinkType` before reading a single byte when it is `None`.

Every decoder produces the same format-neutral output, consumed by the shared L3/L4/L7 pipeline:

```rust
pub struct LinkLayer<'a> {
    link_type: LinkType,               // the LINKTYPE it was decoded as
    network_protocol: NetworkProtocol, // what comes next: Ipv4, Ipv6, Arp, Profinet, Other(u16)
    network_payload: &'a [u8],         // the L3 bytes
    kind: LinkLayerKind<'a>,           // the format-specific view
}

pub enum LinkLayerKind<'a> {
    Ethernet(DataLink<'a>),
    RawIp(RawIpLink<'a>),
    LinuxSll(LinuxSllLink<'a>),
    LinuxSll2(LinuxSll2Link<'a>),
    Ieee80211(Ieee80211Link<'a>),
}
```

`NetworkProtocol` is deliberately independent from Ethernet: RAW IP announces `Ipv4` or `Ipv6` without fabricating an EtherType, while Ethernet and SLL map their protocol field to the same value. The common accessors (`link_type()`, `network_protocol()`, `network_payload()`) never assume Ethernet; the format-specific views are explicit:

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

### Per-format notes

- **BSD loopback (NULL, LINKTYPE 0)**, since 11.2.0: four bytes of address family, then the IP packet. The family is written in the byte order of the *capturing* host and the format keeps no trace of it, so the field is read both ways and only a reading consistent with the IP version nibble is kept: it is a cross-check, not the source of truth. An unknown or contradicting family is `LinkLayerError::InvalidAddressFamily`. `LINKTYPE_LOOP` (108), the OpenBSD twin in network order, is deliberately not handled: no capture attests it.
- **Linux SLL v1** (16-byte cooked header): keeps the packet type, the raw ARPHRD hardware type, the declared address length, the available source-address bytes and the protocol value. An address longer than the 8-byte wire slot is reported as truncated (`address_is_truncated()`) rather than rejected. Use `LinkType::LINUX_SLL` (113): the value 25 shown by some Wireshark fields is an internal WTAP identifier.
- **Linux SLL v2** (20-byte header): additionally keeps the interface index and the reserved-MBZ field. A non-zero reserved value is preserved and reported by `reserved_is_zero()`, matching Tshark's tolerant dissection.
- **RAW IP**: an empty packet or a version nibble other than 4/6 is `LinkLayerError::InvalidIpVersion`. With `LinkType::IPV4`/`IPV6` the declared version is checked against the nibble.
- **IEEE 802.3br**: express mPackets (SMD-E) are decoded as Ethernet after their preamble; preemptible fragments (SMD-S/C) are refused with `LinkLayerError::PreemptibleFragment`, their reassembly being stateful.
- **IEEE 802.11**: modelled (`Ieee80211Link`) for the inner flows of a CAPWAP tunnel, not yet decodable as a top-level LINKTYPE.

### One error path

Whatever the format, a link failure is reported through the same enum, with sizes expressed on the **whole packet**:

```rust
Err(ParseError::InvalidLinkLayer(LinkLayerError::Truncated {
    link_type, required, actual,
}))
```

### STP lives here too

Spanning Tree BPDUs are 802.3 frames (a length field instead of an EtherType) sent to `01:80:c2:00:00:00` with an LLC header `42-42-03`. They have no network layer. Without a dedicated check they came out with L3/L4/L7 all `None` and no signal, so the pipeline validates the BPDU and labels the flow `application_protocol: "STP"` directly from the link layer.

---

## **🚀 Conclusion**
Parsing the **Data Link Layer** requires **careful validation** and **structured extraction**. By following a modular approach:
- **MAC addresses** are extracted safely.
- **EtherType** is correctly mapped, VLAN stacks are consumed.
- **The LINKTYPE is trusted, the bytes are not**: each format has its own decoder, and none of them can be mistaken for another.
- The structure is **extensible** to new link formats without touching the L3/L4/L7 pipeline.

🚀 **Next Step:** exploring the **internet layer (IPv4/IPv6/ARP)**!
