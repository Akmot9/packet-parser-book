# Link types

Everything else in this crate degrades gracefully. The link layer does not, and
this chapter explains why that asymmetry exists.

## The LINKTYPE comes from the caller

```rust
pub struct LinkType(pub u32);
```

`LinkType` is a transparent wrapper over the canonical `LINKTYPE_*` numbering
stored in capture files — not an enum. Unknown values are **preserved as-is**
instead of being collapsed into an `Unknown` variant, so a value this build does
not decode still round-trips through your tooling.

The named constants:

| Constant | Value |
| --- | ---: |
| `LinkType::ETHERNET` | 1 |
| `LinkType::RAW` | 101 |
| `LinkType::IEEE802_11` | 105 |
| `LinkType::LINUX_SLL` | 113 |
| `LinkType::BLUETOOTH_HCI_H4_WITH_PHDR` | 201 |
| `LinkType::IPV4` | 228 |
| `LinkType::IPV6` | 229 |
| `LinkType::LINUX_SLL2` | 276 |

Two caller responsibilities follow from keeping the crate independent of PCAP,
PCAPNG and libpcap:

- A **live capture** hands you `DLT_*` values. Where their numeric value differs
  from the `LINKTYPE_*` value, the adapter normalizes them first.
- For **PCAPNG**, the reader resolves the interface referenced by each packet and
  passes that interface's LINKTYPE — a single file can mix several.

And `parse` takes **exactly one packet**, without the PCAP/PCAPNG record header.

## What is supported

| LINKTYPE | Value | Decoder status |
| --- | ---: | --- |
| Ethernet | 1 | Supported |
| RAW IP | 101 | Supported for IPv4 and IPv6 |
| Native IEEE 802.11 | 105 | Modelled for CAPWAP inner flows; top-level decoder not yet supported |
| Linux SLL v1 | 113 | Supported |
| Bluetooth H4 with pseudo-header | 201 | Identified, explicitly unsupported |
| Linux SLL v2 | 276 | Supported |
| Any other value | Preserved as-is | `ParseError::UnsupportedLinkType` |

An unsupported LINKTYPE is rejected **before any packet byte is decoded**. Check
it once per capture with `is_supported`, not once per packet.

## The Ethernet shortcut is a trap

`PacketFlow::try_from(&[u8])` and `DataLink::try_from(&[u8])` take a bare byte
slice and **assume Ethernet**. They are kept for compatibility and will be
removed in a future major release.

The problem is not that they can fail. It is that they **cannot**:

> Feed a `LINKTYPE_LINUX_SLL` frame — what a capture on the Linux `any`
> interface yields — to the shortcut, and its 16 cooked-header bytes are
> reinterpreted as an Ethernet header. The call returns `Ok`, with **fabricated
> MAC addresses**, `internet: None` and `corrupted: None`. Nothing signals the
> mistake, and a flow matrix built from it fills up with addresses that never
> existed on the wire.

There is no plausibility check: any buffer of at least 14 bytes is a valid
Ethernet header as far as that code path is concerned. Reach for it only when the
capture is known to be Ethernet; otherwise pass the LINKTYPE the capture
declares.

This is the reason the link layer is fail-closed while everything above it is
fail-soft. A wrong guess above L2 produces a `None` you can see. A wrong guess at
L2 produces confident, plausible, wrong data.

## A generic link layer

Every parsed flow carries a `LinkLayer`, not an Ethernet frame:

```rust
pub enum LinkLayerKind<'a> {
    Ethernet(DataLink<'a>),
    RawIp(RawIpLink<'a>),
    LinuxSll(LinuxSllLink<'a>),
    LinuxSll2(LinuxSll2Link<'a>),
    Ieee80211(Ieee80211Link<'a>),
}
```

The common accessors do not assume Ethernet:

```rust
println!("LINKTYPE={}", flow.data_link.link_type());
println!("next={:?}", flow.data_link.network_protocol());

if let Some(ethernet) = flow.data_link.as_ethernet() {
    println!("{} -> {}", ethernet.source_mac, ethernet.destination_mac);
}
```

`network_payload()` returns the borrowed L3 slice, and `network_protocol()`
returns a format-neutral `NetworkProtocol` (`Ipv4`, `Ipv6`, `Arp`, `Profinet`,
`Other(u16)`) rather than an EtherType — RAW IP and SLL have no EtherType to
give.

Format-specific views are **explicit**: `as_ethernet()`, `as_raw_ip()`,
`as_linux_sll()`, `as_linux_sll2()`, `as_ieee80211()`. Each returns an `Option`,
so RAW and both SLL formats cannot silently manufacture Ethernet fields.

## Per-format notes

### RAW IP

An empty packet, or a version nibble other than 4 or 6, returns a structured
`InvalidLinkLayer(LinkLayerError)` — this is genuinely a link-layer failure.

Once IPv4 or IPv6 *is* identified, an invalid or truncated IP header is no longer
a link-layer problem: it becomes a successful partial flow with
`corrupted: Internet`, and the link layer and its accounting are preserved.

### Linux SLL v1 (113)

Decodes its 16-byte cooked header in network byte order and keeps the packet
type, the raw ARPHRD hardware type, the declared address length, the available
source-address bytes and the protocol value.

Unknown numeric values are preserved rather than rejected. An address longer than
the eight-byte wire slot is **reported as truncated** (`address_is_truncated()`),
not treated as a parse failure.

Use the canonical `LinkType::LINUX_SLL` (113). The value 25 that some Wireshark
fields display is an internal WTAP encapsulation identifier, not a LINKTYPE.

### Linux SLL v2 (276)

Independently decodes its own 20-byte header — it is not v1 with extra fields —
and additionally keeps the numeric capture-machine interface index and the
reserved-MBZ field.

A non-zero reserved value is preserved and reported by `reserved_is_zero()`
rather than discarding an otherwise decodable packet, matching Tshark's tolerant
dissection. Interface *names* are not resolved: they belong to the capture
machine, not to the packet.

Use the canonical `LinkType::LINUX_SLL2` (276); Wireshark's current internal WTAP
encapsulation identifier for this format is 210.

### IEEE 802.11 (105)

The 802.11 link model exists and is used for the inner frames of
[CAPWAP tunnels](./tunnels.md), but it is not yet wired as a top-level LINKTYPE
decoder.
