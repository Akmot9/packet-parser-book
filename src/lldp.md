# LLDP

Link Layer Discovery Protocol, IEEE 802.1AB, added in 11.6.0 ([#178](https://github.com/Akmot9/Packet-parser/pull/178)) under the epic of the ICS bench protocols, LLDP, S7CommPlus and MELSOFT ([#177](https://github.com/Akmot9/Packet-parser/issues/177)): every device announces to its direct neighbours, in multicast, who it is (chassis, port, name, description, capabilities, management addresses) and, through organization TLVs, what PROFINET, IEEE 802.1, IEEE 802.3 or LLDP-MED add to it. Until 11.6.0 its EtherType was only named. The module is `packet_parser::parse::internet::protocols::lldp`.

## On Ethernet, as the internet layer

LLDP has no IP and no UDP. Its EtherType, `0x88CC`, maps to `NetworkProtocol::Lldp` (added in 11.6.0 at the end of the enum, where 11.5.0 had `Other(0x88CC)`), and, as for [GOOSE](./goose.md), the LLDPDU *is* the internet layer. The [internet dispatch](./network.md#dispatch-on-the-announced-protocol-not-probing) has one arm for it:

```rust
NetworkProtocol::Lldp => Ok(Self::from_lldp(LldpPacket::try_from(payload)?)),
```

The flow gets an `Internet` with `protocol_name` `"LLDP"`, no addresses, `payload_protocol` `None`, an empty `payload` and the decoded LLDPDU in `InternetDetails::Lldp`; `transport` and `application` stay `None`. The application label does not move, an LLDP frame had none and has none, so the golden histogram is unchanged; what the frame gains is an internet layer, `protocol_internet` `"LLDP"` in JSON, and a `network_protocol` of `{"kind": "lldp"}` where it was `{"kind": "other", "value": 35020}`. The EtherType was already named `"LLDP"`. Every `LldpParseError` is a corrupted internet layer, `InternetError::LldpError`, whose text in `corrupted` starts with `LLDP error: `.

The LLDPDU is what the link layer hands over after the EtherType: 59 LLDP frames of the corpus are [IEEE 802.3br](./ieee802_3br.md) express mPackets, and the decoder sees them without their mCRC.

Frame 29 of `cisagov_profinet_io_cm_mixed_1.pcap`, a Siemens SCALANCE X208 switch (*tested*):

```rust
{{#include ../examples/src/internet_layer.rs:lldp_announcement}}
```

## The LLDPDU: `LldpPacket`

![The LLDPDU of frame 29 of cisagov_profinet_io_cm_mixed_1.pcap, after the EtherType 0x88CC: each TLV starts with two bytes, 7 bits of type and 9 of length; Chassis ID (type 1, subtype 7, siemens-x208-switch), Port ID (type 2, subtype 7, port-004), Time To Live 20 seconds, System Description, System Capabilities 0x0080, Management Address 0.0.0.0, three organization-specific TLVs and the End of LLDPDU; LldpPacket exposes the two identifiers and the TTL as typed fields and the rest as a list of TLVs.](images/network/lldp_struct.svg)

```rust
pub struct LldpPacket<'a> {
    pub chassis_id: LldpId<'a>,
    pub port_id: LldpId<'a>,
    pub time_to_live: u16,        // seconds; 0 withdraws the device
    pub tlvs: Vec<LldpTlv<'a>>,   // every TLV in wire order, the three mandatory
                                  // ones and End of LLDPDU included
    pub padding: &'a [u8],        // after End of LLDPDU: the padding of a short frame
}

pub struct LldpTlv<'a> {
    pub tlv_type: u8,
    pub value: &'a [u8],
}
```

The LLDPDU is a run of TLVs, each a two-byte header, seven bits of type and nine of length, then the value, borrowed from the frame. It opens with Chassis ID, Port ID and Time To Live, in that order, and closes with End of LLDPDU. The decoder stops at that TLV, and what follows is `padding`, kept as is, not checked. Without an End TLV the TLVs run to the end of the frame and `padding` is empty. The 276 LLDPDUs of the corpus all end with an End TLV, and none has padding.

| Type | `type_name()` | Length accepted | Read by |
| --- | --- | --- | --- |
| 0 | End of LLDPDU | 0 | ends the LLDPDU |
| 1 | Chassis ID | 2 to 256 | `chassis_id` |
| 2 | Port ID | 2 to 256 | `port_id` |
| 3 | Time To Live | 2 | `time_to_live` |
| 4 | Port Description | any | `port_description()` |
| 5 | System Name | any | `system_name()` |
| 6 | System Description | any | `system_description()` |
| 7 | System Capabilities | 4 | `system_capabilities()` |
| 8 | Management Address | 9 to 167, tiled by its inner lengths | `management_addresses()` |
| 127 | Organizationally Specific | at least 4 | `organization_tlvs()` |
| 9 to 126 | Reserved | any | `tlv(tlv_type)` |

The three text accessors give the value of the first TLV of their type as `&str` when it is UTF-8, `None` otherwise; `tlv(tlv_type)` gives the first TLV of a type, raw, and `LldpTlv::as_text()` reads any value as text.

### Chassis and port: `LldpId`

```rust
pub struct LldpId<'a> {
    pub subtype: u8,
    pub id: &'a [u8],
}
```

The first byte of the value is the subtype, which says what the ID is:

| Subtype | Chassis ID | Port ID |
| --- | --- | --- |
| 1 | chassis component | interface alias |
| 2 | interface alias | port component |
| 3 | port component | MAC address, `PORT_ID_MAC_ADDRESS` |
| 4 | MAC address, `CHASSIS_ID_MAC_ADDRESS` | network address, `PORT_ID_NETWORK_ADDRESS` |
| 5 | network address, `CHASSIS_ID_NETWORK_ADDRESS` | interface name |
| 6 | interface name | agent circuit ID |
| 7 | locally assigned | locally assigned |

`as_text()`, `as_mac()` and `as_network_address()` read the bytes and do not look at the subtype: `as_mac()` turns any six-byte ID into a `MacAddress`, `as_network_address()` reads an IANA address family (1 for IPv4, 2 for IPv6) followed by an address of the right size. Match on `subtype` first. In the corpus, the 205 LLDPDUs of the PROFINET captures carry locally assigned IDs, the 71 Cisco ones a MAC chassis ID and an interface name.

### Capabilities, management addresses, organizations

`system_capabilities()` returns `SystemCapabilities { capabilities, enabled }`, two bit fields of what the device can do and of what is on. A constant names each bit, `OTHER` (`0x0001`), `REPEATER`, `BRIDGE` (`0x0004`), `WLAN_ACCESS_POINT`, `ROUTER` (`0x0010`), `TELEPHONE`, `DOCSIS_CABLE_DEVICE`, `STATION_ONLY` (`0x0080`), `C_VLAN_COMPONENT`, `S_VLAN_COMPONENT` and `TWO_PORT_MAC_RELAY` (`0x0400`), and `is_enabled(bit)` reads `enabled`.

```rust
pub struct ManagementAddress<'a> {
    pub address_subtype: u8,    // IANA address family: 1 IPv4, 2 IPv6, 6 MAC...
    pub address: &'a [u8],
    pub interface_subtype: u8,  // interface numbering: 1 unknown, 2 ifIndex, 3 system port
    pub interface_number: u32,
    pub oid: &'a [u8],          // the SNMP object that describes the address, often empty
}
```

The value of a Management Address TLV is the length of the address string (2 to 32 bytes, its subtype included), the subtype and the address, the interface numbering subtype, the interface number on four bytes, the length of the OID and the OID, at most 128 bytes. These lengths must tile the value exactly, or the whole LLDPDU is refused with `InvalidManagementAddress`. `management_addresses()` yields the addresses in wire order, and `ip()` gives the `IpAddr` of an IPv4 or IPv6 one.

```rust
pub struct OrganizationTlv<'a> {
    pub oui: [u8; 3],
    pub subtype: u8,
    pub info: &'a [u8],
}
```

`organization_tlvs()` yields the TLVs of type 127 in wire order, and `organization()` names six OUIs: `00-80-C2` IEEE 802.1, `00-12-0F` IEEE 802.3, `00-0E-CF` PROFINET, `00-12-BB` LLDP-MED, `00-80-63` Hirschmann and `00-01-42` Cisco; any other is `None`. `info` stays raw.

Frame 2165 of `The-Ultimate-PCAP.pcapng`, a Cisco C2960, then the same frame cut in the middle of its System Description (*tested*):

```rust
{{#include ../examples/src/internet_layer.rs:lldp_ids_addresses_corruption}}
```

## Validations

All of them are `LldpParseError`, in `packet_parser::errors::internet::lldp`:

| Error | When |
| --- | --- |
| `TruncatedTlvHeader { offset }` | a TLV header starts at `offset` and the frame ends before its second byte |
| `TlvOverflow { tlv_type, offset, declared, available }` | a TLV declares more bytes than remain |
| `MissingMandatoryTlv { position, expected, found }` | TLV number `position` (0 to 2) is not Chassis ID, Port ID and Time To Live in that order; `found` is `None` when the LLDPDU ends first, an empty one included |
| `InvalidTlvLength { tlv_type, length }` | a length outside the bounds of the table above |
| `InvalidManagementAddress` | the inner lengths of a Management Address do not tile its value |

## The blind probe

`Internet::try_from`, the probing parser for callers without an EtherType, tries LLDP last, after GOOSE (see the [internet page](./network.md#dispatch-on-the-announced-protocol-not-probing)), and asks for more than the decoder: the last TLV must be End of LLDPDU, and the padding zeros only. The golden test runs it on the 276 LLDPDUs of the corpus, and recognizes each of them.

## Oracle: 276 frames, TLV by TLV

The golden test `tests/lldp_golden.rs` compares every LLDP frame of three captures with tshark 4.6.6, frozen in `tests/data/lldp_tshark_oracle.tsv` by `tools/lldp_oracle.sh` (run with an empty Wireshark profile): the types and lengths of the TLVs, the chassis, the port, the TTL, the system name, the port description, the capabilities, the management addresses and the organization OUIs. The system descriptions are compared by their length only, since tshark escapes their line breaks. Each of the 276 frames is an internet layer `LLDP`, without corruption, with the values of tshark, and no other frame of the three captures decodes as LLDP. A second test checks the blind probe and that an LLDPDU cut by one byte before its padding is refused. The fuzz target `parse_lldp` runs nightly on the decoder, seeded with the SCALANCE frame and the Cisco one, without its descriptions.

| Capture | LLDP frames | Devices |
| --- | --- | --- |
| `protocols/profinet/cisagov_profinet_io_cm_mixed_1.pcap` | 201 | a Siemens SCALANCE X208 (`siemens-x208-switch`, 134 frames) and `versamax-pns11` (67), PROFINET and IEEE 802.3 TLVs |
| `protocols/profinet/miguelob_pn.pcapng` | 4 | two Siemens devices, `SIMATIC NET` and `SIMATIC S7` in their port descriptions |
| `The-Ultimate-PCAP.pcapng`, read in place | 71 | two Cisco switches: 12 Ethernet frames with an IPv4 and an IPv6 management address, 59 IEEE 802.3br mPackets |

The first two belong to the [PROFINET](./profinet.md) corpus; the third is the Ultimate PCAP of Johannes Weber, at the root of `pcaps_exemple/`.

## What is left out

- **Organization TLVs** are identified, OUI and subtype, not decoded: `info` stays raw, for PROFINET, IEEE 802.1, IEEE 802.3 and LLDP-MED alike.
- **Management addresses** other than IPv4 and IPv6 are only `address_subtype` and `address`; the OID is raw bytes.
- **No neighbour table**: the crate does not age announcements by `time_to_live`, nor keep what a device announced; stateless, one LLDPDU at a time.
- **Reserved TLV types** (9 to 126) are kept, without a bound on their length and without interpretation.
