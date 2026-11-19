# Protocols

The crate gives a flow one of 55 labels, the variants of `ApplicationProtocol::ALL`. This page lists them all, with the route that leads to each one and the page that describes it. The protocols decoded below the application layer, which get no label, come after.

## The 55 labels

The route is how the dispatch reaches the label. A *port* rule asks for a port and a content that agree; a *blind* rule asks for the content alone, on any port; a *terminal* port rule ends the dispatch when the content does not match. The [Application chapter](./application.md#three-detection-routes) explains the three, and the [Glossary](./glossary.md) defines each word. A *tunnel* label is given to the outer flow of an encapsulation.

A label written with "then" has a port rule and a blind rule: the port rule is tried first, and is often the more lenient of the two.

| Label | Route | Transport and ports | Described in | tshark oracle | Since |
|---|---|---|---|---|---|
| `AMS` | port | TCP 48898, UDP 48899 | rules 21, 22 of the [Application](./application.md#reading-the-table) | none | 5.0.0 or earlier |
| `ASTERIX` | blind | UDP | [ASTERIX](./asterix.md) | 44 411 frames, record by record | 11.3.0 |
| `BACnet/IP` | port and blind | UDP 47808 to 47823, then any UDP port | [BACnet/IP](./bacnet.md) | 45 datagrams | 11.6.0 |
| `Bitcoin` | blind | TCP | rule 54 of the [Application](./application.md#reading-the-table) | none | 5.0.0 or earlier |
| `CAPWAP` | tunnel | UDP 5247 | [Tunnels](./tunnels.md#supported-tunnels) | none | 5.0.0 or earlier |
| `COTP` | port | TCP 102 | rule 7 of the [Application](./application.md#reading-the-table) | none | 5.0.0 or earlier |
| `DHCP` | port and blind | UDP 67, 68, then any UDP port | rules 3, 67 of the [Application](./application.md#reading-the-table) | none | 5.0.0 or earlier |
| `DHCPv6` | port | UDP 546, 547 | rule 2 of the [Application](./application.md#reading-the-table) | none | 5.0.0 or earlier |
| `DIS` | port and blind | UDP 3000, then any UDP port | [DIS](./dis.md) | 393 frames | 11.6.0 |
| `DNP3` | blind | TCP and UDP | [DNP3](./dnp3.md) | 218 frames | 11.6.0 |
| `DNS` | port and blind | TCP 53, UDP 53, then any UDP port | [DNS, mDNS and LLMNR](./dns.md) | counts and digests | 5.0.0 or earlier |
| `ESP` | port | UDP 4500 | [ESP](./esp.md#in-udp-4500-behind-a-nat) | 323 packets, 315 of them in UDP | 11.6.0 |
| `EtherNet/IP` | blind | TCP and UDP | rules 56, 57 of the [Application](./application.md#reading-the-table) | none | 5.0.0 or earlier |
| `FTP` | port and blind | TCP 21, then any TCP port but 25, 587, 119 | rules 8, 11 of the [Application](./application.md#reading-the-table) | none | 9.0.0 |
| `Geneve` | tunnel | UDP 6081 | [Tunnels](./tunnels.md#supported-tunnels) | none | 10.5.0 |
| `GIOP` | blind | TCP | [GIOP](./giop.md) | 135 messages | 5.0.0 or earlier |
| `GRE` | tunnel | IP protocol 47 | [Tunnels](./tunnels.md#supported-tunnels) | none | 10.4.0 |
| `GTP-U` | tunnel | UDP 2152 | [Tunnels](./tunnels.md#supported-tunnels) | none | 11.2.0 |
| `HTTP` | blind | TCP | [HTTP](./http.md) | 296 frames | 5.0.0 or earlier |
| `IEC 104` | port | TCP 2404 | [IEC 60870-5-104](./iec104.md) | 373 segments | 11.6.0 |
| `IKE` | port | UDP 500, 4500 | [IKE](./ike.md) | 535 messages | 11.6.0 |
| `IP-in-IP` | tunnel | IP protocols 4 and 41 | [Tunnels](./tunnels.md#supported-tunnels) | none | 10.4.0 |
| `Java RMI` | port and blind | TCP 1099, then any TCP port | [Java RMI](./java_rmi.md) | 236 segments | 13.0.0 |
| `LLMNR` | port, terminal | UDP 5355 | [DNS, mDNS and LLMNR](./dns.md#mdns-and-llmnr) | none | 10.4.0 |
| `mDNS` | port, terminal | UDP 5353 | [DNS, mDNS and LLMNR](./dns.md#mdns-and-llmnr) | none | 9.0.0 |
| `ModbusTCP` | port and blind | TCP 502, then any TCP port | [Modbus/TCP and UMAS](./modbus.md) | 601 segments, with UMAS | 5.0.0 or earlier |
| `ModbusUDP` | port | UDP 502 | [Modbus over UDP](./modbus.md#modbus-over-udp) | 38 datagrams | 12.0.0 |
| `MQTT` | blind | TCP | rule 73 of the [Application](./application.md#reading-the-table) | none | 5.0.0 or earlier |
| `NAT-keepalive` | port | UDP 4500 | [ESP](./esp.md#in-udp-4500-behind-a-nat) | none | 11.6.0 |
| `NBNS` | port | UDP 137 | rule 17 of the [Application](./application.md#reading-the-table) | none | 10.4.0 |
| `NBSS` | port | TCP 139, 445 | rule 18 of the [Application](./application.md#reading-the-table) | none | 10.4.0 |
| `NNTP` | port and blind | TCP 119, then any TCP port but 21, 25, 587 | rules 10, 13 of the [Application](./application.md#reading-the-table) | none | 9.0.0 |
| `NTP` | port and blind | UDP 123, then any UDP port | [NTP](./ntp.md) | 1 308 datagrams | 5.0.0 or earlier |
| `OPC UA` | port and blind | TCP 4840, 12001, then any TCP port | rules 25, 55 of the [Application](./application.md#reading-the-table) | none | 5.0.0 or earlier |
| `OpenVPN` | port | UDP 1194, TCP 1194 | rules 19, 20 of the [Application](./application.md#reading-the-table) | none | 10.4.0 |
| `PostgreSQL` | port and blind | TCP 5432, then any TCP port | [PostgreSQL](./postgresql.md) | 276 segments | 5.0.0 or earlier |
| `PTP` | port | UDP 319, 320 | [PTP](./ptp.md) | 3 328 messages, Ethernet and UDP | 11.5.0 |
| `QUIC` | port and blind | UDP 443 (short header, and the long header of any version), then any UDP port (long header of QUIC v1) | rules 23, 24, 71 of the [Application](./application.md#reading-the-table) | none | 5.0.0 or earlier |
| `RADIUS` | port and blind | UDP 1812, 1813, 1645, 1646, 3799, then any UDP port | [RADIUS](./radius.md) | 95 packets | 11.6.0 |
| `RDP` | port | TCP 3389 | [RDP](./rdp.md) | 861 segments | 11.6.0 |
| `RTPS` | blind | UDP | [RTPS](./rtps.md) | 231 frames | 11.6.0 |
| `S7Comm` | blind | TCP | rule 6 of the [Application](./application.md#reading-the-table) | counts and digests | 5.0.0 or earlier |
| `SMTP` | port and blind | TCP 25, 587, then any TCP port but 21, 119 | rules 9, 12 of the [Application](./application.md#reading-the-table) | none | 9.0.0 |
| `SNMP` | port and blind | UDP 161, 162, then any TCP or UDP port | rules 1, 60 of the [Application](./application.md#reading-the-table) | none | 5.0.0 or earlier |
| `SRVLOC` | port and blind | TCP 427, UDP 427, then any TCP or UDP port | rules 4, 5, 68 of the [Application](./application.md#reading-the-table) | none | 5.0.0 or earlier |
| `SSDP` | port | UDP 1900 | rule 16 of the [Application](./application.md#reading-the-table) | none | 10.4.0 |
| `SSH` | blind | TCP | rules 62, 64 of the [Application](./application.md#reading-the-table) | none | 10.1.0 |
| `STANAG 5066` | port | TCP 5066 | [STANAG 5066 SIS](./stanag5066.md) | 34 segments | 11.6.0 |
| `STP` | link layer | no transport | [STP](./stp.md) | none | 10.4.0 |
| `TLS` | blind | TCP | [TLS](./tls.md) | counts and digests | 5.0.0 or earlier |
| `UMAS` | port and blind | TCP 502, then any TCP port | [Modbus/TCP and UMAS](./modbus.md) | 601 segments, with ModbusTCP | 11.1.0 |
| `Unknown` | no rule matched | any | [Application](./application.md#how-the-label-is-chosen-one-ordered-table) | not a protocol | 5.0.0 or earlier |
| `Valmet DNA` | port and blind | UDP 2517, 4516, 4517, then any UDP port | [Valmet DNA](./valmet_dna.md) | none: tshark has no dissector | 11.8.0 |
| `VXLAN` | tunnel | UDP 4789 | [Tunnels](./tunnels.md#supported-tunnels) | none | 10.5.0 |
| `WireGuard` | port and blind | UDP 51820, then any UDP port | [WireGuard](./wireguard.md) | 128 messages | 11.6.0 |

Three columns need a word.

- **Described in.** A label without a page of its own points to its rows in the dispatch table.
- **tshark oracle.** The number of frames, segments or messages that a golden test of the crate compares with tshark field by field. "Counts and digests" is weaker: `tests/tshark_regression.rs` and `tests/s7comm_regression.rs` compare the set of frames that carry the label, not their fields. "None" means no comparison with tshark; the label is still counted, over the whole corpus, by the golden histogram of `tests/golden_pcaps.rs`.
- **Since.** The first tagged release whose dispatch gives the label. The tags of the repository start at 5.0.0, so "5.0.0 or earlier" is as far back as they tell.

The caller can declare extra ports for the protocols of [Decode As](./application.md#decode-as).

## Decoded without a label

These protocols sit below the application layer. The crate decodes them into a link, internet or transport layer, and `PacketFlow::application` stays `None`.

| Protocol | Where it is found | Layer | Described in | tshark oracle |
|---|---|---|---|---|
| PTP over Ethernet | EtherType `0x88F7` | internet | [PTP](./ptp.md) | 3 328 messages, Ethernet and UDP |
| GOOSE | EtherType `0x88B8` | internet | [GOOSE](./goose.md) | 494 frames |
| LLDP | EtherType `0x88CC` | internet | [LLDP](./lldp.md) | 276 frames |
| Profinet | EtherType `0x8892` | internet | [Profinet](./profinet.md) | 232 frames |
| ARP | EtherType `0x0806` | internet | [ARP](./arp.md) | none |
| ESP, native | IP protocol 50 | transport | [ESP](./esp.md) | 323 packets, 8 of them native |
| ICMPv4 and ICMPv6 | IP protocols 1 and 58 | transport | [ICMPv4 and ICMPv6](./icmp.md) | none |

STP is the exception: it has no internet layer either, and the pipeline labels it `"STP"` from the link layer ([STP](./stp.md)).

## Tunnels

A tunnel is decoded twice: the outer flow takes the tunnel's label, and the conversation it carries is a second `PacketFlow` in `inner`. The [Tunnels chapter](./tunnels.md) has the details.

| Label | Detected from | Carries |
|---|---|---|
| `GRE` | IP protocol 47 | IPv4, IPv6 or Ethernet |
| `IP-in-IP` | IP protocols 4 and 41 | a bare IP packet |
| `CAPWAP` | UDP 5247 | IEEE 802.11, then LLC/SNAP |
| `VXLAN` | UDP 4789 | a full Ethernet frame |
| `Geneve` | UDP 6081 | Ethernet or bare IP |
| `GTP-U` | UDP 2152 | a bare IP packet |

## Link formats

The link layer is chosen by the caller, from the link type of the capture. Each format has its page: [Ethernet](./ethernet.md), with [PPPoE session](./pppoe.md) (6 795 session frames against tshark) and [IEEE 802.3br](./ieee802_3br.md) inside it, [Linux cooked capture](./linux_sll.md), [RAW IP](./raw_ip.md) and [BSD loopback](./null_loopback.md).
