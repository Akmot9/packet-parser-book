# Application

The application layer is where the rule "the port never decides alone" is put to the test, and where most of the design decisions of the crate were taken after real captures proved a naive approach wrong.

## A classification, not a decode

```rust
pub struct Application {
    pub application_protocol: &'static str,   // "DNS", "TLS", "HTTP", "Unknown"...
}
```

`PacketFlow::application` is a **label**. It says *which* protocol the transport payload looks like, not what the message contains. It is `&'static str`, so classification costs no allocation.

For the actual decode, every protocol has a module under `packet_parser::parse::application::protocols`, and every one of them is a `TryFrom<&[u8]>` with its own struct and error:

```rust
use packet_parser::parse::application::protocols::dns::DnsPacket;

if let Some(transport) = &flow.transport
    && let Some(payload) = transport.payload
    && let Ok(dns) = DnsPacket::try_from(payload)
{
    println!("{} questions, {} answers", dns.header.qdcount, dns.header.ancount);
}
```

Why separate the two? Because the label is the thing every consumer needs on every packet (a flow matrix, a protocol histogram), and it must be cheap and stateless. Decoding DNS names or TLS extensions allocates and only some consumers need it.

## Supported protocols

The dispatch table gives 44 labels: DNS (plus its mDNS and LLMNR forms), TLS, SNMP, [NTP](#ntp), DHCP, DHCPv6, HTTP, MQTT, [PostgreSQL](#postgresql), FTP, SMTP, NNTP, SSH (identification string only), SSDP, NetBIOS (NBNS, NBSS), OpenVPN, [Modbus/TCP and UMAS](#modbustcp-and-umas), EtherNet/IP, OPC UA, S7Comm, COTP, AMS, [GIOP](./giop.md), SRVLOC, [ASTERIX](./asterix.md) (eleven categories), QUIC, Bitcoin, [PTP](./ptp.md) (IEEE 1588, on UDP 319/320), and, since 11.6.0, [DNP3](./dnp3.md), [IEC 60870-5-104](./iec104.md), [BACnet/IP](./bacnet.md), [RADIUS](./radius.md), [RDP](./rdp.md), [WireGuard](./wireguard.md), [DIS](./dis.md), [STANAG 5066 SIS](./stanag5066.md), [RTPS](./rtps.md), [IKE](./ike.md), and [ESP](./esp.md) inside UDP 4500 with its one-byte NAT-keepalive. STP gets its label from the link layer (see below).

Some protocols are decoded below the table and get no label: PTP straight over Ethernet (EtherType `0x88F7`), [GOOSE](./goose.md) (`0x88B8`) and [LLDP](./lldp.md) (`0x88CC`) are [internet layers](./network.md), and native ESP, IP protocol 50, is a transport layer whose SPI and sequence number are in `TransportDetails::Esp`, with no application payload, like ICMP.

A probed payload that matches nothing is labelled `"Unknown"`. An empty payload (a pure ACK) is not probed at all and `application` stays `None`.

## How the label is chosen: one ordered table

The first version of the crate was a cascade of `if XxxPacket::try_from(payload).is_ok() { return "Xxx" }`, spread over two files, with port guards applied unevenly and one override where the port beat the content. Three problems showed up on real traffic:

- **false positives**: NTP probed on TCP labelled TLS encrypted alerts "NTP" (`0x15` is a plausible LI/VN/mode byte); a BOOTP packet looked like an SLP header; FTP/SMTP/NNTP replies are byte-for-byte identical;
- **double probing**: the same parser ran twice on the same payload (once port-guarded, once blind);
- **pathological cost**: a 64 KiB GRO segment was fully parsed by every probe in the cascade.

The dispatch is now **one ordered table** in `src/parse/dispatch.rs`. Each rule has:

```rust
struct Rule {
    label: &'static str,
    guard: Guard,                              // Tcp, Udp or Any: the transports the RFC allows
    ports: Option<fn(Option<u16>) -> bool>,    // optional port guard (either port)
    ports_veto: Option<fn(Option<u16>) -> bool>, // ports on which the rule must NOT fire
    probe: ProbeId,                            // the content check
    terminal_on_port: bool,                    // port reserved by RFC: the verdict is final
}
```

and the invariants are:

1. **A rule with a port guard labels only if port *and* content agree.** The port alone never decides. `OPC UA` on port 4840 is still checked by `OpcuaPacket::try_from`.
2. **Every probe runs at most once per payload.** Failures are memoized by `ProbeId` in a bitmask, one bit of a `u64` for each of the 57 probes: a rule sharing a probe with an earlier one (port-priority then blind fallback) never re-runs it.
3. **Probes read at most `PROBE_CAP` = 18 KiB.** Classification is a verdict on the application header, not on the whole segment; the cap is above the largest legitimate message a probe must see in full (an encrypted TLS record: 5 + 16 KiB + tag). The exceptions are the probes that read the real payload, not a prefix: the length prefix of OpenVPN over TCP; the structures that must end exactly with their datagram or segment, the extension fields and MAC of the NTP blind probe, RTPS (a 60 KB `DATA_FRAG` is still RTPS), DIS, DNP3, RADIUS, BACnet/IP, IKE and WireGuard; and RDP and IEC 104, whose TPKTs and APDUs are read on the whole segment, the last one possibly cut by the segmentation. The DNS blind probe stays on the capped prefix: a datagram longer than the cap cannot prove that its sections consume it exactly, and stays `"Unknown"`.
4. **The order of the table is the priority**, inspectable, testable, and locked by a golden snapshot over the reference captures.

![One rule of the table: the transport payload, a TLS ClientHello on TCP 54322 to 443, passes the transport guard, then the port guard, then the content probe, and gets the label TLS; a failed gate moves on to the next rule, the last rule falls through to Unknown, an empty payload is not probed](images/application/dispatch_rule.svg)

Each rule is three gates in a row, and a payload stops at the first rule whose three gates open. The TLS rule has no port guard, so its second gate always opens: the ClientHello is labelled by its content, whatever the port. A probe that fails is not re-run by a later rule that shares it. Two outcomes do not come from a rule: an empty payload is never probed (`application: None`), and a payload no rule matched is `"Unknown"`, except on the terminal mDNS and LLMNR ports, where a failed probe ends the search with `None` (see below).

### Reading the table

In 11.6.0 the table has 62 rules in two blocks: the 38 rules of the port block, then a blind cascade of 24. The port block also holds four rules without a port guard that must come early: the blind S7Comm rule, which must beat COTP even on port 102, and the three rules that recognize FTP, SMTP and NNTP off their ports. The source writes a rule with one of two constructors, or with the whole struct when a field differs from their defaults:

```rust
static RULES: &[Rule] = &[
    port_rule("SNMP", Guard::Udp, is_snmp_udp_port, ProbeId::Snmp),
    port_rule("DHCPv6", Guard::Udp, is_dhcpv6_udp_port, ProbeId::Dhcpv6),
    rule("S7Comm", Guard::Tcp, ProbeId::S7Comm),
    // ...
    Rule {
        label: "FTP",
        guard: Guard::Tcp,
        ports: None,
        ports_veto: Some(is_text_protocol_port),
        probe: ProbeId::FtpUnambiguous,
        terminal_on_port: false,
    },
    // ...
    port_rule("NTP", Guard::Udp, is_ntp_udp_port, ProbeId::Ntp),
    // --- blind cascade, with the transport guards the RFCs impose ---
    rule("NTP", Guard::Udp, ProbeId::NtpBlind),
    // ...
    rule("MQTT", Guard::Tcp, ProbeId::Mqtt),
];
```

Here is the whole table, in order. A port guard matches when either port of the segment or datagram is in its list; a veto skips the rule when either port is in the veto list. "Whole payload" marks the probes of invariant 3 that do not stop at `PROBE_CAP`.

**Port rules**

| # | Label | Guard | Ports | `ProbeId` | The probe |
| --- | --- | --- | --- | --- | --- |
| 1 | SNMP | `Udp` | 161, 162 | `Snmp` | `SnmpPacket::try_from` |
| 2 | DHCPv6 | `Udp` | 546, 547 | `Dhcpv6` | `Dhcpv6Packet::try_from` |
| 3 | S7Comm | `Tcp` | none | `S7Comm` | `S7CommPacket::try_from`: TPKT, COTP DT and S7 header together |
| 4 | COTP | `Tcp` | 102 | `CotpTpkt` | a COTP TPDU behind the first TPKT header (`cotp_from_tpkt`) |
| 5 | FTP | `Tcp` | 21 | `Ftp` | `FtpMessage::try_from` |
| 6 | SMTP | `Tcp` | 25, 587 | `Smtp` | `SmtpMessage::try_from` |
| 7 | NNTP | `Tcp` | 119 | `Nntp` | `NntpMessage::try_from` |
| 8 | FTP | `Tcp` | vetoed on 21, 25, 587, 119 | `FtpUnambiguous` | a complete command whose verb only FTP has: RETR, STOR, PASV, APPE, RNFR, RNTO, MKD, CDUP, EPSV, EPRT, NLST |
| 9 | SMTP | `Tcp` | vetoed on 21, 25, 587, 119 | `SmtpUnambiguous` | the same, for EHLO, HELO, MAIL, RCPT |
| 10 | NNTP | `Tcp` | vetoed on 21, 25, 587, 119 | `NntpUnambiguous` | the same, for ARTICLE, XOVER, XHDR, IHAVE, LISTGROUP, NEWGROUPS, NEWNEWS |
| 11 | mDNS | `Udp` | 5353, terminal | `Mdns` | `DnsPacket::try_from_mdns` |
| 12 | LLMNR | `Udp` | 5355, terminal | `Llmnr` | `DnsPacket::try_from_llmnr` |
| 13 | SSDP | `Udp` | 1900 | `Ssdp` | `SsdpPacket::try_from` |
| 14 | NBNS | `Udp` | 137 | `Nbns` | `NbnsPacket::try_from` |
| 15 | NBSS | `Tcp` | 139, 445 | `Nbss` | `NbssPacket::try_from` |
| 16 | OpenVPN | `Udp` | 1194 | `OpenVpnUdp` | `OpenVpnPacket::try_from` |
| 17 | OpenVPN | `Tcp` | 1194 | `OpenVpnTcp` | `OpenVpnPacket::from_tcp_stream`, whole payload |
| 18 | AMS | `Tcp` | 48898 | `Ams` | `AmsPacket::try_from` |
| 19 | AMS | `Udp` | 48899 | `Ams` | the same probe |
| 20 | QUIC | `Udp` | 443 | `QuicShortHeader` | `is_plausible_short_header`: the 1-RTT header is opaque by design |
| 21 | OPC UA | `Tcp` | 4840, 12001 | `Opcua` | `OpcuaPacket::try_from` |
| 22 | DNS | `Tcp` | 53 | `DnsTcp` | `DnsPacket::try_from_tcp`: the length-prefixed form |
| 23 | DNS | `Udp` | 53 | `Dns` | `DnsPacket::try_from`: the datagram form |
| 24 | [PTP](./ptp.md) | `Udp` | 319, 320 | `Ptp` | `PtpPacket::try_from_udp` |
| 25 | [DIS](./dis.md) | `Udp` | 3000 | `DisLenient` | `DisPacket::try_from_lenient`, whole payload |
| 26 | [RADIUS](./radius.md) | `Udp` | 1812, 1813, 1645, 1646, 3799 | `Radius` | `RadiusPacket::try_from`, whole payload |
| 27 | [BACnet/IP](./bacnet.md) | `Udp` | 47808 to 47823 | `Bacnet` | `BacnetPacket::try_from`, whole payload |
| 28 | [RDP](./rdp.md) | `Tcp` | 3389 | `Rdp` | `RdpPacket::try_from`, whole payload |
| 29 | [IEC 104](./iec104.md) | `Tcp` | 2404 | `Iec104` | `Iec104Packet::try_from`, whole payload |
| 30 | [PostgreSQL](#postgresql) | `Tcp` | 5432 | `PostgresqlPort` | `is_plausible_postgresql_payload`: a decode of compatible shape |
| 31 | [IKE](./ike.md) | `Udp` | 500, 4500 | `Ike` | `IkePacket::from_udp`, bare or behind the non-ESP marker, whole payload |
| 32 | [ESP](./esp.md) | `Udp` | 4500 | `EspNatT` | `UdpEncapsulation::classify` finds ESP and `EspPacket::try_from` accepts it |
| 33 | [NAT-keepalive](./ike.md) | `Udp` | 4500 | `NatKeepalive` | `UdpEncapsulation::classify` finds the one byte `0xFF` |
| 34 | [STANAG 5066](./stanag5066.md) | `Tcp` | 5066 | `Stanag5066` | `SisPdu::try_from` |
| 35 | [UMAS](#modbustcp-and-umas) | `Tcp` | 502 | `Umas` | `UmasPacket::try_from` |
| 36 | [ModbusTCP](#modbustcp-and-umas) | `Tcp` | 502 | `ModbusTcp` | `ModbusTcpPacket::try_from`: the envelope alone |
| 37 | [WireGuard](./wireguard.md) | `Udp` | 51820 | `WireGuardPort` | `WireGuardPacket::is_port_udp_match`, whole payload |
| 38 | [NTP](#ntp) | `Udp` | 123 | `Ntp` | `NtpPacket::try_from`: the decoder alone |

**Blind cascade**

| # | Label | Guard | Ports | `ProbeId` | The probe |
| --- | --- | --- | --- | --- | --- |
| 39 | [NTP](#ntp) | `Udp` | none | `NtpBlind` | `NtpPacket::is_blind_udp_match`, whole payload |
| 40 | [RTPS](./rtps.md) | `Udp` | none | `Rtps` | magic `RTPS` or `RTPX`, then `RtpsPacket::try_from`, whole payload |
| 41 | [ASTERIX](./asterix.md) | `Udp` | none | `Asterix` | `AsterixPacket::try_from` |
| 42 | [DIS](./dis.md) | `Udp` | none | `Dis` | `DisPacket::try_from`: the PDUs tile the datagram, whole payload |
| 43 | [DNP3](./dnp3.md) | `Any` | none | `Dnp3` | `Dnp3Packet::try_from`, whole payload |
| 44 | [RADIUS](./radius.md) | `Udp` | none | `Radius` | rule 26's probe |
| 45 | [BACnet/IP](./bacnet.md) | `Udp` | none | `Bacnet` | rule 27's probe |
| 46 | Bitcoin | `Tcp` | none | `Bitcoin` | `BitcoinPacket::try_from` |
| 47 | OPC UA | `Tcp` | none | `Opcua` | rule 21's probe |
| 48 | EtherNet/IP | `Any` | none | `EthernetIp` | `EtherNetIpPacket::try_from` |
| 49 | [PostgreSQL](#postgresql) | `Tcp` | none | `Postgresql` | `is_likely_postgresql_payload`: compatible shape and a strong proof |
| 50 | DNS | `Udp` | none | `DnsBlind` | `DnsPacket::is_blind_udp_match` |
| 51 | SNMP | `Any` | none | `Snmp` | rule 1's probe |
| 52 | TLS | `Tcp` | none | `Tls` | `TlsPacket::try_from` |
| 53 | SSH | `Tcp` | none | `Ssh` | `SshPacket::try_from` |
| 54 | HTTP | `Tcp` | none | `Http` | `HttpRequest::try_from` |
| 55 | [GIOP](./giop.md) | `Tcp` | none | `Giop` | magic `GIOP`, then `GiopPacket::try_from` |
| 56 | DHCP | `Udp` | none | `Dhcp` | `DhcpPacket::try_from` |
| 57 | SRVLOC | `Any` | none | `Srvloc` | `SrvlocPacket::try_from` |
| 58 | [UMAS](#modbustcp-and-umas) | `Tcp` | none | `Umas` | rule 35's probe |
| 59 | [ModbusTCP](#modbustcp-and-umas) | `Tcp` | none | `ModbusTcpBlind` | `ModbusTcpPacket::is_blind_tcp_match` |
| 60 | QUIC | `Udp` | none | `QuicLongHeader` | `QuicPacket::try_from` |
| 61 | [WireGuard](./wireguard.md) | `Udp` | none | `WireGuardBlind` | `WireGuardPacket::is_blind_udp_match`, whole payload |
| 62 | MQTT | `Tcp` | none | `Mqtt` | `MqttPacket::try_from` |

Six probes serve two rules each: `Ams` its TCP and its UDP port (18, 19), and five others a port rule that gives them priority and a blind rule further down, `Snmp` (1, 51), `Opcua` (21, 47), `Radius` (26, 44), `Bacnet` (27, 45) and `Umas` (35, 58). A failure on the port is memoized, so the blind rule does not run it again. Some probes are crate-internal: `cotp_from_tpkt`, the three verb checks, `is_plausible_short_header`, the `is_blind_*` and `is_port_udp_match` functions and the two PostgreSQL predicates. A consumer reaches them through `parse`, which is where the label is decided. Each comment in the real file cites the capture frame or the issue that motivated the line. That is the point of a table over a cascade: the semantics of the order are written down and cannot silently move.

### Three detection routes

When choosing where a new protocol goes, the question is: *can a valid payload of this protocol also be a valid payload of another protocol we already detect, or of arbitrary text?*

| Route | When | Example |
| --- | --- | --- |
| **Blind probe** (`rule`) | the bytes identify themselves: literal marker (`HTTP/`, `GIOP`, `SSH-`, `RTPS`), CRCs (DNP3), tight binary header with plausible values (DNS, NTP), announced lengths that must cover the payload exactly (RADIUS, BACnet/IP, and PostgreSQL, which also wants a message of strong evidence), or a structure that must tile the datagram to the last byte (ASTERIX, DIS) | `rule("TLS", Guard::Tcp, ..)` |
| **Port-guarded** (`port_rule`) | the signature is weak or ambiguous even with perfect checks: identical reply syntax (FTP/SMTP/NNTP), loose headers (DHCPv6, AMS, COTP, QUIC short header, PTP, IEC 104, STANAG 5066, IKE), a stack other protocols share (RDP: TPKT, COTP and MCS are also T.120's), relaxed validation (mDNS) | `port_rule("FTP", Guard::Tcp, is_ftp_tcp_port, ..)` |
| **Strong signature with transport constraint** | recognizable off-port, but only defined on one transport | S7Comm: the full TPKT + COTP-DT + S7 envelope is probed on any TCP port, and the same bytes on UDP never yield the label |

Whatever the route, the **transport guard** is always there: the RFC says on which transport a protocol exists, and probing it elsewhere only produces false positives.

A protocol with a standard port and a signature strong enough elsewhere takes two routes at once, one rule each. With **one probe**, the port rule only gives it priority over the cascade: SNMP, OPC UA, RADIUS, BACnet/IP and UMAS. With **two probes**, the port rule keeps a lenient decoder and the blind rule a stricter one, because the standard port carries real traffic that no blind probe could prove: NTP on 123 (`Ntp`, `NtpBlind`), Modbus/TCP on 502 (`ModbusTcp`, `ModbusTcpBlind`), PostgreSQL on 5432 (`PostgresqlPort`, `Postgresql`), DIS on 3000 (`DisLenient`, `Dis`) and WireGuard on 51820 (`WireGuardPort`, `WireGuardBlind`). The first three have their section below.

### Tightening a blind probe

A blind probe is only as good as the captures it has been confronted with. The defense corpus added in 11.4.0 showed two probes accepting traffic that was not theirs:

- **SRVLOC**: 829 PTPv2 `Delay_Req` messages were labelled SRVLOC. Their header has exactly the shape of an SLPv1 one (version 1, a `SrvRply` function, a length equal to the datagram). The SLPv1 language field must now be a two-letter ASCII ISO 639 code (RFC 2165 §7); anything else is `SrvlocPacketParseError::InvalidLanguageCode`.
- **DNS**: off port 53, any UDP datagram whose first twelve bytes formed a plausible empty header was DNS, among them 37 datagrams of a radar stream. The blind rule now runs its own probe, `ProbeId::DnsBlind`: the sections must consume the datagram exactly and carry at least one question or record. Port 53 keeps the tolerant decoder, so the two DNS rules no longer share a probe.

In both cases the rule kept its place in the table; what changed is what the probe demands. Both corrections only remove labels: the 866 frames concerned now come out as `"Unknown"`, and the golden histogram moves on those frames and nowhere else.

11.6.0 did the same for two blind rules that ran a whole decoder, NTP ([#164](https://github.com/Akmot9/Packet-parser/issues/164)) and Modbus/TCP ([#167](https://github.com/Akmot9/Packet-parser/issues/167)), and split them as DNS had been split: the tolerant decoder now runs in a port rule on the standard port, where the labels of the corpus did not move, and the blind rule has a stricter probe of its own. The [NTP](#ntp) and [Modbus/TCP](#modbustcp-and-umas) sections give the details.

The reverse defect exists too, a parser refusing its own traffic, and 11.5.0 fixed one in SRVLOC ([#131](https://github.com/Akmot9/Packet-parser/issues/131)): the Char Encoding field of an SLPv1 header was read on one byte instead of two (RFC 2165 §7), which shifted everything after it, the XID and, in a `DAAdvert`, the error code, URL and scope list; the 26 SLPv1 `DAAdvert` of a real capture came out `"Unknown"`. The header now has `SrvlocHeaderV1::char_encoding` (`u16`, the IANA MIBenum, 106 for UTF-8); the old single-byte `encoding` is deprecated, which is what made 11.5.0 a minor and not a patch. 11.6.0 fixed four more, all with real frames: NTP replies refused because of the client's clock ([#161](https://github.com/Akmot9/Packet-parser/issues/161)), timestamps without their era ([#162](https://github.com/Akmot9/Packet-parser/issues/162)), reference ids and polls an implementation does send ([#165](https://github.com/Akmot9/Packet-parser/issues/165)), and the PostgreSQL `p` message of every password or SCRAM authentication ([#98](https://github.com/Akmot9/Packet-parser/issues/98)).

## "Decode As"

Port guards mean a server on a non-standard port is invisible to a port-guarded rule. `ParseConfig::decode_as(port, DecodeAsProtocol::Xxx)` declares extra ports, and `parse_with` applies them. Declared ports are evaluated **before** the table, with the same three constraints: port *and* content, the protocol's transport guard, and failures memoized like the table's. Ports the table marks terminal (mDNS 5353, LLMNR 5355) cannot be overridden: the caller extends the guards, never replaces them.

`DecodeAsProtocol` is `#[non_exhaustive]`. It had twenty variants in 11.5.0, `Ptp` the last; 11.6.0 adds seven at its end, `Stanag5066`, `Dis`, `Ike`, `Esp`, `Rdp`, `Iec104` and `WireGuard`. Each variant resolves to a label, a transport guard and a probe, and a unit test of `dispatch.rs` checks that the label and the probe are those of a rule of the table (for `WireGuard`, those of its 51820 twin), so that the two lists cannot drift apart:

| Variant | Label | Guard | `ProbeId` |
| --- | --- | --- | --- |
| `Ftp` | FTP | `Tcp` | `Ftp` |
| `Smtp` | SMTP | `Tcp` | `Smtp` |
| `Nntp` | NNTP | `Tcp` | `Nntp` |
| `Cotp` | COTP | `Tcp` | `CotpTpkt` |
| `Dns` | DNS | `Tcp` on TCP, `Udp` otherwise | `DnsTcp` on TCP, `Dns` otherwise |
| `Mdns` | mDNS | `Udp` | `Mdns` |
| `Llmnr` | LLMNR | `Udp` | `Llmnr` |
| `Ssdp` | SSDP | `Udp` | `Ssdp` |
| `Nbns` | NBNS | `Udp` | `Nbns` |
| `Nbss` | NBSS | `Tcp` | `Nbss` |
| `Snmp` | SNMP | `Any` | `Snmp` |
| `Dhcpv6` | DHCPv6 | `Udp` | `Dhcpv6` |
| `OpcUa` | OPC UA | `Tcp` | `Opcua` |
| `PostgreSql` | [PostgreSQL](#postgresql) | `Tcp` | `PostgresqlPort` |
| `ModbusTcp` | [ModbusTCP](#modbustcp-and-umas) | `Tcp` | `ModbusTcp` |
| `EthernetIp` | EtherNet/IP | `Any` | `EthernetIp` |
| `Ams` | AMS | `Any` | `Ams` |
| `QuicShortHeader` | QUIC | `Udp` | `QuicShortHeader` |
| `OpenVpn` | OpenVPN | `Tcp` on TCP, `Udp` otherwise | `OpenVpnTcp` on TCP, `OpenVpnUdp` otherwise |
| `Ptp` | [PTP](./ptp.md) | `Udp` | `Ptp` |
| `Stanag5066` | [STANAG 5066](./stanag5066.md) | `Tcp` | `Stanag5066` |
| `Dis` | [DIS](./dis.md) | `Udp` | `DisLenient` |
| `Ike` | [IKE](./ike.md) | `Udp` | `Ike` |
| `Esp` | [ESP](./esp.md) | `Udp` | `EspNatT` |
| `Rdp` | [RDP](./rdp.md) | `Tcp` | `Rdp` |
| `Iec104` | [IEC 104](./iec104.md) | `Tcp` | `Iec104` |
| `WireGuard` | [WireGuard](./wireguard.md) | `Udp` | `WireGuard` |

A declared port gets the probe of the protocol's standard port: the compatible shape of PostgreSQL on 5432, the lenient reading of DIS on 3000, the envelope of Modbus/TCP on 502. `WireGuard` goes further than the 51820 rule: its probe, `WireGuardPacket::try_from`, accepts the reserved bytes whatever the message type, where the port rule wants them null in a cookie or a data message, 51820 being a port that any peer can draw at random. Because declared ports come before the table, a declared port names the protocol of everything its probe accepts: on a port declared `ModbusTcp`, a UMAS frame is `"ModbusTCP"` (see [Modbus/TCP and UMAS](#modbustcp-and-umas)).

The seventeen labels without a variant are all given by a rule without a port guard, which probes any port, except NAT-keepalive, which only UDP 4500 knows. For NTP, whose port rule is more tolerant than its blind probe, this means that off port 123 the strict probe is the only way to the label.

## NTP

Network Time Protocol, RFC 5905, on UDP only. The module is `packet_parser::parse::application::protocols::ntp`; `NtpPacket::try_from` decodes the 48-byte header, and `NtpPacketParseError`, in `packet_parser::errors::application::ntp`, says why it refused. 11.6.0 reworked both sides of the detection with real captures: the decoder stopped refusing real traffic ([#161](https://github.com/Akmot9/Packet-parser/issues/161), [#162](https://github.com/Akmot9/Packet-parser/issues/162), [#165](https://github.com/Akmot9/Packet-parser/issues/165)), and the blind probe stopped accepting traffic that was not NTP ([#164](https://github.com/Akmot9/Packet-parser/issues/164)).

### Lenient on port 123, strict elsewhere

```rust
port_rule("NTP", Guard::Udp, is_ntp_udp_port, ProbeId::Ntp),  // 123, the last port rule
// --- blind cascade ---
rule("NTP", Guard::Udp, ProbeId::NtpBlind),                    // the first blind rule
```

On **UDP 123**, either port (a server's source, a client's destination, both in symmetric mode), `ProbeId::Ntp` runs the decoder alone. The rule is the last of the port rules, which is where the blind rule stood until 11.6.0, with the same decoder, so that the move changed nothing on port 123. Being last, it also lets every other port rule speak first: a DNS query sent from port 123 to port 53 keeps the label DNS even when its bytes read as an NTP header, a case the unit tests of `dispatch.rs` pin down.

On **any other UDP port**, `ProbeId::NtpBlind` runs `NtpPacket::is_blind_udp_match`, crate-internal, on the whole datagram. The decoder must accept the datagram, and the header alone is not enough: until 11.6.0 the blind probe was the decoder, and about one random datagram in 250 passed for NTP; on the 654 test captures of nDPI, 43 of the 59 NTP labels were wrong (QUIC, CryNet, Gnutella, KCP, PFCP, NetBIOS datagrams, obfuscated OpenVPN...). The probe now also demands:

| What | Required off port 123 | Why |
| --- | --- | --- |
| poll | -7 to 24 | chrony's range; ntpd uses 3 to 17, an SNTP client 0; the false positives of nDPI carried 46 to 118 |
| precision | -32 to 0, or 32 | 2⁻³² s is the resolution of a timestamp; chrony puts 32 in its client requests |
| root delay | under 16 s (`MAXDISP`) | the largest real one of the corpora is 1 s; a QUIC v1 header reads as 256 s or more |
| bytes after the header | none; in NTPv4, extension fields (16 bytes or more, a multiple of 4), then an optional MAC: 4 zero bytes (crypto-NAK), 20 bytes (MD5, AES-CMAC) or 24 (SHA-1); or a MAC alone of 36, 52 or 68 bytes (SHA-256, SHA-384, SHA-512); before NTPv4, a crypto-NAK or a MAC of 12 to 72 bytes, the longest being the Extended Authenticator of MS-SNTP | they must end exactly with the datagram |
| Receive and Transmit | Receive not after Transmit, a null timestamp not compared | both are on the sender's clock |
| reference id at stratum 0 | null, an ASCII code, or `127.0.0.1` | the decoder accepts any four bytes there |

The root dispersion is not bounded: the stratum 1 ntpd of the second example below announces 107.8 s. Measured by [#164](https://github.com/Akmot9/Packet-parser/issues/164) on the nDPI captures, the crate now labels exactly the 16 NTP datagrams of modes 1 to 5 that tshark sees there, and none of the 202 558 other UDP datagrams of the 3 110 captures examined. `Application::try_from`, which has no port, uses the strict probe too, and there is no `DecodeAsProtocol::Ntp`.

The examples of this chapter move a real frame off its port with a small helper:

```rust
{{#include ../examples/src/shared.rs:with_ports}}
```

Frame 3 of `pcaps_exemple/protocols/ntp/tcpdump_ntp.pcap`, a chrony request, is NTP on its port and nowhere else (*tested*):

```rust
{{#include ../examples/src/shared.rs:ntp_lenient_on_port_123}}
```

### The header

```rust
pub struct NtpPacket {
    pub flags: (u8, u8, u8),             // leap indicator, version, mode
    pub stratum: u8,
    pub poll: u8,                         // the raw byte: poll_exponent() gives it signed
    pub precision: i8,
    pub root_delay: u32,
    pub root_dispersion: u32,
    pub reference_id: Refid,
    pub reference_timestamp: DateTime<Utc>,
    pub originate_timestamp: DateTime<Utc>,
    pub receive_timestamp: DateTime<Utc>,
    pub transmit_timestamp: DateTime<Utc>,
}

pub enum Refid {
    Ipv4(Ipv4Addr),         // stratum 2 to 15
    KissCode([u8; 4]),      // stratum 0
    ClockSource([u8; 4]),   // stratum 1
}
```

Both are `#[non_exhaustive]`. The decoder reads the header in wire order; the bytes after it (extension fields, MAC) are not decoded, and only the blind probe looks at them.

| Bytes | Field | Check | Error |
| --- | --- | --- | --- |
| | | at least 48 bytes | `InvalidPacketLength` |
| 0 | `flags`: LI (bits 7–6), VN (5–3), mode (2–0) | version 1 to 4, mode 1 to 5 | `InvalidVersion { version }`, `InvalidMode { mode }` |
| 1 | `stratum` | 0 to 15 | `InvalidStratum` |
| 2 | `poll` | signed, -7 or more | `InvalidPoll` |
| 3 | `precision` | | |
| 4–7 | `root_delay` | | |
| 8–11 | `root_dispersion` | | |
| 12–15 | `reference_id` | at stratum 1, a printable ASCII code | `InvalidReferenceIdForStratum1` |
| 16–23 | `reference_timestamp` | | |
| 24–31 | `originate_timestamp` | | |
| 32–39 | `receive_timestamp` | | |
| 40–47 | `transmit_timestamp` | | |

Mode 6 (control messages, `ntpq`) and mode 7 are refused: `NtpPacket` does not model their format. `InconsistentTimestamps` no longer comes out of `try_from`, which compares no timestamps (below).

The reference id depends on the stratum (RFC 5905 §7.3), and 11.6.0 widened the three cases:

- **stratum 1**: a clock source, printable ASCII, left-justified and zero-padded. The list is kept by IANA and is longer than the RFC's excerpt (GOES, GPS, PPS...): any non-empty printable code is accepted, `SHM`, ntpd's shared memory driver, included ([#162](https://github.com/Akmot9/Packet-parser/issues/162));
- **stratum 0**: a kiss code in a server's Kiss-o'-Death, but whatever an unsynchronized client leaves in its request (`127.0.0.1`, `USER`): any four bytes, kept as `KissCode` ([#165](https://github.com/Akmot9/Packet-parser/issues/165));
- **stratum 2 to 15**: the IPv4 address of the upstream server or, for an IPv6 upstream, the first four bytes of the MD5 hash of its address, which can read as any address, multicast included: any four bytes, kept as `Ipv4` ([#165](https://github.com/Akmot9/Packet-parser/issues/165)).

`Refid::code()` gives the code of a kiss code or clock source without its padding, and `Display` prints the code, the address, `NULL` for an empty kiss code, or the bytes. The poll is a signed power of two (RFC 5905 §7.3), down to -7 for chrony since its version 4.3; the decoder used to refuse it as soon as it was negative. `poll` keeps the byte as received (-7 is 249) and `NtpPacket::poll_exponent()` returns it signed ([#165](https://github.com/Akmot9/Packet-parser/issues/165)). Before [#165](https://github.com/Akmot9/Packet-parser/issues/165), 27 NTP packets of `The-Ultimate-PCAP.pcapng` came out `"Unknown"`.

### Timestamps: an era and two clocks

A timestamp is 32 bits of seconds since 1900 and 32 bits of fraction, which the crate turns into a `DateTime<Utc>`:

- the **era** is given by the most significant bit of the seconds (RFC 4330 §3): set, era 0, from 1968 to 2036; clear, era 1, from 2036 to 2104, as tshark reads it. Until 11.6.0 every timestamp counted from 1900, and a Java client of the corpus that sent 37 seconds came out at `1900-01-01T00:00:37Z`, where tshark reads `2036-02-07T06:28:53Z` ([#162](https://github.com/Akmot9/Packet-parser/issues/162));
- an all-zero timestamp means "unknown" (RFC 5905 §6) and comes out as the Unix epoch, `1970-01-01T00:00:00Z`;
- the fraction becomes nanoseconds, rounded down.

Originate (T1) is the client's timestamp, copied as is into the reply; Reference, Receive (T2) and Transmit (T3) are the server's. Until 11.6.0 the decoder demanded `reference <= originate <= receive <= transmit`: as soon as the client's clock was a few milliseconds ahead, which is what NTP is there to correct, or a first request left originate null, the server's reply was `InconsistentTimestamps`, hence `"Unknown"`, and so were 20 of the 26 real replies of the IEC 61850 substation of `protocols/goose/iti_Sample_File_MMS_and_GOOSE.pcap` ([#161](https://github.com/Akmot9/Packet-parser/issues/161)). The decoder now compares no timestamp: Receive and Transmit do share a clock, but in interleaved mode (chrony `xleave`) a reply carries the Transmit of the previous one ([#165](https://github.com/Akmot9/Packet-parser/issues/165)). Only the blind probe checks that Receive does not follow Transmit.

The exchange of the Java client of `protocols/iec104/iti_JavaRMI_and_IEC_Misc.pcap`, frames 1 and 2, shows the three points (*tested*):

```rust
{{#include ../examples/src/shared.rs:ntp_era_and_clocks}}
```

### Oracle: 1 308 datagrams

`tests/ntp_golden.rs` compares the crate with tshark 4.6.6 (`tools/ntp_oracle.sh`, frozen in `tests/data/ntp_tshark_oracle.tsv`) field by field: ports, LI, version, mode, stratum, poll, precision, root delay and dispersion, reference id and the four timestamps to the nanosecond, on **1 308 datagrams**. They come from `pcaps_exemple/protocols/ntp/`, the substation of `goose/iti_Sample_File_MMS_and_GOOSE.pcap`, the Java exchange and, read in place, `The-Ultimate-PCAP.pcapng` and `4SICS-GeekLounge-151020.pcap`: NTS, authenticated MS-SNTP, SHA-256 and SHA-512 MACs, chrony requests with random timestamps, symmetric mode, IPv6 upstreams. Two gaps are named, not masked: the 104 control messages of mode 6 and the 36 ICMP errors quoting an NTP datagram, where the crate labels the ICMP frame. No other frame of `pcaps_exemple/` comes out NTP, among them 31 datagrams of six nDPI captures that the former blind probe took for NTP, and 8 that the lenient decoder accepts but the blind probe refuses. Moved off port 123, the 1 308 datagrams are recognized by the blind probe, except one: the chrony request of the example above. The golden histogram counts 77 NTP labels.

## Modbus/TCP and UMAS

Modbus/TCP wraps each Modbus PDU in a seven-byte MBAP header; UMAS, the proprietary protocol Schneider Electric uses to control its Modicon PLCs, travels inside it under the vendor function code `0x5A`. Two modules, two labels: `packet_parser::parse::application::protocols::modbus_tcp` (`"ModbusTCP"`) and `packet_parser::parse::application::protocols::umas` (`"UMAS"`), on TCP only, port 502 included: the same bytes on UDP get neither label. 11.6.0 made the Modbus/TCP label depend on the port ([#167](https://github.com/Akmot9/Packet-parser/issues/167)).

### Four rules

```rust
// TCP 502 (IANA `mbap`): the MBAP envelope is enough, UMAS first
port_rule("UMAS", Guard::Tcp, is_modbus_tcp_port, ProbeId::Umas),
port_rule("ModbusTCP", Guard::Tcp, is_modbus_tcp_port, ProbeId::ModbusTcp),
// ... blind cascade, after SRVLOC:
rule("UMAS", Guard::Tcp, ProbeId::Umas),
rule("ModbusTCP", Guard::Tcp, ProbeId::ModbusTcpBlind),
```

UMAS comes first, on the port and off it: it is carried by a valid Modbus envelope, so the Modbus probe would accept its frames too, and the most specific protocol gets the label, as S7Comm does before COTP. Its probe, `UmasPacket::try_from`, is the same in both rules: a valid MBAP whose function code is `0x5A`, then a session id and a UMAS function byte.

On **TCP 502**, `ProbeId::ModbusTcp` runs the decoder alone, `ModbusTcpPacket::try_from`: a well-formed envelope is enough, whatever the function code.

**Elsewhere**, `ProbeId::ModbusTcpBlind` runs `ModbusTcpPacket::is_blind_tcp_match`, crate-internal. The envelope was all the former blind probe checked, and it is the shape of any message that starts with two bytes and a four-byte length: off port 502, 97 segments of the corpora came out ModbusTCP, Active Directory's LDAP (`30 84 00 00 ..`, 57 segments of `The-Ultimate-PCAP.pcapng` and 7 of nDPI's `kerberos.pcap`), DICOM, the transport protocol of Elasticsearch, a game. The probe now demands that every MBAP of the segment:

1. carry a PDU that `is_plausible_pdu` accepts: a public function code of common use, and data of the size it imposes, as a request or as a response (Modbus Application Protocol v1.1b3):

   | Function code | Request | Response |
   | --- | --- | --- |
   | `0x01`, `0x02` Read Coils, Read Discrete Inputs | address, quantity 1 to 2 000 | a byte count of 1 to 250, then that many bytes |
   | `0x03`, `0x04` Read Holding, Input Registers | address, quantity 1 to 125 | the same, with an even count |
   | `0x05` Write Single Coil | address, value `0x0000` or `0xFF00` | the echo |
   | `0x06` Write Single Register | address, value | the echo |
   | `0x0F` Write Multiple Coils | quantity 1 to 1 968, a byte count of the quantity divided by 8 rounded up, the values | address, quantity |
   | `0x10` Write Multiple Registers | quantity 1 to 123, a byte count of twice the quantity, the values | address, quantity |
   | `0x16` Mask Write Register | address, AND mask, OR mask | the echo |
   | `0x17` Read/Write Multiple Registers | read quantity 1 to 125, write quantity 1 to 121, the values written | as a read |
   | `0x2B` Encapsulated Interface Transport | Read Device Identification only (MEI type 14): a read code of 1 to 4, an object id | a conformity level, then objects that tile the PDU exactly |
   | `0x81`–`0x86`, `0x8F`, `0x90`, `0x96`, `0x97`, `0xAB` | | the exception response to one of the above: one exception code, 1 to 6, 8, 10 or 11 |

   The serial line codes (7, 8, 11, 12, 17), file record access (20, 21), FIFO queue (24), CANopen (MEI type 13, whose size the specification does not give) and the user-defined codes are refused off port; on port 502 the decoder accepts them.

2. not be one of two lookalikes whose header remains a valid Modbus PDU byte for byte:
   - an Active Directory LDAPMessage, `30 84 00 00 LL LL 02 n`: a SEQUENCE with a four-byte length, then the messageID INTEGER, read as unit 2 and function code n, 1 to 4. An unbindRequest(2) or an abandonRequest is a valid Read Coils there (frame 3627 of `NEWYORK.cap`, OTRF datasets);
   - a DICOM A-ASSOCIATE-RJ, `03 00 00 00 00 04 00 r s c`: the type 3 and its four-byte length, then the result read as the function code and the source as a byte count.

   Off port 502, a real Modbus message loses only transaction `0x3084` of unit 2 with functions 1 to 4, and, at transaction `0x0300`, a one-byte read response of unit 0.

`Application::try_from`, which has no port, uses the strict probe too. A Read Holding Registers request passes it, a scanner's user-defined function code does not (*tested*):

```rust
{{#include ../examples/src/shared.rs:modbus_lenient_on_port_502}}
```

And an Active Directory bindResponse, frame 40035 of `pcaps_exemple/The-Ultimate-PCAP.pcapng`, which the decoder takes for an envelope (*tested*):

```rust
{{#include ../examples/src/shared.rs:modbus_ldap_lookalike}}
```

### On a declared port

`DecodeAsProtocol::ModbusTcp` gives another port the rule of port 502: `("ModbusTCP", Guard::Tcp, ProbeId::ModbusTcp)`, the decoder alone. Declared ports are tried before the table, so on that port the label is `"ModbusTCP"` for everything the decoder accepts, UMAS included: Decode As names the protocol of the port, as it does for any protocol. There is no `DecodeAsProtocol::Umas`, and none is needed, since UMAS is recognized by the same probe on every port (*tested*, frame 6 of `protocols/umas/umas.pcap`):

```rust
{{#include ../examples/src/shared.rs:umas_decode_as}}
```

### The envelope and the UMAS header

```rust
pub struct ModbusTcpPacket<'a> {
    pub mbaps: Vec<MBAP<'a>>,   // several MBAPs in one segment
}

pub struct MBAP<'a> {
    pub transaction_identifier: u16,
    pub protocol_identifier: u16,
    pub length: u16,
    pub unit_identifier: u8,
    pub pdu: Modbus<'a>,
}

pub struct Modbus<'a> {
    pub function_code: u8,
    pub pdu_data: &'a [u8],
}
```

All three are `#[non_exhaustive]`. The MBAPs must tile the segment, each one starting where the previous one ends, 6 + `length` bytes later; all errors are `ModbusTcpError`, in `packet_parser::errors::application::modbus_tcp`:

| Bytes | Field | Check | Error |
| --- | --- | --- | --- |
| | | at least 7 bytes left for each MBAP | `BufferTooSmall { needed, actual }` |
| 0–1 | `transaction_identifier` | | |
| 2–3 | `protocol_identifier` | 0 | `InvalidProtocolIdentifier { got }` |
| 4–5 | `length` | 1 or more, and 6 + `length` bytes present | `InvalidLengthField { got }`, `LengthMismatch { expected, actual }` |
| 6 | `unit_identifier` | | |
| 7 | `pdu.function_code` | present | `PduTooSmall { needed, actual }` |
| 8 to 5 + `length` | `pdu.pdu_data` | | |

The decoder does not interpret the function code: `is_plausible_pdu` is a detection check, not a decode, and the data stay raw.

```rust
pub struct UmasPacket<'a> {
    pub mbap: MBAP<'a>,           // the carrying envelope, function code 0x5A
    pub session_id: u8,           // given by the PLC
    pub function: UmasFunction,   // a request's code or a reply's status
    pub data: &'a [u8],           // not decoded
}
```

`UmasPacket::try_from` decodes the first MBAP of the segment and needs function code `0x5A` (`UmasError::NotUmas { got }`) and two bytes after it, the session id and the function (`UmasError::PduTooSmall { needed, actual }`); an invalid envelope is `UmasError::InvalidEnvelope`, which wraps the `ModbusTcpError`. UMAS has no public specification and the names of its request codes come from reverse engineering, which no capture can confirm: `UmasFunction` names only what a frame of the corpus attests, `Reply` (`0xFE`, the constant `UMAS_REPLY`, carried by the 90 replies of `umas.pcap`), and leaves every other value as `Other(u8)`.

### Oracle: 601 segments

`tests/modbus_golden.rs` compares every MBAP header with tshark 4.6.6 (`tools/modbus_oracle.sh`, frozen in `tests/data/modbus_tshark_oracle.tsv`): transaction, length, unit, function code and exception code, on the 601 Modbus/TCP segments of `protocols/modbus/`, `protocols/umas/` and, read in place, `The-Ultimate-PCAP.pcapng`. The crate labels 420 of them ModbusTCP and 181 UMAS, misses none, and labels no other segment of these captures Modbus: of the 400 TCP 389 segments with a payload of the Ultimate PCAP, LDAP and the TLS that follows StartTLS, 57 have the MBAP shape and none is labelled. Moved off port 502, 358 of the 601 stay recognized; the 243 others are the probes of a scanner that tries the 128 request codes `0x00` to `0x7F`, and their exception responses (`MODBUS-TestDataPart2.pcap`), which only port 502 recognizes. `tests/umas_golden.rs` checks the 180 UMAS frames of `umas.pcap`: two sessions and fourteen values of the function byte. The golden histogram counts 382 ModbusTCP and 181 UMAS labels.

## PostgreSQL

The frontend/backend protocol of PostgreSQL, on TCP only. The module is `packet_parser::parse::application::protocols::postgresql`: `PostgreSqlPacket::try_from` splits a segment into `PostgreSqlMessage`s and decodes the bodies of the main ones; its errors are `PostgreSqlError`, in `packet_parser::errors::application::postgresql`. The largest decoder of the crate had no real frame to exercise it until [#98](https://github.com/Akmot9/Packet-parser/issues/98) brought fourteen captures of Zeek's test corpus, and they rewrote its detection.

### Two message formats, two new types

A typed message is one type byte, a `u32` length that counts itself but not the type byte, and a body; the messages of a segment must tile it exactly. The first messages of a connection have no type byte: a `u32` length equal to the whole payload, then a code, protocol 3.0 or 3.2 for a `StartupMessage`, or the code of `SSLRequest`, `CancelRequest` or `GSSENCRequest`. `try_from` tries the typed form first, then the untyped one, and reports the typed error if both fail.

```rust
pub struct PostgreSqlPacket<'a> {
    pub messages: Vec<PostgreSqlMessage<'a>>,
}

pub struct PostgreSqlMessage<'a> {
    pub message_type: PostgreSqlMessageType,
    pub length: u32,         // typed messages: excludes the type byte
    pub payload: &'a [u8],   // the body
    pub body: PostgreSqlMessageBody<'a>,
}
```

11.6.0 added two variants at the end of `PostgreSqlMessageType`, and one to `PostgreSqlMessageBody`:

- **`PasswordOrSaslResponse`**, the type byte `p`, which PasswordMessage, SASLInitialResponse, SASLResponse and GSSResponse share and only the state of the authentication tells apart; the body stays `Raw`. The decoder used to reject the byte, so every password or SCRAM authentication came out `InvalidMessageType`.
- **`SslResponse`**: the server's one-byte answer to `SSLRequest`, `S` (TLS accepted) or `N`, with the body `PostgreSqlMessageBody::SslResponse { accepted }`. It has neither header nor length, so it is decoded only alone in its segment: `S` and `N` are answers, `SN` is an error.

### Compatible shape on port 5432, strong proof elsewhere

```rust
port_rule("PostgreSQL", Guard::Tcp, is_postgresql_tcp_port, ProbeId::PostgresqlPort),  // 5432
// ... blind cascade, after EtherNet/IP:
rule("PostgreSQL", Guard::Tcp, ProbeId::Postgresql),
```

Both probes are crate-internal, both start from a successful decode, and both demand that **every** message have a *compatible shape*, a body consistent with its type: plain text in a `Query` or a `Parse`, `I`, `T` or `E` in a `ReadyForQuery`, two C-strings in a `ParameterStatus` whatever its name, a known authentication code of the right size, a C-string or a SASL form in a `p` message...

On **TCP 5432** (IANA `postgresql`), or on a port declared with `DecodeAsProtocol::PostgreSql`, `is_plausible_postgresql_payload` stops there: a decode of compatible shape is enough. That is what recognizes the messages that carry no proof of their own: a `Terminate`, a `ReadyForQuery` or a password alone in their segment, and the `S` or `N` answer to `SSLRequest`. Measured on the Zeek corpus, it labels nothing in the HTTP and MySQL sessions replayed on 5432.

**Elsewhere**, `is_likely_postgresql_payload` first discards at constant cost a payload whose first bytes cannot start a message (an untyped length of at least 8, or a printable type byte and a length of at least 4), then demands the compatible shape and, in addition, **one message of strong evidence** at least:

| Message | Strong evidence |
| --- | --- |
| `StartupMessage` | a known parameter (`user`, `database`, `application_name`, `client_encoding`, `options`, `replication`) with a value, and the final NUL |
| `SSLRequest`, `GSSENCRequest` | exactly 8 bytes |
| `CancelRequest` | a secret key of 4 to 256 bytes |
| `Query`, `Parse` | a first word that is an SQL keyword |
| `CommandComplete` | a tag that starts with an SQL keyword |
| `ErrorResponse`, `NoticeResponse` | NUL-terminated fields, among them a message, a five-character SQLSTATE or a severity |
| `ParameterStatus` | a name every server sends (`server_version`, `client_encoding`, `scram_iterations`, `search_path`...), the value possibly empty |
| Authentication | Ok, cleartext, Kerberos, SCM, GSS or SSPI at their fixed size, MD5 with its salt, the list of SASL mechanisms, SCRAM's server-first (`r=…,s=…,i=…`) and server-final (`v=…`) messages |
| `p` | an MD5 hash (`md5` and 32 hexadecimal digits), SCRAM's client-first (`SCRAM-SHA-256`, then `n,,n=…,r=…`) or client-final (`c=…,r=…,p=…`) message |

A cleartext password has no form to recognize: it is compatible, never a proof. Until 11.6.0 the blind probe also refused server replies whose `ParameterStatus` had an empty value (the `application_name` of a client that gave none) or a recent name (`scram_iterations`, `search_path`), and took only an AuthenticationSASL as proof; on the Zeek corpus, those real segments came out `"Unknown"`.

The `N` of frame 6 of `pcaps_exemple/protocols/postgresql/psql-login.pcap` needs the port, or a declared one (*tested*):

```rust
{{#include ../examples/src/shared.rs:postgresql_ssl_answer}}
```

The SASLInitialResponse of frame 12 of the same capture is a `p` message of strong evidence (*tested*):

```rust
{{#include ../examples/src/shared.rs:postgresql_password_message}}
```

### Oracle: 276 segments

`tests/postgresql_golden.rs` runs the fourteen captures of `pcaps_exemple/protocols/postgresql/` against tshark 4.6.6 without TCP reassembly, the view of a stateless parser (`tools/postgresql_oracle.sh`, frozen in `tests/data/postgresql_tshark_oracle.tsv`): twelve real psql sessions (loopback, a VM against AWS RDS, an application in containers, a Windows workstation) and two negatives, HTTP and MySQL replayed on port 5432. Of the 331 segments with a payload, 276 are PostgreSQL, and their 558 messages have tshark's types and lengths, the 8 SSL answers included. Replayed off port 5432, 262 of them are still recognized by the blind probe; the 14 others are the segments without strong evidence, 8 SSL answers, 5 `Terminate` and 1 `ReadyForQuery`, each alone. On the negatives tshark labels 6 segments `pgsql`, the crate none, and nine mutations of two real frames (lengths, protocol version, final NUL, type byte, truncation, trailing byte) are rejected. The golden histogram counts 278 PostgreSQL labels: the 276 segments, and 2 retransmissions that tshark does not dissect.

## STP: the one label without a transport

A Spanning Tree BPDU has no L3, so it can never reach this table. The pipeline checks it from the link layer (802.3 length field, bridge group address, LLC `42-42-03`, valid BPDU) and labels the flow `"STP"` when every other layer is `None`.

## Tunnels take the label

When the transport payload is a recognized encapsulation (CAPWAP, VXLAN, Geneve, GTP-U) the outer flow's `application_protocol` is the tunnel name, and the real conversation is in `inner`. Next chapter.
