# Application

The application layer is where the rule "the port never decides alone" is put to the test, and where most of the design decisions of the crate were taken after real captures proved a naive approach wrong.

## A classification, not a decode

```rust
pub struct Application {
    pub protocol: ApplicationProtocol,   // Dns, Tls, Http, Unknown...
}
```

`PacketFlow::application` is a **label**. It says *which* protocol the transport payload looks like, not what the message contains. Since 12.0.0 the label is an enum, `ApplicationProtocol`, `#[non_exhaustive]`, with one variant per label: a `match` on it is checked by the compiler, where 11.x compared strings (`application_protocol: &'static str`). It is `Copy`, so classification still costs no allocation. `protocol.label()` gives the text the crate has always written, byte for byte (`"DNS"`, `"IEC 104"`, `"BACnet/IP"`); `Display` and the JSON output write that text, under the key `application_protocol` as before, and `FromStr` reads it back, refusing a text that is no label (`UnknownApplicationLabel`). `ApplicationProtocol::ALL` lists the 55 labels of the crate: the 47 of the dispatch table, the six tunnels, `Stp` and `Unknown`.

Since 13.0.0 one more variant, `Custom(&'static str)`, carries the label of a [parser added by the caller](./custom_parsers.md). It is not in `ALL`, and `FromStr` does not build it: the text alone does not say which parser gave it. `ParseConfig::application_protocol` (13.1.0) reads a label back with the configuration that produced it, `Custom` included. A variant that carries data takes away the discriminants of the others, so a cast `protocol as u8` no longer compiles. The rewrite of a 11.x `match` is in `MIGRATION-12.md`, that of a cast in `MIGRATION-13.md`, in the crate repository.

For the actual decode, every protocol has a module under `packet_parser::parse::application::protocols` (except ESP, whose `EspPacket` is a transport decoder, in `packet_parser::parse::transport::protocols::esp`), and every one of them is a `TryFrom<&[u8]>` with its own struct and error:

```rust
use packet_parser::parse::application::protocols::dns::DnsPacket;

if let Some(transport) = &flow.transport
    && let Some(payload) = transport.payload
    && let Ok(dns) = DnsPacket::try_from(payload)
{
    // counts: questions, answers, authority records, additional records
    println!("{} questions, {} answers", dns.header.counts[0], dns.header.counts[1]);
}
```

Why separate the two? Because the label is the thing every consumer needs on every packet (a flow matrix, a protocol histogram), and it must be cheap and stateless. Decoding DNS names or TLS extensions allocates and only some consumers need it.

## Supported protocols

The [Protocols](./protocols.md) page has one row per label: its detection route, its page, its oracle and the release it arrived in.

The dispatch table gives 47 labels: [DNS](./dns.md) (plus its mDNS and LLMNR forms), [TLS](./tls.md), SNMP, [NTP](./ntp.md), DHCP, DHCPv6, [HTTP](./http.md) (requests and, since 11.7.0, responses), MQTT, [PostgreSQL](./postgresql.md), FTP, SMTP, NNTP, SSH (identification string only), SSDP, NetBIOS (NBNS, NBSS), OpenVPN, [Modbus/TCP and UMAS](./modbus.md) (and, since 12.0.0, Modbus over UDP 502), EtherNet/IP, OPC UA, S7Comm, COTP, AMS, [GIOP](./giop.md), SRVLOC, [ASTERIX](./asterix.md) (eleven categories), QUIC, Bitcoin, [PTP](./ptp.md) (IEEE 1588, on UDP 319/320), and, since 11.6.0, [DNP3](./dnp3.md), [IEC 60870-5-104](./iec104.md), [BACnet/IP](./bacnet.md), [RADIUS](./radius.md), [RDP](./rdp.md), [WireGuard](./wireguard.md), [DIS](./dis.md), [STANAG 5066 SIS](./stanag5066.md), [RTPS](./rtps.md), [IKE](./ike.md), and [ESP](./esp.md) inside UDP 4500 with its one-byte NAT-keepalive; since 11.8.0, [Valmet DNA](./valmet_dna.md), the proprietary process network of Metso and Valmet distributed control systems; since 13.0.0, [Java RMI](./java_rmi.md). STP gets its label from the link layer (see below).

Some protocols are decoded below the table and get no label: PTP straight over Ethernet (EtherType `0x88F7`), [GOOSE](./goose.md) (`0x88B8`) and [LLDP](./lldp.md) (`0x88CC`) are [internet layers](./network.md), and native ESP, IP protocol 50, is a transport layer whose SPI and sequence number are in `TransportDetails::Esp`, with no application payload, like ICMP.

A probed payload that matches nothing is labelled `"Unknown"`. An empty payload (a pure ACK) is not probed at all and `application` stays `None`.

## How the label is chosen: one ordered table

The words of this chapter, probe, rule, guard, blind, terminal port, are defined in the [Glossary](./glossary.md).

The first version of the crate was a cascade of `if XxxPacket::try_from(payload).is_ok() { return "Xxx" }`, spread over two files, with port guards applied unevenly and one override where the port beat the content. Three problems showed up on real traffic:

- **false positives**: NTP probed on TCP labelled TLS encrypted alerts "NTP" (`0x15` is a plausible LI/VN/mode byte); a BOOTP packet looked like an SLP header; FTP/SMTP/NNTP replies are byte-for-byte identical;
- **double probing**: the same parser ran twice on the same payload (once port-guarded, once blind);
- **pathological cost**: a 64 KiB GRO segment was fully parsed by every probe in the cascade.

The dispatch is now **one ordered table**, `RULES`, in `src/parse/dispatch/rules.rs` (`src/parse/dispatch.rs` until 11.8.2 split it into `rules.rs`, `probes.rs`, `ports.rs` and `tests.rs`). Each rule has:

```rust
struct Rule {
    label: ApplicationProtocol,
    guard: Guard,                              // Tcp, Udp or Any: the transports the RFC allows
    ports: Option<fn(Option<u16>) -> bool>,    // optional port guard (either port)
    ports_veto: Option<fn(Option<u16>) -> bool>, // ports on which the rule must NOT fire
    probe: ProbeId,                            // the content check
    terminal_on_port: bool,                    // port reserved by RFC: the verdict is final
}
```

and the invariants are:

1. **A rule with a port guard labels only if port *and* content agree.** The port alone never decides. `OPC UA` on port 4840 is still checked by `OpcuaPacket::try_from`.
2. **Every probe runs at most once per payload.** Failures are memoized by `ProbeId` in a bitmask, one bit of a `u128` for each of the 66 probes (a `u64` until 12.1.0, which had 59): a rule sharing a probe with an earlier one (port-priority then blind fallback) never re-runs it.
3. **A probe judges the bytes its decoder will read; only the text probes stop at `PROBE_CAP`** ([Limits](./limits.md#what-the-crate-chooses-not-to-do))**.** Since 11.7.0 every other probe runs on the real payload ([#184](https://github.com/Akmot9/Packet-parser/issues/184), [#185](https://github.com/Akmot9/Packet-parser/issues/185)): most decoders want it tiled to the last byte (SNMP, Modbus/TCP, ASTERIX, DIS, RTPS...) or covered by a declared length that must fit in it (NBSS, DNS over TCP, TLS...), and a prefix proves neither. The probes of the four text protocols, FTP, SMTP, NNTP and HTTP, keep the cap, `PROBE_CAP` = 18 432 bytes (18 KiB). They validate their text over its whole length: in UTF-8 for FTP and SMTP, the first line in UTF-8 and the octets of what follows for NNTP, the head in UTF-8 for HTTP. The fuzz oracle of FTP, SMTP and NNTP off their ports, `fuzz/oracles/text_protocols.rs`, copies the cap so that it judges the same bytes as their probes. What lies beyond the cap is not seen: a text message is judged on its first 18 432 bytes alone.

   Before 11.7.0, 43 of the 57 probes read only that prefix, the bound that [#20](https://github.com/Akmot9/Packet-parser/issues/20) put on the cost of 64 KiB GRO segments. Beyond the prefix, a probe could label what its decoder refuses, or miss a complete message:

   | Payload | Before 11.7.0 | The fault |
   |---|---|---|
   | an SNMP GetResponse of 18 432 bytes followed by a hundred null bytes | `"SNMP"` | the decoder refuses it |
   | an exact DNS response of 20 041 bytes | `"Unknown"` | a complete message, missed |
   | a TLS 1.2 record of 18 437 bytes, the maximum of RFC 5246 §6.2.3 | `"Unknown"` | a complete message, missed |

   Reading everything keeps the cost linear. A UDP payload is bounded by its datagram, and on TCP each decoder stops at its first structural error. The measures, in release:

   | Input | Cost | Source |
   |---|---|---|
   | a 60 000-byte TCP segment, through `parse()` | at most 31 µs | [#185](https://github.com/Akmot9/Packet-parser/issues/185) |
   | 65 505 bytes of ASTERIX records | 2.7 ms, 3.8 times the cost of the 18 432 bytes of the cap | [#184](https://github.com/Akmot9/Packet-parser/issues/184) |
   | the worst DNS case: a 255-byte name pointed at by 10 871 questions, in 65 497 bytes | 39 ms | [#184](https://github.com/Akmot9/Packet-parser/issues/184) |

   The bound on names is what keeps the DNS cost linear (see [Tightening a blind probe](./application.md#tightening-a-blind-probe)). No label of the corpus moved: apart from six RTPS datagrams, already read whole, none of its 210 captures carries a payload longer than the cap.
4. **The order of the table is the priority**, inspectable, testable, and locked by a golden snapshot over the reference captures.

![One rule of the table: the transport payload, a TLS ClientHello on TCP 54322 to 443, passes the transport guard, then the port guard, then the content probe, and gets the label TLS; a failed gate moves on to the next rule, the last rule falls through to Unknown, an empty payload is not probed](images/application/dispatch_rule.svg)

Each rule is three gates in a row, and a payload stops at the first rule whose three gates open. The TLS rule has no port guard, so its second gate always opens: the ClientHello is labelled by its content, whatever the port. A probe that fails is not re-run by a later rule that shares it. Two outcomes do not come from a rule: an empty payload is never probed (`application: None`), and a payload no rule matched is `"Unknown"`, except on the terminal mDNS and LLMNR ports, where a failed probe ends the search with `None` (rules 14 and 15 below).

### Reading the table

In 13.1.1 the table has 73 rules in two blocks: the 45 rules of the port block, then a blind cascade of 28. 12.0.0 had 65, 40 then 25. Eight rules came in with 13.x:

| Release | Rules | Why |
| --- | --- | --- |
| 13.0.0 | 35 and 66, Java RMI on TCP 1099, then blind after GIOP | the new decoder ([#313](https://github.com/Akmot9/Packet-parser/issues/313)) |
| 13.1.0 | 3, DHCP on UDP 67 and 68 | a DHCP message whose `secs` equals the datagram length came out DIS, even from 68 to 67 ([#294](https://github.com/Akmot9/Packet-parser/issues/294)) |
| 13.1.0 | 4 and 5, SRVLOC on UDP and TCP 427 | an SLPv1 SrvTypeRqst of 20 bytes came out RADIUS on UDP 427 ([#294](https://github.com/Akmot9/Packet-parser/issues/294)) |
| 13.1.0 | 24, QUIC long header of any version on UDP 443 | a Version Negotiation or a reserved version came out Unknown ([#299](https://github.com/Akmot9/Packet-parser/issues/299)) |
| 13.1.0 | 57, EtherNet/IP on UDP | the blind EtherNet/IP rule split in two: on TCP, several complete messages may tile a segment ([#288](https://github.com/Akmot9/Packet-parser/issues/288)) |
| 13.1.0 | 64, SSH after other lines | a server may send lines before its banner (RFC 4253 §4.2); this rule comes after HTTP ([#307](https://github.com/Akmot9/Packet-parser/issues/307)) |

Every rule from DHCP on is therefore lower than in an edition of the book for 12.x: compare rules by label, not by number. The port block also holds four rules without a port guard that must come early: the blind S7Comm rule, which must beat COTP even on port 102, and the three rules that recognize FTP, SMTP and NNTP off their ports. The source writes a rule with one of two constructors, or with the whole struct when a field differs from their defaults:

```rust
static RULES: &[Rule] = &[
    port_rule(ApplicationProtocol::Snmp, Guard::Udp, is_snmp_udp_port, ProbeId::Snmp),
    port_rule(ApplicationProtocol::Dhcpv6, Guard::Udp, is_dhcpv6_udp_port, ProbeId::Dhcpv6),
    rule(ApplicationProtocol::S7Comm, Guard::Tcp, ProbeId::S7Comm),
    // ...
    Rule {
        label: ApplicationProtocol::Ftp,
        guard: Guard::Tcp,
        ports: None,
        ports_veto: Some(is_text_protocol_port),
        probe: ProbeId::FtpUnambiguous,
        terminal_on_port: false,
    },
    // ...
    port_rule(ApplicationProtocol::Ntp, Guard::Udp, is_ntp_udp_port, ProbeId::Ntp),
    // --- blind cascade, with the transport guards the RFCs impose ---
    rule(ApplicationProtocol::Ntp, Guard::Udp, ProbeId::NtpBlind),
    // ...
    rule(ApplicationProtocol::Mqtt, Guard::Tcp, ProbeId::Mqtt),
];
```

Since 12.0.0 the label of a rule is a variant of `ApplicationProtocol`, where 11.x wrote the text: a rule cannot give a label the enum does not have. The tables below show the text, `label()`.

Here is the whole table, in order. A port guard matches when either port of the segment or datagram is in its list; a veto skips the rule when either port is in the veto list. Every probe reads the whole payload, except the text probes of rules 8 to 13 and 63, which read its first `PROBE_CAP` bytes (invariant 3).

**Port rules**

| # | Label | Guard | Ports | `ProbeId` | The probe |
| --- | --- | --- | --- | --- | --- |
| 1 | SNMP | `Udp` | 161, 162 | `Snmp` | `SnmpPacket::try_from` |
| 2 | DHCPv6 | `Udp` | 546, 547 | `Dhcpv6` | `Dhcpv6Packet::try_from` |
| 3 | DHCP | `Udp` | 67, 68 | `Dhcp` | `DhcpPacket::try_from` |
| 4 | SRVLOC | `Udp` | 427 | `Srvloc` | `SrvlocPacket::try_from` |
| 5 | SRVLOC | `Tcp` | 427 | `Srvloc` | the same probe |
| 6 | S7Comm | `Tcp` | none | `S7Comm` | `S7CommPacket::try_from`: TPKT, COTP DT and S7 header together |
| 7 | COTP | `Tcp` | 102 | `CotpTpkt` | a COTP TPDU behind the first TPKT header (`cotp_from_tpkt`) |
| 8 | FTP | `Tcp` | 21 | `Ftp` | `FtpMessage::try_from`, first `PROBE_CAP` bytes |
| 9 | SMTP | `Tcp` | 25, 587 | `Smtp` | `SmtpMessage::try_from`, first `PROBE_CAP` bytes |
| 10 | NNTP | `Tcp` | 119 | `Nntp` | `NntpMessage::try_from`, first `PROBE_CAP` bytes |
| 11 | FTP | `Tcp` | vetoed on 21, 25, 587, 119 | `FtpUnambiguous` | a complete command whose verb only FTP has: RETR, STOR, PASV, APPE, RNFR, RNTO, MKD, CDUP, EPSV, EPRT, NLST; first `PROBE_CAP` bytes |
| 12 | SMTP | `Tcp` | vetoed on 21, 25, 587, 119 | `SmtpUnambiguous` | a complete command whose verb only SMTP has: EHLO, HELO, MAIL, RCPT; first `PROBE_CAP` bytes |
| 13 | NNTP | `Tcp` | vetoed on 21, 25, 587, 119 | `NntpUnambiguous` | a complete command whose verb only NNTP has: ARTICLE, XOVER, XHDR, IHAVE, LISTGROUP, NEWGROUPS, NEWNEWS; first `PROBE_CAP` bytes |
| 14 | [mDNS](./dns.md) | `Udp` | 5353, terminal | `Mdns` | `DnsPacket::try_from_mdns` |
| 15 | [LLMNR](./dns.md) | `Udp` | 5355, terminal | `Llmnr` | `DnsPacket::try_from_llmnr` |
| 16 | SSDP | `Udp` | 1900 | `Ssdp` | `SsdpPacket::try_from` |
| 17 | NBNS | `Udp` | 137 | `Nbns` | `NbnsPacket::try_from` |
| 18 | NBSS | `Tcp` | 139, 445 | `Nbss` | `NbssPacket::try_from` |
| 19 | OpenVPN | `Udp` | 1194 | `OpenVpnUdp` | `OpenVpnPacket::try_from` |
| 20 | OpenVPN | `Tcp` | 1194 | `OpenVpnTcp` | `OpenVpnPacket::from_tcp_stream`: the length-prefixed form |
| 21 | AMS | `Tcp` | 48898 | `AmsTcp` | `AmsPacket::try_from_tcp`: the 6-byte AMS/TCP header, then the first AMS message |
| 22 | AMS | `Udp` | 48899 | `Ams` | `AmsPacket::try_from`: a bare AMS header |
| 23 | QUIC | `Udp` | 443 | `QuicShortHeader` | `is_plausible_short_header`: the 1-RTT header is opaque by design |
| 24 | QUIC | `Udp` | 443 | `QuicLongHeaderPort` | `QuicPacket::is_port_match`: QUIC v1 and Version Negotiation read whole, any other version by its invariants (RFC 8999 §5.1) |
| 25 | OPC UA | `Tcp` | 4840, 12001 | `Opcua` | `OpcuaPacket::try_from`: the last chunk may be partial, or cut in its header |
| 26 | [DNS](./dns.md) | `Tcp` | 53 | `DnsTcp` | `DnsPacket::try_from_tcp`: the length-prefixed form |
| 27 | [DNS](./dns.md) | `Udp` | 53 | `Dns` | `DnsPacket::try_from`: the datagram form |
| 28 | [PTP](./ptp.md) | `Udp` | 319, 320 | `Ptp` | `PtpPacket::try_from_udp` |
| 29 | [DIS](./dis.md) | `Udp` | 3000 | `DisLenient` | `DisPacket::try_from_lenient` |
| 30 | [RADIUS](./radius.md) | `Udp` | 1812, 1813, 1645, 1646, 3799 | `Radius` | `RadiusPacket::try_from` |
| 31 | [BACnet/IP](./bacnet.md) | `Udp` | 47808 to 47823 | `Bacnet` | `BacnetPacket::try_from` |
| 32 | [Valmet DNA](./valmet_dna.md) | `Udp` | 2517, 4516, 4517 | `ValmetDna` | `ValmetDnaPacket::is_port_udp_match`: a coherent header, with a known family at its exact size or an unknown one, or the 42-byte beacon (`TimeBeacon`) |
| 33 | [RDP](./rdp.md) | `Tcp` | 3389 | `Rdp` | `RdpPacket::try_from` |
| 34 | [IEC 104](./iec104.md) | `Tcp` | 2404 | `Iec104` | `Iec104Packet::try_from` |
| 35 | [Java RMI](./java_rmi.md) | `Tcp` | 1099 | `JavaRmi` | `JavaRmiPacket::try_from`: any JRMP message, the one-byte ones, the DgcAck and the ProtocolAck included |
| 36 | [PostgreSQL](./postgresql.md) | `Tcp` | 5432 | `PostgresqlPort` | `is_plausible_postgresql_payload`: a decode of compatible shape |
| 37 | [IKE](./ike.md) | `Udp` | 500, 4500 | `Ike` | `IkePacket::from_udp`, bare or behind the non-ESP marker |
| 38 | [ESP](./esp.md) | `Udp` | 4500 | `EspNatT` | `UdpEncapsulation::classify` finds ESP and `EspPacket::try_from` accepts it |
| 39 | [NAT-keepalive](./esp.md#in-udp-4500-behind-a-nat) | `Udp` | 4500 | `NatKeepalive` | `UdpEncapsulation::classify` finds the one byte `0xFF` |
| 40 | [STANAG 5066](./stanag5066.md) | `Tcp` | 5066 | `Stanag5066` | `SisPdu::try_from` |
| 41 | [UMAS](./modbus.md) | `Tcp` | 502 | `Umas` | `UmasPacket::is_tcp_match`: MBAP headers that tile the segment, each of function `0x5A` with a UMAS header |
| 42 | [ModbusTCP](./modbus.md) | `Tcp` | 502 | `ModbusTcp` | `ModbusTcpPacket::try_from`: the envelope alone |
| 43 | [ModbusUDP](./modbus.md#modbus-over-udp) | `Udp` | 502 | `ModbusTcp` | rule 42's probe |
| 44 | [WireGuard](./wireguard.md) | `Udp` | 51820 | `WireGuardPort` | `WireGuardPacket::is_port_udp_match` |
| 45 | [NTP](./ntp.md) | `Udp` | 123 | `Ntp` | `NtpPacket::try_from`: the decoder alone |

**Blind cascade**

| # | Label | Guard | Ports | `ProbeId` | The probe |
| --- | --- | --- | --- | --- | --- |
| 46 | [NTP](./ntp.md) | `Udp` | none | `NtpBlind` | `NtpPacket::is_blind_udp_match` |
| 47 | [RTPS](./rtps.md) | `Udp` | none | `Rtps` | magic `RTPS` or `RTPX`, then `RtpsPacket::try_from` |
| 48 | [Valmet DNA](./valmet_dna.md) | `Udp` | none | `ValmetDnaBlind` | `ValmetDnaPacket::is_blind_udp_match`: one of the two known message families, at its exact size |
| 49 | [ASTERIX](./asterix.md) | `Udp` | none | `Asterix` | `AsterixPacket::try_from` |
| 50 | [DIS](./dis.md) | `Udp` | none | `Dis` | `DisPacket::try_from`: the PDUs tile the datagram |
| 51 | [DNP3](./dnp3.md) | `Any` | none | `Dnp3` | `Dnp3Packet::try_from` |
| 52 | [RADIUS](./radius.md) | `Udp` | none | `Radius` | rule 30's probe |
| 53 | [BACnet/IP](./bacnet.md) | `Udp` | none | `Bacnet` | rule 31's probe |
| 54 | Bitcoin | `Tcp` | none | `Bitcoin` | `BitcoinPacket::is_tcp_match`: complete messages that tile the segment, all on the network of the first |
| 55 | OPC UA | `Tcp` | none | `OpcuaBlind` | `OpcuaPacket::is_blind_tcp_match`: chunks that tile the segment, the last one partial of at most 16 MiB |
| 56 | EtherNet/IP | `Tcp` | none | `EthernetIpTcp` | `EtherNetIpPacket::is_tcp_match`: complete messages that tile the segment |
| 57 | EtherNet/IP | `Udp` | none | `EthernetIp` | `EtherNetIpPacket::try_from`: one message, whose length covers the datagram |
| 58 | [PostgreSQL](./postgresql.md) | `Tcp` | none | `Postgresql` | `is_likely_postgresql_payload`: compatible shape and a strong proof |
| 59 | [DNS](./dns.md) | `Udp` | none | `DnsBlind` | `DnsPacket::is_blind_udp_match` |
| 60 | SNMP | `Any` | none | `Snmp` | rule 1's probe |
| 61 | [TLS](./tls.md) | `Tcp` | none | `Tls` | `TlsPacket::try_from` |
| 62 | SSH | `Tcp` | none | `Ssh` | a segment that starts with `SSH-`, then `SshPacket::try_from` |
| 63 | [HTTP](./http.md) | `Tcp` | none | `Http` | `HttpRequest::try_from` or `HttpResponse::try_from`, first `PROBE_CAP` bytes |
| 64 | SSH | `Tcp` | none | `SshAfterLines` | `SshPacket::try_from`: the banner after other lines of text, at most 1 024 bytes of them (`SSH_MAX_PRELUDE_LENGTH`) |
| 65 | [GIOP](./giop.md) | `Tcp` | none | `Giop` | magic `GIOP`, then `GiopPacket::try_from` |
| 66 | [Java RMI](./java_rmi.md) | `Tcp` | none | `JavaRmiBlind` | `JavaRmiPacket::try_from` and `is_self_identifying`: a stream header, a Call or a Return |
| 67 | DHCP | `Udp` | none | `Dhcp` | rule 3's probe |
| 68 | SRVLOC | `Any` | none | `Srvloc` | rule 4's probe |
| 69 | [UMAS](./modbus.md) | `Tcp` | none | `Umas` | rule 41's probe |
| 70 | [ModbusTCP](./modbus.md) | `Tcp` | none | `ModbusTcpBlind` | `ModbusTcpPacket::is_blind_tcp_match` |
| 71 | QUIC | `Udp` | none | `QuicLongHeader` | `QuicPacket::is_blind_udp_match`: a QUIC v1 long header, whose length fits in the datagram |
| 72 | [WireGuard](./wireguard.md) | `Udp` | none | `WireGuardBlind` | `WireGuardPacket::is_blind_udp_match` |
| 73 | MQTT | `Tcp` | none | `Mqtt` | `MqttPacket::try_from` |

Seven probes serve more than one rule. `Srvloc` serves three, its UDP and TCP ports and the blind rule (4, 5, 68), and `ModbusTcp` two, port 502 on TCP and on UDP (42, 43). Five others serve a port rule that gives them priority and a blind rule further down: `Snmp` (1, 60), `Dhcp` (3, 67), `Radius` (30, 52), `Bacnet` (31, 53) and `Umas` (41, 69). A failure on the port is memoized, so the blind rule does not run it again. Some probes are crate-internal: `cotp_from_tpkt`, the three verb checks, `is_plausible_short_header`, the `is_blind_*`, `is_port_*` and `is_tcp_match` functions and the two PostgreSQL predicates. A consumer reaches them through `parse`, which is where the label is decided. In the real file most lines carry a comment that says why they are there, often with the issue, the capture frame or the RFC section behind them. That is the point of a table over a cascade: the semantics of the order are written down and cannot silently move.

### Three detection routes

When choosing where a new protocol goes, the question is: *can a valid payload of this protocol also be a valid payload of another protocol the crate already detect, or of arbitrary text?*

| Route | When | Example |
| --- | --- | --- |
| **Blind probe** (`rule`) | the bytes identify themselves: literal marker (`HTTP/`, `GIOP`, `SSH-`, `RTPS`), CRCs (DNP3), tight binary header with plausible values (DNS, NTP), announced lengths that must cover the payload exactly (RADIUS, BACnet/IP, and PostgreSQL, which also wants a message of strong evidence), or a structure that must tile the datagram to the last byte (ASTERIX, DIS) | `rule(ApplicationProtocol::Tls, Guard::Tcp, ..)` |
| **Port-guarded** (`port_rule`) | the signature is weak or ambiguous even with perfect checks: identical reply syntax (FTP/SMTP/NNTP), loose headers (DHCPv6, AMS, COTP, QUIC short header, PTP, IEC 104, STANAG 5066, IKE), a stack other protocols share (RDP: TPKT, COTP and MCS are also T.120's), relaxed validation (mDNS) | `port_rule(ApplicationProtocol::Ftp, Guard::Tcp, is_ftp_tcp_port, ..)` |
| **Strong signature with transport constraint** | recognizable off-port, but only defined on one transport | S7Comm: the full TPKT + COTP-DT + S7 envelope is probed on any TCP port, and the same bytes on UDP never yield the label |

Whatever the route, the **transport guard** is always there: the RFC says on which transport a protocol exists, and probing it elsewhere only produces false positives.

A protocol with a standard port and a signature strong enough elsewhere takes two routes at once, one rule each. With **one probe**, the port rule only gives it priority over the cascade: SNMP, DHCP, SRVLOC, RADIUS, BACnet/IP and UMAS. DHCP and SRVLOC got theirs in 13.1.0, when DIS and RADIUS, earlier in the cascade, took some of their messages. With **two probes**, the port rule keeps a lenient decoder and the blind rule a stricter one, because the standard port carries real traffic that no blind probe could prove: DNS on UDP 53 (`Dns`, `DnsBlind`, below), NTP on 123 (`Ntp`, `NtpBlind`), Modbus/TCP on 502 (`ModbusTcp`, `ModbusTcpBlind`), PostgreSQL on 5432 (`PostgresqlPort`, `Postgresql`), DIS on 3000 (`DisLenient`, `Dis`), WireGuard on 51820 (`WireGuardPort`, `WireGuardBlind`) and [Valmet DNA](./valmet_dna.md) on UDP 2517, 4516 and 4517, ports observed on a process network rather than registered (`ValmetDna`, `ValmetDnaBlind`). Since 13.x, OPC UA on 4840 and 12001 (`Opcua`, `OpcuaBlind`) and [Java RMI](./java_rmi.md) on 1099 (`JavaRmi`, `JavaRmiBlind`) join them. NTP, Modbus/TCP and PostgreSQL have their section below.

Three protocols have more than one rule for another reason:

| Protocol | Rules | Why |
| --- | --- | --- |
| QUIC | 23 and 24 on UDP 443, 71 on any UDP port | the opaque short header and a long header of any version only on 443; off it, the long header of QUIC v1 alone |
| SSH | 62 before HTTP, 64 after it | a segment that starts with its banner is tried first; a banner behind other lines comes after HTTP, so that an HTTP response whose body quotes a banner stays HTTP |
| EtherNet/IP | 56 on TCP, 57 on UDP | TCP may put several messages in a segment; a UDP datagram carries one |

### Tightening a blind probe

A blind probe is only as good as the captures it has been confronted with. The defense corpus added in 11.4.0 showed two probes accepting traffic that was not theirs:

- **SRVLOC**: 829 PTPv2 `Delay_Req` messages were labelled SRVLOC. Their header has exactly the shape of an SLPv1 one (version 1, a `SrvRply` function, a length equal to the datagram). The SLPv1 language field must now be a two-letter ASCII ISO 639 code (RFC 2165 §7); anything else is `SrvlocPacketParseError::InvalidLanguageCode`.
- **DNS**: off port 53, any UDP datagram whose first twelve bytes formed a plausible empty header was DNS, among them 37 datagrams of a radar stream. The blind rule now runs its own probe, `ProbeId::DnsBlind`: the sections must consume the datagram exactly and carry at least one question or record. Port 53 keeps the tolerant decoder, so the two DNS rules no longer share a probe.

In both cases the rule kept its place in the table; what changed is what the probe demands. Both corrections only removed labels: in 11.4.0 the 866 frames concerned came out as `"Unknown"`, and the golden histogram moved on those frames and nowhere else. The 829 `Delay_Req` have had their own label since 11.5.0, `"PTP"`, from the port rule of UDP 319; the 37 radar datagrams are still `"Unknown"`.

11.6.0 did the same for two blind rules that ran a whole decoder, NTP ([#164](https://github.com/Akmot9/Packet-parser/issues/164)) and Modbus/TCP ([#167](https://github.com/Akmot9/Packet-parser/issues/167)), and split them as DNS had been split: the tolerant decoder now runs in a port rule on the standard port, where the labels of the corpus did not move, and the blind rule has a stricter probe of its own. The [NTP](./ntp.md) and [Modbus/TCP](./modbus.md) sections give the details.

11.7.0 came back to the DNS blind probe ([#184](https://github.com/Akmot9/Packet-parser/issues/184), [#196](https://github.com/Akmot9/Packet-parser/issues/196)). The probe judged only the first `PROBE_CAP` bytes, with two consequences:

- Sections that ended exactly at byte 18 432 were enough, whatever followed. A hundred null bytes after a response still came out `"DNS"`, although the probe demands sections that consume the datagram exactly.
- An exact response of 20 041 bytes stayed `"Unknown"`.

The probe now reads the whole datagram, as the NTP blind probe does (invariant 3).

Reading more needed a bound. The length of a domain name was not limited, and each name pointing to the same QNAME read it again in full, in a time quadratic in the size of the message. A forged response of 18 425 bytes, with a QNAME of 4 602 labels and 767 records pointing to it, cost 193 ms to `DnsPacket::try_from`, and came out `"DNS"`.

A name is now at most 255 bytes on the wire, pointers followed (RFC 1035 §3.1). A longer one makes `DnsPacket::try_from` fail in a few microseconds, and its mDNS, LLMNR and TCP variants with it. The error is `DnsQueryParseError::OutOfBoundParse`, the one of a name that runs past the message. tshark shows such a name as `<Name too long>` and goes on; the crate no longer labels the message. No frame of the corpus changed. The [DNS](./dns.md#names-and-compression) page has the rules.

ASTERIX, whose data blocks must tile the datagram, was judged on the same prefix. It has read the whole datagram since [#184](https://github.com/Akmot9/Packet-parser/issues/184).

13.1.0 tightened two more probes, after a review of the decoders against their specifications ([#288](https://github.com/Akmot9/Packet-parser/issues/288)). Both read only the start of a TCP segment:

| Probe | Before 13.1.0 | Since 13.1.0 |
| --- | --- | --- |
| UMAS (rules 41, 69) | the first MBAP header alone: a UMAS header followed by text came out `"UMAS"` on any TCP port | MBAP headers that tile the segment, each of function `0x5A` with a UMAS header ([#295](https://github.com/Akmot9/Packet-parser/issues/295)) |
| OPC UA, blind (rule 55) | three letters of message type and one of chunk type: `CLOCK 12:00:00` came out `"OPC UA"` | chunks that tile the segment, the last one partial of at most 16 MiB, `OPCUA_BLIND_MAX_PARTIAL_SIZE` ([#296](https://github.com/Akmot9/Packet-parser/issues/296)) |

The 181 UMAS frames and the 187 OPC UA frames of the corpus kept their labels.

Two probes went the other way, because TCP does not keep the boundaries of messages. EtherNet/IP and Bitcoin wanted the declared length to cover the whole segment: two RegisterSession, or `verack` then `ping`, in one segment came out `"Unknown"`, even on TCP 44818. Since 13.1.0 complete messages that tile the segment are recognized, each one valid, as PostgreSQL and OPC UA already were. A last message cut by the end of the segment is still refused, as these probes are blind. The decoders did not change: `TryFrom` reads one message.

On its ports, OPC UA accepts the reverse case: a complete chunk followed by 1 to 7 bytes of the next one, cut by TCP in its header. Those bytes must start one of the seven message types, `HEL`, `ACK`, `ERR`, `RHE`, `OPN`, `MSG` or `CLO`. 13.1.0 let them in ([#296](https://github.com/Akmot9/Packet-parser/issues/296)); 13.1.1 checks them from the first byte, where 13.1.0 checked nothing below three bytes ([#333](https://github.com/Akmot9/Packet-parser/issues/333), found by the nightly fuzz).

The reverse defect exists too, a parser refusing its own traffic, and 11.5.0 fixed one in SRVLOC ([#131](https://github.com/Akmot9/Packet-parser/issues/131)): the Char Encoding field of an SLPv1 header was read on one byte instead of two (RFC 2165 §7), which shifted everything after it, the XID and, in a `DAAdvert`, the error code, URL and scope list; the 26 SLPv1 `DAAdvert` of a real capture came out `"Unknown"`. The header now has `SrvlocHeaderV1::char_encoding` (`u16`, the IANA MIBenum, 106 for UTF-8); the old single-byte `encoding` is deprecated, a change that on its own calls for a minor version, not a patch. 11.6.0 fixed four more, all with real frames: NTP replies refused because of the client's clock ([#161](https://github.com/Akmot9/Packet-parser/issues/161)), timestamps without their era ([#162](https://github.com/Akmot9/Packet-parser/issues/162)), reference ids and polls an implementation does send ([#165](https://github.com/Akmot9/Packet-parser/issues/165)), and the PostgreSQL `p` message of every password or SCRAM authentication ([#98](https://github.com/Akmot9/Packet-parser/issues/98)).

The same review fixed parsers that refused their own traffic in 13.0.0 and 13.1.0. Each fault left a valid message `"Unknown"`, often on the protocol's own port:

| Protocol | The refused traffic | Issue |
| --- | --- | --- |
| NBNS | the negative response to a name query (rcode 3), and the refresh with opcode 9 | [#292](https://github.com/Akmot9/Packet-parser/issues/292) |
| DHCPv6 | Relay-Forward and Relay-Reply were read with the client header; their 34-byte header is now `Dhcpv6Packet::relay` | [#289](https://github.com/Akmot9/Packet-parser/issues/289) |
| AMS | on TCP 48898 the 6-byte AMS/TCP header before each message (`AmsPacket::try_from_tcp`) | [#290](https://github.com/Akmot9/Packet-parser/issues/290) |
| MQTT | four valid MQTT 5 forms, AUTH (type 15) among them | [#291](https://github.com/Akmot9/Packet-parser/issues/291) |
| TLS | a record of version 3.0, which RFC 5246 lets a client send | [#300](https://github.com/Akmot9/Packet-parser/issues/300) |
| Bitcoin | the real regtest magic, and Testnet4; two magics of no network were accepted | [#301](https://github.com/Akmot9/Packet-parser/issues/301) |
| SNMP | a Counter64 of 2<sup>63</sup> or more, 9 bytes in BER | [#304](https://github.com/Akmot9/Packet-parser/issues/304) |
| FTP, SMTP, NNTP | a segment cut between CR and LF | [#305](https://github.com/Akmot9/Packet-parser/issues/305) |
| FTP, NNTP | standard verbs: `XPWD`, `XMKD`, `XRMD`, `XCUP`, `XCWD`, `LPSV`, `ADAT`, `CCC`, `MIC`, `CONF`, `ENC`, `LANG`, `HOST`; `STARTTLS`, `CHECK`, `TAKETHIS` | [#306](https://github.com/Akmot9/Packet-parser/issues/306) |
| SSH | lines before the banner | [#307](https://github.com/Akmot9/Packet-parser/issues/307) |
| COTP | a class 0 CR that announces a TPDU of 4 096 or 8 192 bytes, which a real IEC 61850 station sends | [#298](https://github.com/Akmot9/Packet-parser/issues/298) |
| DHCP | `hlen` 0 over InfiniBand and IEEE 1394, and BOOTP with a null `vend` area | [#303](https://github.com/Akmot9/Packet-parser/issues/303) |
| SRVLOC | an error reply stopped after its code, and SLPv1 strings in Latin-1 or UCS-2 | [#302](https://github.com/Akmot9/Packet-parser/issues/302) |
| [DNS](./dns.md) | a label that is not UTF-8, and on TCP a response without a question (AXFR) | [#297](https://github.com/Akmot9/Packet-parser/issues/297) |
| QUIC | Version Negotiation and reserved versions on UDP 443 | [#299](https://github.com/Akmot9/Packet-parser/issues/299) |
| [LLMNR](./dns.md#mdns-and-llmnr) | Z bits set, and the RCODE of a query, which a receiver must ignore | [#288](https://github.com/Akmot9/Packet-parser/issues/288) |

QUIC also lost a field it could not read. Header protection (RFC 9001 §5.4) masks the packet number and its length in an Initial, a 0-RTT or a Handshake packet, so `packet_number` is always `None` since 13.0.0 ([#293](https://github.com/Akmot9/Packet-parser/issues/293)). The DNS, LLMNR and TLS changes are on their pages.

## "Decode As"

Port guards mean a server on a non-standard port is invisible to a port-guarded rule. `ParseConfig::decode_as(port, DecodeAsProtocol::Xxx)` declares extra ports, and `parse_with` applies them. Declared ports are evaluated **before** the table, with the same three constraints: port *and* content, the protocol's transport guard, and failures memoized like the table's. Ports the table marks terminal (mDNS 5353, LLMNR 5355) cannot be overridden: the caller extends the guards, never replaces them.

`DecodeAsProtocol` is `#[non_exhaustive]`. It had twenty variants in 11.5.0, `Ptp` the last; 11.6.0 adds seven at its end, `Stanag5066`, `Dis`, `Ike`, `Esp`, `Rdp`, `Iec104` and `WireGuard`, 11.8.0 one more, `ValmetDna`, 12.0.0 another, `ModbusUdp`, and 13.0.0 `JavaRmi`: 30 in all. Each variant resolves to a label, a transport guard and a probe, and a unit test of `dispatch/tests.rs` checks that the label and the probe are those of a rule of the table (for `WireGuard`, those of its 51820 twin), so that the two lists cannot drift apart:

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
| `PostgreSql` | [PostgreSQL](./postgresql.md) | `Tcp` | `PostgresqlPort` |
| `ModbusTcp` | [ModbusTCP](./modbus.md) | `Tcp` | `ModbusTcp` |
| `EthernetIp` | EtherNet/IP | `Any` | `EthernetIp` |
| `Ams` | AMS | `Tcp` on TCP, `Any` otherwise | `AmsTcp` on TCP, `Ams` otherwise |
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
| `ValmetDna` | [Valmet DNA](./valmet_dna.md) | `Udp` | `ValmetDna` |
| `ModbusUdp` | [ModbusUDP](./modbus.md#modbus-over-udp) | `Udp` | `ModbusTcp` |
| `JavaRmi` | [Java RMI](./java_rmi.md) | `Tcp` | `JavaRmi` |

A declared port gets the probe of the protocol's standard port: the compatible shape of PostgreSQL on 5432, the lenient reading of DIS on 3000, the envelope of Modbus/TCP on 502, the AMS/TCP header of 48898 on TCP, every message family and the beacon of Valmet DNA on 2517, 4516 and 4517. `WireGuard` goes further than the 51820 rule: its probe, `WireGuardPacket::try_from`, accepts the reserved bytes whatever the message type, where the port rule wants them null in a cookie or a data message, 51820 being a port that any peer can draw at random. Because declared ports come before the table, a declared port names the protocol of everything its probe accepts: on a port declared `ModbusTcp`, a UMAS frame is `"ModbusTCP"` (see [Modbus/TCP and UMAS](./modbus.md)).

Since 12.1.0, `DecodeAsProtocol::ALL` is every variant, in declaration order: the list a caller shows when it lets its user bind a protocol to a port ([#274](https://github.com/Akmot9/Packet-parser/issues/274)). The enum and `ALL` are written by one macro from one list, as `ApplicationProtocol` and its own `ALL` are, so a variant cannot be missing from it. Three lists were written by hand until then, the one of the dispatch tests and those of the fuzz targets `parse_packetflow` and `policy_dispatch`; in 11.8.0 the fuzz one lacked `ValmetDna`. All three now read `ALL` (*tested*):

```rust
{{#include ../examples/src/lib.rs:decode_as_all}}
```

The seventeen labels without a variant are all given by a rule without a port guard, which probes any port, except NAT-keepalive, which only UDP 4500 knows. For NTP, whose port rule is more tolerant than its blind probe, this means that off port 123 the strict probe is the only way to the label.

## Parsers added by the caller

Since 13.0.0 the caller can add parsers for protocols the crate does not decode, in Rust or, since 13.1.0, as rules in a TOML file. They run after the table, on a TCP or UDP payload that it left `"Unknown"`: they never take a frame from the crate. Their label is `ApplicationProtocol::Custom`. The [Custom parsers and rules](./custom_parsers.md) chapter describes both.

## STP: the one label without a transport

A Spanning Tree BPDU has no L3, so it can never reach this table. The pipeline checks it from the link layer (802.3 length field, bridge group address, LLC `42-42-03`, valid BPDU) and labels the flow `"STP"` when every other layer is `None`.

## Tunnels take the label

When the transport payload is a recognized encapsulation (CAPWAP, VXLAN, Geneve, GTP-U) the outer flow's `Application::protocol` is the tunnel name, and the real conversation is in `inner`. Next chapter.
