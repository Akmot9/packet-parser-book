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

DNS (plus mDNS and LLMNR forms), TLS, SNMP, NTP, DHCP, DHCPv6, HTTP, MQTT, PostgreSQL, FTP, SMTP, NNTP, SSH (identification string only), SSDP, NetBIOS (NBNS, NBSS), OpenVPN, Modbus TCP, UMAS, EtherNet/IP, OPC UA, S7Comm, COTP, AMS, GIOP, SRVLOC, QUIC, Bitcoin, and STP from the link layer.

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
2. **Every probe runs at most once per payload.** Failures are memoized by `ProbeId` in a bitmask: a rule sharing a probe with an earlier one (port-priority then blind fallback) never re-runs it.
3. **Probes read at most `PROBE_CAP` = 18 KiB.** Classification is a verdict on the application header, not on the whole segment; the cap is above the largest legitimate message a probe must see in full (an encrypted TLS record: 5 + 16 KiB + tag). The one exception is OpenVPN over TCP, whose length prefix is checked against the real payload.
4. **The order of the table is the priority**, inspectable, testable, and locked by a golden snapshot over the reference captures.

### Reading the table

```rust
static RULES: &[Rule] = &[
    // --- port-guarded rules: weak signature confirmed by the port ---
    port_rule("SNMP",   Guard::Udp, is_snmp_udp_port,   ProbeId::Snmp),     // 161, 162
    port_rule("DHCPv6", Guard::Udp, is_dhcpv6_udp_port, ProbeId::Dhcpv6),   // 546, 547
    rule("S7Comm", Guard::Tcp, ProbeId::S7Comm),   // strong enough for blind TCP probing, before COTP
    port_rule("COTP",   Guard::Tcp, is_iso_tsap_tcp_port, ProbeId::CotpTpkt), // 102
    port_rule("FTP",    Guard::Tcp, is_ftp_tcp_port,  ProbeId::Ftp),        // 21
    port_rule("SMTP",   Guard::Tcp, is_smtp_tcp_port, ProbeId::Smtp),       // 25, 587
    port_rule("NNTP",   Guard::Tcp, is_nntp_tcp_port, ProbeId::Nntp),       // 119
    // FTP/SMTP/NNTP off-port: only verbs that exist in exactly one of the three
    // (RETR, STOR, EHLO, MAIL, ARTICLE, XOVER...), vetoed on the three standard ports
    // where such a verb is probably content in transit (a DATA body, an article).
    Rule { label: "FTP", ports_veto: Some(is_text_protocol_port), probe: ProbeId::FtpUnambiguous, .. },
    // mDNS 5353 and LLMNR 5355 are reserved by their RFCs: terminal ports.
    Rule { label: "mDNS", ports: Some(is_mdns_udp_port), terminal_on_port: true, .. },
    port_rule("SSDP",    Guard::Udp, is_ssdp_udp_port, ProbeId::Ssdp),      // 1900
    port_rule("NBNS",    Guard::Udp, is_nbns_udp_port, ProbeId::Nbns),      // 137
    port_rule("NBSS",    Guard::Tcp, is_nbss_tcp_port, ProbeId::Nbss),      // 139, 445
    port_rule("OpenVPN", Guard::Udp, is_openvpn_port,  ProbeId::OpenVpnUdp),// 1194
    port_rule("AMS",     Guard::Tcp, is_ams_tcp_port,  ProbeId::Ams),       // 48898
    port_rule("QUIC",    Guard::Udp, is_quic_udp_port, ProbeId::QuicShortHeader), // 443: 1-RTT header is opaque
    port_rule("OPC UA",  Guard::Tcp, is_opcua_tcp_port, ProbeId::Opcua),    // 4840: priority, not sufficiency
    port_rule("DNS",     Guard::Tcp, is_dns_port, ProbeId::DnsTcp),         // 53: length-prefixed form
    port_rule("DNS",     Guard::Udp, is_dns_port, ProbeId::Dns),            // 53: datagram form
    // --- blind cascade, with the transport guards the RFCs impose ---
    rule("NTP",         Guard::Udp, ProbeId::Ntp),
    rule("Bitcoin",     Guard::Tcp, ProbeId::Bitcoin),
    rule("OPC UA",      Guard::Tcp, ProbeId::Opcua),       // memoized: not re-run if the port rule failed
    rule("EtherNet/IP", Guard::Any, ProbeId::EthernetIp),  // truly bi-transport (TCP 44818, UDP 2222)
    rule("PostgreSQL",  Guard::Tcp, ProbeId::Postgresql),
    rule("DNS",         Guard::Udp, ProbeId::Dns),         // datagram form exists only on UDP
    rule("SNMP",        Guard::Any, ProbeId::Snmp),        // SNMP over TCP exists (RFC 3430)
    rule("TLS",         Guard::Tcp, ProbeId::Tls),
    rule("SSH",         Guard::Tcp, ProbeId::Ssh),         // literal "SSH-" prefix, before HTTP
    rule("HTTP",        Guard::Tcp, ProbeId::Http),
    rule("GIOP",        Guard::Tcp, ProbeId::Giop),
    rule("DHCP",        Guard::Udp, ProbeId::Dhcp),        // before SRVLOC: a BOOTP mimicked an SLP header
    rule("SRVLOC",      Guard::Any, ProbeId::Srvloc),
    rule("UMAS",        Guard::Tcp, ProbeId::Umas),
    rule("ModbusTCP",   Guard::Tcp, ProbeId::ModbusTcp),
    rule("QUIC",        Guard::Udp, ProbeId::QuicLongHeader),
    rule("MQTT",        Guard::Tcp, ProbeId::Mqtt),        // last: its fixed header is barely discriminating
];
```

Each comment in the real file cites the capture frame or the issue that motivated the line. That is the point of a table over a cascade: the semantics of the order are written down and cannot silently move.

### Three detection routes

When choosing where a new protocol goes, the question is: *can a valid payload of this protocol also be a valid payload of another protocol we already detect, or of arbitrary text?*

| Route | When | Example |
| --- | --- | --- |
| **Blind probe** (`rule`) | the bytes identify themselves: literal marker (`HTTP/`, `GIOP`, `SSH-`), tight binary header (DNS, NTP), announced length that must match exactly (PostgreSQL) | `rule("TLS", Guard::Tcp, ..)` |
| **Port-guarded** (`port_rule`) | the signature is weak or ambiguous even with perfect checks: identical reply syntax (FTP/SMTP/NNTP), loose headers (DHCPv6, AMS, COTP, QUIC short header), relaxed validation (mDNS) | `port_rule("FTP", Guard::Tcp, is_ftp_tcp_port, ..)` |
| **Strong signature with transport constraint** | recognizable off-port, but only defined on one transport | S7Comm: the full TPKT + COTP-DT + S7 envelope is probed on any TCP port, and the same bytes on UDP never yield the label |

Whatever the route, the **transport guard** is always there: the RFC says on which transport a protocol exists, and probing it elsewhere only produces false positives.

## "Decode As"

Port guards mean a server on a non-standard port is invisible to a port-guarded rule. `ParseConfig::decode_as(port, DecodeAsProtocol::Xxx)` declares extra ports. Declared ports are evaluated **before** the table, with the same three constraints: port *and* content, the protocol's transport guard, and failures memoized like the table's. Ports the table marks terminal (mDNS 5353, LLMNR 5355) cannot be overridden: the caller extends the guards, never replaces them.

## STP: the one label without a transport

A Spanning Tree BPDU has no L3, so it can never reach this table. The pipeline checks it from the link layer (802.3 length field, bridge group address, LLC `42-42-03`, valid BPDU) and labels the flow `"STP"` when every other layer is `None`.

## Tunnels take the label

When the transport payload is a recognized encapsulation (CAPWAP, VXLAN, Geneve, GTP-U) the outer flow's `application_protocol` is the tunnel name, and the real conversation is in `inner`. Next chapter.
