# Application

## A classification, not a decode

This layer is the one that surprises people, so it is worth stating plainly:

```rust
pub struct Application {
    pub application_protocol: &'static str,
}
```

That is the whole structure. In a `PacketFlow`, the application layer reports
**which protocol was detected**, not a parsed message. It is a `&'static str`,
not even an allocation.

The detailed parsers exist — they are what performs the detection — but their
output is not carried in the flow. When you want the decoded message, call the
parser directly:

```rust
use packet_parser::parse::application::protocols::dns::DnsPacket;

let dns = DnsPacket::try_from(transport_payload)?;
```

The rationale is cost. A flow matrix over a million packets wants a label, not a
million allocated DNS trees. Paying for the deep parse is the caller's decision,
made per packet.

## Supported protocols

Parser modules under `packet_parser::parse::application::protocols`:

| | | |
| --- | --- | --- |
| DNS (and mDNS) | TLS | SNMP |
| NTP | DHCP | DHCPv6 |
| HTTP | MQTT | PostgreSQL |
| FTP | SMTP | NNTP |
| SSH | Modbus TCP | EtherNet/IP |
| OPC UA | S7Comm | COTP |
| AMS | GIOP | SRVLOC |
| QUIC | Bitcoin | |

A few notes on individual ones:

- **mDNS** is distinct from classic DNS (`DnsPacket::try_from_mdns`): it must
  accept announcements with no question, and it decodes the QU and cache-flush
  bits.
- **SSH** is the identification string only. Everything after the version
  exchange is encrypted, so a stateless parser labels the banner frames and
  nothing else. Claiming "SSH" on the encrypted remainder would be a guess.
- **S7Comm** wins over the generic COTP label when both match, since S7Comm is a
  COTP DT user. TPKT is decoded before COTP on TCP/102.

## Detection is best-effort — and that is a design constraint

There is no field in a TCP segment that says "this is HTTP". Detection is
signature matching, and signature matching has false positives. The crate handles
this by splitting protocols into two regimes.

### Strong signatures: probed on content

A protocol with a distinctive, structurally validated header can be detected on
any port. TLS records, QUIC long headers, DNS, S7Comm over TCP — a full parse
that succeeds on these is evidence, not a coincidence.

### Weak signatures: parser-validated *and* port-restricted

FTP, SMTP and NNTP are line-oriented ASCII. `PASV`, `PORT`, `220 ` — these
strings occur inside the *body* of other text protocols. An SMTP message
quoting an FTP session is not an FTP session.

So detection of these in `PacketFlow` requires both a successful parse **and**
the protocol's plaintext control port:

| Protocol | Required TCP port |
| --- | --- |
| FTP | 21 |
| SMTP | 25, 587 |
| NNTP | 119 |

Payloads on other ports are simply not labelled as these protocols. SNMP and
DHCPv6 are guarded the same way on their UDP ports.

This is not a contradiction of the "parse each layer independently" rule from
[the packet chapter](./packet.md). The port never *causes* a protocol to be
claimed — the parser still has to accept the bytes. The port only vetoes claims
that would otherwise be plausible noise.

### Implicit TLS ports

A complete TLS record on an implicit-TLS port such as 465, 563 or 990 is reported
as **TLS**, not as the tunnelled protocol. That is the honest answer: the SMTP or
NNTP payload is encrypted and this crate does not see it. To inspect externally
decrypted application data, call the detailed protocol parser directly on the
plaintext.

### Guards that come from the layers below

Two rules from earlier chapters do most of the work in preventing nonsense here:

- **ICMP keeps `payload: None`** — so quoted datagrams are never submitted to
  application detection ([Transport](./transport.md)).
- **Fragments set `payload_protocol: None`** — so no application detection runs
  on a partial datagram ([Internet](./network.md)).

## Where detection happens

`PacketFlow` builds the application layer from the transport payload, applying
the port guards described above. `Application::try_from(&[u8])` is the raw
probing entry point: given a bare payload with no context, it tries the parsers
and returns the first match. It has no port information, so it cannot apply the
weak-signature guards — use it only when you know what you are handing it.
