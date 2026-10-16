# PPPoE session

PPP over Ethernet, RFC 2516: the link that a fibre or xDSL subscriber's router keeps with the provider's access concentrator, and that carries all of the subscriber's IP traffic. Up to 11.5.0 its session stage, EtherType `0x8864`, was only named, and the IP packets inside had no internet layer; since 11.6.0 the session is peeled ([#172](https://github.com/Akmot9/Packet-parser/issues/172), [#173](https://github.com/Akmot9/Packet-parser/issues/173)). The module is `packet_parser::parse::data_link::pppoe`. The session is not a layer of `PacketFlow`: like a VLAN tag, it is consumed by the [Ethernet](./ethernet.md) decoder and kept in the Ethernet view, `DataLink::pppoe`.

## Peeled like a VLAN tag

There is no port, no probe and no Decode As: the EtherType announces the session, and the Ethernet decoder takes its word, as it does for a TPID. `DataLink::try_from` reads the EtherType after the two MAC addresses; a TPID sends the frame through the VLAN stack first, and `parse_tagged` makes the same test on the EtherType that follows the last tag. A session is therefore peeled under any number of tags, or none:

```rust
// DataLink::try_from, after the two MAC addresses.
let raw_ethertype = u16::from_be_bytes([packets[12], packets[13]]);
if VlanTag::is_tpid(raw_ethertype) {
    return Self::parse_tagged(packets, destination_mac, source_mac, raw_ethertype);
}
if raw_ethertype == PPPOE_SESSION_ETHERTYPE {
    return Ok(Self::parse_pppoe(
        destination_mac,
        source_mac,
        None,
        VlanStack::default(),
        &packets[DATALINK_HEADER_LEN..],
    ));
}
```

`parse_pppoe` then decides what `ethertype` and `payload` become:

```rust
#[inline(never)]
fn parse_pppoe(
    destination_mac: MacAddress,
    source_mac: MacAddress,
    vlan: Option<VlanTag>,
    vlan_stack: VlanStack<'a>,
    payload: &'a [u8],
) -> Self {
    let (pppoe, ethertype, payload) = match peel_session(payload) {
        Some((session, inner)) => (
            Some(session),
            session.inner_ethertype().unwrap_or(PPPOE_SESSION_ETHERTYPE),
            inner,
        ),
        None => (None, PPPOE_SESSION_ETHERTYPE, payload),
    };
    DataLink {
        destination_mac,
        source_mac,
        vlan,
        vlan_stack,
        pppoe,
        ethertype: Ethertype::from(ethertype),
        payload,
    }
}
```

Three outcomes, then:

| After EtherType `0x8864` | `pppoe` | `ethertype` | `payload` | Internet layer |
| --- | --- | --- | --- | --- |
| a session carrying PPP IPv4 (`0x0021`) or IPv6 (`0x0057`) | `Some(session)` | `0x0800` or `0x86DD` | the IP packet | IPv4 or IPv6, then transport and application as usual |
| a session carrying any other PPP protocol (LCP, IPCP, IPv6CP, PAP, CHAP...) | `Some(session)` | `0x8864` | the PPP packet, after its protocol field | `None`, nothing in `corrupted` |
| no well-formed session data frame | `None` | `0x8864` | all the bytes after the EtherType | `None`, nothing in `corrupted` |

`inner_ethertype` (crate-internal) maps `0x0021` to `0x0800` and `0x0057` to `0x86DD`, and nothing else. From there on, the layers above see what they would see without PPPoE: `network_protocol()` is `Ipv4` or `Ipv6`, `network_payload()` is the packet, and the [internet layer](./network.md) dispatches on it as on any other. Tags, when there are any, are kept as they were read: `vlan.inner_ethertype` still says `0x8864`, the value that follows the tag on the wire. Like the tag stack, the session is unwrapped in a separate `#[inline(never)]` function, off the straight line of an untagged frame.

Since the peeling lives in `DataLink::try_from`, it happens wherever the crate reads an Ethernet frame: LINKTYPE 1, an [802.3br](./ieee802_3br.md) express mPacket, and the inner frame of a VXLAN tunnel or of a GRE or Geneve one announcing `0x6558` ([tunnels](./tunnels.md)).

An IPv4 session under two VLAN tags, then an IPv6 one under a single tag that reaches the application layer (*tested*):

```rust
{{#include ../examples/src/link_layer.rs:pppoe_peeled}}
```

```rust
{{#include ../examples/src/link_layer.rs:pppoe_ipv6}}
```

## The session: `PppoeSession`

Doc comments shortened:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[non_exhaustive]
pub struct PppoeSession {
    /// The session identifier, chosen by the access concentrator.
    pub session_id: u16,
    /// Declared length of the PPPoE payload, PPP protocol field included.
    pub length: u16,
    /// PPP protocol (RFC 1661 §2). A field compressed on one byte (PFC,
    /// RFC 1661 §6.5) is widened to sixteen bits: 0x21 is 0x0021.
    pub ppp_protocol: u16,
}

impl PppoeSession {
    /// The name of the PPP protocol, when it is known.
    pub fn ppp_protocol_name(&self) -> Option<&'static str>;
}
```

The six bytes of the PPPoE header, then the PPP protocol field; offsets from the first byte after the EtherType `0x8864`, which is byte 14 of an untagged frame, 18 under one tag, 22 under two:

| Bytes | Field | Note |
| --- | --- | --- |
| 0 | version (high nibble), type (low nibble) | both 1: `0x11` |
| 1 | code | `0x00`, session data |
| 2–3 | `session_id` | |
| 4–5 | `length` | the PPPoE payload: the protocol field and the PPP packet |
| 6–7 | `ppp_protocol` | byte 6 alone when the field is compressed |
| 8… | the PPP packet | `payload`, from byte 7 when the field is compressed |

`PppoeSession` is `#[non_exhaustive]`: it is read from a parsed frame, never built outside the crate. `PPPOE_SESSION_ETHERTYPE`, the public constant `0x8864`, lives in the same module. `ppp_protocol_name()` knows nine protocols, and only the first two are peeled:

| `ppp_protocol` | `ppp_protocol_name()` | `ethertype` after peeling |
| --- | --- | --- |
| `0x0021` | `"IPv4"` | `0x0800` |
| `0x0057` | `"IPv6"` | `0x86DD` |
| `0xC021` | `"LCP"` | `0x8864` |
| `0xC023` | `"PAP"` | `0x8864` |
| `0xC223` | `"CHAP"` | `0x8864` |
| `0x8021` | `"IPCP"` | `0x8864` |
| `0x8057` | `"IPv6CP"` | `0x8864` |
| `0xC025` | `"LQR"` | `0x8864` |
| `0x80FD` | `"CCP"` | `0x8864` |
| any other | `None` | `0x8864` |

The `Display` of `DataLink` gives the session a line of its own, `PPPoE: session 0x8f9e, PPP LCP`, the protocol in hexadecimal when it has no name.

## What makes a session

`peel_session`, crate-internal, is the whole check:

```rust
pub(crate) fn peel_session(payload: &[u8]) -> Option<(PppoeSession, &[u8])> {
    let header = payload.get(..PPPOE_HEADER_LEN)?;
    if header[0] != PPPOE_VERSION_TYPE || header[1] != PPPOE_SESSION_DATA {
        return None;
    }
    // The low byte of a PPP protocol is odd, its high byte even (RFC 1661
    // §2): an odd first byte is a compressed field (PFC), which RFC 2516 §7
    // discourages without forbidding it.
    let (ppp_protocol, protocol_len) = match *payload.get(PPPOE_HEADER_LEN..)? {
        [low, ..] if low & 1 == 1 => (u16::from(low), PPP_COMPRESSED_PROTOCOL_LEN),
        [high, low, ..] => (u16::from_be_bytes([high, low]), PPP_PROTOCOL_LEN),
        _ => return None,
    };
    let length = u16::from_be_bytes([header[4], header[5]]);
    let declared = usize::from(length);
    if declared < protocol_len {
        return None;
    }
    let end = payload.len().min(PPPOE_HEADER_LEN + declared);
    Some((
        PppoeSession {
            session_id: u16::from_be_bytes([header[2], header[3]]),
            length,
            ppp_protocol,
        },
        &payload[PPPOE_HEADER_LEN + protocol_len..end],
    ))
}
```

A session data frame (RFC 2516 §6) has the six header bytes, version and type `0x11`, code `0x00`, a PPP protocol field, and a `length` that covers at least that field. When one of them is missing, nothing is an error: the frame is left as it is, `pppoe` `None`, EtherType `0x8864` and the whole payload, like an unknown EtherType. No internet layer, nothing in `corrupted`, and the parse never fails because of it; there is no PPPoE error type.

The protocol field may be compressed to one byte (PFC). A PPP protocol has an even high byte and an odd low byte, so an odd first byte can only be the low byte of a one-byte field, which is how tshark reads it too: `0x21` is IPv4 and is reported as `0x0021`. No frame of the corpus uses it (all 6 881 session frames of the two captures below carry a two-byte field); the unit tests of `pppoe.rs` cover it on built bytes.

## Bounded like tshark does

Counted from the PPPoE header, the PPP packet ends at byte `6 + length` or at the end of the frame, whichever comes first:

- **the PPPoE length first**: what the frame holds after it is not PPP, and the padding of a short Ethernet frame is left out of `payload`;
- **then the end of the frame**: a length beyond the captured bytes, a truncated capture, is bounded by them;
- **a PPPoE length shorter than the IP packet truncates it**, as tshark does, and the Linux kernel's `pppoe_rcv`, which trims the frame to that length. The internet layer then finds a total length beyond its buffer, and the frame is reported corrupted.

The last case is real: six ACKs of `pcaps_exemple/vlan/pppoe-over-qinq.pcap` (frames 19, 33, 41, 47, 63 and 81) carry a PPPoE length of 42 for a 46-byte IPv4 packet, and tshark flags them as well (`Possible bad payload length 42 != 48`, `IPv4 total length exceeds packet length (40 bytes)`). The session is kept; the IPv4 layer is the one reported (*tested*):

```rust
{{#include ../examples/src/link_layer.rs:pppoe_short_length}}
```

## Control protocols keep `0x8864`

LCP, the authentication protocols (PAP, CHAP) and the network control protocols (IPCP, IPv6CP) set up the link and carry no IP packet. The session is kept in `pppoe`, but `ethertype` stays `0x8864`, `network_protocol()` is `NetworkProtocol::Other(0x8864)`, and `payload` is the PPP packet after its protocol field, raw. The internet layer is `None` with nothing in `corrupted`, which is how every PPPoE frame came out up to 11.5.0. An LCP Configure-Request of the [Ultimate PCAP](#oracle-6-795-session-frames), whose 64-byte frame holds 24 bytes beyond the PPPoE length (*tested*):

```rust
{{#include ../examples/src/link_layer.rs:pppoe_control}}
```

## Flow identity

`DataLink` compares and hashes the session through one key, the session identifier and the PPP protocol:

```rust
/// What identifies a flow in a PPPoE session: the session and the PPP
/// protocol. The PPPoE length changes with every packet, like the payload,
/// and is not part of it.
fn pppoe_flow_key(&self) -> Option<(u16, u16)> {
    self.pppoe
        .map(|session| (session.session_id, session.ppp_protocol))
}
```

Two packets that differ only by their PPPoE length and their payload are one flow, and two sessions are two flows. Since a control protocol leaves the EtherType at `0x8864`, the PPP protocol is what separates the LCP of a session from its IPCP. `PppoeSession` itself derives `PartialEq`, `length` included: the key is a property of `DataLink`, not of the session value.

The [owned model](./getting_started.md#owned-flows-and-serialization) has no session at all (next section), so it makes neither distinction: as `PacketFlowOwned`, the LCP and the IPCP of a session are the same flow, and so are two sessions that agree on everything else (*tested* for the first):

```rust
{{#include ../examples/src/link_layer.rs:pppoe_flow_identity}}
```

## JSON: not yet

`pppoe` is `#[serde(skip_serializing)]`. Adding the field to `DataLink` was not a break, the struct being `#[non_exhaustive]`; `DataLinkOwned` is an exhaustive struct and cannot gain it without one, and both models must serialize to the same JSON. So the session is not serialized yet, but what it carries is: `ethertype` names the packet, `"IPv4"` where 11.5.0 wrote `"Pppoe Session Stage"`, and the internet, transport and application layers are there as for any frame (*tested*):

```rust
{{#include ../examples/src/link_layer.rs:pppoe_json}}
```

## Oracle: 6 795 session frames

The golden test `tests/pppoe_golden.rs` reads `pcaps_exemple/The-Ultimate-PCAP.pcapng` in place and compares every frame that tshark 4.6.6 decodes as `pppoes` with the oracle frozen in `tests/data/pppoe_tshark_oracle.tsv` (`tools/pppoe_oracle.sh`): session identifier, PPPoE length, PPP protocol, the protocol after the first IP header, and the UDP or TCP ports. The crate peels a session on exactly those 6 795 frames and on no other frame of the capture, all of them without a corruption. The Ultimate PCAP merges many captures, and these frames belong to five sessions between four pairs of MAC addresses, all under VLAN 7. `0x001e` carries the 6 486 IPv4 frames, `0x8f9e` 34 control messages and 194 DHCPv6 messages, `0xe579` the 78 IPv4 packets in IPv6, `0x1f3d` two more DHCPv6 messages, and `0x8f80`, between the same two MAC addresses as `0x8f9e`, a single LCP message before the PADT that ends it. By PPP protocol:

| PPP protocol | Frames | What PPP carries, as tshark reads it |
| --- | --- | --- |
| IPv4 `0x0021` | 6 486 | 6 483 UDP datagrams (RTP and SIP), 2 ICMP messages, 1 non-initial fragment |
| IPv6 `0x0057` | 274 | 196 DHCPv6 messages over UDP, 78 IPv4 packets in IPv6 (TCP) |
| LCP `0xC021` | 26 | control |
| IPCP `0x8021` | 5 | control |
| IPv6CP `0x8057` | 4 | control |

One difference is named: frame 15 114, the first of two fragments of a 2 017-byte SIP datagram, whose UDP header tshark reads while the crate decodes no transport in a fragment ([IPv4 fragments](./ipv4.md#fragments)).

On the 11.5.0 corpus, the IP frames of these sessions gained their internet and transport layers: 6 482 went from no application to `"Unknown"`, 196 to `"DHCPv6"` and 78 to the `"IP-in-IP"` tunnel label.

The second capture, `pcaps_exemple/vlan/pppoe-over-qinq.pcap`, is the one of `tests/qinq_golden.rs`: 86 frames under two 802.1Q tags (VID 3704 then 2474), session `0x0f07`, PPP IPv4 throughout. Since 11.6.0 the test follows them past the session down to TCP, except the six frames of the [short PPPoE length](#bounded-like-tshark-does). No fuzz target is dedicated to the session: `parse_packetflow` and `parse_linktype` hand arbitrary bytes to the Ethernet decoder, the peeling included.

## What is left out

- **The discovery stage**, EtherType `0x8863` (PADI, PADO, PADR, PADS, PADT), is only named (`"Pppoe Discovery Stage"`): `pppoe` stays `None` and there is no internet layer. The Ultimate PCAP has eight of them, among which the PADT that ends session `0x8f80` (frame 10 396) and the PADS that assigns session `0x8f9e` (frame 10 400), just before the first LCP message of that session.
- **PPP control protocols** are named, not decoded: LCP options, the PAP or CHAP exchange and the IPCP addresses stay in the raw `payload`.
- **No session state**: the crate does not follow a discovery to its session, nor tie a session identifier to its MAC addresses. One frame at a time, like the rest of the crate.
- **The JSON and the owned model** do not carry the session yet (see above).
- **Only the Ethernet view peels it**: a Linux cooked capture whose protocol field is `0x8864` keeps `NetworkProtocol::Other(0x8864)`, and a capture declared as LINKTYPE 51 (`PPP_ETHER`), whose packets start at the PPPoE header, is refused like any LINKTYPE without a decoder (`ParseError::UnsupportedLinkType`).
