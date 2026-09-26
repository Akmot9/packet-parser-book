# Tunnels

Some packets carry a **whole other packet** inside their payload. The base pipeline is layered and single-level: without help it only sees the *outer* flow (say, UDP between two data centres) and misses the real conversation nested inside.

## `inner` and `flatten()`

When a tunnel is recognized, its name goes into the outer flow's `application_protocol`, its headers are peeled, and the encapsulated packet is fed back into the **same** L3/L4/L7 pipeline, recursively, into `inner`:

```rust
pub struct PacketFlow<'a> {
    // ...
    pub inner: Option<Box<PacketFlow<'a>>>,
}
```

One wire packet then yields several flow levels, outermost first:

```rust
let flow = parse(LinkType::ETHERNET, &packet)?;

for level in flow.flatten() {
    println!("{:?} -> {:?}", level.internet, level.transport);
}
```

A non-tunneled packet yields one entry. The inner flows borrow the same buffer as the outer one: peeling is zero-copy, only the recursion boxes.

Nesting is bounded by `MAX_TUNNEL_DEPTH = 4`, an anti-loop guard against malformed traffic that could claim endless encapsulation.

## Supported tunnels

| Tunnel | Detected from | Inner |
| --- | --- | --- |
| CAPWAP-Data (RFC 5415) | UDP/5247 | IEEE 802.11 → LLC/SNAP → L3 |
| GRE v0 (RFC 2784/2890) | IP protocol 47 | IPv4, IPv6 or Ethernet (0x6558) |
| IP-in-IP | IP protocols 4 and 41 | bare IPv4 / IPv6 |
| VXLAN (RFC 7348) | UDP/4789 | full Ethernet frame |
| Geneve (RFC 8926) | UDP/6081 | Ethernet (0x6558) or bare IP, options skipped |
| GTP-U (3GPP TS 29.281) | UDP/2152 | bare IP, no L2 |

## Two detection points

Tunnels are looked for at two places in the pipeline, because they live at two levels:

- **IP-level** (`detect_inner_l3`), from `Internet::payload_protocol`, *before* transport parsing: GRE and IP-in-IP have no transport layer, so their detection cannot depend on the hollow `Transport` the catch-all branch of `try_from_parts` builds for them. For IP-in-IP, the outer protocol number *announces* the inner version (4 or 41), and the raw-IP decoder checks it against the inner version nibble: a mismatch is refused.
- **Transport-level** (`detect_inner`), from a UDP port and the payload shape: CAPWAP, VXLAN, Geneve, GTP-U.

Detection returns `None`, never an error: no tunnel, an encrypted payload (CAPWAP over DTLS), a truncated one, or a shape we don't decode all mean "this is just an ordinary flow".

## Refuse, don't guess

Every tunnel decoder rejects the variants it cannot attest instead of guessing a shape: GRE version 1 (PPTP), ERSPAN and routing bits; VXLAN GBP/GPE flag extensions; Geneve OAM control messages; GTPv0, GTP' (a billing protocol on the same port) and every GTP-U message type other than G-PDU (echo requests and the whole control plane carry no user packet).

GTP-U is special in one way: alone among these, its header says **nothing** about what it carries (VXLAN is always Ethernet, Geneve announces an EtherType). So it is the only tunnel whose label requires the inner packet to parse cleanly first.

A fragmented outer datagram is never peeled: reassembly is stateful, and a tunnel must not be reported as more complete than the datagram carrying it.

## The inner link layer is honest

The inner packet enters the pipeline through the same `DecodedLink` as a top-level packet: VXLAN produces an `Ethernet` link layer, GRE/Geneve/GTP-U produce a `RawIp` one, and CAPWAP produces an `Ieee80211Link` with the real 802.11 addresses and the SNAP protocol. Nothing fabricates an Ethernet header for a tunnel that does not carry one, which is the same principle as the [data link chapter](./data_link.md).

The "Decode As" configuration is propagated into the inner flows, so a declared port works inside a tunnel too.
