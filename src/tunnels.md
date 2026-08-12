# Tunnels

Some packets carry **a whole other packet** inside their payload. A layered,
single-level parser only sees the outer flow and misses the real conversation
nested inside — which, in a wireless deployment, is *every* conversation.

## The `inner` field

```rust
pub struct PacketFlow<'a> {
    // …
    pub inner: Option<Box<PacketFlow<'a>>>,
}
```

When a tunnel is detected, its headers are peeled and the encapsulated packet is
re-parsed as a full `PacketFlow`, recursively. One wire packet then yields
several flow levels: the outer tunnel, then the conversation(s) inside it.

`flatten()` walks the chain from outermost to innermost:

```rust
let flow = parse(LinkType::ETHERNET, &packet)?;

for level in flow.flatten() {
    println!("{:?} -> {:?}", level.internet, level.transport);
}
```

The outer flow is index 0 and is always present, so `flatten()` never returns an
empty vector.

## What is supported today

One path, end to end:

```text
Ethernet
└── IP / UDP port 5247
    └── CAPWAP-Data (RFC 5415)
        └── IEEE 802.11
            └── LLC / SNAP
                └── inner L3 packet → inner PacketFlow
```

The tunnel is recognized **at the transport layer** (UDP/5247), its name is
reported as the outer flow's application protocol, and the inner packet gets an
honest IEEE 802.11 link layer — not a fabricated Ethernet header. That is the
same principle as [the LINKTYPE rule](./link_types.md): the inner frame really is
802.11, so it is presented as 802.11, and `as_ieee80211()` is how you read it.

## The depth guard

```rust
pub(crate) const MAX_TUNNEL_DEPTH: u8 = 4;
```

Malformed or hostile traffic can claim endless encapsulation. Recursion stops at
depth 4 — the outer flow being depth 0 — so a crafted packet cannot turn a parse
into an unbounded allocation loop.

## Growing the list

`detect_inner` is the single extension point. VXLAN, GRE, GTP-U and IP-in-IP
plug in the same way: recognize the encapsulation from the transport layer,
return the tunnel name and the byte range of the inner packet, and let
`PacketFlow` re-parse it.

## Known limit

Tunnel recursion boxes the inner flow, so it allocates — one of the documented
exceptions to the zero-copy rule. And timed parsing does not yet recursively
measure `inner` flows; the timings you get describe the outer parse only (see
[Performance](./performance.md)).
