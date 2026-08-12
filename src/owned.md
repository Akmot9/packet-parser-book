# Owned flows and serialization

## Why an owned form exists

`PacketFlow<'a>` borrows the buffer you passed to `parse`. That is what makes
parsing cheap, and it is also what makes the flow unusable the moment the buffer
goes away: you cannot store it in a cache, send it to another thread that
outlives the capture loop, or hold it past the next `read_packet()`.

The answer is an explicit conversion rather than a silent copy on every packet:

```rust
let owned = flow.to_owned(); // -> PacketFlowOwned
```

`PacketFlowOwned` has no lifetime. It mirrors the borrowed structure field for
field:

```rust
pub struct PacketFlowOwned {
    pub data_link: LinkLayerOwned,
    pub internet: Option<InternetOwned>,
    pub transport: Option<TransportOwned>,
    pub application: Option<ApplicationOwned>,
    pub inner: Option<Box<PacketFlowOwned>>,
    pub corrupted: Option<CorruptedLayer>,
}
```

Tunnels survive the conversion — `inner` is converted recursively — and so does
the corruption report.

## What the owned form drops

**Payload bytes and the per-layer `details`.**

This is intentional and worth understanding before you reach for `to_owned()`.
The owned form keeps *flow identity*: link-layer information, addresses and their
classification, protocol names, ports, application label. It does not keep the
IPv4 options, the TCP flags, or a single byte of payload.

```rust
pub struct InternetOwned {
    pub source_ip: Option<IpAddr>,
    pub ip_source_type: Option<IpType>,
    pub destination_ip: Option<IpAddr>,
    pub ip_destination_type: Option<IpType>,
    pub protocol: String,
}
```

If you need TTLs or TCP options, read them from `details` **before** converting,
while you still hold the borrowed flow.

## Serialization

Both forms implement `Serialize`, and — deliberately — they **serialize
identically**. A pipeline can convert to owned at any stage without changing its
output schema. Payload bytes are never serialized in either form.

The schema introduced in 7.0 nests the link layer and uses stable tags:

```json
{
  "data_link": {
    "link_type": 1,
    "network_protocol": { "kind": "ipv4" },
    "link_kind": "ethernet",
    "link_details": {
      "destination_mac": "00:11:22:33:44:55",
      "source_mac": "66:77:88:99:aa:bb",
      "ethertype": "IPv4"
    }
  }
}
```

Three things to note:

- `link_type` is the **numeric** canonical LINKTYPE — it round-trips even for a
  value this build cannot decode.
- `link_kind` / `link_details` is a tagged union, so a consumer can branch on the
  frame format without guessing from which fields are present.
- MAC addresses serialize as `"aa:bb:cc:dd:ee:ff"` strings even though they are
  `[u8; 6]` in memory, and EtherTypes serialize by name (`"IPv4"`).

The upper layers are flattened into the object, which keeps the JSON close to the
flat, one-row-per-packet shape that analysis tools want.

## Equality and hashing

Like the borrowed form, `PacketFlowOwned` derives `PartialEq`, `Eq` and `Hash`
over the identity fields. Since the owned form has already dropped payloads and
`details`, the two forms agree on what "the same flow" means — which is what
makes it safe to key a long-lived `HashMap` on the owned version of a flow you
matched while borrowed.
