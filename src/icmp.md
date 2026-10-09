# ICMPv4 and ICMPv6

IP protocol 1 and IPv6 next header 58, parsed by the [transport layer](./transport.md).

ICMP has neither ports nor sessions. It is reached through the IP protocol number (1, or next header 58 for ICMPv6), **never through probing**, and the two versions have separate parsers: their type numbering is disjoint (128 is an echo request in ICMPv6, 8 is undefined there).

Two deliberate choices:

- `payload` stays **`None`**: nothing stacks above ICMP, and exposing its bytes would hand them to the application probes, which would mislabel them. The decoded message is in `details` (`TransportDetails::Icmp` / `Icmpv6`).
- an **unreadable ICMP message does not corrupt the flow**: the protocol is correctly identified by the IP header, so `protocol` is set and only `details` falls back to `None`. The `IcmpError` / `Icmpv6Error` is discarded; to know why, run `IcmpPacket::try_from` or `Icmpv6Packet::try_from` on `internet.payload`.

Decoded messages, in `IcmpPacket::body` (`IcmpBody`) and `Icmpv6Packet::body` (`Icmpv6Body`), after the common `message_type`, `code` and `checksum`:

- **Echo** request/reply (ICMPv4 8/0, ICMPv6 128/129): identifier, sequence number, data.
- **Error reports**, which quote the datagram that caused them: ICMPv4 destination unreachable (3), redirect (5), time exceeded (11) and parameter problem (12); ICMPv6 destination unreachable (1), packet too big (2), time exceeded (3) and parameter problem (4). The four type-dependent bytes stay raw in `rest_of_header` (next-hop MTU, parameter-problem pointer..., to read according to type and code), and the quoted bytes are exposed zero-copy as `original_datagram` / `invoking_packet`, not parsed.
- **Neighbor discovery** (ICMPv6 only, RFC 4861): router solicitation (133), router advertisement (134: current hop limit, M/O flags, router lifetime, reachable time, retransmit timer), neighbor solicitation (135: target address) and neighbor advertisement (136: R/S/O flags, target address), each with its NDP options as raw bytes. Redirect (137) is not interpreted.
- any other type: `Other`, the raw bytes after the common header.

What makes a message unreadable:

| Check (error variant) | ICMPv4 (`IcmpError`) | ICMPv6 (`Icmpv6Error`) |
| --- | --- | --- |
| Common header: type, code, checksum (`InvalidLength`) | 4 bytes | 4 bytes |
| Code defined for the type (`InvalidCodeForType`) | echo: 0; destination unreachable: 0–15; redirect: 0–3; time exceeded: 0–1; parameter problem: 0–2 | destination unreachable: 0–7; packet too big: 0; time exceeded: 0–1; parameter problem: 0–2; echo and the four ND messages: 0 |
| Echo: identifier and sequence (`InvalidEchoLength`) | 8 bytes | 8 bytes |
| Error report (`InvalidErrorPayloadLength`) | 8 + 28 bytes: an option-less IPv4 header and the first 8 data bytes, as RFC 792 requires | 8 + 40 bytes: the fixed IPv6 header (RFC 4443 §3) |
| Neighbor solicitation/advertisement: target address (`InvalidNeighborLength`) | – | 24 bytes |
| Router solicitation / advertisement: fixed fields (`InvalidRouterLength`) | – | 8 / 16 bytes |

An error report quoting less than that minimum is refused rather than exposed: routers sometimes truncate below it, and the consumer would read a partial IP header. A type the crate does not interpret has no code constraint: it parses as `Other` and never fails.
