# Limits

`parse` is stateless: it reads one packet, keeps nothing, and knows nothing of the packets before it. Most of the limits of the crate follow from that choice. This page lists them once, with what each one costs a consumer and what the crate exposes to detect it. The limits of a single protocol are in the "What is left out" section of its page.

## What a stateless parser cannot see

| Limit | What follows for a consumer | What the crate exposes | With a stateful layer |
|---|---|---|---|
| No TCP reassembly | A message cut by segmentation is read as far as its first segment goes. The segments that carry the rest start in the middle of a message and are `"Unknown"`. | `truncated` on the last unit of a segment, for the decoders that tile it: GIOP, RDP, IEC 104, STANAG 5066 | Reassemble each direction of a flow, then probe |
| A record over several segments | A TLS record that runs into the next segment makes the following segments `"Unknown"`: they start with ciphertext, not with a record header. | Nothing | The same reassembly |
| One label per packet, no memory of the flow | A flow can carry several labels: `"Unknown"` for its continuation segments, `"TLS"` after a STARTTLS or an RDP negotiation. SSH is recognized by its identification string alone, one segment in each direction. | The flow identity, which stays the same: the consumer can keep the first label that is not `"Unknown"` | Pin the label of a flow, and decide when a protocol switch may change it |
| Retransmissions are parsed again | A retransmitted segment gets the label of the segment it repeats, and is counted twice. The HTTP oracle sets 6 such segments aside, the RDP oracle 10. | The TCP sequence number, in `TransportDetails` | Compare sequence numbers per flow |
| No IP reassembly | A fragmented datagram has no transport layer, no ports and no label, its first fragment included. | `Ipv4Packet::is_fragmented()`, `Ipv6Packet::is_fragmented()` | Reassemble, then parse the transport layer |
| A fragmented tunnel is not peeled | The outer flow has no `inner`: the conversation inside the tunnel is not seen. | `is_fragmented()` on the outer packet | The same reassembly |
| A reply is not paired with its request | Nothing matches a response to a request, by transaction identifier or otherwise. A reply that is one byte long, like PostgreSQL's answer to an `SSLRequest`, is recognized on its port only. | The identifiers each decoder reads | Keep the pending requests of a flow |
| A header that is opaque without the handshake | A QUIC short header is plausible on UDP 443 and undecidable elsewhere: off that port, the datagrams of an established connection are `"Unknown"`. | [Decode As](./application.md#decode-as), `QuicShortHeader` | Remember the connection IDs of the handshake |
| Preempted frames | An IEEE 802.3br fragment of a preemptible frame is refused. | `Err`, with `LinkLayerError::PreemptibleFragment` | Reassemble the mPackets |

## What the crate chooses not to do

| Limit | What follows for a consumer | What the crate exposes |
|---|---|---|
| Checksums are never verified during a parse | A packet damaged in transit parses like a healthy one. The choice is deliberate: on a sender-side capture with hardware offloading the checksums are not computed yet. | `packet_parser::checksum::verify_ipv4_header_checksum`, `verify_tcp_checksum`, `verify_udp_checksum` |
| Nothing is decrypted | TLS, SSH, ESP, WireGuard, OpenVPN and QUIC are labelled from their cleartext envelope. What they carry is not seen: HTTP inside TLS is `"TLS"`. | The label of the envelope |
| The application layer is a label | `parse` names the protocol and decodes nothing above the transport layer. | The decoder of each protocol, called on the transport payload: `XxxPacket::try_from` |
| Tunnels are peeled four levels deep | At `MAX_TUNNEL_DEPTH`, the fourth level, a tunnel is no longer peeled and its payload stays opaque. | `flatten()`, which returns at most four flows |
| The text probes read a prefix | The FTP, SMTP, NNTP and HTTP probes validate the first `PROBE_CAP` bytes of a payload, 18 KiB, and nothing beyond. | The decoder, which reads the whole payload when called directly |
| A truncated capture is not told apart | `parse` receives the captured bytes only. A packet cut by the snapshot length fails its length checks and is reported like a packet with a lying header. | `corrupted`, with the layer and the text of the error |

## Three fields to look at

- `corrupted` is `Some` when a layer was announced and its bytes were refused. The layers below it are valid; the layers above it are absent, not empty ([Getting started](./getting_started.md#reading-the-outcome)).
- `is_fragmented()` explains a flow with an internet layer and no transport ([IPv4](./ipv4.md#fragments)).
- `truncated` marks a message whose end is in a later segment. It is on the decoded structs, not on `PacketFlow`.

A layer that is `None` with `corrupted` also `None` is neither an error nor a limit: the crate has no decoder for that protocol.
