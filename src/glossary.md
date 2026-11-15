# Glossary

The words the book relies on, each with the page that puts it to work.

## Blind

A blind [rule](#rule) has no port guard: its [probe](#probe) runs on any port, and the content alone gives the label. A blind probe is stricter than the probe of the same protocol behind a port. See [Three detection routes](./application.md#three-detection-routes).

## Corpus

The real captures of the crate, under `pcaps_exemple/`, each with its provenance in a `SOURCE.md`. The golden tests and the oracles run on it. See [Adding a new protocol](./adding_a_protocol.md#5-tests).

## Corrupted layer

A layer that a lower layer announced and whose bytes were refused. It stays `None`, and `PacketFlow::corrupted` names it and carries the text of the error. See [Reading the outcome](./getting_started.md#reading-the-outcome).

## Decode As

A port the caller declares for a protocol, through `ParseConfig`. It extends a port guard and never replaces the probe: the content must still match. See ["Decode As"](./application.md#decode-as).

## Flow identity

The MAC addresses, IP addresses, protocols and ports of a packet. `PacketFlow` compares and hashes on it, not on the payloads. See [Flow identity](./packet.md#flow-identity).

## Golden test

A test of the crate that parses real frames of the corpus and compares the result with values frozen in the repository. See [Adding a new protocol](./adding_a_protocol.md#5-tests).

## Inner flow

The `PacketFlow` of the packet a tunnel carries, held in the `inner` field of the outer flow. See [Tunnels](./tunnels.md#inner-and-flatten).

## Label

The name the crate gives the application protocol of a flow: a variant of `ApplicationProtocol`, written as text in the JSON output. See [Protocols](./protocols.md#the-54-labels).

## Oracle

The output of tshark on the corpus, frozen in a file of the repository. A golden test compares the crate with it, field by field. See [Protocols](./protocols.md#the-54-labels).

## Owned flow

`PacketFlowOwned`, the form of a flow that does not borrow the capture buffer. It keeps the identity and drops the payloads and the `details`. See [Owned flows and serialization](./getting_started.md#owned-flows-and-serialization).

## Port guard

The list of ports of a [rule](#rule). The rule is tried only when the source or the destination port is in the list. See [Reading the table](./application.md#reading-the-table).

## Probe

The function that says whether a payload is a given protocol. It usually runs the decoder of the protocol and keeps only the verdict. See [How the label is chosen](./application.md#how-the-label-is-chosen-one-ordered-table).

## `PROBE_CAP`

The number of bytes a text probe reads, 18 KiB. Only the FTP, SMTP, NNTP and HTTP probes stop there; every other probe reads the [whole payload](#whole-payload). See [How the label is chosen](./application.md#how-the-label-is-chosen-one-ordered-table).

## Rule

One row of the dispatch table: a label, a transport guard, an optional port guard and a probe. The rules are tried in order, and the first whose probe accepts the payload gives the label. See [Reading the table](./application.md#reading-the-table).

## Stateless

`parse` reads one packet and keeps nothing between two calls: no reassembly, no memory of a flow. See [Limits](./limits.md).

## Terminal port

A port whose [rule](#rule) ends the dispatch when its probe refuses the payload: the flow gets no label, and no later rule is tried. mDNS (5353) and LLMNR (5355) are the two. See [Reading the table](./application.md#reading-the-table).

## Transport guard

The transport a [rule](#rule) accepts: `Tcp`, `Udp` or `Any`. See [Reading the table](./application.md#reading-the-table).

## Truncated

A message whose end is in a later segment. The decoders that tile a segment keep its beginning and set `truncated` on it. See [Limits](./limits.md#what-a-stateless-parser-cannot-see).

## Whole payload

What a probe judges: every byte the transport layer hands up, not a prefix. Most decoders want the payload tiled to its last byte. See [How the label is chosen](./application.md#how-the-label-is-chosen-one-ordered-table).
