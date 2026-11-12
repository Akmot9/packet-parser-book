# Valmet DNA

Valmet DNA (Metso DNA), the process network of the distributed control systems of Metso and Valmet, added in 11.8.0, the only decoder of that release ([PR #229](https://github.com/Akmot9/Packet-parser/pull/229)). On the network the crate was built from, the nodes send UDP datagrams to a multicast group: periodic status telegrams, messages that name a tag, and a beacon. The module is `packet_parser::parse::application::protocols::valmet_dna`, its error `packet_parser::errors::application::valmet_dna::ValmetDnaParseError`.

## Observed, not specified

The protocol is proprietary: there is no public specification and no public dissector, and tshark has none. The decoder is built on the observation of traffic alone, one capture taken on the mirror port of a process network in operation and anonymized in `pcaps_exemple/protocols/valmet_dna/` of the crate, without code or documentation from the vendor. It reads: it rebuilds no control logic and emits nothing. The names of the fields are those of the observation, not those of the vendor. Nothing on this page comes from the vendor either.

What the capture establishes, what the crate infers from it, and what stays unknown:

| Point | Status |
| --- | --- |
| The magic `AB 01`, the length equal to the datagram minus two, the two families and their sizes | established: true of every message of the capture |
| The node address and the multicast group in the status telegram | established: equal to the IP source and the IP destination of every telegram |
| The node number, low byte of the source node `0x80NN` | established: equal on every telegram |
| The order of the fields of the BCD clock | established on the original capture, which is not in the corpus (see [the clock](#the-bcd-clock)) |
| The two counters of the status telegram, the second repeating the first of the previous telegram | established: checked telegram after telegram; microseconds, since they advance by about 640 000 every 640 ms |
| The tag length written twice, the tag that ends the datagram, the form `:e:<class>:<path>` | established on the 400 tag messages, 360 of which have the readable form |
| The destination `0x00FF` as "all nodes" | inferred: every frame observed carries it, and all are multicast |
| The convention of the weekday | unknown: one day observed, two conventions fit |
| 87 of the 126 bytes of the status telegram, 56 of the 72 bytes of the tag message header, 16 of the 42 bytes of the beacon | not identified, kept as bytes |
| What the classes, the beacon's code and counter, and any other family mean | unknown |

## The capture

The corpus capture, `valmet-dna-multicast-anon.pcap`, is the first twelve seconds of DNA traffic of a 212-second capture made by the maintainer on 2026-11-03. Its 720 UDP datagrams all go to the multicast group `239.0.171.1`, whose last two bytes, 171 and 1, are the magic `AB 01`:

- 719 on UDP 2517 → 2517: 319 status telegrams of 126 bytes, sent every 640 ms by each of 17 nodes, `0x8008` to `0x802D`, 18 or 19 each; and 400 tag messages of 82 to 116 bytes from 14 of those nodes;
- 1 on UDP 4516 → 4517: the 42-byte beacon, frame 591.

The anonymization renumbered the unicast MAC and IPv4 addresses (the IPv4 ones into `10.0.2.0/24`, with the node address inside the payload), substituted the site-specific part of the tags letter by letter and digit by digit, and rewrote the clocks on the timestamp of their frame, rebased to 2020-01-01 00:00:00 UTC. Everything else in the payloads, headers, families, lengths, counters and bytes not identified, is identical byte for byte to the original, according to the folder's `SOURCE.md`.

## Detection: three ports, then a blind probe

As for [PTP](./ptp.md) on UDP, the pipeline gives the datagram a label, `"Valmet DNA"`, and nothing more: the decode is `ValmetDnaPacket::try_from`, or `TimeBeacon::try_from` for the beacon, on the transport payload. No port is registered in the protocol's name; 2517, 4516 and 4517 are the ports the capture shows. The crate therefore has three routes, from the most tolerant to the strictest:

| Where | Probe | Accepts |
| --- | --- | --- |
| UDP 2517, 4516 or 4517, on either side | `ProbeId::ValmetDna` | a message with a coherent header, of a known family or not, or a beacon |
| a port declared with `ParseConfig::decode_as(port, DecodeAsProtocol::ValmetDna)` | `ProbeId::ValmetDna` | the same |
| any other UDP port | `ProbeId::ValmetDnaBlind` | a message of one of the two known families, at its exact size |

In the table of `src/parse/dispatch.rs`:

```rust
// among the port rules, after BACnet/IP: UDP 2517 for the AB 01 messages,
// 4516 -> 4517 for the beacon, the observed ports. On these ports an unknown
// message family is accepted with its body as bytes; elsewhere, the blind
// probe below only accepts the two known families.
port_rule("Valmet DNA", Guard::Udp, is_valmet_dna_udp_port, ProbeId::ValmetDna),
// ...
// --- blind cascade ---
rule("NTP", Guard::Udp, ProbeId::NtpBlind),
rule("RTPS", Guard::Udp, ProbeId::Rtps),
// Magic AB 01, a length equal to the datagram minus two and a known family
// at its exact size: more than 64 bits of constraint, enough to do without
// the port.
rule("Valmet DNA", Guard::Udp, ProbeId::ValmetDnaBlind),
rule("ASTERIX", Guard::Udp, ProbeId::Asterix),
```

with the probes, both on the whole datagram and not on its first `PROBE_CAP` bytes, since the length must equal the datagram minus two:

```rust
ProbeId::ValmetDna => ValmetDnaPacket::is_port_udp_match(payload),
ProbeId::ValmetDnaBlind => ValmetDnaPacket::is_blind_udp_match(payload),

impl ValmetDnaPacket<'_> {
    pub(crate) fn is_port_udp_match(payload: &[u8]) -> bool {
        ValmetDnaPacket::try_from(payload).is_ok() || TimeBeacon::try_from(payload).is_ok()
    }

    pub(crate) fn is_blind_udp_match(payload: &[u8]) -> bool {
        ValmetDnaPacket::try_from(payload).is_ok_and(|packet| packet.kind.is_some())
    }
}
```

The blind rule comes right after RTPS and before ASTERIX in the [blind cascade](./application.md#reading-the-table), and takes the same place in `Application::try_from`, which has no ports. The beacon has no blind route: off its ports, it needs a declared port. [Decode As](./application.md#decode-as) resolves `DecodeAsProtocol::ValmetDna` to `("Valmet DNA", Guard::Udp, ProbeId::ValmetDna)`, the probe of the port rule, behind the same UDP guard: a unit test of `dispatch.rs` checks that a status telegram on TCP 2517 is not Valmet DNA, Decode As included.

Frames 1, 9 and 591 moved to UDP 40000 → 40001: the status telegram and the tag message keep their label, the beacon needs Decode As (*tested*):

```rust
{{#include ../examples/src/dcs.rs:valmet_detection}}
```

## The header

![The 126-byte status telegram of frame 1 of valmet-dna-multicast-anon.pcap, 32 bits per row: the 12-byte header with the magic AB 01, the source node 0x801D, the destination 0x00FF, the length 124 and the message kind 0x00000FFF, then the fields the crate names, the node address 10.0.2.1, the ten-byte BCD clock with its fraction and its year little-endian (2020-01-01 00:00:00.0000, weekday 3, rewritten by the anonymization), the node number 0x1D, the multicast group 239.0.171.1 and the two microsecond counters 0x540F5BF1 and 0x54059702, with the bytes not identified summarised in between; ValmetDnaPacket keeps the header fields, the body and a StatusTelegram with the named values.](images/application/valmet_dna_status.svg)

```rust
#[non_exhaustive]
pub struct ValmetDnaPacket<'a> {
    /// The sending node: 0x80NN on every frame observed, NN the node number.
    pub source_node: u16,
    /// 0x00FF on every frame observed, all multicast.
    pub destination: u16,
    /// The declared length: the datagram minus two.
    pub length: u16,
    /// The message family, as read.
    pub kind_code: u32,
    /// The named family, when MessageKind knows it.
    pub kind: Option<MessageKind>,
    /// Everything after the 12-byte header, as is.
    pub body: &'a [u8],
    pub message: ValmetDnaMessage<'a>,
}

#[non_exhaustive]
pub enum MessageKind {
    /// 0x00000FFF: the periodic status telegram, 126 bytes.
    Status,
    /// 0x001E00D0: the tag message.
    Tag,
}

#[non_exhaustive]
pub enum ValmetDnaMessage<'a> {
    Status(StatusTelegram),
    Tag(TagMessage<'a>),
    /// Unknown family: the body is in ValmetDnaPacket::body.
    Unknown,
}
```

| Bytes | Field | Note |
| --- | --- | --- |
| 0–1 | magic | `AB 01`, checked, not kept |
| 2–3 | `source_node` | `0x80NN` on every frame of the capture; `node_number()` returns `NN` |
| 4–5 | `destination` | `0x00FF` on every frame of the capture: "all nodes", likely |
| 6–7 | `length` | the bytes after the magic: the datagram minus two, exactly |
| 8–11 | `kind_code` | `MessageKind::from_code` names `0x00000FFF` and `0x001E00D0` |
| 12– | `body` | everything after the header, the named fields included |

Every integer is read big-endian, except the two words of the clock. The family decides the rest: a status telegram, a tag message, or `Unknown`.

## The status telegram

The family `0x00000FFF`, 126 bytes exactly, sent by each node every 640 ms: the frame timestamps of the capture, whose gaps the anonymization kept, put two telegrams of a node between 638.8 and 642.3 ms apart.

```rust
#[non_exhaustive]
pub struct StatusTelegram {
    /// The node's IPv4 address: the IP source on every frame observed.
    pub node_ip: Ipv4Addr,
    /// The node's clock, when its ten bytes form a valid date.
    pub clock: Option<DnaClock>,
    /// The low byte of ValmetDnaPacket::source_node on every frame observed.
    pub node_number: u8,
    /// The network's multicast group: the IP destination.
    pub multicast_group: Ipv4Addr,
    /// A 32-bit counter in microseconds, modulo 2^32.
    pub tick: u32,
    /// The tick of the node's previous telegram.
    pub previous_tick: u32,
}
```

| Bytes | Field | What ties it down |
| --- | --- | --- |
| 0–11 | header | family `0x00000FFF`, length 124 |
| 12–35 | not identified | |
| 36–39 | `node_ip` | equal to the IP source of all 319 telegrams |
| 40–41 | not identified | |
| 42–51 | `clock` | a [`DnaClock`](#the-bcd-clock) |
| 52–57 | not identified | |
| 58 | `node_number` | equal to the low byte of `source_node` on all 319 |
| 59–69 | not identified | |
| 70–73 | `multicast_group` | equal to the IP destination |
| 74–105 | not identified | |
| 106–109 | `tick` | see [the counters](#the-two-counters) |
| 110–113 | `previous_tick` | the `tick` of the node's previous telegram |
| 114–125 | not identified | |

The telegram of node `0x801D`, frame 1 of the capture (*tested*):

```rust
{{#include ../examples/src/dcs.rs:valmet_status_telegram}}
```

### The BCD clock

The status telegram and the beacon carry the same ten-byte clock, every digit in BCD, two digits per byte:

```rust
#[non_exhaustive]
pub struct DnaClock {
    /// Fraction of a second, in units of 100 µs (0 to 9999).
    pub fraction: u16,
    pub second: u8,
    pub minute: u8,
    pub hour: u8,
    pub weekday: u8,
    pub day: u8,
    pub month: u8,
    pub year: u16,
}
```

| Bytes | Field | Note |
| --- | --- | --- |
| 0–1 | `fraction` | two BCD bytes, low byte first: `86 95` is 9586, in units of 100 µs |
| 2 | `second` | 0 to 59 |
| 3 | `minute` | 0 to 59 |
| 4 | `hour` | 0 to 23 |
| 5 | `weekday` | 0 to 7 |
| 6 | `day` | 1 to 31 |
| 7 | `month` | 1 to 12 |
| 8–9 | `year` | two BCD bytes, low byte first: `26 20` is 2026; no range |

**How the order was established.** On the original capture, not on the corpus one: the seconds go from 59 to 00 with a carry into the minutes, the fraction advances by 6 400 per telegram, the 640 ms of the period, and the hour and the weekday are those of the day of the capture. The corpus capture cannot show this again. Its clocks were rewritten on the timestamps of the frames, which start at midnight on 2020-01-01 and last twelve seconds: no minute rolls over, and the year is `20 20`, which does not show the order of its two bytes. On the original capture, the clocks of the nodes were twenty-nine minutes off the legal time, by the same amount on every node: the clock dates the exchanges between nodes, not the outside world.

**The weekday** was 2 on the day of the original capture, a Tuesday: Monday is 1 (ISO 8601), or Sunday is 0. With a single day observed, the two conventions agree, and the crate does not choose. The rewritten clocks of the corpus say 3, 2020-01-01 being a Wednesday.

`DnaClock::from_bytes` reads the first ten bytes of its argument and returns `None` if there are fewer, if a nibble is not a decimal digit, or if a field is out of its range: an unset clock, not a decoding error. A telegram or a beacon with such a clock still decodes, with `clock: None`. `microseconds_of_day()` gives the microseconds since midnight, to compare two clocks of the same day.

The clock of the beacon, the vector of the crate's unit test for the year, and an unset clock (*tested*):

```rust
{{#include ../examples/src/dcs.rs:valmet_clock}}
```

### The two counters

`tick` and `previous_tick` are two 32-bit counters, read big-endian. `previous_tick` repeats the `tick` of the same node's previous telegram: the golden test checks it on the 302 telegrams of the capture that have a predecessor. From one telegram to the next, `tick` advances by about 640 000, 639 111 to 642 481 on the capture, over a period of 640 ms: microseconds, modulo 2³². The crate does not interpret them further; what they count from is not known.

## The tag message

The family `0x001E00D0`: a fixed 72-byte header, then a tag that ends the datagram.

```rust
#[non_exhaustive]
pub struct TagMessage<'a> {
    /// The declared tag length, equal to tag.len().
    pub tag_length: u16,
    /// The tag, as is: `:e:<class>:<path>` when it is readable, ten bytes
    /// that are not text otherwise.
    pub tag: &'a [u8],
}

impl<'a> TagMessage<'a> {
    pub fn tag_text(&self) -> Option<&'a str>;  // the tag, when it is valid UTF-8
    pub fn class(&self) -> Option<&'a str>;     // <class> of `:e:<class>:<path>`
    pub fn path(&self) -> Option<&'a str>;      // <path> of the same form
}
```

| Bytes | Field | Note |
| --- | --- | --- |
| 0–11 | header | family `0x001E00D0` |
| 12–27 | not identified | |
| 28–29 | `tag_length` | |
| 30–69 | not identified | |
| 70–71 | the tag length, again | must equal the first |
| 72– | `tag` | `tag_length` bytes, up to the end of the datagram |

The decoder checks that the datagram holds the 72 bytes of the header, that the two lengths are equal, and that 72 plus the tag length is the datagram; the tag is borrowed, not copied. An empty tag, two zero lengths in 72 bytes, is accepted.

The tags of the capture start with `:e:`. 360 of the 400 are readable text of the form `:e:<class>:<path>`, with a class of two letters: `di` 286 times, `pr` 57, `sn` 9, `hw` 6 and `li` 2. `class()` and `path()` answer when the text starts with `:e:`, has a non-empty class and a second colon; the path may be empty. The 40 others are ten bytes that are not UTF-8: frame 2, in the crate's unit tests, is `:e:A2`, then `0xC1`, `1`, a NUL and `0xFE 0xFF`; `tag_text`, `class` and `path` are `None` for them, and `tag` keeps the bytes. The crate calls the two letters a class, after their place in the tag; what they mean is not known. In the corpus, the path is the anonymized one: the marker, the class, the delimiters and the length are the original ones, the letters and digits of the path are not.

A tag of class `di` sent by node `0x8028`, frame 9 of the capture (*tested*):

```rust
{{#include ../examples/src/dcs.rs:valmet_tag_message}}
```

## Unknown families

A message whose header is coherent, magic and length, but whose family is neither `0x00000FFF` nor `0x001E00D0`, decodes with `kind: None` and `message: ValmetDnaMessage::Unknown`; its bytes are in `body`, as they are in every message. The port rule and Decode As accept it, the blind probe does not: off the ports, a magic and a length alone are not enough. The capture has no such message: its 719 `AB 01` messages are of the two known families.

Frame 1 with the family `0x00000FFE`, on its port and moved (*tested*):

```rust
{{#include ../examples/src/dcs.rs:valmet_unknown_family}}
```

## The beacon

On UDP 4516 → 4517, to the same group, a node sends a 42-byte beacon that carries the same clock. It does not start with `AB 01`, so `ValmetDnaPacket::try_from` refuses it (`InvalidMagic(0)`); `TimeBeacon::try_from` reads it.

```rust
#[non_exhaustive]
pub struct TimeBeacon {
    pub code: u16,
    pub counter: u32,
    /// The same clock as in the status telegrams.
    pub clock: Option<DnaClock>,
    /// The node's IPv4 address: the IP source of the datagram.
    pub node_ip: Ipv4Addr,
}
```

| Bytes | Field | Note |
| --- | --- | --- |
| 0–3 | prefix | four zero bytes, checked, not kept |
| 4–5 | magic | `AB CC`, checked, not kept |
| 6–7 | `code` | 6 in the capture |
| 8–11 | `counter` | `0x23800000` in the capture |
| 12–27 | not identified | |
| 28–37 | `clock` | a `DnaClock` |
| 38–41 | `node_ip` | equal to the IP source |

The module documentation gives the beacon a period of 30 s; the twelve seconds of the corpus capture hold a single one, frame 591, sent from the address of node `0x802C`, so the period cannot be checked there. With one beacon, the code and the counter are kept as read, without a meaning. The beacon is recognized on UDP 2517, 4516 and 4517 and on a declared port, never blind.

Frame 591 (*tested*):

```rust
{{#include ../examples/src/dcs.rs:valmet_beacon}}
```

## Validations

All of them are `ValmetDnaParseError`:

| Error | When |
| --- | --- |
| `Truncated { expected, actual }` | fewer than the 12 bytes of the header, or a tag message shorter than its 72-byte header |
| `InvalidMagic(u16)` | the first two bytes are not `AB 01` |
| `LengthMismatch { declared, actual }` | the declared length plus two is not the size of the datagram |
| `InvalidMessageLength { kind, expected, actual }` | a status telegram of another size than 126 bytes, or a tag message whose header and tag do not make the datagram |
| `TagLengthMismatch { declared, echo }` | the tag lengths at offsets 28 and 70 differ |
| `InvalidBeaconLength { actual }` | a beacon of another size than 42 bytes |
| `InvalidBeaconPrefix(u32)` | the first four bytes of a beacon are not zero |
| `InvalidBeaconMagic(u16)` | the next two are not `AB CC` |

A clock that is not a date is not an error: it is `clock: None`. Like every application decoder, a failure is not a corruption: the datagram goes on to the next rules of the table, and nothing goes to `corrupted`.

Four refusals, and an altered telegram that stays on UDP 2517 and comes out `"Unknown"` (*tested*):

```rust
{{#include ../examples/src/dcs.rs:valmet_refused}}
```

## Validation without tshark

Without a dissector there is no tshark oracle to compare with. The golden test `tests/valmet_dna_golden.rs` checks the structure against what the capture carries elsewhere, and against itself over time. Each of the 720 datagrams must be labelled `"Valmet DNA"` and decode, and:

- every `AB 01` message has a length equal to the datagram minus two, a source node `0x80NN`, the destination `0x00FF`, and a body of the datagram minus twelve;
- every status telegram has 126 bytes, the IP source as `node_ip`, the IP destination as `multicast_group`, the low byte of its source node as `node_number`, one address per node, and a valid clock; from one telegram of a node to the next, the clock advances by 630 to 650 ms, `tick` by 630 000 to 650 000, and `previous_tick` equals the previous `tick`;
- every tag message is 72 bytes plus its tag, the tag starts with `:e:`, a readable tag has a non-empty path, and a tag that is not text has ten bytes;
- the beacon has the IP source as `node_ip`, the code 6, the counter `0x23800000`, and comes from the address of node `0x802C`.

The test then freezes the counts: 319 status telegrams, 400 tag messages, 1 beacon; the 17 nodes, with 18 or 19 telegrams each; the classes; the 40 tags that are not text; tags of 10 to 44 bytes, sent by 14 nodes. A second test moves frames 1, 9 and 591 off their ports, as in the [detection example](#detection-three-ports-then-a-blind-probe). The checks are consistency checks: they tie each named field to the IP header, to the message header or to the node's next telegram, and cannot confirm a field against a reference, since there is none.

In the golden histogram of `pcaps_exemple/protocols/` (`tests/golden_pcaps.rs`), `"Valmet DNA"` went from 0 to 720 with 11.8.0: the 720 datagrams of the new capture, and no frame of the rest of the corpus, where nothing else moved. The fuzz target `parse_valmet_dna` runs nightly ([data validation](./data_validation.md#no-panic-on-hostile-bytes)), on its input and on mutations of frames 1, 9 and 591: no panic, and when a decode succeeds, the length is the input minus two, the body and the tag are borrowed from the input, the clock is within its ranges, and `Application::try_from` says `"Valmet DNA"` exactly when the family is known.

## What is left out

- **The bytes not identified** stay bytes: 87 of the 126 of the status telegram, 56 of the 72 of the tag message header, 16 of the 42 of the beacon. Those of a message are in `body`; `TimeBeacon` does not expose its own, which stay in the transport payload.
- **No meaning is given** to the classes of the tags, to the code and the counter of the beacon, or to the families the capture does not show. What a tag message says about its tag, beyond naming it, is not known.
- **The destination `0x00FF`** reads as "all nodes" only because every frame observed carries it and goes to the multicast group; no other value was observed.
- **The weekday** is kept as read, without a convention.
- **One site, one capture**: the ports, the group and the families are those of one network. On other ports, the blind probe still recognizes the two known families; anything else needs a declared port.
- **Read-only**: the crate builds no message, rebuilds no control logic, and emits nothing.
