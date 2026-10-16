# ASTERIX

ASTERIX (All Purpose STructured EUROCONTROL SuRveillance Information EXchange, EUROCONTROL-SPEC-0149) is the exchange format of air traffic surveillance data: radar plots and tracks, ADS-B reports, system tracks, service and status messages between sensors, trackers and their users. It travels in UDP datagrams, usually multicast, and it is the first protocol of the crate with **neither a magic nor a port**: no IANA assignment (Wireshark proposes 8600, the maintainer's radars use 8611 and 8612, Croatia Control's 21111 to 22135), and nothing in the first bytes names the protocol. What it has is structure, and the crate recognizes it by that alone: a [blind probe](./application.md#three-detection-routes) of the dispatch table, `rule("ASTERIX", Guard::Udp, ProbeId::Asterix)`, placed before DNS, whose datagram form is less constrained.

Eleven categories are decoded, eight of them since 11.6.0 ([#119](https://github.com/Akmot9/Packet-parser/issues/119), defense lot [#125](https://github.com/Akmot9/Packet-parser/issues/125)). On a real surveillance network they mix in the same datagrams, radar plots next to the service messages of the same radar, system tracks next to the status of the tracker that computes them: up to 18 data blocks in one datagram of the corpus. Module: `packet_parser::parse::application::protocols::asterix`, with one submodule `catNNN` per category, `uap` for the tables and `fields` for the types several categories share.

| CAT | Content | UAP edition | FRNs (FSPEC octets) | Typed decoder |
| --- | --- | --- | --- | --- |
| 001 | monoradar plots and tracks, the generation before CAT 048 | 1.4, two UAPs | 21 for plots (3), 22 for tracks (4) | `cat001::TargetReport` |
| 002 | monoradar service messages, the generation before CAT 034 | 1.2 | 14 (2) | `cat002::ServiceMessage` |
| 008 | monoradar derived weather information | 1.3 | 14 (2) | `cat008::WeatherMessage` |
| 021 | ADS-B target reports, editions 2.x | 2.7 | 49 (7) | `cat021::TargetReport` |
| 023 | CNS/ATM ground station and service status | 1.3 | 14 (2) | `cat023::StatusReport` |
| 034 | monoradar service messages | 1.29 | 14 (2) | `cat034::ServiceMessage` |
| 048 | monoradar target reports | 1.32 | 28 (4) | `cat048::TargetReport` |
| 062 | SDPS system tracks | 1.21 | 35 (5) | `cat062::SystemTrack` |
| 063 | sensor status | 1.7 | 14 (2) | `cat063::SensorStatus` |
| 065 | SDPS service status | 1.6 | 14 (2) | `cat065::ServiceStatus` |
| 247 | version number exchange | 1.3 | 7 (1) | `cat247::VersionReport` |

The editions are the ones tshark 4.6.6 uses by default. The tables of the eight new categories are derived from the machine-readable definitions of zoranbosnjak/asterix-specs (BSD-3) and cross-checked with tshark on the corpus. A UAP is stable from one edition to the next, apart from the number of extents of a few extended items (`I021/090`, `I062/080`), and the table keeps the latest edition, which accepts the earlier ones. `uap::uap_for(category)` returns the UAP of a category, `uap::SUPPORTED_CATEGORIES` lists the eleven.

## The datagram: data blocks

![The 66-byte UDP payload of frame 3 of cat_034_048.pcap: a CAT 048 data block of 55 bytes then a CAT 034 block of 11, each with its category byte, two length bytes, FSPEC and items; the two lengths add up to the payload exactly and the flow is labelled ASTERIX; a block of category 62, a length one byte too long or a trailing byte each fail the whole datagram](images/application/asterix_datagram.svg)

A datagram is one or more **data blocks** back to back. Each starts with one byte of category (`CAT`) and two bytes of length (`LEN`, header included), then holds one or more records. `AsterixPacket::try_from` reads blocks until the payload is consumed, and the lengths must add up to the payload exactly: a block shorter than 5 bytes or longer than what is left is `AsterixError::InvalidBlockLength`, fewer than 3 bytes left after a block is `Truncated`, and a category without a UAP is `UnsupportedCategory`. The datagram drawn above is frame 3 of `cat_034_048.pcap`: a CAT 048 track report followed by the CAT 034 sector-crossing message of the same radar (SAC 25, SIC 13), 55 + 11 = 66 bytes.

```rust
#[non_exhaustive]
pub struct AsterixPacket<'a> {
    pub blocks: Vec<AsterixDataBlock<'a>>,
}

#[non_exhaustive]
pub struct AsterixDataBlock<'a> {
    pub category: u8,
    pub length: u16,
    pub records: Vec<AsterixRecord<'a>>,
}
```

## The record: FSPEC, then the UAP

![The 52-byte record of the first data block: the FSPEC ff ff 02 expanded bit by bit, each bit a Field Reference Number, then the fifteen items in FRN order with their format and the values cat048::TargetReport decodes](images/application/asterix_record.svg)

A record starts with its **FSPEC**, a run of octets in which each of the seven high bits announces one data item and the low bit, **FX**, announces one more FSPEC octet. Bit *n* of octet *k* is Field Reference Number 7*k* + *n*. Which item an FRN names, and in what format, is fixed by the **UAP** of the category (`uap.rs`), and the number of its FRNs bounds the FSPEC: 28 FRNs for CAT 048, so at most 4 FSPEC octets (the table above gives the others). An FSPEC longer than the UAP allows, or one whose FX never drops, is `FspecOverflow`; an FSPEC that sets no bit at all is `EmptyRecord`. The FRNs the specification leaves undefined are `None` in the table, and a bit set on one of them is `UnknownFrn`: FRNs 16 to 19 of the CAT 001 plots, 12 of CAT 002 and of CAT 063, 43 to 47 of CAT 021, 10 to 12 of CAT 023, 2 and 29 to 33 of CAT 062, 8 to 12 of CAT 065, 5 of CAT 247.

```rust
#[non_exhaustive]
pub struct Uap {
    pub category: u8,
    pub items: &'static [Option<ItemSpec>],   // items[frn - 1], None for a reserved FRN
    pub selector: Option<UapSelector>,        // when the category has several UAPs
}

#[non_exhaustive]
pub struct ItemSpec {
    pub id: &'static str,   // "I048/010"
    pub format: ItemFormat,
}
```

`Uap::item(frn)` and `Uap::item_by_id("I048/240")` look an item up, and `Uap::max_fspec_octets()` is the bound above. The items are then cut in FRN order, each one a zero-copy slice:

```rust
#[non_exhaustive]
pub struct AsterixRecord<'a> {
    pub category: u8,
    pub fspec: &'a [u8],
    pub items: Vec<AsterixItem<'a>>,
}

#[non_exhaustive]
pub struct AsterixItem<'a> {
    pub frn: u8,
    pub id: &'static str,   // "I048/240"; "I048/SP", "I048/RE", "I001/RFS"
    pub data: &'a [u8],
}
```

`record.item("I048/240")` returns the bytes of an item, `record.has(..)` says whether it is there, and `record.uap()` returns the UAP that cut the record. A record ends where its last item ends, and the next record starts right there, until the block is consumed: the record of the drawing is the whole 52-byte body of its block.

### CAT 001: two UAPs, chosen by the record

CAT 001 has one UAP for plots and one for tracks. They agree on FRNs 1 and 2 and part from FRN 3: `I001/040` for a plot, `I001/161` for a track. `uap::CAT001`, the UAP `uap_for(1)` returns, is the plot one, and the only UAP of the crate with a selector:

```rust
#[non_exhaustive]
pub enum UapSelector {
    Cat001TargetType,   // TYP, bit 8 of the first octet of I001/020: 0 plot, 1 track
}
```

The selector reads TYP in `I001/020` (FRN 2), right after the FSPEC, or after the two bytes of `I001/010` when FRN 1 is set. TYP = 1 selects `uap::CAT001_TRACK`, whose `selector` is `None`; without `I001/020` the record is a plot, as for tshark. The bound on the FSPEC follows the UAP chosen, 3 octets for a plot and 4 for a track, and `record.uap()` tells which one cut the record (*tested*):

```rust
{{#include ../examples/src/defense_b.rs:asterix_cat001_uap}}
```

The corpus has no CAT 001 track: all its CAT 001 records are plots, and the track UAP is covered by the crate's unit tests, on synthetic bytes.

## Eight item formats

The UAP names the format, and the format says where the item ends. The crate cuts along these rules and nothing else: at this level an item is bytes, not a value.

```rust
#[non_exhaustive]
pub enum ItemFormat {
    Fixed(usize),
    Variable,
    Repetitive(usize),
    Compound(&'static [Subfield]),
    Explicit,
    Extended(&'static [usize]),
    RepetitiveFx(usize),
    Rfs,
}
```

The drawing shows five of them on real bytes:

![Five item formats on real bytes: a fixed item whose length comes from the UAP, a variable item that extends while the FX bit is set, a repetitive item that starts with a count, a compound item whose primary subfield says which subfields follow, and an explicit item that starts with its own length](images/application/asterix_formats.svg)

- **Fixed(n)**: *n* bytes, from the UAP.
- **Variable**: one-byte extents chained by their FX bit, like the FSPEC, as many as the record sets: `I048/030`, `I001/130`, `I002/050`. Every `I002/050` of the corpus takes two octets, `0b 02` in frame 30453 of `wireshark_8579_radardata.pcap`, where tshark 4.6.6 stops after one (see [the oracle](#verified-against-tshark-record-by-record)).
- **Extended(extents)**: the bounded form, the `extended` items of the specification. Each extent has a known size and ends with its FX bit, and the FX of the last defined extent must be 0: a record that sets it announces more than the UAP describes, `ExtentOverflow`. `I048/020` has six extents of one byte: one octet in the drawing of the record (`a0`, FX 0), two in the short datagram of the anonymized capture (`01 60`). `I062/080` has seven, `I023/101` a first extent of two bytes then one of one, `I008/100` a single extent of three. The extended items of CAT 021 and 048 (`I021/040`, `I021/090`, `I021/271`, `I048/020`, `I048/170`, and the TIS subfield of `I021/110`) were unbounded `Variable` items before 11.6.0.
- **Repetitive(n)**: a one-byte count `REP`, then `REP × n` bytes. `I048/250` carries the Mode S BDS registers, 8 bytes each.
- **RepetitiveFx(n)**: units of *n* bytes, the FX bit ending the last byte of each unit, as many as the record sets: `I062/510`, three bytes per unit. `Variable` is the case *n* = 1.
- **Compound**: a primary subfield, itself FX-chained, whose bits say which subfields follow. Each subfield is a `Subfield`: `Fixed`, `Variable`, `Repetitive`, `Extended` or `RepetitiveFx`, and a bit set on a `Subfield::Spare`, or beyond the list, is `UnknownSubfield`. `I048/130` here announces its first three subfields, one byte each; in the anonymized capture the same item is a single `00`: a compound with no subfield at all. `record.subfield("I048/130", 1)` returns the bytes of a subfield by its number in the specification, from 1, and `None` when the item is absent, not compound, or without that subfield.
- **Explicit**: the first byte is the length, itself included; zero is `InvalidExplicitLength`. The `RE` and `SP` items of every category are explicit, which is how a record can carry data the UAP does not describe.
- **Rfs**: Random Field Sequencing, next section.

An item that needs more bytes than its block holds is `TruncatedItem`, with the item's id in the error.

## Random Field Sequencing

CAT 001, 002 and 008 reserve an FRN, 21 in both UAPs of CAT 001 and 14 in CAT 002 and 008, for a **Random Field Sequencing** field (Part 1, §5.3): one byte N, then N data items, each introduced by its own FRN on one byte, in any order. The crate cuts the field as one item, `I001/RFS`, `I002/RFS` or `I008/RFS`, whose bytes start with N, and checks the items it carries against the same UAP: N = 0 is `EmptyRfs`; an FRN that names no item, or the RFS itself, is `InvalidRfsFrn`; an item the FSPEC already announces, or that the field carries twice, is `DuplicateRfsFrn`, since a record carries each data item once. `record.rfs_items()` returns the items of the field in wire order, each with its FRN and id, and `record.item(id)` looks through the field: an item is found wherever the record put it. No capture of the corpus carries an RFS field. The crate's unit tests cover it on synthetic bytes, and the fuzz target checks that every RFS item it decodes is the one `record.item` returns.

## Typed values, on demand

The cut is the contract; the decoding is separate, per category, and only runs when asked for. Each `catNNN` module has a type whose `from_record` turns the usual items of a record into typed fields, every one an `Option`, or a `Vec` for the entries of `I002/070` and `I247/550`, and returns `None` for a record of another category:

| Decoder | Items it reads |
| --- | --- |
| `cat001::TargetReport` | 010, 020 (`TargetReportDescriptor`: plot or track, simulated, `RadarDetection`...), 040, 070, 090, 141 (truncated time of day), 050 (Mode 2); for a track, 161, 042, 200 and 170 |
| `cat002::ServiceMessage` | 010, 000 (`MessageType`), 020 (sector), 030, 041 (antenna rotation period), 070 (`PlotCount`s), 090 (collimation error), 100 (dynamic window) |
| `cat008::WeatherMessage` | 010, 000, 020 (vector qualifier), the vector counts of 034, 036 and 038, 040 (contour identifier), 050 (number of contour points), 090, 100 (processing status), 110, 120 |
| `cat021::TargetReport` | 010, 040, 161, 015, 071, 130, 131, 080, 073, 075, 077, 140, 210, 070, 145, 160, 170, 020, 132 |
| `cat023::StatusReport` | 010, 000 (`ReportType`), 015 (service type and identification), 070, 100 (ground station status), 101 (service configuration), 200 (operational range), 110 (service status), 120 (number of statistics) |
| `cat034::ServiceMessage` | 010, 000 (`MessageType`), 030, 020 (sector), 041 |
| `cat048::TargetReport` | 010, 140, 020, 040, 070, 090, 220, 240, 161, 042, 200, 170, 110, 250 (number of BDS registers), and since 11.6.0 050 and 055, the military IFF Mode 2 and Mode 1 codes |
| `cat062::SystemTrack` | 010, 015, 070, 105 (WGS-84), 100, 185, 210, 060, 245, the ADR, ID and MHG subfields of 380, 040, 080, 200, 136, 130, 135, 220, 120 (Mode 2), and the sensor, position, Mode C and Mode 3/A of the last measurement, 340 |
| `cat063::SensorStatus` | 010, 015, 030, 050 (the sensor), 060 (connection and NOGO per technology), 070 (time stamping bias), 080, 081, 090, 091, 092 (range gains and biases, azimuth and elevation biases) |
| `cat065::ServiceStatus` | 010, 000 (`MessageType`), 015, 030, 020 (batch number), 040 (SDPS configuration and status), 050 |
| `cat247::VersionReport` | 010, 015, 140, 550 (a `CategoryVersion` per category announced) |

The values keep what the wire carries and give their conversion beside it, never in its place: `TimeOfDay::seconds()` (LSB 1/128 s), `FlightLevel::flight_level()` (LSB 1/4 FL), `range_nm()` and `azimuth_deg()` on the polar positions (LSB 1/256 NM in CAT 048, 1/128 NM in CAT 001), `latitude_deg()` and `longitude_deg()` on the WGS-84 positions. `Mode3ACode`, and since 11.6.0 `Mode2Code` and `Mode1Code`, display in octal, `AircraftAddress` in hexadecimal, `AircraftIdentification` from its 6-bit ICAO characters (a code outside the alphabet is rendered `?`). On the datagram drawn above, the CAT 048 record and the CAT 034 one (*tested*):

```rust
{{#include ../examples/src/defense_b.rs:asterix_typed_values}}
```

A system track of CAT 062 and the end of batch that follows it in the same datagram (*tested*):

```rust
{{#include ../examples/src/defense_b.rs:asterix_system_track}}
```

And the status categories: an ADS-B ground station (CAT 023) and the editions it announces (CAT 247), a sensor seen by the tracker (CAT 063), the start of a weather picture (CAT 008) (*tested*):

```rust
{{#include ../examples/src/defense_b.rs:asterix_status_messages}}
```

What a typed decoder does not read stays reachable through `record.item(..)`, and `record.subfield(..)` for a compound item: the BDS registers of `I048/250`, the subfields of `I048/130` or `I062/290`, the vectors of a CAT 008 picture, the `RE` of a CAT 021 report.

## The probe: all or nothing

`ProbeId::Asterix` is `AsterixPacket::try_from(payload).is_ok()`: the label is given only when the whole datagram cuts cleanly, every block of a decoded category, every record filling its block to the last byte. `CAT + LEN` alone would match far too many datagrams; the structure of a block of an unknown category cannot be checked, so one such block refuses the whole datagram rather than labelling half of it.

The drawing of the datagram shows three refusals. The CAT 034 block relabelled CAT 062 is still refused, but since 11.6.0 by the CAT 062 UAP, which reads its FSPEC `f0` and finds FRN 2 reserved (`UnknownFrn`); relabelled CAT 010, a category without a UAP, it is `UnsupportedCategory`. A length one byte too long makes the extra byte open a record whose first item is truncated; one trailing byte is `Truncated`, 3 bytes needed. Zero padding inside a block fails the same way: a record of `00` is `EmptyRecord`. A refused datagram goes on to the next rules of the table and usually comes out `"Unknown"`, with nothing in `corrupted`. All five, on the bytes of the drawing (*tested*):

```rust
{{#include ../examples/src/defense_b.rs:asterix_all_or_nothing}}
```

The probe runs on the first `PROBE_CAP` bytes of the payload, 18 KiB: a datagram larger than that is cut before the probe and cannot tile, so it is not labelled. Surveillance datagrams are far smaller.

## Verified against tshark, record by record

`tests/asterix_golden.rs` replays the nine files of `pcaps_exemple/protocols/asterix/` (see its `SOURCE.md`):

- the maintainer's anonymized CAT 048 capture, 203 datagrams on ports 8611 and 8612;
- three samples of Croatia Control: a CAT 034/048 capture (100 datagrams, 20 of them with two blocks), a CAT 062/065 datagram, and a raw stream of two CAT 021 blocks (`cat21_re.ast`);
- five attachments of the Wireshark tracker: `wireshark_8579_radardata.pcap`, 50 000 frames of a control network with 41 928 ASTERIX datagrams on 18 multicast streams; `wireshark_9953_cat021023.pcap`, 1 588 datagrams of CAT 021, 023 and 247; `wireshark_9624_cat62_re.pcap`, 668 datagrams of CAT 062 with their Reserved Expansion Field, some followed by a CAT 065 block; and the two CAT 008 captures of issue 9239, 9 and 10 datagrams.

For every record of every frame, the sequence of items and the length of the record are compared with an oracle produced from tshark 4.6.6 `-V` by `tools/asterix_oracle.py`, frames of the same shape grouped (`tests/data/asterix_tshark_oracle.tsv`): **44 411 frames** in parity, which carry

| CAT | 001 | 002 | 008 | 021 | 023 | 034 | 048 | 062 | 063 | 065 | 247 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| data blocks | 29 520 | 19 512 | 67 | 1 555 | 30 | 7 913 | 7 484 | 7 759 | 307 | 1 526 | 3 |
| records | 65 146 | 19 677 | 67 | 1 555 | 30 | 7 913 | 33 665 | 16 434 | 331 | 1 526 | 3 |

The **96 other frames** of `radardata.pcap` are those where tshark stumbles (`tests/data/asterix_tshark_limits.tsv`). Each carries a CAT 002 record whose `I002/050` takes two octets: tshark reads one, then takes the other for a parasite record read beyond the block (26 frames) or declares the frame malformed (70). The crate follows the specification and decodes these records whole; the test expects the shape tshark gives without the parasite record, `I002/050` counting for two octets. On frame 30453 (*tested*):

```rust
{{#include ../examples/src/defense_b.rs:asterix_beyond_tshark}}
```

The typed values are cross-checked with the `-V` output of tshark on real frames, in the unit tests of the `catNNN` modules and, for CAT 048 and 034, in the golden test. The golden histogram of `pcaps_exemple/protocols/` (`tests/golden_pcaps.rs`) counts 44 507 ASTERIX datagrams, exactly the 44 411 and the 96 of the two oracle files: no frame of another folder comes out ASTERIX. The eight new categories moved that count from 13 739, and `"Unknown"` from 40 177 to 9 409: the 30 047 datagrams of `radardata.pcap` that carry one of them, and 721 in the other captures (668 of `cat62_re`, 33 CAT 023/247 datagrams of `cat021023`, 19 of the two CAT 008 captures, 1 of `cat_062_065`).

The fuzz target `parse_asterix` covers the eleven categories and both UAPs of CAT 001. On whatever it decodes, it asserts that the block lengths add up to the input, that every record has an item and a UAP, that every item and every RFS item is non-empty and lies inside the buffer, as do the subfields, that the FSPECs and items of a block cover its length exactly, and it runs every typed decoder on every record.

## Validations

All of them are `AsterixError`, in `packet_parser::errors::application::asterix`; the last four are new in 11.6.0:

| Error | When |
| --- | --- |
| `Truncated { needed, actual }` | fewer than 3 bytes where a data block must start |
| `InvalidBlockLength { category, declared, available }` | a `LEN` below 5, or beyond the bytes left |
| `UnsupportedCategory(u8)` | a category without a UAP |
| `EmptyRecord { category }` | an FSPEC that announces no item |
| `FspecOverflow { category }` | an FSPEC longer than the UAP allows, or whose FX never drops |
| `UnknownFrn { category, frn }` | an FSPEC bit on a reserved FRN, or beyond the UAP |
| `UnknownSubfield { item, subfield }` | a primary subfield bit on a spare subfield, or beyond the item |
| `InvalidExplicitLength { item }` | an explicit item (`RE`, `SP`) of length 0 |
| `TruncatedItem { item, needed, actual }` | an item, a subfield or an RFS item that overflows its block |
| `BlockNotConsumed { category }` | declared, never returned (see below) |
| `ExtentOverflow { item }` | an extended item whose last defined extent sets FX |
| `EmptyRfs { category }` | an RFS field that announces no item |
| `InvalidRfsFrn { category, frn }` | an RFS item whose FRN names no item of the UAP, or the RFS itself |
| `DuplicateRfsFrn { category, frn }` | an RFS item the FSPEC already announces, or that the field carries twice |

## What is left out

- **Other categories.** A category outside the eleven, CAT 010, 019, 020 or 240 for instance, is `UnsupportedCategory` and refuses its datagram; the corpus has no capture of them.
- **Other editions.** One UAP per category, from the latest edition, which accepts the earlier ones. The CAT 021 editions 0.2x, whose UAP is entirely different from 2.x, are not described: nothing in the bytes tells the editions apart, and the crate decodes 2.x. The CAT 247 reports of `cat021023.pcap` announce CAT 021 edition 0.26, yet its 1 555 CAT 021 records cut cleanly along the 2.x UAP, for the crate as for tshark.
- **Item contents** beyond the typed subset: `RE` and `SP` stay opaque, BDS registers and weather vectors are raw bytes, the subfields of a compound item are cut and reachable by number, most of them not interpreted.
- **CAT 001 tracks and RFS fields** occur in no capture of the corpus: only the crate's unit tests, on synthetic bytes, decode them.
- `AsterixError::BlockNotConsumed` is declared but never returned: a block of at least 5 bytes always yields a record or a more precise error.
