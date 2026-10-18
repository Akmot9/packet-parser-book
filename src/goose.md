# GOOSE

Generic Object Oriented Substation Event, IEC 61850-8-1, added in 11.6.0 ([#160](https://github.com/Akmot9/Packet-parser/pull/160)) with IEC 60870-5-104 and BACnet/IP, the remaining Tier 2 protocols of the epic [#102](https://github.com/Akmot9/Packet-parser/issues/102): the events of an electrical substation, published by its IEDs in multicast, straight over Ethernet. Sampled Values, named with GOOSE in the epic, is not decoded: no redistributable capture was found. The module is `packet_parser::parse::internet::protocols::goose`.

## On Ethernet, as the internet layer

GOOSE has no IP and no UDP. It is announced by EtherType `0x88B8`, often under a VLAN tag that the [link layer](./ethernet.md) consumes, and, like [PTP](./ptp.md) on `0x88F7`, the frame *is* the internet layer. The link layer maps the EtherType to `NetworkProtocol::Goose` (added in 11.6.0, at the end of the enum), and the [internet dispatch](./network.md#dispatch-on-the-announced-protocol-not-probing) has one arm for it:

```rust
NetworkProtocol::Goose => Ok(Self::from_goose(GoosePacket::try_from(payload)?)),
```

The flow gets an `Internet` with `protocol_name` `"GOOSE"`, no addresses, `payload_protocol` `None`, an empty `payload` and the decoded frame in `InternetDetails::Goose`; `transport` and `application` stay `None`, and the golden histogram counts GOOSE frames as frames without application. There is no port and no Decode As: the EtherType decides. Nor is any error softened into "unsupported", as PTP does for an unknown version: the EtherType announced GOOSE, so every `GooseParseError` is a corrupted internet layer, `InternetError::GooseError`, whose text in `corrupted` starts with `GOOSE error: `.

In JSON, `protocol_internet` is `"GOOSE"`. The data link changed too in 11.6.0: `ethertype` is `"GOOSE"` (`Ethertype::static_name`), where 11.5.0 wrote `"Unknown (0x88B8)"`, and `network_protocol` is `{"kind": "goose"}`, where it was `{"kind": "other", "value": 35000}`.

Frame 1 of `iti_GOOSE.pcap`, a GE F650 relay, without VLAN tag (*tested*):

```rust
{{#include ../examples/src/internet_layer.rs:goose_frame}}
```

## The frame: `GoosePacket`

![The GOOSE frame of a GE F650 relay, frame 1 of iti_GOOSE.pcap, after the EtherType 0x88B8: APPID 1, length 145, two zero reserved fields, then the BER-encoded goosePdu (tag 61, length 134) whose fields are shown with their tag and length bytes: gocbRef, timeAllowedtoLive 40000, datSet, goID, the timestamp, stNum 1, sqNum 10, simulation false, confRev 1, ndsCom false, numDatSetEntries 8 and the 32-byte allData; GoosePacket and GoosePdu on the right carry the decoded values.](images/network/goose_struct.svg)

```rust
pub struct GoosePacket<'a> {
    pub app_id: u16,
    pub length: u16,
    pub reserved1: u16,
    pub reserved2: u16,
    pub pdu: GoosePdu<'a>,
}
```

| Bytes | Field | Note |
| --- | --- | --- |
| 0–1 | `app_id` | APPID |
| 2–3 | `length` | from the APPID to the end: it must be exactly the number of bytes after the EtherType |
| 4–5 | `reserved1` | bit 15 is the simulation bit, read by `simulation_bit()` |
| 6–7 | `reserved2` | |
| 8… | `pdu` | the goosePdu in BER, tag `0x61` (`[APPLICATION 1]`, constructed) |

Since `length` covers the frame exactly, the goosePdu must end where the frame ends: bytes after it are `UnexpectedTrailingBytes`, a frame cut short no longer matches its `length`. GOOSE has no `trailing` slice like PTP's.

### The goosePdu: `GoosePdu`

The PDU is a sequence of context-tagged BER elements. They are read in the order they come; a tag the PDU does not define is skipped, a mandatory field that never comes is `MissingField(tag)`:

```rust
pub struct GoosePdu<'a> {
    pub gocb_ref: &'a str,           // control block reference, LD/LLN0$GO$gcb
    pub time_allowed_to_live: u32,   // ms before a subscriber holds the publisher for lost
    pub data_set: &'a str,
    pub go_id: Option<&'a str>,
    pub timestamp: UtcTime,
    pub st_num: u32,                 // state number: incremented at each change of the data
    pub sq_num: u32,                 // sequence number: incremented at each retransmission,
                                     // back to zero with the state
    pub simulation: bool,
    pub conf_rev: u32,
    pub nds_com: bool,               // needs commissioning
    pub num_dat_set_entries: u32,
    pub all_data: Vec<GooseData<'a>>,
    pub security: Option<&'a [u8]>,  // edition 2, as is
}
```

| Tag | Field | Decoded as | When absent |
| --- | --- | --- | --- |
| `0x80` | `gocb_ref` | `&str` | `MissingField` |
| `0x81` | `time_allowed_to_live` | `u32` | `MissingField` |
| `0x82` | `data_set` | `&str` | `MissingField` |
| `0x83` | `go_id` | `&str` | `None` |
| `0x84` | `timestamp` | `UtcTime`, exactly 8 bytes | `MissingField` |
| `0x85` | `st_num` | `u32` | `MissingField` |
| `0x86` | `sq_num` | `u32` | `MissingField` |
| `0x87` | `simulation` | `bool`, exactly 1 byte | `false` |
| `0x88` | `conf_rev` | `u32` | `MissingField` |
| `0x89` | `nds_com` | `bool`, exactly 1 byte | `false` |
| `0x8A` | `num_dat_set_entries` | `u32` | `MissingField` |
| `0xAB` | `all_data` | `Vec<GooseData>` | `MissingField` |
| `0x8C` | `security` | raw bytes | `None` |

BER lengths are read in the short form and in the long form of one to four length octets. The integers are read as `u32`: one to four bytes, or five whose first is zero, which is how the simulator of `iti_GOOSE_DEMO.pcap` writes all of them. The strings borrow the frame; if their bytes are not UTF-8, the string stops before the first invalid one.

The timestamp is the `UtcTime` of §8.1.3.7:

```rust
pub struct UtcTime {
    pub seconds: u32,   // since 1970
    pub fraction: u32,  // of a second, in 1/2^24
    pub quality: u8,    // bit 7 leap second known, 6 clock failure,
                        // 5 clock not synchronized, 0–4 accuracy
}
```

`leap_second_known()`, `clock_failure()` and `clock_not_synchronized()` read the quality bits, and `nanoseconds()` converts the fraction, rounded down: 258 165 836 for the F650 frame, the value tshark prints.

### `allData`: `GooseData`

`all_data` keeps each value of the data set as BER gave it:

```rust
pub struct GooseData<'a> {
    pub tag: u8,
    pub kind: Option<DataKind>,
    pub value: &'a [u8],
}
```

`kind` names the choice of the `Data` type from the number of the tag (`tag & 0x1F`): 1 `Array`, 2 `Structure`, 3 `Boolean`, 4 `BitString`, 5 `Integer`, 6 `Unsigned`, 7 `FloatingPoint`, 9 `OctetString`, 10 `VisibleString`, 11 `GeneralizedTime`, 12 `BinaryTime`, 13 `Bcd`, 14 `BooleanArray`, 15 `ObjId`, 16 `MmsString`, 17 `UtcTime`; any other number is `None`. The value stays raw, an array or a structure keeps its encoded elements in `value`, and the one accessor is `as_bool()`, for a boolean of one byte. The number of elements is not compared with `num_dat_set_entries`.

## Validations

All of them are `GooseParseError`, in `packet_parser::errors::internet::goose`:

| Error | When |
| --- | --- |
| `Truncated { expected, actual }` | fewer than 10 bytes: the header, the PDU tag and one length byte |
| `LengthMismatch { declared, actual }` | `length` is not the number of bytes after the EtherType |
| `InvalidPduTag(u8)` | the PDU does not start with `0x61` |
| `InvalidBerLength(usize)` | at that offset, a BER length cut short, in the indefinite form, or of more than four octets |
| `ElementOverflow { tag, declared, available }` | an element declares more bytes than remain |
| `UnexpectedTrailingBytes(usize)` | bytes after the goosePdu |
| `IntegerTooLong { tag, length }` | an integer field of zero bytes, or of more than four, unless it is a zero followed by four |
| `InvalidBoolean { tag, length }` | `simulation` or `nds_com` not on one byte |
| `InvalidTimestamp(usize)` | a timestamp not on eight bytes |
| `MissingField(u8)` | a mandatory field, named by its tag |

The simulator frame, under its VLAN tag, in JSON, probed without its EtherType, then cut by one byte (*tested*):

```rust
{{#include ../examples/src/internet_layer.rs:goose_vlan_probe_corruption}}
```

## The blind probe

`Internet::try_from`, the probing parser for callers without an EtherType, tries GOOSE after ARP, IPv4, IPv6 and Profinet (see the [internet page](./network.md#dispatch-on-the-announced-protocol-not-probing)). The proof is the `length` that covers the bytes exactly and a goosePdu complete with its mandatory fields. The golden test runs the probe on every GOOSE frame of the corpus and gets the same packet back; on the frames of the other folders of `pcaps_exemple/protocols/`, neither the EtherType nor the probe gives GOOSE.

## Oracle: 494 frames, field by field

The golden test `tests/goose_golden.rs` runs the four captures of `pcaps_exemple/protocols/goose/` and compares every GOOSE frame with tshark 4.6.6, frozen in `tests/data/goose_tshark_oracle.tsv` by `tools/goose_oracle.sh`: VLAN, APPID, length, reserved words, `gocbRef`, `timeAllowedtoLive`, `datSet`, `goID`, `stNum`, `sqNum`, `simulation`, `confRev`, `ndsCom`, `numDatSetEntries`, and the number and types of the `allData` elements. The crate recognizes exactly the frames tshark sees, 452 of them under a VLAN tag that the link layer removed. The fuzz target `parse_goose` runs nightly on the decoder, seeded with the two frames of the examples.

| Capture | GOOSE frames | Publisher | VLAN |
| --- | --- | --- | --- |
| `iti_GOOSE.pcap` | 8 | a GE F650 relay, `GEDeviceF650/LLN0$GO$gcb01` | none |
| `iti_GOOSE_DEMO.pcap` | 1 | a simulator, APPID `0x2000`, ten booleans | 10 |
| `iti_Sample_File_GOOSE.pcap` | 451 | three IEDs of a substation, `AA1C1Q01A1LD0`, `AA1C1Q05A1LD0` and `AA1C1Q07A1LD0`, 25 entries per message | 0 |
| `iti_Sample_File_MMS_and_GOOSE.pcap` | 34 of 301 | the same IEDs, among MMS, NTP and TCP | none |

The four come from the ICS-Security-Tools repository of ITI (CC-BY-4.0); `pcaps_exemple/protocols/goose/SOURCE.md` says why they are taken for real traffic. A second test follows the retransmission scheme on the substation capture: of the 448 transitions between two messages of the same IED, 250 are a change of state (`stNum` + 1, `sqNum` back to 0) and 198 a retransmission (`sqNum` + 1); none is a gap.

## What is left out

- **Sampled Values** (IEC 61850-9-2, EtherType `0x88BA`) is not decoded: it maps to `NetworkProtocol::Other(0x88BA)`, and the internet layer stays `None`.
- **Only EtherType `0x88B8`**: no rule of the [dispatch table](./application.md) recognizes GOOSE carried over UDP.
- **Values are not interpreted**: `allData` keeps tags and bytes; arrays and structures are not walked, a bit string keeps its unused-bits byte, floats and times are not converted.
- **No subscriber state**: the crate does not follow `stNum` and `sqNum` from one frame to the next, does not time `timeAllowedtoLive` out, and does not check `confRev` or `numDatSetEntries` against a data set. One frame at a time, like the rest of the crate.
- **Security** (`security`, edition 2) is kept as is, not checked.
