# DIS

Distributed Interactive Simulation, IEEE 1278.1, added in 11.6.0 ([#123](https://github.com/Akmot9/Packet-parser/issues/123)) as part of the defense lot ([#125](https://github.com/Akmot9/Packet-parser/issues/125)): the protocol that links military simulators, carrying the position of each entity, fire, simulated radios and the environment. The PDU formats are openly documented by the Open-DIS project, the enumerations by SISO-REF-010. The module is `packet_parser::parse::application::protocols::dis`.

A UDP datagram carries one or more PDUs, each behind the same 12-byte header. The decoder names every PDU, decodes three bodies into typed values, Entity State, Transmitter and Signal, and keeps the other bodies as bytes.

## Detection: a customary port and a strict blind probe

Like [ASTERIX](./asterix.md), DIS has neither a magic nor an IANA port. UDP 3000 is the customary one, the port Wireshark registers for DIS by default; the corpus also carries DIS on 6993 and 22999. The [dispatch table](./application.md#reading-the-table) has two rules for it, which read the same bytes in two ways:

```rust
// among the port rules, right after PTP: UDP 3000 on either side
port_rule("DIS", Guard::Udp, is_dis_udp_port, ProbeId::DisLenient),
// in the blind cascade, after ASTERIX and before DNP3
rule("DIS", Guard::Udp, ProbeId::Dis),
```

with the probes

```rust
ProbeId::Dis => DisPacket::try_from(full_payload).is_ok(),
ProbeId::DisLenient => DisPacket::try_from_lenient(full_payload).is_ok(),
```

- **The blind probe** is `DisPacket::try_from`, the **strict** read: every PDU must be valid (a version from 1 to 7, a type from 1 to 72, a family of the standard or an experimental one, a length that covers the header and stays within the datagram, the fixed fields of a typed body), and the PDUs must tile the datagram to the last byte. This exact tiling is the signature that lets the blind rule label DIS without a port guard. It is still not reached on the terminal mDNS and LLMNR ports, UDP 5353 and 5355, where a failed probe ends the dispatch with no label.
- **On UDP 3000** the port already says DIS, and the probe is `DisPacket::try_from_lenient`: a declared length shorter than the datagram is accepted, and the rest is kept in `trailing`. Three real PDUs of the corpus declare 48 bytes in a 160-byte datagram, and tshark dissects them without stopping at the length.
- **On another port**, `ParseConfig::decode_as(port, DecodeAsProtocol::Dis)` gives the same lenient read: the variant maps to `("DIS", Guard::Udp, ProbeId::DisLenient)`, evaluated before the table like every [Decode As](./application.md#decode-as) port.

Both probes run on the whole payload, not on the 18 KiB prefix (`PROBE_CAP`) that most probes see: an exact tiling can only be proven on the real datagram. `Application::try_from`, which has no ports, runs the strict read, after ASTERIX.

Neither read demands a family consistent with the type. `DIS_signal_and_transmitter.pcapng` puts family 0 ("other") instead of 4 (radio communications) on all its radio PDUs: not conforming, but real. Family 0 is admitted, and no rule ties a family to a type.

In the corpus, the 263 frames on UDP 3000 get their label from the port rule, and 127 of the 130 on 6993 and 22999 from the blind probe; the other three need the lenient read ([below](#the-datagram-and-its-pdus)). One frame of each kind, a Transmitter on port 3000 and a Signal on 6993 (*tested*):

```rust
{{#include ../examples/src/defense_a.rs:dis_transmitter_port_3000}}
```

```rust
{{#include ../examples/src/defense_a.rs:dis_blind_probe}}
```

## The datagram and its PDUs

![The Transmitter PDU of frame 1 of wireshark_12043_dis_v7_transmitter.pcap, 32 bits per row: the 12-byte header with protocol version 7 (IEEE 1278.1-2012), exercise 1, PDU type 25 (Transmitter), protocol family 4 (Radio Communications), the timestamp, length 104, status 0 and a padding byte, then the first fields of the body, the entity identifier site 64128, application 61467, entity 65534, and radio ID 65534, the 88 remaining bytes summarised; DisHeader on the right holds the header fields.](images/application/dis_struct.svg)

```rust
#[non_exhaustive]
pub struct DisPacket<'a> {
    pub pdus: Vec<DisPdu<'a>>,
    /// Bytes after the last PDU that do not form a PDU: always empty from
    /// `try_from`, possibly not from `try_from_lenient`.
    pub trailing: &'a [u8],
}

#[non_exhaustive]
pub struct DisPdu<'a> {
    pub header: DisHeader,
    pub pdu_type: PduType,   // the named type
    pub body: DisBody<'a>,
    /// The whole PDU, header included, as its length delimits it.
    pub raw: &'a [u8],
}
```

The first PDU must decode, and its error is the error of the datagram. The next PDUs are read one after the other, each where the length of the previous one ends, until the end of the datagram or the first bytes that do not form a PDU: those bytes are `trailing`. `try_from` refuses a non-empty `trailing` with `UnexpectedTrailingBytes`, `try_from_lenient` keeps it. Every datagram of the corpus carries a single PDU; the path with several PDUs is checked on synthetic bytes by the crate's unit tests.

The three PDUs that need the lenient read are the Set Data, Data Query and Data of `wireshark_3492_dis_test2.pcap`, on UDP 6993. Here is the Set Data, refused by the blind probe and labelled once its port is declared (*tested*):

```rust
{{#include ../examples/src/defense_a.rs:dis_strict_and_lenient}}
```

## The header: `DisHeader`

```rust
#[non_exhaustive]
pub struct DisHeader {
    pub protocol_version: u8,
    pub exercise_id: u8,
    pub pdu_type: u8,        // the raw code; DisPdu::pdu_type names it
    pub protocol_family: u8,
    /// Raw: 31 bits of time in units of 1/2^31 hour, and the low bit set
    /// for an absolute time.
    pub timestamp: u32,
    /// Declared length of the PDU, header included.
    pub length: u16,
    /// PDU Status in version 7; padding before.
    pub pdu_status: u8,
    pub padding: u8,
}
```

| Bytes | Field | Note |
| --- | --- | --- |
| 0 | `protocol_version` | 1 to 7, from DIS PDU version 1.0 to IEEE 1278.1-2012 |
| 1 | `exercise_id` | |
| 2 | `pdu_type` | 1 to 72 |
| 3 | `protocol_family` | 0 to 13 from the standard, or 129 to 255, experimental |
| 4–7 | `timestamp` | read with `absolute_timestamp()` and `timestamp_units()` |
| 8–9 | `length` | at least 12, at most the bytes left in the datagram |
| 10 | `pdu_status` | `status()` is `Some` from version 7 on, `None` before |
| 11 | `padding` | |

Version 7, IEEE 1278.1-2012, is the first with a PDU Status field. `absolute_timestamp()` reads the low bit of `timestamp`, and `timestamp_units()` returns the other 31 bits, a count of 1/2^31 hour, so always less than an hour: 1 033 452 647 on the Transmitter above, 28 min 52.46 s, which is what tshark prints. The crate converts nothing further.

`PduType` names the 72 types of SISO-REF-010 in the order of their codes, from 1 `EntityState`, 2 `Fire` and 3 `Detonation` to 72 `Attribute`; the corpus has 18 `DataQuery`, 19 `SetData`, 20 `Data`, 25 `Transmitter`, 26 `Signal` and 29 `UnderwaterAcoustic`. The header keeps the raw code, `DisPdu::pdu_type` the name.

## Three typed bodies

```rust
#[non_exhaustive]
pub enum DisBody<'a> {
    /// Entity State (§7.2.2): the position and appearance of an entity.
    EntityState {
        entity_id: EntityId,
        force_id: u8,
        /// Number of articulation or attachment parameters that follow.
        variable_parameter_count: u8,
        entity_type: EntityType,
        alternative_entity_type: EntityType,
        linear_velocity: Vector3,        // meters per second
        location: WorldCoordinates,
        orientation: Vector3,            // Euler angles psi, theta, phi, radians
        appearance: u32,
        /// Dead reckoning algorithm, the first byte of its parameters.
        dead_reckoning_algorithm: u8,
        /// Character set, then eleven bytes of marking.
        marking: [u8; 12],
        capabilities: u32,
        /// The variable parameters, sixteen bytes each.
        variable_parameters: &'a [u8],
    },
    /// Transmitter (§7.7.2): the state of a simulated radio transmitter.
    Transmitter {
        entity_id: EntityId,
        radio_id: u16,
        radio_entity_type: EntityType,
        transmit_state: u8,              // 0 off, 1 on but not transmitting, 2 transmitting
        input_source: u8,
        /// Version 7: number of variable transmitter parameters; padding before.
        variable_parameter_count: u16,
        antenna_location: WorldCoordinates,
        relative_antenna_location: Vector3,
        antenna_pattern_type: u16,
        antenna_pattern_length: u16,
        frequency_hz: u64,
        bandwidth_hz: f32,
        power_dbm: f32,                  // decibel-milliwatts
        modulation_type: ModulationType,
        crypto_system: u16,
        crypto_key_id: u16,
        modulation_parameter_length: u8,
    },
    /// Signal (§7.7.3): audio samples or radio data.
    Signal {
        entity_id: EntityId,
        radio_id: u16,
        encoding_scheme: u16,
        tdl_type: u16,
        sample_rate: u32,
        data_length: u16,                // in bits
        samples: u16,
        /// The data, final padding included.
        data: &'a [u8],
    },
    /// Any other type: the raw body, header excluded.
    Opaque(&'a [u8]),
}
```

The records inside the bodies are small `#[non_exhaustive]` structs, read but never built outside the crate:

```rust
pub struct EntityId { pub site: u16, pub application: u16, pub entity: u16 }

pub struct EntityType {      // the seven fields of the SISO enumeration
    pub kind: u8, pub domain: u8, pub country: u16, pub category: u8,
    pub subcategory: u8, pub specific: u8, pub extra: u8,
}

pub struct ModulationType {
    /// Bits: 0 frequency hopping, 1 pseudo-noise, 2 time hopping.
    pub spread_spectrum: u16,
    pub major: u16,
    pub detail: u16,
    pub system: u16,
}

pub struct Vector3 { pub x: f32, pub y: f32, pub z: f32 }
pub struct WorldCoordinates { pub x: f64, pub y: f64, pub z: f64 }   // geocentric, meters
```

All values are big-endian. The offsets below count from the start of the PDU, header included, so the body starts at byte 12.

**Entity State** (type 1):

| Bytes | Field | Note |
| --- | --- | --- |
| 12–17 | `entity_id` | `EntityId` |
| 18 | `force_id` | |
| 19 | `variable_parameter_count` | records from byte 144 on |
| 20–27 | `entity_type` | `EntityType` |
| 28–35 | `alternative_entity_type` | `EntityType` |
| 36–47 | `linear_velocity` | `Vector3` |
| 48–71 | `location` | `WorldCoordinates` |
| 72–83 | `orientation` | `Vector3` |
| 84–87 | `appearance` | raw bits |
| 88 | `dead_reckoning_algorithm` | the first of the 40 bytes of dead-reckoning parameters (88–127); the other 39 are not exposed |
| 128–139 | `marking` | character set, then 11 characters |
| 140–143 | `capabilities` | raw bits |
| 144– | `variable_parameters` | 16 bytes per record, raw |

**Transmitter** (type 25):

| Bytes | Field | Note |
| --- | --- | --- |
| 12–17 | `entity_id` | `EntityId` |
| 18–19 | `radio_id` | |
| 20–27 | `radio_entity_type` | `EntityType` |
| 28 | `transmit_state` | |
| 29 | `input_source` | |
| 30–31 | `variable_parameter_count` | version 7; padding before |
| 32–55 | `antenna_location` | `WorldCoordinates` |
| 56–67 | `relative_antenna_location` | `Vector3` |
| 68–69 | `antenna_pattern_type` | |
| 70–71 | `antenna_pattern_length` | |
| 72–79 | `frequency_hz` | |
| 80–83 | `bandwidth_hz` | `f32` |
| 84–87 | `power_dbm` | `f32` |
| 88–95 | `modulation_type` | `ModulationType` |
| 96–97 | `crypto_system` | |
| 98–99 | `crypto_key_id` | |
| 100 | `modulation_parameter_length` | |
| 101–103 | padding | not exposed |

**Signal** (type 26):

| Bytes | Field | Note |
| --- | --- | --- |
| 12–17 | `entity_id` | `EntityId` |
| 18–19 | `radio_id` | |
| 20–21 | `encoding_scheme` | raw: `0x0001` on the Signal above, encoded audio, 8-bit mu-law for tshark |
| 22–23 | `tdl_type` | |
| 24–27 | `sample_rate` | |
| 28–29 | `data_length` | in bits |
| 30–31 | `samples` | |
| 32– | `data` | to the end of the PDU |

A body must hold the fixed fields of its type, or the PDU is `BodyTooShort { pdu_type, expected, actual }`: 132 bytes for an Entity State plus 16 per announced variable parameter (a PDU of 144 + 16 *n* bytes), 92 for a Transmitter (a PDU of 104), 20 for a Signal (a PDU of 32). A longer body is accepted, and what the decoder does not read stays in `raw`. After the 92 fixed bytes of a Transmitter come its modulation parameters, its antenna pattern and, in version 7, the variable transmitter parameter records that `variable_parameter_count` announces; none of them are decoded. The 120-byte Transmitters of `dis_voice_sample.pcap` carry 16 bytes of modulation parameters. The 149-byte Transmitters of `DIS_signal_and_transmitter.pcapng`, in version 5, announce no modulation parameters and no antenna pattern, and still run 45 bytes past the fixed fields; they decode all the same.

The corpus has no Entity State: the wiki captures that carry some were set aside as replayed PDUs rather than recorded exercises (see the `SOURCE.md` of the corpus folder), so this body is checked on synthetic bytes only, by a unit test of the crate.

## Validations

All of them are `DisParseError`, in `packet_parser::errors::application::dis`:

| Error | When |
| --- | --- |
| `Truncated { expected, actual }` | fewer than the 12 bytes of a header |
| `UnsupportedVersion(u8)` | a version other than 1 to 7 |
| `ReservedPduType(u8)` | a type other than 1 to 72 |
| `ReservedProtocolFamily(u8)` | a family from 14 to 128 |
| `InvalidLength(u16)` | a declared length shorter than the header |
| `LengthOverflow { declared, available }` | a declared length beyond the bytes left in the datagram |
| `UnexpectedTrailingBytes { trailing }` | `try_from` only: bytes after the last PDU that do not form a PDU |
| `BodyTooShort { pdu_type, expected, actual }` | an Entity State, Transmitter or Signal body shorter than its fixed fields, plus 16 bytes per announced variable parameter for an Entity State |

Only the first PDU reports its own error. After it, a PDU that fails ends the list, and from `try_from` the datagram is then refused with `UnexpectedTrailingBytes`. Like every application decoder, a failure only means no label: the dispatch moves on to the next rule, and nothing goes to `corrupted`.

## Oracle: 393 frames, frame by frame

The golden test `tests/dis_golden.rs` runs the five captures of `pcaps_exemple/protocols/dis/` and compares every frame with tshark 4.6.6, frozen in `tests/data/dis_tshark_oracle.tsv` by `tools/dis_oracle.sh` with DIS decoding forced on UDP 3000, 6993 and 22999: version, exercise, type, family, length, PDU Status and the first entity identifier of the body. The crate is queried the way tshark is, ports 6993 and 22999 declared by Decode As, and all 393 frames are labelled `"DIS"` and match. Without the declarations, 390 are labelled `"DIS"`; the three PDUs of `wireshark_3492_dis_test2.pcap` stay `"Unknown"`. By type, 302 Signal, 72 Transmitter, 16 Underwater Acoustic and one each of Data Query, Set Data and Data; by version, 3 in version 4, 269 in version 5, 111 in version 6 and 10 in version 7.

| Capture | Frames | Version, PDUs | Port | Origin |
| --- | --- | --- | --- | --- |
| `dis_voice_sample.pcap` | 111 | v6, Signal and Transmitter | UDP 6993 | Wireshark `test/captures` |
| `DIS_signal_and_transmitter.pcapng` | 253 | v5, Signal and Transmitter, family 0 | UDP 3000 | Wireshark wiki |
| `wireshark_8185_dis_ua.pcapng` | 16 | v5, Underwater Acoustic | UDP 22999 | Wireshark issue 8185 |
| `wireshark_12043_dis_v7_transmitter.pcap` | 10 | v7, Transmitter | UDP 3000 | Wireshark issue 12043 |
| `wireshark_3492_dis_test2.pcap` | 3 | v4, Data Query, Set Data, Data | UDP 6993 | Wireshark issue 3492 |

In the golden histogram of the whole corpus, `"DIS"` went from 0 to 390 with 11.6.0, all taken from `"Unknown"`. The fuzz target `parse_dis` runs nightly on both reads: no panic, and when a decode succeeds, the PDUs and `trailing` tile the input exactly and the strict read accepts nothing the lenient one refuses.

## What is left out

- **69 of the 72 types** keep their body raw, in `DisBody::Opaque`: Fire, Detonation, Underwater Acoustic, the simulation management PDUs...
- **Inside the typed bodies**: the dead-reckoning parameters after the algorithm byte, the variable parameters (raw 16-byte records), the modulation parameters, antenna pattern and variable transmitter parameters of a Transmitter, and the data of a Signal (no audio, no tactical data link message) are not decoded. `appearance` and `capabilities` are raw bits.
- **Enumerations are numbers**: entity kinds, countries, modulations and encodings are the values of SISO-REF-010, not names.
- **No state**: no dead reckoning, no pairing of a Signal with its Transmitter, no time conversion. One datagram at a time, like the rest of the crate.
