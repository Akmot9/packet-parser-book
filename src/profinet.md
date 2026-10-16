# Profinet

Announced by EtherType `0x8892`, and checked by the [internet layer](./network.md). PROFINET is the industrial Ethernet of Siemens and the PROFIBUS & PROFINET International group (IEC 61158): cyclic I/O data, alarms, clock synchronization (PTCP) and a discovery protocol, **DCP**, all carried directly in Ethernet frames, without IP. Every real-time frame starts with a two-byte **Frame ID**, whose range says what the frame carries. Since 11.6.0, the internet layer accepts every assigned Frame ID ([#133](https://github.com/Akmot9/Packet-parser/issues/133)) and decodes a DCP message block by block ([#141](https://github.com/Akmot9/Packet-parser/issues/141)), both fixed by [#142](https://github.com/Akmot9/Packet-parser/pull/142) on a corpus of real captures ([#140](https://github.com/Akmot9/Packet-parser/pull/140)). The module is `packet_parser::parse::internet::protocols::profinet`.

## What the internet layer checks: `validate_frame`

The internet dispatch has one arm for the EtherType:

```rust
NetworkProtocol::Profinet => {
    // Every RT frame is valid by its Frame ID; only a DCP Frame ID must
    // carry a readable DCP message (#133).
    profinet::validate_frame(payload)?;
    Ok(Self::profinet())
}
```

and `validate_frame`, new in 11.6.0, works on two levels:

```rust
pub fn validate_frame(data: &[u8]) -> Result<FrameId, ProfinetPacketError> {
    let frame_id = validate_frame_id(data)?;
    if frame_id.is_dcp() {
        ProfinetPacket::try_from(data)?;
    }
    Ok(frame_id)
}
```

The Frame ID must be assigned, otherwise `UnknownFrameId`, and a payload of fewer than two bytes is `FrameTooShort`. A DCP Frame ID must, in addition, carry a DCP message that decodes. Cyclic data, alarms, PTCP and fragments are valid by their Frame ID alone: nothing past the first two bytes is read. A failure is reported in `corrupted` (`layer: Internet`), since the EtherType said PROFINET, with a text that starts with `Profinet error: `.

![A DCP Identify request field by field, next to the Internet struct that keeps only the name Profinet, and the ProfinetPacket a caller can build from the link payload](images/network/profinet_dcp.svg)

A PROFINET frame has no network addresses, and the crate gives it none: the `Internet` built by the private `Internet::profinet()` has `protocol_name: "Profinet"`, `source` and `destination` `None`, no `payload_protocol`, an empty `payload` and `details: None`. `InternetDetails` has no PROFINET variant: the `FrameId` that `validate_frame` returns is dropped, and nothing is parsed above. The flow identity of a PROFINET frame is therefore its data link layer: for the Identify request drawn here, the station's MAC address and the PROFINET multicast address `01:0e:cf:00:00:00`, which `display_with_oui()` prints as `PnMc:00:00:00`, the one multicast prefix of the crate's [OUI table](./ethernet.md). A caller who wants the class of the frame or the DCP fields runs `validate_frame` or `ProfinetPacket::try_from` again on `flow.data_link.network_payload()`.

Four real frames, cyclic data and an alarm under a VLAN tag, a PTCP delay request and a fragment, all four `corrupted` in 11.5.0 (*tested*):

```rust
{{#include ../examples/src/internet_layer.rs:profinet_rt_frames}}
```

## Frame IDs: `FrameId`

`FrameId::from_u16`, public since 11.6.0, classes a Frame ID by its range, and returns `None` for a reserved value. The ranges are those of the `pn_rt` dissector of Wireshark, time-aware mode excluded:

| Frame ID | `FrameId` | Carries |
| --- | --- | --- |
| `0x0020`–`0x0021`, `0x0080`–`0x0081` | `Sync` | PTCP RTSync, with and without Follow Up |
| `0x0100`–`0x0FFF` | `RtClass3` | RT_CLASS_3 cyclic data (IRT) |
| `0x8000`–`0xBBFF` | `RtClass1Unicast` | RT_CLASS_1 cyclic data, unicast |
| `0xBC00`–`0xBFFF` | `RtClass1Multicast` | RT_CLASS_1 cyclic data, multicast |
| `0xC000`–`0xF7FF` | `Unicast` | RT_CLASS_1 / RT_CLASS_UDP cyclic data, unicast |
| `0xF800`–`0xFBFF` | `Multicast` | RT_CLASS_1 / RT_CLASS_UDP cyclic data, multicast |
| `0xFC01`, `0xFC41` | `AlarmHigh` | high-priority alarm, `0xFC41` with security |
| `0xFE01`, `0xFE41` | `AlarmLow` | low-priority alarm, `0xFE41` with security |
| `0xFE02`, `0xFE42` | `Rsi` | Remote Service Interface, `0xFE42` with security |
| `0xFE03` | `Sxp` | SXP via RTAv3 |
| `0xFEFC` | `Hello` | DCP Hello |
| `0xFEFD` | `GetReqSetReqGetRespSetResp` | DCP Get or Set, request or response |
| `0xFEFE` | `IdentifyReq` | DCP Identify request |
| `0xFEFF` | `IdentifyResp` | DCP Identify response |
| `0xFF00`–`0xFF01` | `PtcpAnnounce` | PTCP Announce |
| `0xFF20`–`0xFF21` | `PtcpFollowUp` | PTCP Follow Up |
| `0xFF40`–`0xFF43` | `PtcpDelay` | PTCP Delay, request and responses |
| `0xFF80`–`0xFF8F` | `Fragment` | a fragment of an RT frame |
| anything else | — | reserved: `UnknownFrameId` |

`FrameId` is `#[repr(u16)]`, each discriminant the start of its range, and `#[non_exhaustive]`. 11.5.0 had the five variants `Unicast`, `Multicast`, `GetReqSetReqGetRespSetResp`, `IdentifyReq` and `IdentifyResp`; the thirteen others were added at the end of the enum. `is_dcp()` is true for the four DCP Frame IDs, `Hello` and the three after it in the table: those frames carry a message that `ProfinetPacket` decodes.

## DCP: `ProfinetPacket`

```rust
pub struct ProfinetPacket<'a> {
    pub frame_id: FrameId,
    pub service_id: u8,
    pub service_type: u8,
    pub xid: u32,
    pub response_delay: u16,
    pub dcp_data_length: u16,
    pub option: u8,                 // of the first block, 0 without block:
    pub suboption: u8,              // the three are kept for compatibility,
    pub dcp_block_length: u16,      // `blocks` holds every block
    pub name_of_station: &'a str,   // from the block option 2 / suboption 2, empty without one
    pub blocks: Vec<DcpBlock<'a>>,  // every block, in message order
}
```

The fixed header is 12 bytes; DCPDataLength counts the blocks that follow, and bytes past it, the Ethernet padding among them, are ignored:

| Bytes | Field | Note |
| --- | --- | --- |
| 0–1 | `frame_id` | one of the four DCP Frame IDs, otherwise `NotDcp` |
| 2 | `service_id` | `DCP_SERVICE_GET` (3), `DCP_SERVICE_SET` (4), `DCP_SERVICE_IDENTIFY` (5), `DCP_SERVICE_HELLO` (6) |
| 3 | `service_type` | `DCP_SERVICE_TYPE_REQUEST` (0) for a request; any other value is read as a response, 1 for success, 5 for not supported |
| 4–7 | `xid` | transaction ID |
| 8–9 | `response_delay` | |
| 10–11 | `dcp_data_length` | the bytes of blocks; beyond the frame, `DcpDataOverflow` |

Then come the blocks, each a 4-byte header and its data:

```rust
pub struct DcpBlock<'a> {
    pub option: u8,
    pub suboption: u8,
    pub block_length: u16,       // DCPBlockLength as announced, qualifier included
    pub qualifier: Option<u16>,  // BlockInfo or BlockQualifier, None when the service has none
    pub data: &'a [u8],          // the block after its qualifier
}
```

| Bytes | Field | Note |
| --- | --- | --- |
| 0 | `option` | |
| 1 | `suboption` | |
| 2–3 | `block_length` | beyond the blocks, `DcpBlockOverflow` |
| 4–5 | `qualifier` | only when the service has one; a block too short for it is `DcpBlockTooShort` |
| … | `data` | |
| | one padding byte | after a block of odd length, counted in DCPDataLength, in neither `data` nor `block_length` |

Whether a block starts with a qualifier depends on the service, as the `pn_dcp` dissector of Wireshark reads it: a **BlockInfo** in the responses to Identify and Get and in a Hello request, a **BlockQualifier** in a Set request, nothing elsewhere, the filter of an Identify request or a Set response for instance. A sender that leaves out the padding byte after the last block is not refused.

`name_of_station` comes from the first block that `is_name_of_station()` recognizes, option 2 / suboption 2, wherever it is in the message: read up to its first NUL byte, as tshark does, and UTF-8, otherwise `InvalidNameOfStation`. The whole block stays in its `DcpBlock::data`. The bug-report capture of the corpus, `iti_profinet-wireshark-bug.pcap`, names its station `%n%n%n ` followed by zeros, and the name comes out as `%n%n%n `. The other blocks, IP parameters, device ID, role or options, keep their bytes as they are.

The Identify response and the Set request of `iti_ChangeIPUsingDCP.pcap`, the two frames of that capture that 11.5.0 refused (*tested*):

```rust
{{#include ../examples/src/internet_layer.rs:profinet_dcp_blocks}}
```

## Validations

All of them are `ProfinetPacketError`, in `packet_parser::errors::internet::profinet`; the five after `InvalidNameOfStation` were added in 11.6.0, at the end of the enum:

| Error | When |
| --- | --- |
| `PacketTooShort(usize)` | a DCP message shorter than its 12-byte header (16 bytes until 11.5.0) |
| `UnknownFrameId(u16)` | a reserved Frame ID |
| `InvalidDcpBlockLength(usize)` | fewer than 4 bytes left for the header of a block; since 11.6.0 nothing else |
| `InvalidNameOfStation` | the NameOfStation block is not UTF-8 |
| `FrameTooShort(usize)` | fewer than two bytes: no Frame ID |
| `NotDcp(u16)` | `ProfinetPacket::try_from` on a Frame ID that is not DCP; `validate_frame` never returns it, so it never reaches `corrupted` |
| `DcpDataOverflow { declared, available }` | DCPDataLength announces more than the bytes after the header |
| `DcpBlockOverflow { option, suboption, declared, available }` | DCPBlockLength announces more than the blocks hold |
| `DcpBlockTooShort { option, suboption, declared, needed }` | a block shorter than the BlockInfo or BlockQualifier its service imposes |

The one PN-RT frame of the corpus that stays corrupted, and that tshark calls malformed too (*tested*):

```rust
{{#include ../examples/src/internet_layer.rs:profinet_dcp_overflow}}
```

## The corpus: 232 PN-RT frames against tshark

The repository had no PROFINET capture until [#140](https://github.com/Akmot9/Packet-parser/pull/140), which is how the defects of 11.5.0 stayed invisible. `pcaps_exemple/protocols/profinet/` now holds seven real captures, 2 685 frames of which 232 are PN-RT for tshark (`-Y pn_rt`), from three documented sources: the CISA's icsnpp-profinet-io-cm (BSD-3-Clause), ITI's ICS-Security-Tools (CC-BY-4.0) and miguelob/ICS-Hacking (GPL-3.0).

| Capture | Frames | PN-RT | PROFINET content |
| --- | --- | --- | --- |
| `cisagov_profinet_io_cm_mixed_1.pcap` | 1 635 | 164 | 102 cyclic `0xC000`/`0xC002`, 41 PTCP `0xFF40`, 18 Identify requests, 1 response, 2 alarms `0xFE01` |
| `cisagov_profinet_io_cm.pcap` | 960 | 10 | 10 fragments, `0xFF83` to `0xFF8D` |
| `iti_ChangeIPUsingDCP.pcap` | 6 | 4 | Identify request and response, then Set request and response |
| `iti_PROFINET-RT.pcap` | 14 | 14 | 14 Identify requests |
| `iti_profinet-wireshark-bug.pcap` | 4 | 4 | an Identify and a Set exchange, VLAN-tagged |
| `miguelob_pn.pcapng` | 48 | 18 | 10 cyclic RT_CLASS_1 `0x8000`/`0x8010`, 4 alarms `0xFE01`, 4 DCP, all VLAN-tagged |
| `miguelob_pn_dcp.pcapng` | 18 | 18 | 15 Identify responses, 3 Identify requests |

The golden test `tests/profinet_corpus.rs` compares every PN-RT frame with tshark 4.6.6, frozen in `tests/data/profinet_tshark_oracle.tsv`: the Frame ID, the service and the NameOfStation of every DCP message, and tshark's malformed flag. The crate must find exactly the PN-RT frames of tshark by their EtherType, VLAN tags included, class every Frame ID, read the same NameOfStation, and refuse only what tshark calls malformed. The outcome is frozen: **231** frames give `internet = Profinet`, and one is `DcpDataOverflow`, frame 3 of `miguelob_pn_dcp.pcapng`, the example above. The 11.5.0 validator gave 103 `Profinet` and 129 `corrupted`, almost all on healthy frames: 67 `UnknownFrameId` (cyclic RT_CLASS_1, PTCP, alarms, fragments), 56 `InvalidDcpBlockLength` (cyclic `0xC000`/`0xC002` frames read as DCP), 5 `InvalidNameOfStation` (the first block read as the name) and 1 `PacketTooShort`.

The corpus covers eight classes of the table: `Unicast`, `RtClass1Unicast`, `AlarmLow`, `PtcpDelay`, `Fragment` and the three DCP Frame IDs other than `Hello`. The ten others, `Sync`, `RtClass3`, `RtClass1Multicast`, `Multicast`, `AlarmHigh`, `Rsi`, `Sxp`, `Hello`, `PtcpAnnounce` and `PtcpFollowUp`, are covered by the crate's unit tests only. The fuzz target `parse_profinet` runs nightly on `validate_frame` and `ProfinetPacket::try_from`.

## What is left out

- **The content of the frames**: cyclic I/O data, alarms, PTCP and fragments are classed, not decoded, and fragments are not reassembled.
- **DCP block values**: only the NameOfStation is read; IP parameters, device ID, role and options stay raw in `DcpBlock::data`.
- **No `details`**: a caller re-runs `validate_frame` or `ProfinetPacket::try_from` on the link payload.
- **The blind probe** of `Internet::try_from` recognizes PROFINET by a complete DCP message only: two bytes of Frame ID are not a proof, so a cyclic frame is not recognized without its EtherType, and a DCP-looking header can be something else (see the [internet page](./network.md#dispatch-on-the-announced-protocol-not-probing)).
- **PROFINET over UDP** is ordinary UDP to the crate: no rule of the [dispatch table](./application.md) names RT_CLASS_UDP (ports 34962 to 34964), nor the DCE/RPC of PROFINET IO-CM, of which the corpus holds 1 000 datagrams.
- **Time-aware Frame IDs** are not classed.
