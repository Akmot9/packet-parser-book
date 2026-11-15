# Modbus/TCP and UMAS

Modbus/TCP wraps each Modbus PDU in a seven-byte MBAP header; UMAS, the proprietary protocol Schneider Electric uses to control its Modicon PLCs, travels inside it under the vendor function code `0x5A`. Two modules, two labels: `packet_parser::parse::application::protocols::modbus_tcp` (`"ModbusTCP"`) and `packet_parser::parse::application::protocols::umas` (`"UMAS"`), on TCP only. On UDP the same envelope is recognized on port 502 alone, under a third label, `"ModbusUDP"`, since 12.0.0 ([Modbus over UDP](#modbus-over-udp)). 11.6.0 made the Modbus/TCP label depend on the port ([#167](https://github.com/Akmot9/Packet-parser/issues/167)).

![A Modbus/TCP Read Holding Registers request, 32 bits per row: the seven-byte MBAP header, transaction identifier 209, protocol identifier 0, length 6 and unit 1, then the PDU, function code 3 and four bytes of data; on the right the MBAP struct, whose pdu keeps the function code and the raw data](images/application/modbus_mbap.svg)

## Detection: four rules on TCP

```rust
// TCP 502 (IANA `mbap`): the MBAP envelope is enough, UMAS first
port_rule(ApplicationProtocol::Umas, Guard::Tcp, is_modbus_tcp_port, ProbeId::Umas),
port_rule(ApplicationProtocol::ModbusTcp, Guard::Tcp, is_modbus_tcp_port, ProbeId::ModbusTcp),
// ... blind cascade, after SRVLOC:
rule(ApplicationProtocol::Umas, Guard::Tcp, ProbeId::Umas),
rule(ApplicationProtocol::ModbusTcp, Guard::Tcp, ProbeId::ModbusTcpBlind),
```

UMAS comes first, on the port and off it: it is carried by a valid Modbus envelope, so the Modbus probe would accept its frames too, and the most specific protocol gets the label, as S7Comm does before COTP. Its probe, `UmasPacket::try_from`, is the same in both rules: a valid MBAP whose function code is `0x5A`, then a session id and a UMAS function byte.

On **TCP 502**, `ProbeId::ModbusTcp` runs the decoder alone, `ModbusTcpPacket::try_from`: a well-formed envelope is enough, whatever the function code.

**Elsewhere**, `ProbeId::ModbusTcpBlind` runs `ModbusTcpPacket::is_blind_tcp_match`, crate-internal. The envelope was all the former blind probe checked, and it is the shape of any message that starts with two bytes and a four-byte length: off port 502, 97 segments of the corpora came out ModbusTCP, Active Directory's LDAP (`30 84 00 00 ..`, 57 segments of `The-Ultimate-PCAP.pcapng` and 7 of nDPI's `kerberos.pcap`), DICOM, the transport protocol of Elasticsearch, a game. The probe now demands that every MBAP of the segment:

1. carry a PDU that `is_plausible_pdu` accepts: a public function code of common use, and data of the size it imposes, as a request or as a response (Modbus Application Protocol v1.1b3):

   | Function code | Request | Response |
   | --- | --- | --- |
   | `0x01`, `0x02` Read Coils, Read Discrete Inputs | address, quantity 1 to 2 000 | a byte count of 1 to 250, then that many bytes |
   | `0x03`, `0x04` Read Holding, Input Registers | address, quantity 1 to 125 | the same, with an even count |
   | `0x05` Write Single Coil | address, value `0x0000` or `0xFF00` | the echo |
   | `0x06` Write Single Register | address, value | the echo |
   | `0x0F` Write Multiple Coils | quantity 1 to 1 968, a byte count of the quantity divided by 8 rounded up, the values | address, quantity |
   | `0x10` Write Multiple Registers | quantity 1 to 123, a byte count of twice the quantity, the values | address, quantity |
   | `0x16` Mask Write Register | address, AND mask, OR mask | the echo |
   | `0x17` Read/Write Multiple Registers | read quantity 1 to 125, write quantity 1 to 121, the values written | as a read |
   | `0x2B` Encapsulated Interface Transport | Read Device Identification only (MEI type 14): a read code of 1 to 4, an object id | a conformity level, then objects that tile the PDU exactly |
   | `0x81`–`0x86`, `0x8F`, `0x90`, `0x96`, `0x97`, `0xAB` | | the exception response to one of the above: one exception code, 1 to 6, 8, 10 or 11 |

   The serial line codes (7, 8, 11, 12, 17), file record access (20, 21), FIFO queue (24), CANopen (MEI type 13, whose size the specification does not give) and the user-defined codes are refused off port; on port 502 the decoder accepts them.

2. not be one of two lookalikes whose header remains a valid Modbus PDU byte for byte:
   - an Active Directory LDAPMessage, `30 84 00 00 LL LL 02 n`: a SEQUENCE with a four-byte length, then the messageID INTEGER, read as unit 2 and function code n, 1 to 4. An unbindRequest(2) or an abandonRequest is a valid Read Coils there (frame 3627 of `NEWYORK.cap`, OTRF datasets);
   - a DICOM A-ASSOCIATE-RJ, `03 00 00 00 00 04 00 r s c`: the type 3 and its four-byte length, then the result read as the function code and the source as a byte count.

   Off port 502, a real Modbus message loses only transaction `0x3084` of unit 2 with functions 1 to 4, and, at transaction `0x0300`, a one-byte read response of unit 0.

`classify_payload`, given TCP and no port (`None`, `None`), reaches the strict probe only. A Read Holding Registers request passes it, a scanner's user-defined function code does not (*tested*):

```rust
{{#include ../examples/src/shared.rs:modbus_lenient_on_port_502}}
```

And an Active Directory bindResponse, frame 40035 of `pcaps_exemple/The-Ultimate-PCAP.pcapng`, which the decoder takes for an envelope (*tested*):

```rust
{{#include ../examples/src/shared.rs:modbus_ldap_lookalike}}
```

## On a declared port

`DecodeAsProtocol::ModbusTcp` gives another port the rule of port 502: `(ApplicationProtocol::ModbusTcp, Guard::Tcp, ProbeId::ModbusTcp)`, the decoder alone. Declared ports are tried before the table, so on that port the label is `"ModbusTCP"` for everything the decoder accepts, UMAS included: Decode As names the protocol of the port, as it does for any protocol. There is no `DecodeAsProtocol::Umas`, and none is needed, since UMAS is recognized by the same probe on every port (*tested*, frame 6 of `protocols/umas/umas.pcap`):

```rust
{{#include ../examples/src/shared.rs:umas_decode_as}}
```

## Modbus over UDP

Modbus over UDP is not in the *Modbus Messaging on TCP/IP* specification, but devices speak it, with the same MBAP envelope in each datagram, and Wireshark has a dissector for it (`mbudp`, UDP 502). Until 12.0.0 the crate labelled those datagrams `"Unknown"`: every Modbus rule had a TCP guard ([#257](https://github.com/Akmot9/Packet-parser/issues/257)). 12.0.0 adds one port rule:

```rust
// right after the two rules of TCP 502
port_rule(ApplicationProtocol::ModbusUdp, Guard::Udp, is_modbus_udp_port, ProbeId::ModbusTcp),
```

The probe is the one of TCP 502, the decoder alone, and the decoder is the same, `ModbusTcpPacket::try_from`. The label is its own, `"ModbusUDP"` (`ApplicationProtocol::ModbusUdp`): `"ModbusTCP"` on a datagram would name the wrong transport. Another UDP port is declared with `DecodeAsProtocol::ModbusUdp`.

There is no blind rule on UDP. Measured on the crate's corpus (387 123 frames, 111 416 UDP flows), the decoder accepts the 38 Modbus datagrams of UDP 502, and 106 more off that port, all of them CLDAP on UDP 389: an LDAPMessage whose BER length is written on four bytes has the shape of an MBAP envelope, as it does on TCP, above. The strict probe of the TCP cascade accepts none of the 106, but one corpus is not enough to trust it on every UDP port. UMAS has no rule on UDP either, for want of a capture: a UMAS message on UDP 502 would be `"ModbusUDP"`.

The 38 datagrams are frames 50281 to 50318 of `pcaps_exemple/The-Ultimate-PCAP.pcapng`, 19 requests and 19 responses, checked one by one against tshark (`tests/modbus_golden.rs`). The first is a Read Coils request (*tested*):

```rust
{{#include ../examples/src/shared.rs:modbus_over_udp}}
```

## The envelope and the UMAS header

```rust
pub struct ModbusTcpPacket<'a> {
    pub mbaps: Vec<MBAP<'a>>,   // several MBAPs in one segment
}

pub struct MBAP<'a> {
    pub transaction_identifier: u16,
    pub protocol_identifier: u16,
    pub length: u16,
    pub unit_identifier: u8,
    pub pdu: Modbus<'a>,
}

pub struct Modbus<'a> {
    pub function_code: u8,
    pub pdu_data: &'a [u8],
}
```

All three are `#[non_exhaustive]`. The MBAPs must tile the segment, each one starting where the previous one ends, 6 + `length` bytes later; all errors are `ModbusTcpError`, in `packet_parser::errors::application::modbus_tcp`:

| Bytes | Field | Check | Error |
| --- | --- | --- | --- |
| | | at least 7 bytes left for each MBAP | `BufferTooSmall { needed, actual }` |
| 0–1 | `transaction_identifier` | | |
| 2–3 | `protocol_identifier` | 0 | `InvalidProtocolIdentifier { got }` |
| 4–5 | `length` | 1 or more, and 6 + `length` bytes present | `InvalidLengthField { got }`, `LengthMismatch { expected, actual }` |
| 6 | `unit_identifier` | | |
| 7 | `pdu.function_code` | present | `PduTooSmall { needed, actual }` |
| 8 to 5 + `length` | `pdu.pdu_data` | | |

The decoder does not interpret the function code: `is_plausible_pdu` is a detection check, not a decode, and the data stay raw.

```rust
pub struct UmasPacket<'a> {
    pub mbap: MBAP<'a>,           // the carrying envelope, function code 0x5A
    pub session_id: u8,           // given by the PLC
    pub function: UmasFunction,   // a request's code or a reply's status
    pub data: &'a [u8],           // not decoded
}
```

`UmasPacket::try_from` decodes the first MBAP of the segment and needs function code `0x5A` (`UmasError::NotUmas { got }`) and two bytes after it, the session id and the function (`UmasError::PduTooSmall { needed, actual }`); an invalid envelope is `UmasError::InvalidEnvelope`, which wraps the `ModbusTcpError`. UMAS has no public specification and the names of its request codes come from reverse engineering, which no capture can confirm: `UmasFunction` names only what a frame of the corpus attests, `Reply` (`0xFE`, the constant `UMAS_REPLY`, carried by the 90 replies of `umas.pcap`), and leaves every other value as `Other(u8)`.

## Oracle: 601 segments

`tests/modbus_golden.rs` compares every MBAP header with tshark 4.6.6 (`tools/modbus_oracle.sh`, frozen in `tests/data/modbus_tshark_oracle.tsv`): transaction, length, unit, function code and exception code, on the 601 Modbus/TCP segments of `protocols/modbus/`, `protocols/umas/` and, read in place, `The-Ultimate-PCAP.pcapng`. The crate labels 420 of them ModbusTCP and 181 UMAS, misses none, and labels no other segment of these captures Modbus: of the 400 TCP 389 segments with a payload of the Ultimate PCAP, LDAP and the TLS that follows StartTLS, 57 have the MBAP shape and none is labelled. Moved off port 502, 358 of the 601 stay recognized; the 243 others are the probes of a scanner that tries the 128 request codes `0x00` to `0x7F`, and their exception responses (`MODBUS-TestDataPart2.pcap`), which only port 502 recognizes. `tests/umas_golden.rs` checks the 180 UMAS frames of `umas.pcap`: two sessions and fourteen values of the function byte. The 38 datagrams of [Modbus over UDP](#modbus-over-udp) have their own comparison in the same test, against `tests/data/modbus_udp_tshark_oracle.tsv` (`tools/modbus_udp_oracle.sh`). The golden histogram counts 382 ModbusTCP, 181 UMAS and 38 ModbusUDP labels.

## What is left out

- **The PDU.** The decoder does not interpret the function code, and the data stay raw: no register, no coil, no exception name. `is_plausible_pdu` is a detection check, internal to the crate.
- **UMAS beyond its header.** The session id and the function byte are read; `data` is not decoded, and `UmasFunction` names only `Reply`.
- **UMAS over UDP.** No rule looks for it: on UDP 502 it is `"ModbusUDP"`.
- **Modbus over UDP off port 502.** There is no blind rule; another port must be declared.
- **Serial Modbus.** RTU and ASCII framing, and Modbus RTU carried over TCP without an MBAP header, have no decoder.
- **Pairing.** Nothing matches a response to its request by transaction identifier.
