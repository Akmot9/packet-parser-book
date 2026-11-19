# NTP

Network Time Protocol, RFC 5905, on UDP only. The module is `packet_parser::parse::application::protocols::ntp`; `NtpPacket::try_from` decodes the 48-byte header, and `NtpPacketParseError`, in `packet_parser::errors::application::ntp`, says why it refused. 11.6.0 reworked both sides of the detection with real captures: the decoder stopped refusing real traffic ([#161](https://github.com/Akmot9/Packet-parser/issues/161), [#162](https://github.com/Akmot9/Packet-parser/issues/162), [#165](https://github.com/Akmot9/Packet-parser/issues/165)), and the blind probe stopped accepting traffic that was not NTP ([#164](https://github.com/Akmot9/Packet-parser/issues/164)).

![The NTP header of a chrony client request, 32 bits per row: the LI, version and mode byte, stratum, poll and precision, root delay and dispersion, the reference id, then the four 64-bit timestamps; on the right the NtpPacket struct, with the flags (0, 4, 3), stratum 0, a NULL kiss code, an unknown reference timestamp and the receive and transmit timestamps in two different eras; the 24 bytes after the header are not decoded](images/application/ntp_header.svg)

## Detection: lenient on port 123, strict elsewhere

```rust
port_rule(ApplicationProtocol::Ntp, Guard::Udp, is_ntp_udp_port, ProbeId::Ntp),  // 123, the last port rule
// --- blind cascade ---
rule(ApplicationProtocol::Ntp, Guard::Udp, ProbeId::NtpBlind),                    // the first blind rule
```

On **UDP 123**, either port (a server's source, a client's destination, both in symmetric mode), `ProbeId::Ntp` runs the decoder alone. The rule is the last of the port rules. Until 11.6.0 the blind rule stood at that place, with the same decoder, so the move changed nothing on port 123. Being last, the rule also lets every other port rule speak first: a DNS query sent from port 123 to port 53 keeps the label DNS even when its bytes read as an NTP header. The unit tests of the dispatch pin that case down.

On **any other UDP port**, `ProbeId::NtpBlind` runs `NtpPacket::is_blind_udp_match`, crate-internal, on the whole datagram. The decoder must accept the datagram, and the header alone is not enough: until 11.6.0 the blind probe was the decoder, and about one random datagram in 250 passed for NTP; on the 654 test captures of nDPI, 43 of the 59 NTP labels were wrong (QUIC, CryNet, Gnutella, KCP, PFCP, NetBIOS datagrams, obfuscated OpenVPN...). The probe now also demands:

| What | Required off port 123 | Why |
| --- | --- | --- |
| poll | -7 to 24 | chrony's range; ntpd uses 3 to 17, an SNTP client 0; the false positives of nDPI carried 46 to 118 |
| precision | -32 to 0, or 32 | 2⁻³² s is the resolution of a timestamp; chrony puts 32 in its client requests |
| root delay | under 16 s (`MAXDISP`) | the largest real one of the corpora is 1 s; a QUIC v1 header reads as 256 s or more |
| bytes after the header | none; in NTPv4, extension fields (16 bytes or more, a multiple of 4), then an optional MAC: 4 zero bytes (crypto-NAK), 20 bytes (MD5, AES-CMAC) or 24 (SHA-1); or a MAC alone of 36, 52 or 68 bytes (SHA-256, SHA-384, SHA-512); before NTPv4, a crypto-NAK or a MAC of 12 to 72 bytes, the longest being the Extended Authenticator of MS-SNTP | they must end exactly with the datagram |
| Receive and Transmit | Receive not after Transmit, a null timestamp not compared | both are on the sender's clock |
| reference id at stratum 0 | null, an ASCII code, or `127.0.0.1` | the decoder accepts any four bytes there |

The root dispersion is not bounded: the stratum 1 ntpd of the second example below announces 107.8 s. Measured by [#164](https://github.com/Akmot9/Packet-parser/issues/164) on the nDPI captures, the crate now labels exactly the 16 NTP datagrams of modes 1 to 5 that tshark sees there, and none of the 202 558 other UDP datagrams of the 3 110 captures examined. `Application::try_from`, which has no port, uses the strict probe too, and there is no `DecodeAsProtocol::Ntp`.

The examples of this page, like those of [Modbus](./modbus.md) and [PostgreSQL](./postgresql.md), move a real frame off its port with a small helper:

```rust
{{#include ../examples/src/shared.rs:with_ports}}
```

Frame 3 of `pcaps_exemple/protocols/ntp/tcpdump_ntp.pcap`, a chrony request, is NTP on its port and nowhere else (*tested*):

```rust
{{#include ../examples/src/shared.rs:ntp_lenient_on_port_123}}
```

## The header

```rust
pub struct NtpPacket {
    pub flags: (u8, u8, u8),             // leap indicator, version, mode
    pub stratum: u8,
    pub poll: u8,                         // the raw byte: poll_exponent() gives it signed
    pub precision: i8,
    pub root_delay: u32,
    pub root_dispersion: u32,
    pub reference_id: Refid,
    pub reference_timestamp: NtpTimestamp,
    pub originate_timestamp: NtpTimestamp,
    pub receive_timestamp: NtpTimestamp,
    pub transmit_timestamp: NtpTimestamp,
}

pub struct NtpTimestamp {
    pub seconds: u32,                     // since the start of the era
    pub fraction: u32,                    // in units of 2^-32 s
}

pub enum Refid {
    Ipv4(Ipv4Addr),         // stratum 2 to 15
    KissCode([u8; 4]),      // stratum 0
    ClockSource([u8; 4]),   // stratum 1
}
```

Both are `#[non_exhaustive]`. The decoder reads the header in wire order; the bytes after it (extension fields, MAC) are not decoded, and only the blind probe looks at them.

| Bytes | Field | Check | Error |
| --- | --- | --- | --- |
| | | at least 48 bytes | `InvalidPacketLength` |
| 0 | `flags`: LI (bits 7–6), VN (5–3), mode (2–0) | version 1 to 4, mode 1 to 5 | `InvalidVersion { version }`, `InvalidMode { mode }` |
| 1 | `stratum` | 0 to 15 | `InvalidStratum` |
| 2 | `poll` | signed, -7 or more | `InvalidPoll` |
| 3 | `precision` | | |
| 4–7 | `root_delay` | | |
| 8–11 | `root_dispersion` | | |
| 12–15 | `reference_id` | at stratum 1, a printable ASCII code | `InvalidReferenceIdForStratum1` |
| 16–23 | `reference_timestamp` | | |
| 24–31 | `originate_timestamp` | | |
| 32–39 | `receive_timestamp` | | |
| 40–47 | `transmit_timestamp` | | |

Mode 6 (control messages, `ntpq`) and mode 7 are refused: `NtpPacket` does not model their format. `InconsistentTimestamps` no longer comes out of `try_from`, which compares no timestamps (below).

The reference id depends on the stratum (RFC 5905 §7.3), and 11.6.0 widened the three cases:

- **stratum 1**: a clock source, printable ASCII, left-justified and zero-padded. The list is kept by IANA and is longer than the RFC's excerpt (GOES, GPS, PPS...): any non-empty printable code is accepted, `SHM`, ntpd's shared memory driver, included ([#162](https://github.com/Akmot9/Packet-parser/issues/162));
- **stratum 0**: a kiss code in a server's Kiss-o'-Death, but whatever an unsynchronized client leaves in its request (`127.0.0.1`, `USER`): any four bytes, kept as `KissCode` ([#165](https://github.com/Akmot9/Packet-parser/issues/165));
- **stratum 2 to 15**: the IPv4 address of the upstream server or, for an IPv6 upstream, the first four bytes of the MD5 hash of its address, which can read as any address, multicast included: any four bytes, kept as `Ipv4` ([#165](https://github.com/Akmot9/Packet-parser/issues/165)).

`Refid::code()` gives the code of a kiss code or clock source without its padding, and `Display` prints the code, the address, `NULL` for an empty kiss code, or the bytes. The poll is a signed power of two (RFC 5905 §7.3), down to -7 for chrony since its version 4.3; the decoder used to refuse it as soon as it was negative. `poll` keeps the byte as received (-7 is 249) and `NtpPacket::poll_exponent()` returns it signed ([#165](https://github.com/Akmot9/Packet-parser/issues/165)). Before [#165](https://github.com/Akmot9/Packet-parser/issues/165), 27 NTP packets of `The-Ultimate-PCAP.pcapng` came out `"Unknown"`.

## Timestamps: an era and two clocks

A timestamp is 32 bits of seconds since the start of an era and 32 bits of fraction. Since 13.0.0 the crate keeps them as they are on the wire, in `NtpTimestamp`; until 12.x it turned them into a `DateTime<Utc>` of `chrono`, which is no longer maintained (RUSTSEC-2026-0543) and is no longer a dependency [#315](https://github.com/Akmot9/Packet-parser/issues/315). The dates did not change: they were checked against tshark on every NTP datagram of the corpus. The type reads them:

| Method | Gives |
| --- | --- |
| `unix_seconds()` | whole seconds since 1970, negative before; 0 for a null timestamp |
| `subsec_nanos()` | the fraction, in nanoseconds, rounded down |
| `is_null()` | whether all 64 bits are zero: "unknown" |
| `to_system_time()` | a `SystemTime`, `None` only where the platform cannot hold the date |
| `Display` | RFC 3339 in UTC, to the nanosecond: `2008-07-31T11:45:31.067669303Z` |
| `Ord` | the order in time, eras included |

`NtpPacketParseError::TimestampConversionError` is gone: every timestamp has a date. The rules:

- the **era** is given by the most significant bit of the seconds (RFC 4330 §3): set, era 0, from 1968 to 2036; clear, era 1, from 2036 to 2104, as tshark reads it. Until 11.6.0 every timestamp counted from 1900, and a Java client of the corpus that sent 37 seconds came out at `1900-01-01T00:00:37Z`, where tshark reads `2036-02-07T06:28:53Z` ([#162](https://github.com/Akmot9/Packet-parser/issues/162));
- an all-zero timestamp means "unknown" (RFC 5905 §6) and comes out as the Unix epoch, `1970-01-01T00:00:00.000000000Z`;
- the fraction becomes nanoseconds, rounded down.

Originate (T1) is the client's timestamp, copied as is into the reply; Reference, Receive (T2) and Transmit (T3) are the server's. Until 11.6.0 the decoder demanded `reference <= originate <= receive <= transmit`: as soon as the client's clock was a few milliseconds ahead, which is what NTP is there to correct, or a first request left originate null, the server's reply was `InconsistentTimestamps`, hence `"Unknown"`, and so were 20 of the 26 real replies of the IEC 61850 substation of `protocols/goose/iti_Sample_File_MMS_and_GOOSE.pcap` ([#161](https://github.com/Akmot9/Packet-parser/issues/161)). The decoder now compares no timestamp: Receive and Transmit do share a clock, but in interleaved mode (chrony `xleave`) a reply carries the Transmit of the previous one ([#165](https://github.com/Akmot9/Packet-parser/issues/165)). Only the blind probe checks that Receive does not follow Transmit.

The exchange of the Java client of `protocols/iec104/iti_JavaRMI_and_IEC_Misc.pcap`, frames 1 and 2, shows the era, the null timestamp and the two clocks (*tested*):

```rust
{{#include ../examples/src/shared.rs:ntp_era_and_clocks}}
```

## Oracle: 1 308 datagrams

`tests/ntp_golden.rs` compares the crate with tshark 4.6.6 (`tools/ntp_oracle.sh`, frozen in `tests/data/ntp_tshark_oracle.tsv`) on **1 308 datagrams**, field by field: ports, LI, version, mode, stratum, poll, precision, root delay and dispersion, reference id, and the four timestamps to the nanosecond.

The datagrams come from `pcaps_exemple/protocols/ntp/`, the substation of `goose/iti_Sample_File_MMS_and_GOOSE.pcap`, the Java exchange and, read in place, `The-Ultimate-PCAP.pcapng` and `4SICS-GeekLounge-151020.pcap`. They cover NTS, authenticated MS-SNTP, SHA-256 and SHA-512 MACs, chrony requests with random timestamps, symmetric mode and IPv6 upstreams.

| What the test counts | Datagrams |
|---|---|
| compared with tshark | 1 308 |
| control messages of mode 6, a named gap | 104 |
| ICMP errors quoting an NTP datagram, where the crate labels the ICMP frame, a named gap | 36 |
| datagrams of six nDPI captures that the former blind probe took for NTP, named one by one | 31 |
| datagrams that only the lenient decoder of [#165](https://github.com/Akmot9/Packet-parser/issues/165) accepts, named too | 8 |
| of the 1 308, recognized by the blind probe once moved off port 123 | 1 307 |

The two gaps are named, not masked, and no other frame of `pcaps_exemple/` comes out NTP. The 39 named datagrams are KCP, QUIC and CryNet datagrams, and ASTERIX CAT 021 datagrams of `wireshark_9953_cat021023.pcap`, 1 555 of which have the shape of an NTP header. The one datagram the blind probe refuses is the chrony request of the example above. The golden histogram counts 77 NTP labels.

## What is left out

The limits every protocol shares, reassembly and checksums among them, are on the [Limits](./limits.md) page. The ones below are this protocol's own.

- **Modes 6 and 7.** Control messages (`ntpq`) and the private mode are refused: `NtpPacket` does not model their format. The 104 mode 6 messages of the corpus come out `"Unknown"`.
- **What follows the header.** Extension fields, NTS fields and the MAC are not decoded; only the blind probe looks at them.
- **TCP.** Both rules have a UDP guard.
- **The exchange.** The decoder compares no timestamp with another, and nothing pairs a reply with its request: the offset and the delay of RFC 5905 §8 are the consumer's to compute.
- **An NTP datagram quoted by an ICMP error.** The frame is labelled as ICMP, and the quoted datagram is not probed.
