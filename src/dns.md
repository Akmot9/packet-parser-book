# DNS

The Domain Name System (RFC 1035), with the two protocols that reuse its wire format on the local link: mDNS (RFC 6762) and LLMNR (RFC 4795). The module is `packet_parser::parse::application::protocols::dns`. `DnsPacket` has one constructor per form, and its errors are `DnsPacketError`, in `packet_parser::errors::application::dns`.

![A DNS response, 32 bits per row: the 12-byte header with its transaction identifier, flags and four counts, the question wireshark.org with its type and class, then one answer whose name is a two-byte compression pointer to offset 12, followed by type, class, TTL, data length and four bytes of address; on the right the DnsPacket struct, with the header, the question, and the answer whose name is rebuilt](images/application/dns_message.svg)

## Detection: five rules, three labels

| Rule | Label | Transport | Port | Constructor |
|---|---|---|---|---|
| 11 | `mDNS` | UDP | 5353, terminal | `DnsPacket::try_from_mdns` |
| 12 | `LLMNR` | UDP | 5355, terminal | `DnsPacket::try_from_llmnr` |
| 22 | `DNS` | TCP | 53 | `DnsPacket::try_from_tcp` |
| 23 | `DNS` | UDP | 53 | `DnsPacket::try_from` |
| 53 | `DNS` | UDP | none | `DnsPacket::is_blind_udp_match` |

The three formats overlap on the wire. A unicast DNS query with RD set is a valid LLMNR header, since RD sits where LLMNR puts its T bit, and an mDNS query is a valid DNS query. Only the port tells them apart, so each of the two link-local ports is [terminal](./glossary.md#terminal-port): when the probe of rule 11 or 12 refuses a datagram on its port, the dispatch stops and the flow has no application. A later rule would otherwise label a damaged mDNS message `"DNS"`.

On port 53 the decoder alone decides. Off port 53, rule 53 asks for more, because a 12-byte header of plausible flags is weak evidence:

- the sections must end exactly where the datagram ends: a DNS message over UDP has no padding (RFC 1035 §4.2.1);
- the four counts must not all be zero.

Without them, the 37 datagrams of a radar feed in `asterix/wireshark_8579_radardata.pcap`, a header with four zero counts followed by 120 bytes, came out `"DNS"` ([#118](https://github.com/Akmot9/Packet-parser/issues/118)). There is no blind rule on TCP: off port 53, DNS over TCP needs a [Decode As](./application.md#decode-as) port. `DecodeAsProtocol::Dns` picks the datagram form on UDP and the length-prefixed form on TCP; `Mdns` and `Llmnr` exist too.

A query and its response, on port 53 and off it (*tested*):

```rust
{{#include ../examples/src/dns.rs:dns_query_and_response}}
```

## The message

```rust
#[non_exhaustive]
pub struct DnsPacket<'a> {
    pub header: DnsHeader,                                     // id, flags, four counts
    pub queries: DnsQueries,                                   // the question section
    pub answers: Option<Vec<Answer<'a>>>,                      // None when the count is 0
    pub authorities: Option<Vec<AuthoritativeNameServer<'a>>>,
    pub additionals: Option<Vec<AdditionalRecord<'a>>>,
}
```

`DnsHeader` keeps the transaction identifier, the flags as the raw `u16` once they are checked, and `counts`, the four section counts in wire order. A question is a `DnsQuery`: `name`, `qtype`, `qclass`. A record of any of the three sections has the same fields: `name`, its type and class, `ttl`, `data_length`, and the record data as a borrowed slice, `address` in an `Answer`. `DnsType` and `DnsClass` are newtypes over `u16` that display the IANA name when they know it.

The record data is not decoded. An A record's four bytes are ready to use; the target of a PTR or a CNAME is a name in wire form, compression pointers included, and stays that way.

### Names and compression

A name is a sequence of labels, each a length byte and that many bytes, ended by a zero byte. A length byte whose two high bits are set is a pointer instead: with the next byte it gives an offset from the start of the message, where the name continues (RFC 1035 §4.1.4). In the diagram the answer's name is `c0 0c`, offset 12, the name of the question.

`parse_dns_name` rebuilds the name as a `String`, labels joined by dots, and bounds the work a hostile message can ask for:

| Rule | Refused as |
|---|---|
| A pointer must point strictly backwards | `DnsQueryParseError::InvalidCompressionPointer` |
| At most 8 pointers are followed for one name | `InvalidCompressionPointer` |
| A length byte starting with `01` or `10` is reserved | `ReservedLabelType` |
| A name is at most 255 bytes on the wire, the labels reached through pointers included | `OutOfBoundParse` |
| Every label must be UTF-8 | the UTF-8 error |

The 255-byte bound is the one of RFC 1035 §3.1, and tshark shows such a name as `<Name too long>`. It is also what bounds the cost of a message: before 11.7.0, records that all pointed to one very long question name had it read again each time, in time quadratic in the size of the message ([#184](https://github.com/Akmot9/Packet-parser/issues/184)). A name of exactly 255 bytes is accepted, one of 256 refused.

Since 11.7.0 the probes read the whole datagram and not its first 18 432 bytes ([#185](https://github.com/Akmot9/Packet-parser/issues/185)). A response larger than that is judged to its last byte, which is what the blind rule's "sections end where the datagram ends" needs.

### Over TCP

Over TCP each message is preceded by its length on two bytes (RFC 1035 §4.2.2). `try_from_tcp` wants that length to cover at least a header and to fit in the segment, then decodes the first message. The length is also what tells DNS over TCP from an arbitrary payload on port 53 (*tested*):

```rust
{{#include ../examples/src/dns.rs:dns_over_tcp}}
```

### mDNS and LLMNR

`try_from_mdns` relaxes two checks of unicast DNS. A responder announces its records without being asked, so a message may carry answers and no question; and RFC 6762 tells a receiver to ignore most header bits, so only a non-zero opcode or response code is refused.

`try_from_llmnr` applies the LLMNR header instead: opcode 0, the four reserved bits at zero, exactly one question, and in a query no response code and no answer or authority record.

An announcement that unicast DNS refuses, and a DNS response on the LLMNR port (*tested*):

```rust
{{#include ../examples/src/dns.rs:mdns_terminal_port}}
```

## Validations

The checks of `DnsPacket::try_from`, in order. Bytes count from the start of the message.

| Bytes | Field | Check | Error |
|---|---|---|---|
| 0–11 | Header | the message holds at least 12 bytes | `DnsPacketError::InsufficientData` |
| 2–3 | Flags, bit 6 | the one bit still reserved is zero; AD and CD are free | `DnsFlagsError::InvalidZField` |
| 2–3 | Flags, opcode | 0 to 5 | `InvalidOpcode` |
| 2–3 | Flags, RCODE | 0 to 5 | `InvalidRCode` |
| 2–3 | Flags, RA | zero in a query | `RaInQuery` |
| 2–3 | Flags, AA and TC | zero in the response to a STATUS request | `AaTcInStatusResponse` |
| 2–3 | Flags, AA | zero when the response code is 2 (server failure) or 5 (refused) | `AaInServerFailure`, `AaInRefused` |
| 4–11 | Counts | no record without a question | `DnsHeaderError::InvalidCounts` |
| 12– | Questions | each name follows the rules above, and four bytes of type and class follow it | `DnsQueryParseError` |
| after | Records | each name, then ten bytes of type, class, TTL and data length, then that many bytes of data | `DnsQueryParseError` |

Bytes after the last section are accepted on port 53. Only the blind rule refuses them.

## Oracle: counts and digests

DNS has no field-by-field oracle. `tests/tshark_regression.rs` compares, for the eleven captures of `pcaps_exemple/protocols/dns/`, the set of frames the crate labels `"DNS"` or `"mDNS"` with the frames of `tshark -Y dns`: 50 frames, a count and a digest of the frame numbers per capture. Two differences are named. In `dns_axfr.pcapng` and `dns_tcp.pcapng`, tshark also reports one message it reassembles from two segments; the crate labels the frames that hold a whole message.

`tests/llmnr_golden.rs` decodes real LLMNR queries of `The-Ultimate-PCAP.pcapng`, and checks that a DNS query of the same capture is a valid LLMNR header too. The golden histogram counts 104 DNS, 136 LLMNR and 12 mDNS labels.

## What is left out

The limits every protocol shares, reassembly and checksums among them, are on the [Limits](./limits.md) page. The ones below are this protocol's own.

- **The record data.** No record type is decoded: an address, a name, an SOA or an OPT pseudo-record all come out as bytes.
- **Response codes above 5 and opcodes above 5.** They are refused, so a dynamic update that answers `NOTAUTH` is not `"DNS"`.
- **A message over several TCP segments.** A zone transfer larger than a segment is recognized in the segments that start with a whole message; `try_from_tcp` reads the first message of a segment and stops.
- **Pairing.** Nothing matches a response to its query by transaction identifier.
- **DNS over TLS, HTTPS or QUIC.** They are labelled by their envelope.
