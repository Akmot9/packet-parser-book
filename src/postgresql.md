# PostgreSQL

The frontend/backend protocol of PostgreSQL, on TCP only. The module is `packet_parser::parse::application::protocols::postgresql`: `PostgreSqlPacket::try_from` splits a segment into `PostgreSqlMessage`s and decodes the bodies of the main ones; its errors are `PostgreSqlError`, in `packet_parser::errors::application::postgresql`. The largest single-file decoder of the crate had no real frame to exercise it until [#98](https://github.com/Akmot9/Packet-parser/issues/98) brought fourteen captures of Zeek's test corpus, and they rewrote its detection.

![A PostgreSQL typed message, the SASLInitialResponse of a psql login, 32 bits per row: the type byte p, a length of 54 that counts itself and the body, then the body, the mechanism name SCRAM-SHA-256, the length of the initial response and the SCRAM client-first-message; on the right the PostgreSqlMessage struct, with the type PasswordOrSaslResponse, the length, the 50 body bytes and a Raw body](images/application/postgresql_message.svg)

## Two message formats, two new types

A typed message is one type byte, a `u32` length that counts itself but not the type byte, and a body; the messages of a segment must tile it exactly. The first messages of a connection have no type byte: a `u32` length equal to the whole payload, then a code, protocol 3.0 or 3.2 for a `StartupMessage`, or the code of `SSLRequest`, `CancelRequest` or `GSSENCRequest`. `try_from` tries the typed form first, then the untyped one, and reports the typed error if both fail.

```rust
pub struct PostgreSqlPacket<'a> {
    pub messages: Vec<PostgreSqlMessage<'a>>,
}

pub struct PostgreSqlMessage<'a> {
    pub message_type: PostgreSqlMessageType,
    pub length: u32,         // typed messages: excludes the type byte
    pub payload: &'a [u8],   // the body
    pub body: PostgreSqlMessageBody<'a>,
}
```

11.6.0 added two variants at the end of `PostgreSqlMessageType`, and one to `PostgreSqlMessageBody`:

- **`PasswordOrSaslResponse`**, the type byte `p`, which PasswordMessage, SASLInitialResponse, SASLResponse and GSSResponse share and only the state of the authentication tells apart; the body stays `Raw`. The decoder used to reject the byte, so every password or SCRAM authentication came out `InvalidMessageType`.
- **`SslResponse`**: the server's one-byte answer to `SSLRequest`, `S` (TLS accepted) or `N`, with the body `PostgreSqlMessageBody::SslResponse { accepted }`. It has neither header nor length, so it is decoded only alone in its segment: `S` and `N` are answers, `SN` is an error.

## Detection: compatible shape on port 5432, strong proof elsewhere

```rust
port_rule(ApplicationProtocol::PostgreSql, Guard::Tcp, is_postgresql_tcp_port, ProbeId::PostgresqlPort),  // 5432
// ... blind cascade, after EtherNet/IP:
rule(ApplicationProtocol::PostgreSql, Guard::Tcp, ProbeId::Postgresql),
```

Both probes are crate-internal, both start from a successful decode, and both demand that **every** message have a *compatible shape*, a body consistent with its type: plain text in a `Query` or a `Parse`, `I`, `T` or `E` in a `ReadyForQuery`, two C-strings in a `ParameterStatus` whatever its name, a known authentication code of the right size, a C-string or a SASL form in a `p` message...

On **TCP 5432** (IANA `postgresql`), or on a port declared with `DecodeAsProtocol::PostgreSql`, `is_plausible_postgresql_payload` stops there: a decode of compatible shape is enough. That is what recognizes the messages that carry no proof of their own: a `Terminate`, a `ReadyForQuery` or a password alone in their segment, and the `S` or `N` answer to `SSLRequest`. Measured on the Zeek corpus, it labels nothing in the HTTP and MySQL sessions replayed on 5432.

**Elsewhere**, `is_likely_postgresql_payload` first discards at constant cost a payload whose first bytes cannot start a message (an untyped length of at least 8, or a printable type byte and a length of at least 4), then demands the compatible shape and, in addition, **one message of strong evidence** at least:

| Message | Strong evidence |
| --- | --- |
| `StartupMessage` | a known parameter (`user`, `database`, `application_name`, `client_encoding`, `options`, `replication`) with a value, and the final NUL |
| `SSLRequest`, `GSSENCRequest` | exactly 8 bytes |
| `CancelRequest` | a secret key of 4 to 256 bytes |
| `Query`, `Parse` | a first word that is an SQL keyword |
| `CommandComplete` | a tag that starts with an SQL keyword |
| `ErrorResponse`, `NoticeResponse` | NUL-terminated fields, among them a message, a five-character SQLSTATE or a severity |
| `ParameterStatus` | a name every server sends (`server_version`, `client_encoding`, `scram_iterations`, `search_path`...), the value possibly empty |
| Authentication | Ok, cleartext, Kerberos, SCM, GSS or SSPI at their fixed size, MD5 with its salt, the list of SASL mechanisms, SCRAM's server-first (`r=…,s=…,i=…`) and server-final (`v=…`) messages |
| `p` | an MD5 hash (`md5` and 32 hexadecimal digits), SCRAM's client-first (`SCRAM-SHA-256`, then `n,,n=…,r=…`) or client-final (`c=…,r=…,p=…`) message |

A cleartext password has no form to recognize: it is compatible, never a proof. Until 11.6.0 the blind probe also refused server replies whose `ParameterStatus` had an empty value (the `application_name` of a client that gave none) or a recent name (`scram_iterations`, `search_path`), and took only an AuthenticationSASL as proof; on the Zeek corpus, those real segments came out `"Unknown"`.

The `N` of frame 6 of `pcaps_exemple/protocols/postgresql/psql-login.pcap` needs the port, or a declared one (*tested*):

```rust
{{#include ../examples/src/shared.rs:postgresql_ssl_answer}}
```

The SASLInitialResponse of frame 12 of the same capture is a `p` message of strong evidence (*tested*):

```rust
{{#include ../examples/src/shared.rs:postgresql_password_message}}
```

## Oracle: 276 segments

`tests/postgresql_golden.rs` runs the fourteen captures of `pcaps_exemple/protocols/postgresql/` against tshark 4.6.6 without TCP reassembly, the view of a stateless parser (`tools/postgresql_oracle.sh`, frozen in `tests/data/postgresql_tshark_oracle.tsv`): twelve real psql sessions (loopback, a VM against AWS RDS, an application in containers, a Windows workstation) and two negatives, HTTP and MySQL replayed on port 5432. Of the 331 segments with a payload, 276 are PostgreSQL, and their 558 messages have tshark's types and lengths, the 8 SSL answers included. Replayed off port 5432, 262 of them are still recognized by the blind probe; the 14 others are the segments without strong evidence, 8 SSL answers, 5 `Terminate` and 1 `ReadyForQuery`, each alone. On the negatives tshark labels 6 segments `pgsql`, the crate none, and nine mutations of two real frames (lengths, protocol version, final NUL, type byte, truncation, trailing byte) are rejected. The golden histogram counts 278 PostgreSQL labels: the 276 segments, and 2 retransmissions that tshark does not dissect.

## What is left out

The limits every protocol shares, reassembly and checksums among them, are on the [Limits](./limits.md) page. The ones below are this protocol's own.

- **Most bodies.** The decoder types every message and decodes the bodies of the main ones; the others stay `PostgreSqlMessageBody::Raw`, the `p` messages among them, which only the state of the authentication tells apart.
- **The state of the connection.** Nothing follows the startup, the authentication or the extended query protocol from one segment to the next.
- **A message cut by the segment.** The messages must tile the segment: one that runs into the next segment makes the whole segment `"Unknown"`.
- **What follows an accepted `SSLRequest`.** The session continues in TLS and is labelled TLS: the crate does not decrypt.
