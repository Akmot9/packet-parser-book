# Custom parsers and rules

The crate names the protocols it decodes. For one it does not decode, a proprietary format or an in-house protocol, the caller can add a parser of its own. There are three ways:

| Way | Since | What it is | What it can do |
| --- | --- | --- | --- |
| A Rust parser | 13.0.0 | a type that implements `ApplicationParser`, registered with `ParseConfig::with_parser` | anything Rust can do |
| A plugin | 13.0.0 | the same type, compiled into a native library (`.so`, `.dylib`, `.dll`) loaded at run time | anything, with every right of the process |
| A rule file | 13.1.0 | a TOML file read at run time, behind the `rules` feature | recognize byte patterns at fixed offsets, and show fields at fixed offsets |

A rule file runs no code, and that is its point. What a reviewer reads is exactly what runs: an application that must show it is passive can load rules where it cannot load native code.

The examples of this chapter use ACME and DEMO, two made-up protocols.

## What an added parser can do

An added parser runs **after** the [dispatch table](./application.md#how-the-label-is-chosen-one-ordered-table), and only on a payload the table left `"Unknown"`:

- a non-empty TCP or UDP payload;
- of a flow at any level, the inner flows of a [tunnel](./tunnels.md) included;
- with the transports and ports the parser declares.

It never takes a payload from the crate: an SSH banner stays `"SSH"` even if every parser accepts it. The parsers run in the order they were registered. The first one that accepts the payload names the flow `ApplicationProtocol::Custom(label)`, and the JSON output writes that label like any other: `"application_protocol": "ACME"`.

It cannot read a protocol carried by something other than TCP or UDP, reassemble a stream, rename a protocol the crate recognizes, or see the flows the table names.

## A Rust parser

The trait has five methods. Only `label` and `matches` have no default (*tested*):

```rust
{{#include ../examples/src/custom.rs:acme_parser}}
```

`matches` is called on many payloads. It must be fast and decide from the bytes and the context alone: no file, no network, no clock, no global state. It must not panic: a parser registered in the application has no net. A signature too weak to stand alone, such as two magic bytes, should come with a port list.

`fields` is not called while parsing. The application asks for the fields when it shows one packet, with `ParseConfig::custom_fields(&flow)` (*tested*):

```rust
{{#include ../examples/src/custom.rs:acme_registered}}
```

The label is checked on registration (`ParserRegistrationError`). It is refused when it is empty, longer than 64 bytes, has a control character or spaces around it, is the label of a built-in protocol, or is already registered. The last two comparisons ignore ASCII case. A parser that accepts everything shows the guarantee (*tested*):

```rust
{{#include ../examples/src/custom.rs:never_takes_a_frame}}
```

`ParseConfig` has the rest of the API:

| Method | What it does |
| --- | --- |
| `with_parser(parser)` | adds a parser, by value |
| `add_parser(&mut self, parser)` | adds a parser to an existing configuration; a refusal leaves it unchanged |
| `remove_parser(label)` | removes a parser and returns it |
| `parser(label)` | returns a parser |
| `parser_labels()` | lists the labels, in the order they run |
| `custom_fields(&flow)` | the fields of a flow an added parser named; `None` otherwise |
| `application_protocol(label)` | reads a stored label back (13.1.0) |

`classify_payload_with` goes through the same parsers.

### Reading a stored label back

An application that stores its labels as text, in an export or a flow matrix, must read them back. `FromStr` knows only the labels of the crate: it refuses a custom label, since the text does not say which parser gave it. Since 13.1.0, `config.application_protocol(label)` answers with the configuration that produced the label ([#323](https://github.com/Akmot9/Packet-parser/issues/323)). The comparison is exact, case included. A parser removed since the export gives `UnknownApplicationLabel`, and the application decides whether to keep the text or to report the missing parser (*tested*):

```rust
{{#include ../examples/src/custom.rs:label_read_back}}
```

## A plugin

A plugin is a `cdylib` crate that calls `export_parser!` once on a type that implements `ApplicationParser`. The host loads it with `load_parser`, which checks what the library declares: the entry point, the version of the ABI (`packet_parser_plugin_v1`), the size of the descriptor, the label, the transports and the ports. A panic of the parser is caught at the boundary, and the payload is then not recognized.

Both sides are in the kit `packet_parser_plugin`, in the `plugin/` folder of the crate repository. The kit is **not published on crates.io**: a plugin depends on it through git or a path. It is the only `unsafe` code of the repository, outside the published crate.

A plugin is native code, not a sandbox. Once loaded, it can read the memory and the files of the application, use the network, and crash it by a fault other than a panic. `load_parser` is `unsafe` for that reason: the kit checks the shape of what the plugin declares, not what its code does. Load only a library whose origin you checked. `docs/plugins.md`, in the crate repository, has the build, the loading and the advice for an "Import parsers" button.

## A rule file

The feature is off by default. Without it, the crate does not depend on `toml`:

```toml
[dependencies]
packet_parser = { version = "13.1", features = ["rules"] }
```

`RuleSet::from_toml` reads and checks a whole file. `ParseConfig::with_rules` and `add_rules` then register one parser per label, every label of the file or none. A label stored as text reads back with `application_protocol`, as above (*tested*):

```rust
{{#include ../examples/src/custom.rs:acme_rules}}
```

### Recognizing a payload

A rule recognizes a payload when every condition holds:

1. the transport is one of `transport`: `"tcp"`, `"udp"` or `"tcp+udp"`, the default;
2. the source or the destination port is in `ports`, when it is given;
3. the length is between `min_length`, by default the end of the last pattern, and `max_length`;
4. each pattern holds: for each byte `i`, `payload[offset + i] & mask[i] == bytes[i]`. Without `mask`, every bit counts.

Several rules with the same label are **variants** of one protocol, such as a request and a response. The label goes to a payload that any of them recognizes, and the fields are those of the first that does. The labels of a file run in the order of their first rule.

### Fields

| `type` | Shown as | Keys |
| --- | --- | --- |
| `u8`, `u16be`, `u16le`, `u32be`, `u32le`, `u64be`, `u64le` | an unsigned integer, in decimal; `request (1)` when `values` names it | optional `mask`, `values` |
| `hex` | the bytes in hexadecimal: `DE AD BE EF` | `length`, required |
| `text` | the bytes up to the first NUL: printable ASCII as is, `\` as `\\`, any other byte as `\xNN` | `length`, required |

`mask` on an integer keeps some bits and shifts them down: for a `u16be`, `mask = "0F F0"` turns `0x1234` into `0x23`. A field that does not fit in the payload is not shown: nothing is made up.

### What is refused

The file is refused at its first mistake. `RulesError` gives the line, the column and the reason, in French. A rule must check at least **16 bits** with its patterns. Below that, a random payload matches more than once in 65 536, and a busy network would show the label on traffic that is not the protocol. A rule on a port alone is therefore impossible: a port is a convention, not proof (*tested*):

```rust
{{#include ../examples/src/custom.rs:weak_rule}}
```

The other refusals:

| Mistake | Why it is refused |
| --- | --- |
| a key the format does not have | a typo such as `masq` would drop a condition without a word |
| `version` missing, or other than 1 | the format can change only with a new version |
| a label invalid, built-in, or equal to another of the file but for case | the rules of a Rust parser's label |
| a rule without a pattern | — |
| invalid hexadecimal, a `mask` of another length than its `bytes`, a byte with bits outside its mask, a mask of zeros | a pattern that cannot match, or matches anything |
| `min_length` before the end of a pattern, `max_length` below `min_length` | a rule that can never match |
| a field with an unknown `type`, a `length` it does not use or lacks, `mask` or `values` on a non-integer, a value it can never hold, a value or a field name used twice | — |

Each file has bounds:

| Bound | Value |
| --- | --- |
| `offset` of a pattern or a field | 65 535 |
| `bytes` of a pattern | 64 bytes |
| `length` of a `hex` or `text` field | 256 bytes |
| rules in a file | 256 |
| `ports` of a rule | 256 |
| fields of a rule | 64 |
| `values` of a field | 256 |
| name of a field or a value | 64 bytes |

### What a rule cannot do

- Read a protocol carried by something other than TCP or UDP: the payload of a proprietary EtherType is out of reach.
- Follow a position read from the payload: a length, a TLV, a repeated structure. Positions are fixed.
- Reassemble a stream. On TCP, only the segment that starts a message is recognized, and the segments after it stay `"Unknown"`.
- Rename what the crate recognizes.

A protocol that needs any of these deserves a decoder in the crate ([Adding a new protocol](./adding_a_protocol.md)).

### Cost

A rule is tried only on payloads the crate left `"Unknown"`, so a file costs nothing on traffic the crate recognizes. On an `"Unknown"` payload, the length bounds and the most selective byte of each rule turn away almost every payload of another protocol before the patterns are read. Measured on the corpus of the crate repository, 384 395 frames whose flows are 14 % `"Unknown"`, with rules that match none of them:

| Labels | Cost per `"Unknown"` flow | Whole corpus |
| --- | --- | --- |
| 1 | 27 ns | +1.2 % |
| 5 | 58 ns | +2.4 % |
| 20 | 220 ns | +9.3 % |
| 50 | 460 ns | +18.6 % |

### Trying a rule file

The crate repository has a command-line tool, `examples/rules_check.rs`:

```text
cargo run --release --features rules --example rules_check -- \
    site-rules.toml capture1.pcapng capture2.pcap --fields 3
```

It prints every mistake of the file with its line, the number of flows each label names, the number of `"Unknown"` flows before and after the rules, and with `--fields N` the fields of the first N flows of each label. It fails if a flow that the crate had named changed label, which would be a defect of the crate. `examples/acme_rules.toml` is a complete file, with ACME and DEMO.

### Confidential rules

The rules of a confidential protocol never need to leave the machine they are written on:

- the rule file is data that the application reads at start-up, not part of the crate, of the application's source or of its build;
- `rules_check` reads only the files on its command line and writes only to the terminal;
- a problem with the feature is reported with made-up bytes, as ACME and DEMO are.

Recording which rules produced a result is the application's job: it can store the name and a digest of the file it loaded.

If a later version of the crate decodes a protocol under the label of a rule, `RuleSet::from_toml` refuses the file, since the label is now built in. The crate's decoder then names the traffic: remove the rule, or rename it.
