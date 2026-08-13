# Performance and benchmarks

## The `parse_timing` feature

Per-layer timing is not in the normal path. Reading a clock four times per packet
would show up in the numbers it is supposed to measure, so it lives behind a
feature flag:

| Feature | Effect |
| --- | --- |
| `doc-diagrams` | Enables Rustdoc diagrams through `aquamarine` |
| `parse_timing` | Exposes `ParseTiming`, `parse_timed` and `PacketFlow::try_from_timed` |

```rust
use packet_parser::{LinkType, parse_timed, timing::ParseTiming};

let mut timing = ParseTiming::default();
let flow = parse_timed(LinkType::ETHERNET, &packet, &mut timing)?;

println!("L2={}ns L3={}ns L4={}ns L7={}ns total={}ns",
    timing.l2_ns,
    timing.l3_ns,
    timing.l4_ns,
    timing.l7_ns,
    timing.total_ns,
);
```

```bash
cargo test --features parse_timing
```

When the feature is off, `ParseTiming` is a zero-sized type and the timing calls
compile away — the measured path and the production path are the same code, not
two implementations that can drift.

Two limits to keep in mind: the timed path is for measurement and should not be
treated as the standard parsing path, and it does not yet recursively measure the
`inner` flows produced by [tunnel parsing](./tunnels.md).

## `tools/verbench`: comparing versions

The main benchmark harness compares published crate versions from crates.io
against the local working copy, on a fixed reference packet after warmup, and
reports average `l2_ns`, `l3_ns`, `l4_ns`, `l7_ns` and `total_ns`.

```bash
tools/verbench/run.sh          # full run → perf_by_version.json + .html
python3 tools/verbench/report.py   # regenerate only the HTML from existing JSON
xdg-open perf_by_version.html
```

The HTML report is standalone: it opens directly in a browser and needs no
Docker, Postgres, Grafana or CDN.

Read those numbers as **trends between versions on the same machine**, not as
universal absolute latency claims. A refactor that moves `total_ns` from 900 to
700 on your laptop is a real signal; the 700 itself is not a promise.

## The optional PCAP pipeline

The workspace also contains `benchmark_db`, a binary that parses local PCAP files
and writes JSONL events:

```bash
cargo run -p benchmark_db --release
```

Each event contains `run_id`, `crate_code`, `pcap`, the packet index, the packet
hash, the total duration, and the OSI timings when `parse_timing` is enabled.
Output goes to:

```text
~/.local/share/packet_parser_bench/jsonl/
```

The optional `docker-compose.yml` pipeline ingests those files into Postgres and
displays them in Grafana. It is entirely optional — the standalone `verbench`
HTML report does not need it.

## Known limitations

Stated plainly, because each is a deliberate trade against statefulness:

- **No TCP reassembly.** Segments are parsed individually.
- **No IP reassembly.** Fragments set `payload_protocol: None` rather than
  parsing L4 from an incomplete datagram.
- **Application detection is heuristic and best-effort.** See
  [the application chapter](./application.md).
- **The `parse_timing` path is for measurement**, not the standard path.
- **Timed parsing does not recurse into `inner` flows.**
