# Profinet

Announced by EtherType `0x8892`, and checked by the [internet layer](./network.md).

Profinet (EtherType `0x8892`) is validated so that a corrupt frame is reported, but the crate keeps no detailed header for it: the `Internet` built by the private `Internet::profinet()` has `protocol_name: "Profinet"`, no addresses, no `payload_protocol`, an empty payload and `details: None`.

The validation is `ProfinetPacket::try_from`, a DCP parser: at least 16 bytes, a Frame ID in `0xC000..=0xF7FF`, `0xF800..=0xFBFF`, `0xFEFD`, `0xFEFE` or `0xFEFF`, and a first block (header at offset 12) whose declared length fits in the buffer and whose bytes are UTF-8, read as the NameOfStation. Its result is discarded; `ProfinetPacket::try_from(flow.data_link.network_payload())` gives the DCP fields to a caller who wants them.

That validator is narrower than Profinet: a frame with any other Frame ID (a DCP Hello `0xFEFC` or an alarm, for instance) fails with `ProfinetPacketError::UnknownFrameId` and is reported in `corrupted` although it is healthy, and a cyclic real-time frame in the accepted ranges passes or fails depending on whether its first data bytes happen to read as a DCP block.
