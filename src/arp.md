# ARP

Announced by EtherType `0x0806`, and parsed by the [internet layer](./network.md).

ARP carries no transport, but it does carry protocol addresses, and those are worth a flow identity: `source`/`destination` are the sender/target protocol addresses, `payload_protocol` is `None`, `payload` is empty, and `details` holds the full `ArpPacket` (hardware/protocol types and lengths, operation, both hardware addresses as `[u8; 6]`).

✅ Minimum length **28 bytes**, hardware type **1** (Ethernet) with length **6**, protocol type IPv4 (length 4) or IPv6 (length 16), operation request/reply, and the dynamic length `8 + 2×hlen + 2×plen` available. Bytes past it (Ethernet padding) are ignored. A failure is an `ArpError` (`InvalidLength`, `UnsupportedHardwareType`, `UnsupportedProtocolType`, `InvalidHardwareLength`, `InvalidProtocolLength`, `UnsupportedOperation`), and since the EtherType said ARP, it is reported in `corrupted`, not dropped.
