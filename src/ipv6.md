# IPv6

Announced by EtherType `0x86DD`, or directly by a RAW IP capture, and parsed by the [internet layer](./network.md).

✅ **Header length** – at least **40 bytes**, otherwise `Ipv6Error::InvalidLength`.  
✅ **Version** – the high nibble is **6**, otherwise `InvalidVersion`.  
✅ **Payload length** – the buffer holds `40 + payload_length` bytes, otherwise `InvalidPayloadLength`. Bytes beyond it (Ethernet padding) are not handed up, as for IPv4.  
✅ **Extension chain** – every extension header walked fits in the payload, otherwise `InvalidExtensionHeader`.  

Extension headers are walked (RFC 8200 §4) to find the real transport protocol: `Ipv6Packet::transport_protocol` is the next header after the extension chain, `extension_headers` keeps the raw bytes of the chain, `payload` starts after it, and `next_header` keeps the fixed header's value, which may name an extension. Five types are walked: Hop-by-Hop (0), Routing (43) and Destination Options (60), whose length counts 8-byte units after the first 8; Fragment (44), a fixed 8 bytes; and AH (51), whose length counts 4-byte units minus 2 (RFC 4302). Any other value ends the walk and becomes `transport_protocol`: ESP (50), whose contents are encrypted, and the Mobility (135), HIP (139) and Shim6 (140) headers included.

As for IPv4, a Fragment extension header (or a `No Next Header` value, 59) sets `transport_protocol` to `None`, so nothing is parsed above an incomplete datagram; `Ipv6Packet::is_fragmented()` tells the two cases apart.
