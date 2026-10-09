# IPv6

Announced by EtherType `0x86DD`, or directly by a RAW IP capture, and parsed by the [internet layer](./network.md).

![The book's TCP SYN carried by IPv6, 32 bits per row: the 40-byte fixed header with its Next header byte 00, the 8-byte Hop-by-Hop extension header, then the TCP segment; the Internet struct gets both addresses, payload_protocol Some(Tcp) from the end of the chain, and the 40-byte payload](images/network/ipv6_struct.svg)

The same SYN as in the [IPv4 page](./ipv4.md), carried by IPv6 behind one Hop-by-Hop extension header. The fixed header is 40 bytes, and its **Next header** byte does not name the transport here: it says `0`, an extension. The addresses and the payload come out as for IPv4; `payload_protocol` comes from the end of the chain, and `details` keeps the chain's bytes.

✅ **Header length** – at least **40 bytes**, otherwise `Ipv6Error::InvalidLength`.  
✅ **Version** – the high nibble is **6**, otherwise `InvalidVersion`.  
✅ **Payload length** – the buffer holds `40 + payload_length` bytes, otherwise `InvalidPayloadLength`. Bytes beyond it (Ethernet padding) are not handed up, as for IPv4.  
✅ **Extension chain** – every extension header walked fits in the payload, otherwise `InvalidExtensionHeader`.  

![Walking the chain: the fixed header's Next header is 0, a Hop-by-Hop header of 8 bytes whose own Next header is 6, TCP; next_header keeps 0, extension_headers the 8 bytes, transport_protocol Some(6); a Fragment header or No Next Header makes transport_protocol None](images/network/ipv6_extensions.svg)

Extension headers are walked (RFC 8200 §4) to find the real transport protocol: `Ipv6Packet::transport_protocol` is the next header after the extension chain, `extension_headers` keeps the raw bytes of the chain, `payload` starts after it, and `next_header` keeps the fixed header's value, which may name an extension. Five types are walked: Hop-by-Hop (0), Routing (43) and Destination Options (60), whose length counts 8-byte units after the first 8; Fragment (44), a fixed 8 bytes; and AH (51), whose length counts 4-byte units minus 2 (RFC 4302). Any other value ends the walk and becomes `transport_protocol`: ESP (50), whose contents are encrypted, and the Mobility (135), HIP (139) and Shim6 (140) headers included.

As for IPv4, a Fragment extension header (or a `No Next Header` value, 59) sets `transport_protocol` to `None`, so nothing is parsed above an incomplete datagram; `Ipv6Packet::is_fragmented()` tells the two cases apart.
