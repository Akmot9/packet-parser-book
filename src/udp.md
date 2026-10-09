# UDP

IP protocol 17, parsed by the [transport layer](./transport.md).

✅ **Minimum length** – at least **8 bytes** (`UdpError::PacketTooShort { expected, actual }`).  
✅ **Length field** – equal to the buffer length (`UdpError::InvalidLength { length, actual }`). UDP is the one header whose declared length must match exactly: the internet layer already trimmed the Ethernet padding (IPv4 to its total length, IPv6 to its payload length), so a mismatch is a corrupt datagram.  

`payload` is everything after the 8-byte header. UDP has no semantic anomaly: a datagram either parses or corrupts the layer.
