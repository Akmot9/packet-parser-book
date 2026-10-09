# Linux cooked capture (SLL)

The *Linux cooked* formats are what a capture on the Linux `any` interface produces: a pseudo-header instead of an Ethernet one.

## SLL v1

A 16-byte cooked header, in network byte order. The decoder keeps the packet type, the raw ARPHRD hardware type, the declared address length, the available source-address bytes and the protocol value. Packet types and hardware types outside the known constants are preserved as numbers, so a newer kernel does not turn packets into errors. An address longer than the 8-byte wire slot is reported as truncated (`address_is_truncated()`) rather than rejected. Use `LinkType::LINUX_SLL` (113): the value 25 shown by some Wireshark fields is an internal WTAP identifier.

## SLL v2

A 20-byte header. The decoder additionally keeps the interface index, numeric because resolving its name belongs to the capture machine, and the reserved-MBZ field. A non-zero reserved value is preserved and reported by `reserved_is_zero()`, matching Tshark's tolerant dissection. Use `LinkType::LINUX_SLL2` (276); Wireshark's internal WTAP identifier for this format is 210.
