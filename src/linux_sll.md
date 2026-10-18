# Linux cooked capture (SLL)

The *Linux cooked* formats are what a capture on the Linux `any` interface produces: a pseudo-header instead of an Ethernet one.

## SLL v1

![The 16-byte SLL v1 pseudo-header of frame 1 of sll.pcap, 32 bits per row: packet type 0 (unicast to us), hardware type 1 (Ethernet), address length 6, the source address 44:15:24:20:a5:64 padded to 8 bytes, and protocol 0x0800; the LinuxSllLink struct on the right holds the same values and the 52 bytes after the header are the IPv4 packet.](images/datalink/sll_v1_struct.svg)

A 16-byte cooked header, in network byte order. The decoder keeps the packet type, the raw ARPHRD hardware type, the declared address length, the available source-address bytes and the protocol value. Packet types and hardware types outside the known constants are preserved as numbers, so a newer kernel does not turn packets into errors. An address longer than the 8-byte wire slot is reported as truncated (`address_is_truncated()`) rather than rejected. Use `LinkType::LINUX_SLL` (113): the value 25 shown by some Wireshark fields is an internal WTAP identifier.

## SLL v2

![The 20-byte SLL v2 pseudo-header of frame 1 of capture_sll2.pcap: protocol 0x86DD first, a zero reserved field, interface index 2, hardware type 1, packet type 4 (sent by us), address length 6 and the address e0:d5:5e:28:9b:d4 padded to 8 bytes; LinuxSll2Link keeps the interface index numeric, and the 72 bytes after the header are the IPv6 packet.](images/datalink/sll_v2_struct.svg)

A 20-byte header. The decoder additionally keeps the interface index, numeric because resolving its name belongs to the capture machine, and the reserved-MBZ field. A non-zero reserved value is preserved and reported by `reserved_is_zero()`, matching Tshark's tolerant dissection. Use `LinkType::LINUX_SLL2` (276); Wireshark's internal WTAP identifier for this format is 210.
