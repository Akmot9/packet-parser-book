# RAW IP

LINKTYPE RAW (101), IPV4 (228) and IPV6 (229): the bytes start directly at the IP header. An empty packet is `LinkLayerError::Truncated` (one byte required), a version nibble other than 4/6 is `LinkLayerError::InvalidIpVersion`. With `LinkType::IPV4`/`IPV6` the declared version is checked against the nibble, a mismatch being `InvalidIpVersion` too, and `link_type()` reports the LINKTYPE the capture declared instead of normalizing it to RAW. Once the version is known, an invalid IP header is an L3 corruption reported in `corrupted`, not a link error.

![Frame 1 of ndpi_pfcp.pcapng starts directly at the IPv4 header: the first byte 45 carries the version nibble 4 that selects the IPv4 decoder, then IHL 5, DSCP, total length 52, identification, flags, TTL 64, protocol 17 (UDP), checksum and the two loopback addresses; RawIpLink records ip_version 4 and hands the whole 52 bytes to the internet layer.](images/datalink/raw_ip_struct.svg)
