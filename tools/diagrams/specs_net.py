"""Feature #39: internet (GOOSE, LLDP) and transport (ESP, ICMPv4, ICMPv6)
diagrams. Real frames: iti_GOOSE.pcap 1, cisagov_profinet_io_cm_mixed_1.pcap
29, ikev2_s2s_ipsec_vpn_aes_gcm.pcapng 5, icmp_echo.pcapng 1,
icmpv6_neighbor_solicitation.pcapng 1."""

GOOSE = {
    "out": "images/network/goose_struct.svg",
    "title": "GOOSE: 8 header bytes, then the goosePdu",
    "subtitle": "frame 1 of iti_GOOSE.pcap, EtherType 0x88B8 · 145 bytes after the EtherType",
    "desc": "The GOOSE frame of a GE F650 relay, frame 1 of iti_GOOSE.pcap, after the EtherType 0x88B8: APPID 1, length 145, two zero reserved fields, then the BER-encoded goosePdu (tag 61, length 134) whose fields are shown with their tag and length bytes: gocbRef, timeAllowedtoLive 40000, datSet, goID, the timestamp, stNum 1, sqNum 10, simulation false, confRev 1, ndsCom false, numDatSetEntries 8 and the 32-byte allData; GoosePacket and GoosePdu on the right carry the decoded values.",
    "palette": "transport",
    "fields": [
        {"label": "APPID", "hex": "0001", "color": "orange", "emph": True},
        {"label": "Length", "hex": "0091", "color": "orange"},
        {"label": "Reserved 1", "hex": "0000"},
        {"label": "Reserved 2", "hex": "0000"},
        {"label": "goosePdu tag · length 134", "hex": "618186", "color": "yellow", "emph": True},
        {"label": "[0]", "hex": "80", "color": "yellow"},
        {"label": "len 26", "hex": "1a", "color": "yellow"},
        {"label": "gocbRef · GED…", "hex": "474544"},
        {"skip": "… 23 more bytes: GEDeviceF650/LLN0$GO$gcb01"},
        {"skip": "[1] 81 03 00 9c 40 · timeAllowedtoLive 40000"},
        {"skip": "[2] 82 18 … · datSet GEDeviceF650/LLN0$GOOSE1 (24 bytes)"},
        {"skip": "[3] 83 0b … · goID F650_GOOSE1 (11 bytes)"},
        {"skip": "[4] 84 08 38 6e bb f3 42 17 28 0a · t, a UtcTime"},
        {"skip": "[5] stNum 1 · [6] sqNum 10 · [7] simulation false (9 bytes)"},
        {"skip": "[8] confRev 1 · [9] ndsCom false · [10] numDatSetEntries 8 (9 bytes)"},
        {"skip": "[11] ab 20 … · allData: 8 values, boolean and bit-string (34 bytes)"},
    ],
    "card": {"title": "GoosePacket", "width": 250, "fields": [
        {"name": "app_id", "value": "1", "color": "orange", "arrow": 0},
        {"name": "length", "value": "145 · header included", "color": "orange", "arrow": 1},
        {"name": "pdu: GoosePdu", "value": "the goosePdu, decoded", "color": "yellow", "arrow": 4, "arrow_color": "dark"},
        {"name": "pdu.gocb_ref", "value": "GEDeviceF650/LLN0$GO$gcb01", "arrow": 7, "arrow_color": "gray"},
        {"name": "pdu.time_allowed_to_live", "value": "40000 ms", "arrow": 9, "arrow_color": "gray"},
        {"name": "pdu.st_num · sq_num", "value": "1 · 10", "arrow": 13, "arrow_color": "gray"},
        {"name": "pdu.num_dat_set_entries", "value": "8", "arrow": 14, "arrow_color": "gray"},
        {"name": "pdu.all_data", "value": "Vec<GooseData>, 8 items", "arrow": 15, "arrow_color": "dark"},
    ]},
}

LLDP = {
    "out": "images/network/lldp_struct.svg",
    "title": "LLDP: TLVs, 7 bits of type, 9 of length",
    "subtitle": "frame 29 of cisagov_profinet_io_cm_mixed_1.pcap, EtherType 0x88CC · 152 bytes, a SCALANCE X208",
    "desc": "The LLDPDU of frame 29 of cisagov_profinet_io_cm_mixed_1.pcap, after the EtherType 0x88CC: each TLV starts with two bytes, 7 bits of type and 9 of length; Chassis ID (type 1, subtype 7, siemens-x208-switch), Port ID (type 2, subtype 7, port-004), Time To Live 20 seconds, System Description, System Capabilities 0x0080, Management Address 0.0.0.0, three organization-specific TLVs and the End of LLDPDU; LldpPacket exposes the two identifiers and the TTL as typed fields and the rest as a list of TLVs.",
    "palette": "transport",
    "fields": [
        {"label": "Chassis ID · type 1, len 20", "hex": "0214", "color": "orange", "emph": True},
        {"label": "subtype 7", "hex": "07", "color": "orange"},
        {"label": "id · s…", "hex": "73", "color": "orange"},
        {"skip": "… 18 more bytes: siemens-x208-switch"},
        {"label": "Port ID · type 2, len 9", "hex": "0409", "color": "orange", "emph": True},
        {"label": "subtype 7", "hex": "07", "color": "orange"},
        {"label": "id · p…", "hex": "70", "color": "orange"},
        {"skip": "… 7 more bytes: port-004"},
        {"label": "TTL · type 3, len 2", "hex": "0602", "color": "yellow", "emph": True},
        {"label": "seconds", "hex": "0014", "color": "yellow"},
        {"label": "System Description · type 6, len 50", "hex": "0c32"},
        {"label": "text · Si…", "hex": "5369"},
        {"skip": "… 48 more bytes: Siemens AG SIMATIC S7 MULTIPORT SCALANCE X 200 FAM"},
        {"label": "Capabilities · type 7, len 4", "hex": "0e04"},
        {"label": "system 0x0080", "hex": "0080"},
        {"label": "enabled 0x0080", "hex": "0080"},
        {"label": "Mgmt Address · type 8, len 20", "hex": "1014"},
        {"skip": "… 20 bytes: length 5, IPv4 0.0.0.0, ifIndex 4, OID 1.3.6.1.4.1.24686"},
        {"skip": "fe 08 00 0e cf 02 … · type 127, OUI 00:0e:cf (PROFIBUS), port status (10 bytes)"},
        {"skip": "fe 0a 00 0e cf 05 … chassis MAC (12 bytes) · fe 09 00 12 0f 01 … IEEE 802.3 (11 bytes)"},
        {"label": "End of LLDPDU · type 0, len 0", "hex": "0000", "color": "yellow"},
    ],
    "card": {"title": "LldpPacket", "width": 250, "fields": [
        {"name": "chassis_id", "value": "LldpId { 7, siemens-x208-switch }", "color": "orange", "arrow": 0},
        {"name": "port_id", "value": "LldpId { 7, port-004 }", "color": "orange", "arrow": 4},
        {"name": "time_to_live", "value": "20 s", "color": "yellow", "arrow": 9, "arrow_color": "dark"},
        {"name": "tlvs", "value": "Vec<LldpTlv>, 6 more", "arrow": 10, "arrow_color": "gray"},
        {"name": "padding", "value": "&[] · nothing after the End", "arrow": 20, "arrow_color": "gray"},
    ]},
}

ESP = {
    "out": "images/transport/esp_struct.svg",
    "title": "ESP: two clear words, then the ciphertext",
    "subtitle": "frame 5 of ikev2_s2s_ipsec_vpn_aes_gcm.pcapng, IP protocol 50 · 120 bytes, AES-GCM",
    "desc": "The native ESP packet of frame 5 of ikev2_s2s_ipsec_vpn_aes_gcm.pcapng, IP protocol 50: the SPI 0x5fbd60dc and the sequence number 1 are the only fields the crate can read; the 8-byte AES-GCM IV that follows is in clear too, then 88 bytes of ciphertext (the inner packet, its padding and the next-header byte) and the 16-byte ICV; EspPacket keeps the SPI, the sequence and the 112 bytes after them as payload, and nothing is probed above it.",
    "palette": "transport",
    "fields": [
        {"label": "Security Parameters Index", "hex": "5fbd60dc", "color": "orange", "emph": True},
        {"label": "Sequence number", "hex": "00000001", "color": "orange"},
        {"label": "IV · in clear, not encrypted", "hex": "0000000000000001", "color": "yellow", "cont": "IV, continued"},
        {"label": "ciphertext", "hex": "fe32d6d0"},
        {"skip": "… 84 more bytes: the inner packet, padding, next header"},
        {"skip": "… then the 16-byte ICV, in clear as well"},
    ],
    "payload": "payload: 112 bytes · IV, ciphertext, ICV",
    "card": {"title": "EspPacket", "width": 250, "fields": [
        {"name": "Transport.protocol", "value": "Esp (50), from the IP header"},
        {"name": "spi", "value": "0x5fbd60dc", "color": "orange", "arrow": 0},
        {"name": "sequence", "value": "1", "color": "orange", "arrow": 1},
        {"name": "payload", "value": "&[u8] · 112 bytes, opaque", "color": "green", "arrow": "payload", "arrow_color": "dark"},
        {"name": "application", "value": "\"ESP\" · nothing probed"},
    ]},
}

ICMP_ECHO = {
    "out": "images/transport/icmp_echo_struct.svg",
    "title": "ICMPv4 Echo request: header, then body",
    "subtitle": "frame 1 of icmp_echo.pcapng, IP protocol 1 · 40 bytes",
    "desc": "The ICMPv4 Echo request of frame 1 of icmp_echo.pcapng, 32 bits per row: type 8, code 0, checksum 0x145c, then the Echo body with identifier 0x0500, sequence 0x3400 and 32 bytes of pattern data; IcmpPacket keeps the common header as fields and the body as IcmpBody::Echo, and the transport payload stays None so nothing is probed above it.",
    "palette": "transport",
    "fields": [
        {"label": "Type", "hex": "08", "color": "orange", "emph": True},
        {"label": "Code", "hex": "00", "color": "orange"},
        {"label": "Checksum", "hex": "145c"},
        {"label": "Identifier", "hex": "0500", "color": "yellow"},
        {"label": "Sequence number", "hex": "3400", "color": "yellow"},
        {"label": "Data · abcdefgh", "hex": "6162636465666768"},
        {"skip": "… 24 more bytes: ijklmnopqrstuvwabcdefghi"},
    ],
    "card": {"title": "IcmpPacket", "width": 250, "fields": [
        {"name": "message_type", "value": "8 → Echo request", "color": "orange", "arrow": 0},
        {"name": "code", "value": "0 · the only one for type 8", "color": "orange", "arrow": 1},
        {"name": "checksum", "value": "0x145c", "arrow": 2, "arrow_color": "gray"},
        {"name": "body", "value": "Echo { 1280, 13312, 32 bytes }", "color": "yellow", "arrow": 3, "arrow_color": "dark"},
        {"name": "Transport.payload", "value": "None · nothing stacks above"},
    ]},
}

ICMPV6_NS = {
    "out": "images/transport/icmpv6_ns_struct.svg",
    "title": "ICMPv6 Neighbor Solicitation",
    "subtitle": "frame 1 of icmpv6_neighbor_solicitation.pcapng, IPv6 next header 58 · 32 bytes",
    "desc": "The ICMPv6 Neighbor Solicitation of frame 1 of icmpv6_neighbor_solicitation.pcapng, 32 bits per row: type 135, code 0, checksum 0x44b7, a reserved word, the target address 2001:db8:1:2::1000 and one option, Source Link-Layer Address (type 1, length 1) carrying 00:0c:29:2f:80:31; Icmpv6Packet keeps the common header as fields and the body as Icmpv6Body::NeighborSolicitation.",
    "palette": "transport",
    "fields": [
        {"label": "Type", "hex": "87", "color": "orange", "emph": True},
        {"label": "Code", "hex": "00", "color": "orange"},
        {"label": "Checksum", "hex": "44b7"},
        {"label": "Reserved", "hex": "00000000"},
        {"label": "Target address · 2001:db8:1:2::1000", "hex": "20010db8000100020000000000001000", "color": "yellow", "cont": "Target address, continued"},
        {"label": "Option type 1 · length 1 (8 bytes)", "hex": "0101", "color": "cream"},
        {"label": "Source link-layer address", "hex": "000c292f8031", "color": "cream"},
    ],
    "card": {"title": "Icmpv6Packet", "width": 250, "fields": [
        {"name": "message_type", "value": "135 → Neighbor Solicitation", "color": "orange", "arrow": 0},
        {"name": "code", "value": "0", "color": "orange", "arrow": 1},
        {"name": "checksum", "value": "0x44b7", "arrow": 2, "arrow_color": "gray"},
        {"name": "body", "value": "NeighborSolicitation { target, options }", "color": "yellow", "arrow": 4, "arrow_color": "dark"},
        {"name": "body.options", "value": "&[u8] · 8 bytes, one SLLA option", "color": "cream", "arrow": 5, "arrow_color": "gray"},
    ]},
}

ALL = [GOOSE, LLDP, ESP, ICMP_ECHO, ICMPV6_NS]
