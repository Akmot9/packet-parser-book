//! The examples of the Valmet DNA chapter (`valmet_dna.md`), the process
//! network of Metso/Valmet distributed control systems (DCS). Each `#[test]`
//! is a chapter snippet, delimited by `ANCHOR` comments that mdBook includes
//! verbatim.
//!
//! Every frame comes from the crate's tracked corpus,
//! `pcaps_exemple/protocols/valmet_dna/valmet-dna-multicast-anon.pcap`, the
//! maintainer's capture, anonymized before it was committed (provenance in
//! the folder's `SOURCE.md`); the bytes were read from the capture file,
//! frame by frame, and match the fixtures of the crate's unit tests.

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use packet_parser::errors::application::valmet_dna::ValmetDnaParseError;
    use packet_parser::parse::application::protocols::valmet_dna::{
        DnaClock, MessageKind, TimeBeacon, ValmetDnaMessage, ValmetDnaPacket,
    };
    use packet_parser::{
        Application, DecodeAsProtocol, LinkType, PacketFlow, ParseConfig, parse, parse_with,
    };

    /// Frame 1 of `valmet_dna/valmet-dna-multicast-anon.pcap`: Ethernet /
    /// IPv4 / UDP 2517 -> 2517, 10.0.2.1 -> 239.0.171.1, the 126-byte status
    /// telegram of node 0x801D.
    const STATUS_TELEGRAM_HEX: &str = concat!(
        "01005e00ab0102000000000108004500009a08bf40001e11ad910a000201ef00",
        "ab0109d509d500862a4dab01801d00ff007c00000fff001003b00000048ace48",
        "18e03d0018803f000000000000000a0002010005000000000003010120200000",
        "000000001d00018a0052c59c00000001ef00ab01000000000000000000000000",
        "0000000000000000000000000000000000000000540f5bf15405970200000000",
        "0000000009d609d6",
    );

    /// Frame 9 of the same capture: UDP 2517 -> 2517 from 10.0.2.6, a tag
    /// message of node 0x8028 whose 43-byte tag has the class `di`.
    const TAG_MESSAGE_HEX: &str = concat!(
        "01005e00ab0102000000000608004500008fe49300001e1111c30a000206ef00",
        "ab0109d509d5007b8378ab01802800ff0071001e00d0000105060a3b00005103",
        "000000000000002b000000000000000081a47c18000300000000000000000000",
        "0000000200000000000005f4fcd80000002b3a653a64693a414b30353a6e7269",
        "7330353a6f696777786a3032363a6f69787767652832293a6177637273",
    );

    /// Frame 591 of the same capture: UDP 4516 -> 4517 from 10.0.2.9 to the
    /// same group, the 42-byte beacon, the only one of the capture.
    const BEACON_HEX: &str = concat!(
        "01005e00ab010200000000090800450000466b1500001e118b870a000209ef00",
        "ab0111a411a50032443100000000abcc0006238000003e0f252702d8ffe00000",
        "000000000000869509000003010120200a000209",
    );

    /// Ethernet and IPv4 without options: the UDP ports are bytes 34-37 of
    /// the frame, the datagram starts at byte 42.
    const DATAGRAM: usize = 42;

    fn label(flow: &PacketFlow<'_>) -> Option<&'static str> {
        flow.application.as_ref().map(|application| application.application_protocol)
    }

    // ANCHOR: valmet_status_telegram
    #[test]
    fn a_status_telegram_carries_its_node_a_clock_and_two_counters() {
        // Frame 1, UDP 2517 -> 2517: the pipeline gives the label, the
        // decoder reads the datagram, borrowed from the frame.
        let raw = hex::decode(STATUS_TELEGRAM_HEX).unwrap();
        let flow = parse(LinkType::ETHERNET, &raw).unwrap();
        assert_eq!(label(&flow), Some("Valmet DNA"));
        let internet = flow.internet.as_ref().unwrap();
        let payload = flow.transport.as_ref().unwrap().payload.unwrap();
        assert_eq!(payload.len(), 126);

        // The header: the magic AB 01 (checked, not kept), node 0x801D,
        // destination 0x00FF, a length of 124, the datagram minus two, and
        // the family 0x00000FFF.
        let packet = ValmetDnaPacket::try_from(payload).unwrap();
        assert_eq!((packet.source_node, packet.destination, packet.length), (0x801d, 0x00ff, 124));
        assert_eq!(packet.kind_code, 0x0000_0fff);
        assert_eq!(packet.kind, Some(MessageKind::Status));
        assert_eq!(packet.node_number(), 0x1d);
        assert_eq!(packet.body, &payload[12..]); // everything after the header, as is

        let ValmetDnaMessage::Status(status) = packet.message else {
            panic!("expected a status telegram, got {:?}", packet.message);
        };
        // What the golden test checks on the 319 telegrams of the capture:
        // the node address is the IP source, the group the IP destination,
        // the node number the low byte of the node identifier.
        assert_eq!(status.node_ip, Ipv4Addr::new(10, 0, 2, 1));
        assert_eq!(internet.source, Some(IpAddr::V4(status.node_ip)));
        assert_eq!(status.multicast_group, Ipv4Addr::new(239, 0, 171, 1));
        assert_eq!(internet.destination, Some(IpAddr::V4(status.multicast_group)));
        assert_eq!(status.node_number, 29);
        assert_eq!(status.node_number, packet.node_number());

        // Two 32-bit counters, 640 239 apart over one period of 640 ms:
        // microseconds. `previous_tick` is the `tick` of the node's previous
        // telegram, which the capture does not hold for frame 1.
        assert_eq!((status.tick, status.previous_tick), (0x540f_5bf1, 0x5405_9702));
        assert_eq!(status.tick.wrapping_sub(status.previous_tick), 640_239);

        // The clock, rewritten by the anonymization from the frame's rebased
        // timestamp: 2020-01-01 00:00:00.0000, weekday 3.
        let clock = status.clock.expect("a valid date");
        assert_eq!((clock.year, clock.month, clock.day, clock.weekday), (2020, 1, 1, 3));
        assert_eq!((clock.hour, clock.minute, clock.second, clock.fraction), (0, 0, 0, 0));
        assert_eq!(clock.microseconds_of_day(), 0);
    }
    // ANCHOR_END: valmet_status_telegram

    // ANCHOR: valmet_clock
    #[test]
    fn the_clock_is_ten_bcd_bytes_with_two_little_endian_words() {
        // The beacon of frame 591 carries the clock at offset 28 of its
        // datagram.
        let raw = hex::decode(BEACON_HEX).unwrap();
        let bytes = &raw[DATAGRAM + 28..DATAGRAM + 38];
        assert_eq!(bytes, [0x86, 0x95, 0x09, 0x00, 0x00, 0x03, 0x01, 0x01, 0x20, 0x20]);
        let clock = DnaClock::from_bytes(bytes).unwrap();
        // The fraction is a word, low byte first: 86 then 95 is 9586, in
        // units of 100 us. Then second, minute, hour, weekday, day and
        // month, one BCD byte each, and the year, low byte first.
        assert_eq!(clock.fraction, 9586);
        assert_eq!((clock.second, clock.minute, clock.hour), (9, 0, 0));
        assert_eq!((clock.weekday, clock.day, clock.month, clock.year), (3, 1, 1, 2020));
        assert_eq!(clock.microseconds_of_day(), 9_958_600);

        // Every clock of the capture has the year 20 20, which cannot show
        // the order of its two bytes. The vector of the crate's own unit
        // test does: 26 20 is 2026.
        let unit_test = [0x70, 0x08, 0x37, 0x52, 0x10, 0x02, 0x03, 0x11, 0x26, 0x20];
        let clock = DnaClock::from_bytes(&unit_test).unwrap();
        assert_eq!((clock.year, clock.month, clock.day, clock.weekday), (2026, 11, 3, 2));
        assert_eq!((clock.hour, clock.minute, clock.second, clock.fraction), (10, 52, 37, 870));

        // A nibble above 9, a field out of range or fewer than ten bytes is
        // not a clock.
        let mut not_bcd = unit_test;
        not_bcd[2] = 0x3a;
        assert_eq!(DnaClock::from_bytes(&not_bcd), None);
        assert_eq!(DnaClock::from_bytes(&[0; 10]), None); // day 0, month 0
        assert_eq!(DnaClock::from_bytes(&unit_test[..9]), None);

        // In a telegram, an invalid clock is `None`, not a refusal: frame 1
        // with ten zero bytes in place of its clock still decodes.
        let status = hex::decode(STATUS_TELEGRAM_HEX).unwrap();
        let mut unset = status[DATAGRAM..].to_vec();
        unset[42..52].fill(0);
        let packet = ValmetDnaPacket::try_from(unset.as_slice()).unwrap();
        let ValmetDnaMessage::Status(telegram) = packet.message else {
            panic!("expected a status telegram, got {:?}", packet.message);
        };
        assert_eq!(telegram.clock, None);
    }
    // ANCHOR_END: valmet_clock

    // ANCHOR: valmet_tag_message
    #[test]
    fn a_tag_message_borrows_its_tag_and_splits_the_readable_form() {
        // Frame 9: 115 bytes, the fixed 72-byte header and a 43-byte tag.
        let raw = hex::decode(TAG_MESSAGE_HEX).unwrap();
        let flow = parse(LinkType::ETHERNET, &raw).unwrap();
        assert_eq!(label(&flow), Some("Valmet DNA"));
        let payload = flow.transport.as_ref().unwrap().payload.unwrap();
        assert_eq!(payload.len(), 115);

        let packet = ValmetDnaPacket::try_from(payload).unwrap();
        assert_eq!((packet.source_node, packet.destination, packet.length), (0x8028, 0x00ff, 113));
        assert_eq!(packet.kind_code, 0x001e_00d0);
        assert_eq!(packet.kind, Some(MessageKind::Tag));
        let ValmetDnaMessage::Tag(tag) = packet.message else {
            panic!("expected a tag message, got {:?}", packet.message);
        };

        // The tag length is written twice, at offsets 28 and 70; the tag
        // starts at 72 and ends with the datagram. It is borrowed, not copied.
        assert_eq!(payload[28..30], [0x00, 0x2b]);
        assert_eq!(payload[70..72], [0x00, 0x2b]);
        assert_eq!(tag.tag_length, 43);
        assert!(std::ptr::eq(tag.tag, &payload[72..]));

        // The readable form `:e:<class>:<path>`. The anonymization kept the
        // marker, the class and the delimiters, and substituted the path
        // letter by letter and digit by digit.
        assert_eq!(tag.tag_text(), Some(":e:di:AK05:nris05:oigwxj026:oixwge(2):awcrs"));
        assert_eq!(tag.class(), Some("di"));
        assert_eq!(tag.path(), Some("AK05:nris05:oigwxj026:oixwge(2):awcrs"));
    }
    // ANCHOR_END: valmet_tag_message

    // ANCHOR: valmet_beacon
    #[test]
    fn the_beacon_of_udp_4516_is_not_an_ab01_message() {
        // Frame 591, UDP 4516 -> 4517: the port rule accepts the beacon.
        let raw = hex::decode(BEACON_HEX).unwrap();
        let flow = parse(LinkType::ETHERNET, &raw).unwrap();
        assert_eq!(label(&flow), Some("Valmet DNA"));
        let transport = flow.transport.as_ref().unwrap();
        assert_eq!((transport.source_port, transport.destination_port), (Some(4516), Some(4517)));
        let payload = transport.payload.unwrap();
        assert_eq!(payload.len(), 42);

        // It does not start with AB 01: it is not a message.
        assert_eq!(ValmetDnaPacket::try_from(payload), Err(ValmetDnaParseError::InvalidMagic(0)));

        // Four zero bytes and AB CC, then a code and a counter, kept as read:
        // a single beacon cannot say what they mean.
        assert_eq!(payload[..6], [0x00, 0x00, 0x00, 0x00, 0xab, 0xcc]);
        let beacon = TimeBeacon::try_from(payload).unwrap();
        assert_eq!((beacon.code, beacon.counter), (6, 0x2380_0000));
        // The node address is the IP source, as in a status telegram.
        assert_eq!(beacon.node_ip, Ipv4Addr::new(10, 0, 2, 9));
        assert_eq!(flow.internet.as_ref().unwrap().source, Some(IpAddr::V4(beacon.node_ip)));
        // The same clock, here 9.9586 s after the rebased start of the capture.
        let clock = beacon.clock.unwrap();
        assert_eq!((clock.second, clock.fraction), (9, 9586));
    }
    // ANCHOR_END: valmet_beacon

    // ANCHOR: valmet_detection
    #[test]
    fn three_ports_then_a_blind_probe_for_the_two_known_families() {
        let default = ParseConfig::new();
        let declared = ParseConfig::new().decode_as(40_001, DecodeAsProtocol::ValmetDna);
        let label_of = |frame: &[u8], config: &ParseConfig| {
            let flow = parse_with(LinkType::ETHERNET, frame, config).unwrap();
            flow.application.as_ref().map(|application| application.application_protocol)
        };
        let off_port = |frame: &[u8]| {
            let mut moved = frame.to_vec();
            moved[34..38].copy_from_slice(&[0x9c, 0x40, 0x9c, 0x41]); // 40000 -> 40001
            moved
        };
        let status = hex::decode(STATUS_TELEGRAM_HEX).unwrap();
        let tag = hex::decode(TAG_MESSAGE_HEX).unwrap();
        let beacon = hex::decode(BEACON_HEX).unwrap();

        // Frames 1 and 9 moved to UDP 40000 -> 40001: the magic, the length
        // and the exact size of a known family are enough.
        assert_eq!(label_of(&off_port(&status), &default), Some("Valmet DNA"));
        assert_eq!(label_of(&off_port(&tag), &default), Some("Valmet DNA"));
        // The public cascade of `Application::try_from`, which has no ports,
        // agrees.
        let blind = Application::try_from(&status[DATAGRAM..]).unwrap();
        assert_eq!(blind.application_protocol, "Valmet DNA");

        // The beacon is recognized on its ports, or on a declared port.
        assert_eq!(label_of(&beacon, &default), Some("Valmet DNA"));
        assert_eq!(label_of(&off_port(&beacon), &default), Some("Unknown"));
        assert_eq!(label_of(&off_port(&beacon), &declared), Some("Valmet DNA"));
    }
    // ANCHOR_END: valmet_detection

    // ANCHOR: valmet_unknown_family
    #[test]
    fn an_unknown_family_is_kept_as_bytes_on_the_ports_only() {
        let label_of = |frame: &[u8], config: &ParseConfig| {
            let flow = parse_with(LinkType::ETHERNET, frame, config).unwrap();
            flow.application.as_ref().map(|application| application.application_protocol)
        };
        // Frame 1 with the family 0x00000FFE, which the capture does not show.
        let mut unknown = hex::decode(STATUS_TELEGRAM_HEX).unwrap();
        unknown[DATAGRAM + 11] = 0xfe;

        let packet = ValmetDnaPacket::try_from(&unknown[DATAGRAM..]).unwrap();
        assert_eq!((packet.kind_code, packet.kind), (0x0000_0ffe, None));
        assert_eq!(packet.message, ValmetDnaMessage::Unknown);
        assert_eq!(packet.body, &unknown[DATAGRAM + 12..]); // the body, as is

        // On UDP 2517 the header is enough; off the ports, the blind probe
        // refuses a family it does not know, and Decode As accepts it again.
        let default = ParseConfig::new();
        let declared = ParseConfig::new().decode_as(40_001, DecodeAsProtocol::ValmetDna);
        let mut moved = unknown.clone();
        moved[34..38].copy_from_slice(&[0x9c, 0x40, 0x9c, 0x41]); // 40000 -> 40001
        assert_eq!(label_of(&unknown, &default), Some("Valmet DNA"));
        assert_eq!(label_of(&moved, &default), Some("Unknown"));
        assert_eq!(label_of(&moved, &declared), Some("Valmet DNA"));
    }
    // ANCHOR_END: valmet_unknown_family

    // ANCHOR: valmet_refused
    #[test]
    fn a_header_or_a_size_out_of_line_is_refused_and_not_a_corruption() {
        let raw = hex::decode(STATUS_TELEGRAM_HEX).unwrap();
        let telegram = &raw[DATAGRAM..];

        // One byte less: the declared length, 124, is no longer the
        // datagram minus two.
        assert_eq!(
            ValmetDnaPacket::try_from(&telegram[..125]),
            Err(ValmetDnaParseError::LengthMismatch { declared: 124, actual: 125 })
        );
        // The same 125 bytes with a coherent length: the header passes, but
        // a status telegram is 126 bytes.
        let mut short = telegram[..125].to_vec();
        short[7] = 123;
        assert_eq!(
            ValmetDnaPacket::try_from(short.as_slice()),
            Err(ValmetDnaParseError::InvalidMessageLength {
                kind: 0x0000_0fff,
                expected: 126,
                actual: 125
            })
        );

        // Frame 9 with its two tag lengths at odds, 43 then 42.
        let tag = hex::decode(TAG_MESSAGE_HEX).unwrap();
        let mut echo = tag[DATAGRAM..].to_vec();
        echo[71] = 42;
        assert_eq!(
            ValmetDnaPacket::try_from(echo.as_slice()),
            Err(ValmetDnaParseError::TagLengthMismatch { declared: 43, echo: 42 })
        );

        // Frame 591 cut by one byte: a beacon is 42 bytes.
        let beacon = hex::decode(BEACON_HEX).unwrap();
        assert_eq!(
            TimeBeacon::try_from(&beacon[DATAGRAM..DATAGRAM + 41]),
            Err(ValmetDnaParseError::InvalidBeaconLength { actual: 41 })
        );

        // A refusal is not a corruption. Frame 1 declaring 125 bytes stays on
        // UDP 2517, goes on to the next rules of the table, and ends "Unknown".
        let mut altered = raw.clone();
        altered[DATAGRAM + 7] = 0x7d;
        let flow = parse(LinkType::ETHERNET, &altered).unwrap();
        assert_eq!(label(&flow), Some("Unknown"));
        assert!(flow.corrupted.is_none());
        let error = ValmetDnaPacket::try_from(&altered[DATAGRAM..]).unwrap_err();
        assert_eq!(
            error.to_string(),
            "Valmet DNA length 125 does not match the 126 bytes of the datagram"
        );
    }
    // ANCHOR_END: valmet_refused
}
