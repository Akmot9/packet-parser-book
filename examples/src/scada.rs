//! The SCADA chapters: DNP3 (IEEE 1815) and IEC 60870-5-104. Every frame
//! comes from the crate's corpus, `pcaps_exemple/protocols/dnp3/` (the Zeek
//! test corpus) and `pcaps_exemple/protocols/iec104/` (Wireshark wiki), see
//! their `SOURCE.md`. The bytes were taken with tshark, never by hand.

#[cfg(test)]
mod tests {
    use packet_parser::errors::application::dnp3::Dnp3ParseError;
    use packet_parser::errors::application::iec104::Iec104ParseError;
    use packet_parser::parse::application::protocols::dnp3::{
        ApplicationFunction, Dnp3Packet, LinkFunction, PrefixCode, RangeSpecifier,
    };
    use packet_parser::parse::application::protocols::iec104::{
        ApciFormat, AsduType, Iec104Packet, UnnumberedFunction,
    };
    use packet_parser::parse::transport::protocols::TransportProtocol;
    use packet_parser::{DecodeAsProtocol, LinkType, ParseConfig, parse, parse_with};

    /// Frame 4 of `dnp3/dnp3_read_p20001.pcap`: Ethernet / IPv4 / TCP
    /// 51006 -> 20001, a read of classes 1, 2, 3 and 0 by master 3, sent to
    /// outstation 2 on a port that no rule of the table knows.
    const DNP3_TCP_READ_REQUEST_HEX: &str = concat!(
        "001b210b1524b8ac6fab457a0800450000437e24400080065bb4827e8efa827e",
        "8ce5c73e4e21c194df2f5e0ef5d650184029e0e20000056414c4020003004503",
        "c7c8013c02063c03063c04063c010642ac"
    );

    /// Frame 5 of `dnp3/dnp3_udp_read.pcap`: a read of the same four classes,
    /// over UDP 1128 -> 20000, from master 100 to outstation 1.
    const DNP3_UDP_READ_REQUEST_HEX: &str = concat!(
        "0050c24f9464001676c7cedb080045000037cb93000080114d25c0a850a0c0a8",
        "500c04684e200023915f056414c40100640067d6c6c7013c02063c03063c0406",
        "3c010673c0"
    );

    /// Frame 6 of `dnp3/dnp3_read.pcap`: TCP 20000 -> 51006, the response of
    /// outstation 2 to the read: binary inputs, binary outputs, analog inputs.
    const DNP3_TCP_RESPONSE_HEX: &str = concat!(
        "b8ac6fab457a001b210b15240800450000af1ac940008006bea3827e8ce5827e",
        "8efa4e20c73e5e0ef5d6c194df4a501801005cce000005647444030002006854",
        "f4c88100000102000008810181010101d3740101010a02000006000000000000",
        "011e6ca40100000e01ef030000010300000001ed2178030000012bd1ffff01ed",
        "03000001e62e41c9000001170d0200000000000001b50c02c650000000000000",
        "018a0d020000000000000693000000000000000000000000000000ffff"
    );

    /// Frame 4 of `dnp3/dnp3_read.pcap`: the read request of
    /// `DNP3_TCP_READ_REQUEST_HEX`, on its original port, TCP 51006 -> 20000.
    const DNP3_TCP_READ_REQUEST_20000_HEX: &str = concat!(
        "001b210b1524b8ac6fab457a0800450000437e24400080065bb4827e8efa827e",
        "8ce5c73e4e20c194df2f5e0ef5d650184029e0e30000056414c4020003004503",
        "c7c8013c02063c03063c04063c010642ac"
    );

    /// Frame 1 of `dnp3/dnp3_link_only.pcap`: TCP 20000 -> 1128, a link
    /// status request from outstation 1 to master 100, without user data.
    const DNP3_REQUEST_LINK_STATUS_HEX: &str = concat!(
        "001676c7cedb0050c24f9464080045000032026a400040061606c0a8500cc0a8",
        "50f94e200468353ccb1923cecf7650184000193c000005640549640001007e5f"
    );

    /// Frame 6 of `dnp3/dnp3_udp_read.pcap`: UDP 20000 -> 1128, the first of
    /// the nine transport segments (frames 6 to 14) of the first fragment of
    /// a response; frames 15 to 21 carry its second and last fragment.
    const DNP3_UDP_FIRST_SEGMENT_HEX: &str = concat!(
        "001676c7cedb0050c24f94640800450001400cd9000040114ad7c0a8500cc0a8",
        "50a04e200468012c5b200564ff4464000100ff2f60878190000101010000ff03",
        "03000000800600000000000000000000000000000000ffff0000000000000000",
        "0000000000000000ffff00000000000000000000000000000000ffff00000000",
        "000000000000000000000000ffff00000000000000000000000000000000ffff",
        "00000000000000000000000000000000ffff0000000000000000000000000000",
        "0000ffff0000000000000000000000000a020100475a00ff0101010101010101",
        "010101010101a01401010101010101010101010101010101bbc3010101010101",
        "01010101010101010101bbc301010101010101010101010101010101bbc30101",
        "0101010101010101010101010101bbc301010101010101010101010101010101",
        "bbc3010101010101010101018d7b"
    );

    /// Frame 7 of `dnp3/dnp3_udp_read.pcap`: the second segment of the same
    /// response.
    const DNP3_UDP_NEXT_SEGMENT_HEX: &str = concat!(
        "001676c7cedb0050c24f94640800450001400cda000040114ad6c0a8500cc0a8",
        "50a04e200468012c37bb0564ff4464000100ff2f210101010101010101010101",
        "0101010178ce01010101010101010101010101010101bbc30101010101010101",
        "0101010101010101bbc301010101010101010101010101010101bbc301010101",
        "010101010101010101010101bbc301010101010101010101010101010101bbc3",
        "01010101010101010101010101010101bbc30101010101010101010101010101",
        "0101bbc301010101010101010101010101010101bbc301010101010101010101",
        "010101010101bbc301010101010101010101010101010101bbc3010101010101",
        "01010101010101010101bbc301010101010101010101010101010101bbc30101",
        "0101010101010101010101010101bbc301010101010101010101010101010101",
        "bbc3010101010101010101018d7b"
    );

    /// Frame 9 of `iec104/wireshark_iec104.pcap` (Wireshark wiki): TCP
    /// 46413 -> 2404, the general interrogation of station 10.
    const IEC104_INTERROGATION_HEX: &str = concat!(
        "0016d1000905002215560b540800450000385d2640008006bf040a1466010a14",
        "646cb54d0964cddab497009e59725018ff645a6a0000680e0000000064010600",
        "0a0000000014"
    );

    /// Frame 7 of the same capture: STARTDT act, a U-format APDU.
    const IEC104_STARTDT_ACT_HEX: &str = concat!(
        "0016d1000905002215560b5408004500002e5d2540008006bf0f0a1466010a14",
        "646cb54d0964cddab491009e596c5018ff6ac7990000680407000000"
    );

    /// Frame 15 of the same capture: an S-format APDU with N(R) 13.
    const IEC104_S_FORMAT_HEX: &str = concat!(
        "0016d1000905002215560b5408004500002e5d2940008006bf0b0a1466010a14",
        "646cb54d0964cddab4b7009e5b7e5018ff70b15b0000680401001a00"
    );

    /// Frame 12 of the same capture: TCP 2404 -> 46413, three I-format APDUs
    /// in one segment.
    const IEC104_THREE_APDUS_HEX: &str = concat!(
        "002215560b540016d10009050800450000703a550000ff06a29d0a14646c0a14",
        "66010964b54d009e5982cddab4b75018083419f60000680e0200020064010700",
        "0a0000000014681a04000200010414000a000100000002000000030000000400",
        "0000681a06000200030414000a0001000000020000000300000004000000"
    );

    /// Frame 1 of `iec104/wireshark_IEC104_SQ.pcapng` (Wireshark wiki): TCP
    /// 2404 -> 4446, four APDUs, each an ASDU M_SP_NA_1 in sequence (SQ = 1).
    const IEC104_SEQUENCE_HEX: &str = concat!(
        "00224d371ca2d072dca093b20800450000a4258e40007d0619220acc465a0a68",
        "63160964115e5fabf8c189078cc05018fd4c9c750000681d0200020001901400",
        "1e0400000000000000000000000000000000000101681d04000200019014001e",
        "0410000000010000000101000100000001010001681d06000200019014001e04",
        "20000000000001010001000000010100010000681d08000200019014001e0430",
        "000000000000000000000000000000000000"
    );

    // ANCHOR: dnp3_blind_probe
    #[test]
    fn dnp3_is_recognized_by_its_crcs_on_any_port_tcp_or_udp() {
        // Frame 4 of dnp3_read_p20001.pcap: TCP 51006 -> 20001. No rule of
        // the table knows that port: the label comes from the content.
        let raw = hex::decode(DNP3_TCP_READ_REQUEST_HEX).unwrap();
        let flow = parse(LinkType::ETHERNET, &raw).unwrap();
        let transport = flow.transport.as_ref().unwrap();
        assert_eq!(transport.destination_port, Some(20001));
        assert_eq!(flow.application.as_ref().unwrap().application_protocol, "DNP3");

        let packet = Dnp3Packet::try_from(transport.payload.unwrap()).unwrap();
        let [frame] = &packet.frames[..] else {
            panic!("expected one link frame");
        };

        // Link layer: LENGTH 20, control 0xC4, from master 3 to outstation 2.
        let link = frame.header;
        assert_eq!((link.length, link.control), (20, 0xc4));
        assert!(link.direction_from_master() && link.primary());
        assert_eq!(link.function(), Some(LinkFunction::UnconfirmedUserData));
        assert_eq!((link.destination, link.source), (2, 3));
        assert_eq!(link.crc, 0x0345);
        // 27 bytes on the wire, 15 of user data once the two CRCs are removed.
        assert_eq!((frame.raw.len(), frame.user_data.len()), (27, 15));

        // Transport: a single segment, first and last of its fragment.
        let segment = frame.transport.unwrap();
        assert!(segment.is_first() && segment.is_final());
        assert_eq!(segment.sequence(), 7);

        // Application: a Read of the four class objects, without range or data.
        let application = frame.application.as_ref().unwrap();
        assert_eq!(application.header.function(), Some(ApplicationFunction::Read));
        assert_eq!(application.header.sequence(), 8);
        assert_eq!(application.header.internal_indications, None);
        let objects: Vec<(u8, u8, u8)> = application
            .objects
            .iter()
            .map(|object| (object.group, object.variation, object.qualifier))
            .collect();
        assert_eq!(objects, [(60, 2, 0x06), (60, 3, 0x06), (60, 4, 0x06), (60, 1, 0x06)]);
        assert!(application.objects.iter().all(|object| object.range == RangeSpecifier::All));
        assert!(application.objects.iter().all(|object| object.data.is_empty()));
        assert!(application.undecoded.is_empty());

        // Frame 5 of dnp3_udp_read.pcap: a read of the same four classes, over
        // UDP 1128 -> 20000, labelled by the same rule.
        let raw = hex::decode(DNP3_UDP_READ_REQUEST_HEX).unwrap();
        let flow = parse(LinkType::ETHERNET, &raw).unwrap();
        let transport = flow.transport.as_ref().unwrap();
        assert_eq!(transport.protocol, TransportProtocol::Udp);
        assert_eq!(flow.application.as_ref().unwrap().application_protocol, "DNP3");
        let udp = Dnp3Packet::try_from(transport.payload.unwrap()).unwrap();
        let udp_read = udp.frames[0].application.as_ref().unwrap();
        assert_eq!(udp_read.header.function(), Some(ApplicationFunction::Read));
        assert_eq!(udp_read.objects, application.objects);
    }
    // ANCHOR_END: dnp3_blind_probe

    // ANCHOR: dnp3_response_objects
    #[test]
    fn dnp3_object_headers_locate_the_data_the_caller_reads() {
        // Frame 6 of dnp3_read.pcap: the outstation answers the read.
        let raw = hex::decode(DNP3_TCP_RESPONSE_HEX).unwrap();
        let flow = parse(LinkType::ETHERNET, &raw).unwrap();
        let payload = flow.transport.as_ref().unwrap().payload.unwrap();
        let packet = Dnp3Packet::try_from(payload).unwrap();
        let frame = &packet.frames[0];

        // 111 bytes of user data in seven blocks (6 x 16 + 15), each followed
        // by its CRC: 10 + 111 + 7 x 2 = 135 bytes on the wire.
        assert_eq!(frame.header.length, 116);
        assert_eq!((payload.len(), frame.user_data.len()), (135, 111));
        assert!(!frame.header.direction_from_master());

        let application = frame.application.as_ref().unwrap();
        assert_eq!(application.header.function(), Some(ApplicationFunction::Response));
        assert_eq!(application.header.internal_indications, Some([0x00, 0x00]));

        // Three headers, qualifier 0x00: no prefix, start and stop on one byte.
        let [inputs, outputs, analogs] = &application.objects[..] else {
            panic!("expected three object headers");
        };
        assert_eq!((inputs.group, inputs.variation), (1, 2)); // binary inputs with flags
        assert_eq!((outputs.group, outputs.variation), (10, 2)); // binary output status
        assert_eq!((analogs.group, analogs.variation), (30, 1)); // 32-bit analog inputs
        assert!(application.objects.iter().all(|object| object.prefix == PrefixCode::None));
        assert_eq!(
            analogs.range,
            RangeSpecifier::StartStop { start: 0, stop: 14, octets: 1 }
        );
        assert_eq!(analogs.range.object_count(), Some(15));

        // Where the objects are in `user_data`. Their size comes from the table
        // of annex A: one byte per point for the first two, five (a flag and
        // an i32) for the analogs, 15 x 5 = 75 bytes.
        assert_eq!(inputs.data, 10..19);
        assert_eq!(outputs.data, 24..31);
        assert_eq!(analogs.data, 36..111);
        assert!(application.undecoded.is_empty());

        // The crate locates the objects; reading the values is the caller's job.
        let points = frame.object_data(analogs);
        let point = |index: usize| {
            let bytes = &points[index * 5..index * 5 + 5];
            (bytes[0], i32::from_le_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]))
        };
        assert_eq!(point(0), (0x01, 1007)); // flag ONLINE, value 1007, as tshark shows
        assert_eq!(point(3), (0x01, -11989));
    }
    // ANCHOR_END: dnp3_response_objects

    // ANCHOR: dnp3_transport
    #[test]
    fn dnp3_link_only_frames_and_fragments_over_several_frames() {
        // Frame 1 of dnp3_link_only.pcap: a link function, LENGTH 5, no user
        // data, hence no transport header and no application.
        let raw = hex::decode(DNP3_REQUEST_LINK_STATUS_HEX).unwrap();
        let flow = parse(LinkType::ETHERNET, &raw).unwrap();
        let payload = flow.transport.as_ref().unwrap().payload.unwrap();
        let packet = Dnp3Packet::try_from(payload).unwrap();
        let status = &packet.frames[0];
        assert_eq!(status.header.function(), Some(LinkFunction::RequestLinkStatus));
        assert!(status.user_data.is_empty());
        assert!(status.transport.is_none() && status.application.is_none());

        // Frame 6 of dnp3_udp_read.pcap: a full link frame (LENGTH 255, 250
        // bytes of user data), first of the nine segments of the first
        // fragment of a response.
        let raw = hex::decode(DNP3_UDP_FIRST_SEGMENT_HEX).unwrap();
        let flow = parse(LinkType::ETHERNET, &raw).unwrap();
        let payload = flow.transport.as_ref().unwrap().payload.unwrap();
        let packet = Dnp3Packet::try_from(payload).unwrap();
        let first = &packet.frames[0];
        assert_eq!((payload.len(), first.user_data.len()), (292, 250));
        let segment = first.transport.unwrap();
        assert!(segment.is_first() && !segment.is_final());
        assert_eq!(segment.sequence(), 32);

        // FIR: the application fragment starts here, and its header is read.
        let application = first.application.as_ref().unwrap();
        assert_eq!(application.header.control, 0x87); // FIR, not FIN: fragment 1 of 2
        assert_eq!(application.header.function(), Some(ApplicationFunction::Response));
        assert_eq!(application.header.internal_indications, Some([0x90, 0x00]));
        // 1 024 packed binary inputs fit in 128 bytes; the next header is
        // read, but its 512 bytes of data go beyond the frame: the chain stops.
        let [inputs, outputs] = &application.objects[..] else {
            panic!("expected two object headers");
        };
        assert_eq!((inputs.group, inputs.variation, inputs.data.len()), (1, 1, 128));
        assert_eq!((outputs.group, outputs.variation), (10, 2));
        assert_eq!(outputs.range.object_count(), Some(512));
        assert!(outputs.data.is_empty());
        assert_eq!(application.undecoded, 147..250);

        // Frame 7, the next segment of the same fragment: not FIR, so link
        // and transport only. The stateless parser does not reassemble.
        let raw = hex::decode(DNP3_UDP_NEXT_SEGMENT_HEX).unwrap();
        let flow = parse(LinkType::ETHERNET, &raw).unwrap();
        let payload = flow.transport.as_ref().unwrap().payload.unwrap();
        let packet = Dnp3Packet::try_from(payload).unwrap();
        let next = &packet.frames[0];
        let segment = next.transport.unwrap();
        assert!(!segment.is_first() && !segment.is_final());
        assert_eq!(segment.sequence(), 33);
        assert!(next.application.is_none());
    }
    // ANCHOR_END: dnp3_transport

    // ANCHOR: dnp3_crc
    #[test]
    fn dnp3_one_altered_byte_breaks_a_crc_and_the_label() {
        // Frame 4 of dnp3_read.pcap, TCP 51006 -> 20000: the 27-byte DNP3
        // frame ends the Ethernet frame.
        let raw = hex::decode(DNP3_TCP_READ_REQUEST_20000_HEX).unwrap();
        let start = raw.len() - 27;
        assert_eq!(raw[start..start + 2], [0x05, 0x64]);

        // One bit of the destination address: the header CRC no longer matches.
        let mut header = raw.clone();
        header[start + 4] ^= 0x01;
        assert!(matches!(
            Dnp3Packet::try_from(&header[start..]),
            Err(Dnp3ParseError::HeaderCrcMismatch { actual: 0x0345, .. })
        ));

        // One bit of an object header, in the first block of user data.
        let mut block = raw.clone();
        block[start + 14] ^= 0x01;
        assert!(matches!(
            Dnp3Packet::try_from(&block[start..]),
            Err(Dnp3ParseError::BlockCrcMismatch { block: 0, actual: 0xac42, .. })
        ));

        // On port 20000 itself, neither altered frame is DNP3 any more.
        for altered in [&header, &block] {
            let flow = parse(LinkType::ETHERNET, altered).unwrap();
            assert_eq!(flow.application.as_ref().unwrap().application_protocol, "Unknown");
            assert!(flow.corrupted.is_none());
        }
    }
    // ANCHOR_END: dnp3_crc

    // ANCHOR: iec104_port_guard
    #[test]
    fn iec104_needs_port_2404_or_a_decode_as() {
        // Frame 9 of wireshark_iec104.pcap: TCP 46413 -> 2404.
        let raw = hex::decode(IEC104_INTERROGATION_HEX).unwrap();
        let flow = parse(LinkType::ETHERNET, &raw).unwrap();
        assert_eq!(flow.application.as_ref().unwrap().application_protocol, "IEC 104");

        let payload = flow.transport.as_ref().unwrap().payload.unwrap();
        let packet = Iec104Packet::try_from(payload).unwrap();
        let [apdu] = &packet.apdus[..] else {
            panic!("expected one APDU");
        };
        assert_eq!(apdu.length, 14);
        assert_eq!(
            apdu.format,
            ApciFormat::Information { send_sequence: 0, receive_sequence: 0 }
        );
        // A general interrogation (C_IC_NA_1), cause 6 (activation), station 10.
        let asdu = apdu.asdu.as_ref().unwrap();
        assert_eq!((asdu.type_id, asdu.kind), (100, Some(AsduType::CIcNa1)));
        assert_eq!((asdu.sequence, asdu.count), (false, 1));
        assert_eq!((asdu.cause, asdu.negative, asdu.test), (6, false, false));
        assert_eq!((asdu.originator, asdu.common_address), (0, 10));
        let [object] = &asdu.objects[..] else {
            panic!("expected one information object");
        };
        assert_eq!(object.address, 0);
        assert_eq!(object.element, [20]); // QOI 20: station interrogation
        assert!(asdu.undecoded.is_empty());

        // The same segment, destination port rewritten to 2405: the bytes of
        // the APDU have not changed, but no rule guards that port.
        let mut moved = raw.clone();
        moved[36..38].copy_from_slice(&2405u16.to_be_bytes());
        let flow = parse(LinkType::ETHERNET, &moved).unwrap();
        assert_eq!(flow.application.as_ref().unwrap().application_protocol, "Unknown");

        // Declared by the caller, the port is tried first, content included.
        let config = ParseConfig::new().decode_as(2405, DecodeAsProtocol::Iec104);
        let flow = parse_with(LinkType::ETHERNET, &moved, &config).unwrap();
        assert_eq!(flow.application.as_ref().unwrap().application_protocol, "IEC 104");
    }
    // ANCHOR_END: iec104_port_guard

    // ANCHOR: iec104_formats
    #[test]
    fn iec104_the_control_field_gives_the_format() {
        // Frame 7 of wireshark_iec104.pcap: U format, STARTDT act.
        let raw = hex::decode(IEC104_STARTDT_ACT_HEX).unwrap();
        let flow = parse(LinkType::ETHERNET, &raw).unwrap();
        let payload = flow.transport.as_ref().unwrap().payload.unwrap();
        let packet = Iec104Packet::try_from(payload).unwrap();
        let startdt = &packet.apdus[0];
        assert_eq!((startdt.length, startdt.control), (4, [0x07, 0x00, 0x00, 0x00]));
        assert_eq!(
            startdt.format,
            ApciFormat::Unnumbered(UnnumberedFunction::StartDtAct)
        );
        assert!(startdt.asdu.is_none());

        // Frame 15: S format, an acknowledgement with N(R) 13.
        let raw = hex::decode(IEC104_S_FORMAT_HEX).unwrap();
        let flow = parse(LinkType::ETHERNET, &raw).unwrap();
        let payload = flow.transport.as_ref().unwrap().payload.unwrap();
        let packet = Iec104Packet::try_from(payload).unwrap();
        assert_eq!(packet.apdus[0].format, ApciFormat::Supervisory { receive_sequence: 13 });
        assert!(packet.apdus[0].asdu.is_none());

        // Frame 12: three I-format APDUs in one 72-byte segment.
        let raw = hex::decode(IEC104_THREE_APDUS_HEX).unwrap();
        let flow = parse(LinkType::ETHERNET, &raw).unwrap();
        let payload = flow.transport.as_ref().unwrap().payload.unwrap();
        let packet = Iec104Packet::try_from(payload).unwrap();
        assert_eq!(packet.apdus.len(), 3);
        assert!(!packet.truncated);
        let numbers: Vec<(u16, u16)> = packet
            .apdus
            .iter()
            .map(|apdu| match apdu.format {
                ApciFormat::Information { send_sequence, receive_sequence } => {
                    (send_sequence, receive_sequence)
                }
                other => panic!("expected the I format, got {other:?}"),
            })
            .collect();
        assert_eq!(numbers, [(1, 1), (2, 1), (3, 1)]);

        let asdus: Vec<_> = packet.apdus.iter().map(|apdu| apdu.asdu.as_ref().unwrap()).collect();
        let kinds: Vec<_> = asdus.iter().map(|asdu| (asdu.kind, asdu.cause)).collect();
        assert_eq!(
            kinds,
            [
                (Some(AsduType::CIcNa1), 7),  // the interrogation is confirmed
                (Some(AsduType::MSpNa1), 20), // single points, interrogated
                (Some(AsduType::MDpNa1), 20), // double points, interrogated
            ]
        );
        // Not in sequence: every object carries its own address, then its
        // one-byte element (the quality descriptor and the value).
        let single = asdus[1];
        assert!(!single.sequence);
        let addresses: Vec<u32> = single.objects.iter().map(|object| object.address).collect();
        assert_eq!(addresses, [1, 2, 3, 4]);
        assert!(single.objects.iter().all(|object| object.element.len() == 1));
    }
    // ANCHOR_END: iec104_formats

    // ANCHOR: iec104_sequence
    #[test]
    fn iec104_an_asdu_in_sequence_carries_one_address() {
        // Frame 1 of wireshark_IEC104_SQ.pcapng: TCP 2404 -> 4446.
        let raw = hex::decode(IEC104_SEQUENCE_HEX).unwrap();
        let flow = parse(LinkType::ETHERNET, &raw).unwrap();
        assert_eq!(flow.application.as_ref().unwrap().application_protocol, "IEC 104");
        let payload = flow.transport.as_ref().unwrap().payload.unwrap();
        assert_eq!(payload.len(), 124);

        let packet = Iec104Packet::try_from(payload).unwrap();
        assert_eq!(packet.apdus.len(), 4);
        for (index, apdu) in packet.apdus.iter().enumerate() {
            // Control field, ASDU header, one address, sixteen elements.
            assert_eq!(apdu.length, 4 + 6 + 3 + 16);
            let asdu = apdu.asdu.as_ref().unwrap();
            assert_eq!(asdu.kind, Some(AsduType::MSpNa1));
            assert!(asdu.sequence);
            assert_eq!((asdu.count, asdu.cause, asdu.common_address), (16, 20, 1054));
            // Only the first address is on the wire; the others are counted.
            let first = 16 * index as u32;
            let addresses: Vec<u32> = asdu.objects.iter().map(|object| object.address).collect();
            assert_eq!(addresses, (first..first + 16).collect::<Vec<u32>>());
            assert!(asdu.undecoded.is_empty());
        }
    }
    // ANCHOR_END: iec104_sequence

    // ANCHOR: iec104_truncated
    #[test]
    fn iec104_an_apdu_cut_by_the_segment_is_decoded_as_far_as_it_goes() {
        // The payload of the same frame, cut where a TCP segment could end.
        let raw = hex::decode(IEC104_SEQUENCE_HEX).unwrap();
        let flow = parse(LinkType::ETHERNET, &raw).unwrap();
        let payload = flow.transport.as_ref().unwrap().payload.unwrap();

        // 51 bytes: the first APDU (31 bytes), then the APCI, the ASDU header,
        // the address and five of the sixteen elements of the second.
        let packet = Iec104Packet::try_from(&payload[..51]).unwrap();
        assert!(packet.truncated);
        let second = packet.apdus[1].asdu.as_ref().unwrap();
        assert_eq!((second.count, second.objects.len()), (16, 5));
        assert_eq!(second.objects[4].address, 20);

        // 40 bytes: the APCI of the second APDU is there, but only half of its
        // ASDU header. The APDU is kept, without an ASDU.
        let packet = Iec104Packet::try_from(&payload[..40]).unwrap();
        assert!(packet.truncated);
        assert!(matches!(
            packet.apdus[1].format,
            ApciFormat::Information { send_sequence: 2, .. }
        ));
        assert!(packet.apdus[1].asdu.is_none());

        // 35 bytes: not even the six bytes of APCI of the second APDU.
        assert_eq!(
            Iec104Packet::try_from(&payload[..35]),
            Err(Iec104ParseError::Truncated { expected: 6, actual: 4 })
        );

        // And what the next segment would start with, the rest of an APDU, is
        // not IEC 104: there is no resynchronization.
        assert!(matches!(
            Iec104Packet::try_from(&payload[51..]),
            Err(Iec104ParseError::InvalidStartByte(_))
        ));
    }
    // ANCHOR_END: iec104_truncated
}
