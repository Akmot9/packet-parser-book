//! Examples of the RTPS and ASTERIX chapters (defense lot, packet_parser
//! 11.6.0; the DDS layer of RTPS, 13.0.0). Every frame comes from the
//! crate's tracked corpus, `pcaps_exemple/protocols/`, byte for byte: the
//! comment above each constant names the capture and the frame number. Where
//! a test alters a frame, its comments say how.

#[cfg(test)]
mod tests {
    use packet_parser::errors::application::asterix::AsterixError;
    use packet_parser::errors::application::rtps::RtpsParseError;
    use packet_parser::parse::application::protocols::asterix::uap::{
        self, ItemFormat, UapSelector,
    };
    use packet_parser::parse::application::protocols::asterix::{
        AsterixPacket, cat001, cat002, cat008, cat023, cat034, cat048, cat062, cat063, cat065,
        cat247,
    };
    use packet_parser::parse::application::protocols::rtps::dds::{
        RtpsBuiltinTopic, RtpsEncapsulation, RtpsLocatorRole, RtpsReliabilityKind,
    };
    use packet_parser::parse::application::protocols::rtps::{
        RtpsChecksum, RtpsPacket, RtpsSubmessage, SubmessageDetails, SubmessageKind,
    };
    use packet_parser::{LinkType, parse};
    use std::net::Ipv4Addr;

    // rtps/talker-listener-rtps.pcapng frame 9 (LINKTYPE_NULL, 164 bytes):
    // Cyclone DDS (ROS 2 talker/listener), 10.0.0.46:54020 -> 10.0.0.46:58584.
    const CYCLONE_FRAME_9_HEX: &str = concat!(
        "02000000450000a0ff010000401100000a00002e0a00002ed304e4d8008c14f9",
        "525450530201011054a61001319843eca3669a350e010c005ab810011636c7d5",
        "1895c54e09010800b7eee960f395406e1505300000001000000200c7000200c2",
        "00000000010000000001000054a61001319843eca3669a350000000101000000",
        "0000000007011c00000200c7000200c200000000010000000000000001000000",
        "02000000"
    );

    // rtps/wireshark_6449_opendds_messenger.pcap frame 1 (Ethernet, 118 bytes):
    // OpenDDS Messenger, 10.201.200.162:58018 -> 239.255.0.1:7401.
    const OPENDDS_FRAME_1_HEX: &str = concat!(
        "01005e7f000100215a68c54908004500006859fe000001119c1b0ac9c8a2efff",
        "0001e2a21ce90054c3d152545053020101030103000000000000000000010901",
        "0800ed58934e4ed4d2d4150b0000000010000000000000000102ffffffff0000",
        "00007100040000000000010000000001000063000000"
    );

    // rtps/rtps.pcap frame 1 (Ethernet, 58 bytes, nDPI test corpus): RTI
    // Connext, 127.0.0.1:28108 -> 127.0.0.1:7410.
    const RTI_PING_FRAME_1_HEX: &str = concat!(
        "00000000000000000000000008004500002c0000400040113cbf7f0000017f00",
        "00016dcc1cf20018fe2b52545053020101014e44445350494e47"
    );

    // rtps/talker-listener-rtps.pcapng frame 3 (LINKTYPE_NULL, 316 bytes):
    // the SPDP announcement of the participant of frame 9,
    // 10.0.0.46:54020 -> 239.255.0.1:7400.
    const CYCLONE_FRAME_3_HEX: &str = concat!(
        "02000000450001386cdc0000201132ab0a00002eefff0001d3041ce80124fb63",
        "525450530201011054a61001319843eca3669a3509010800b7eee9609fcc3f6e",
        "1505f8000000100000000000000100c20000000001000000000300002c001000",
        "0a000000656e636c6176653d2f3b000015000400020100001600040001100000",
        "020008000a000000000000005000100054a61001319843eca3669a35000001c1",
        "580004003f0c00000f00040000000000310018000100000091ef000000000000",
        "00000000000000000a00002e320018000100000091ef00000000000000000000",
        "000000000a00002e07804400000000002c000000000000000000000000000000",
        "2c0000004a6f686e732d4d6163426f6f6b2d50726f2e6c6f63616c2f302e382e",
        "302f44617277696e2f44617277696e00198004000000100001000000"
    );

    // rtps/talker-listener-rtps.pcapng frame 57 (LINKTYPE_NULL, 236 bytes):
    // SEDP, the same participant announces its writer of rt/chatter,
    // 10.0.0.46:54020 -> 10.0.0.46:58584.
    const CYCLONE_FRAME_57_HEX: &str = concat!(
        "02000000450000e858410000401100000a00002e0a00002ed304e4d800d41541",
        "525450530201011054a61001319843eca3669a3509010800b7eee9606b0e1084",
        "1505a8000000100000000000000003c2000000000a0000000003000005001000",
        "0b00000072742f636861747465720000070024001d0000007374645f6d736773",
        "3a3a6d73673a3a6464735f3a3a537472696e675f000000001a000c0002000000",
        "ffffff7fffffffff400008000000000007000000150004000201000016000400",
        "011000005a00100054a61001319843eca3669a35000015030c80040001000000",
        "038004000000000001000000"
    );

    // rtps/talker-listener-rtps.pcapng frame 70 (LINKTYPE_NULL, 144 bytes):
    // the first sample of that writer, 10.0.0.46:54020 -> 10.0.0.46:58584.
    const CYCLONE_FRAME_70_HEX: &str = concat!(
        "020000004500008c07470000401100000a00002e0a00002ed304e4d8007814e5",
        "525450530201011054a61001319843eca3669a3509010800b8eee960c505a085",
        "15052c000000100000000000000015030000000001000000000100000f000000",
        "48656c6c6f20576f726c643a2031000007011c00000000000000150300000000",
        "01000000000000000100000002000000"
    );

    // rtps/rtps.pcap frame 29 (Ethernet, 130 bytes, nDPI test corpus): RTI
    // Connext, a participant that leaves, 127.0.0.1:28108 -> 127.0.0.1:7410.
    const RTI_FRAME_29_HEX: &str = concat!(
        "0000000000000000000000000800450000740000400040113c777f0000017f00",
        "00016dcc1cf20060fe735254505302010101c0a87a0100003a4c000000010901",
        "0800790d4a5931b4c8ae150334000000100000000000000100c2000000000200",
        "000070001000c0a87a0100003a4c00000001000001c171000400000000030100",
        "0100"
    );

    // asterix/cat_034_048.pcap frame 3 (Ethernet, 108 bytes, CroatiaControlLtd
    // sample): 10.17.58.184:21154 -> 232.2.1.13:22113.
    const CAT_034_048_FRAME_3_HEX: &str = concat!(
        "01005e02010dbc1665fe5fc208004500005e000040003d110fb70a113ab8e802",
        "010d52a25661004a869d300037ffff02190d356deea0c2d35b9004c305a0e056",
        "0bb84baacd50867951882001c65632b0a800004001e24bf6c304081ebb734020",
        "f522000bf0190d02356dfa60"
    );

    // asterix/wireshark_8579_radardata.pcap frame 772 (Ethernet, 96 bytes):
    // UDP 2604 -> 224.1.1.1:20101.
    const RADARDATA_FRAME_772_HEX: &str = concat!(
        "01005e010101001ebe7961f4080045000052000040000511de70ac120a16e001",
        "01010a2c4e85003e1d81010014fb802daa301ca0aa1000c40578dc3e80000200",
        "14d9802daa0159ddc104a703041d08130c2301000ee22daa518000800000ddc1"
    );

    // asterix/wireshark_8579_radardata.pcap frame 30453 (Ethernet, 60 bytes):
    // UDP 2606 -> 224.1.1.1:20101.
    const RADARDATA_FRAME_30453_HEX: &str = concat!(
        "01005e010101001ebe7961f4080045000028000040000511de9aac120a16e001",
        "01010a2e4e850014acb902000cd43208015a15f60b02000000000000"
    );

    // asterix/cat_062_065.pcap frame 1 (Ethernet, 215 bytes, CroatiaControlLtd
    // sample): UDP 56798 -> 227.0.6.1:10001.
    const CAT_062_065_FRAME_1_HEX: &str = concat!(
        "01005e000601442b036474dd080045c800c900004000011175330a131015e300",
        "0601ddde271100b5cd0c3e00a1bfdffd021964015981b3007518fc002caed9ff",
        "196bf086600393ff43000002bdc1204ca7a84994b1df40e020f6126919030108",
        "70170d0d00900d0d061816cd06180000dc190c93ba88e8061802bda0bfdffd02",
        "1964015981b30075cee5003726bd08813bf18a9ffcbdfff10009087dc1204cac",
        "7f2534f2c30de020f61aaf11030108702010104090101005f01a7505f00000dc",
        "190cb98e5eb505f0087da041000cf8196402015981b301"
    );

    // asterix/wireshark_9953_cat021023.pcap frame 1 (Ethernet, 60 bytes):
    // UDP 47878 -> 239.1.20.1:56610.
    const CAT021023_FRAME_1_HEX: &str = concat!(
        "01005e011401902b34545d4808004500002d000040000111ea5c0a608201ef01",
        "1401bb06dd220019e760170011f780930d02125d18e4020104ff0800"
    );

    // asterix/wireshark_9953_cat021023.pcap frame 428 (Ethernet, 60 bytes):
    // the same stream.
    const CAT021023_FRAME_428_HEX: &str = concat!(
        "01005e011401902b34545d4808004500002d000040000111ea5c0a608201ef01",
        "1401bb06dd220019f07af70011f0930d015d1d280215001a17011400"
    );

    // asterix/wireshark_8579_radardata.pcap frame 1105 (Ethernet, 60 bytes):
    // UDP 32850 -> 224.3.2.1:30202.
    const RADARDATA_FRAME_1105_HEX: &str = concat!(
        "01005e030201001f295bb80f08004500002b0000400001117cd4ac126ed7e003",
        "0201805275fa00179e463f000ffc93640259de69221a3e004b000000"
    );

    // asterix/wireshark_9239_cat008only-2.pcap frame 1 (Ethernet, 60 bytes):
    // UDP 58674 -> 239.1.20.1:56520.
    const CAT008ONLY_2_FRAME_1_HEX: &str = concat!(
        "01005e011401902b34545d48080045000027000040000111ea620a608201ef01",
        "1401e532dcc80013101608000bc1409319fe30000000000000000000"
    );

    // ANCHOR: rtps_random_port
    #[test]
    fn rtps_is_recognized_by_its_magic_on_any_udp_port() {
        // Frame 9 of talker-listener-rtps.pcapng: Cyclone DDS on the macOS
        // loopback (LINKTYPE_NULL), between two random unicast ports.
        let raw = hex::decode(CYCLONE_FRAME_9_HEX).unwrap();
        let flow = parse(LinkType::NULL, &raw).unwrap();
        let transport = flow.transport.as_ref().unwrap();
        assert_eq!(
            (transport.source_port, transport.destination_port),
            (Some(54020), Some(58584))
        );
        assert_eq!(flow.application.as_ref().unwrap().protocol.label(), "RTPS");

        // The pipeline gives the label; the protocol parser decodes the payload.
        let payload = transport.payload.unwrap();
        let RtpsPacket::Message(message) = RtpsPacket::try_from(payload).unwrap() else {
            panic!("expected a message, not a ping");
        };
        assert_eq!(&message.header.magic, b"RTPS");
        assert_eq!((message.header.version_major, message.header.version_minor), (2, 1));
        assert_eq!(message.header.vendor_id, 0x0110); // Eclipse Cyclone DDS

        // Four submessages tile the datagram after the 20-byte header, every
        // one of them little-endian (flag E).
        let kinds: Vec<SubmessageKind> = message.submessages.iter().map(|s| s.kind).collect();
        assert_eq!(
            kinds,
            [
                SubmessageKind::InfoDestination,
                SubmessageKind::InfoTimestamp,
                SubmessageKind::Data,
                SubmessageKind::Heartbeat,
            ]
        );
        let bodies: Vec<usize> = message.submessages.iter().map(|s| s.body.len()).collect();
        assert_eq!(bodies, [12, 8, 48, 28]);
        assert_eq!(20 + bodies.iter().map(|len| 4 + len).sum::<usize>(), payload.len());
        assert!(message.submessages.iter().all(|s| s.little_endian));

        let SubmessageDetails::InfoTimestamp { timestamp: Some(time) } =
            message.submessages[1].details
        else {
            panic!("expected an INFO_TS with a timestamp");
        };
        assert_eq!(time.seconds, 1_625_943_735); // 2021-07-10 19:02:15 UTC
        let SubmessageDetails::Data {
            reader_id,
            writer_id,
            writer_sequence_number,
            serialized_payload,
            ..
        } = message.submessages[2].details
        else {
            panic!("expected a DATA");
        };
        // The built-in participant message reader and writer, as tshark names them.
        assert_eq!((reader_id, writer_id), (0x0002_00c7, 0x0002_00c2));
        assert_eq!(writer_sequence_number, 1);
        assert!(serialized_payload);
        assert!(matches!(
            message.submessages[3].details,
            SubmessageDetails::Heartbeat {
                first_sequence_number: 1,
                last_sequence_number: 1,
                count: 2,
                ..
            }
        ));
    }
    // ANCHOR_END: rtps_random_port

    // ANCHOR: rtps_to_the_end
    #[test]
    fn a_zero_octets_to_next_header_runs_to_the_end_of_the_message() {
        // Frame 1 of wireshark_6449_opendds_messenger.pcap: OpenDDS, an INFO_TS
        // then a DATA whose octetsToNextHeader is 0.
        let raw = hex::decode(OPENDDS_FRAME_1_HEX).unwrap();
        let flow = parse(LinkType::ETHERNET, &raw).unwrap();
        assert_eq!(flow.application.as_ref().unwrap().protocol.label(), "RTPS");
        let payload = flow.transport.as_ref().unwrap().payload.unwrap();
        let packet = RtpsPacket::try_from(payload).unwrap();
        assert_eq!(packet.vendor_id(), 0x0103); // OpenDDS
        let message = packet.message().expect("a message, not a ping");

        let data = &message.submessages[1];
        assert_eq!(data.kind, SubmessageKind::Data);
        assert_eq!(data.flags, 0x0b); // K, Q and E
        assert_eq!(data.octets_to_next_header, 0); // as carried by the wire...
        assert_eq!(data.body.len(), payload.len() - 20 - (4 + 8) - 4); // ...to the end
        let SubmessageDetails::Data {
            writer_id,
            writer_sequence_number,
            inline_qos,
            serialized_payload,
            serialized_key,
            ..
        } = data.details
        else {
            panic!("expected a DATA");
        };
        assert_eq!(writer_id, 0x0000_0102);
        // high = -1, low = 0: `tshark -T fields` prints -4294967296 too.
        assert_eq!(writer_sequence_number, -4_294_967_296);
        assert!(inline_qos && serialized_key && !serialized_payload);
    }
    // ANCHOR_END: rtps_to_the_end

    // ANCHOR: rtps_ping
    #[test]
    fn the_rti_ping_is_rtps_without_submessages() {
        // Frame 1 of rtps.pcap: sixteen bytes, magic, version, vendorId, NDDSPING.
        let raw = hex::decode(RTI_PING_FRAME_1_HEX).unwrap();
        let flow = parse(LinkType::ETHERNET, &raw).unwrap();
        assert_eq!(flow.application.as_ref().unwrap().protocol.label(), "RTPS");
        let payload = flow.transport.as_ref().unwrap().payload.unwrap();
        assert_eq!(payload.len(), 16);

        let packet = RtpsPacket::try_from(payload).unwrap();
        let RtpsPacket::Ping(ping) = &packet else {
            panic!("expected a ping");
        };
        assert_eq!(&ping.text, b"NDDSPING");
        assert_eq!(packet.vendor_id(), 0x0101); // RTI Connext
        assert_eq!(packet.version(), (2, 1));
        assert!(packet.message().is_none());
    }
    // ANCHOR_END: rtps_ping

    // ANCHOR: rtps_refusals
    #[test]
    fn a_message_that_does_not_tile_its_datagram_is_refused() {
        // The 132-byte payload of frame 9 of talker-listener-rtps.pcapng, then
        // one modification at a time.
        let raw = hex::decode(CYCLONE_FRAME_9_HEX).unwrap();
        let payload = &raw[4 + 20 + 8..]; // after LINKTYPE_NULL, IPv4 and UDP
        assert_eq!(payload.len(), 132);

        assert_eq!(RtpsPacket::try_from(&payload[..20]), Err(RtpsParseError::NoSubmessage));
        let mut other_magic = payload.to_vec();
        other_magic[..4].copy_from_slice(b"GIOP");
        assert_eq!(
            RtpsPacket::try_from(other_magic.as_slice()),
            Err(RtpsParseError::InvalidMagic(*b"GIOP"))
        );
        let mut version_1 = payload.to_vec();
        version_1[4] = 1; // RTPS 1.x, another format
        assert_eq!(
            RtpsPacket::try_from(version_1.as_slice()),
            Err(RtpsParseError::UnsupportedVersion { major: 1, minor: 1 })
        );
        let mut reserved = payload.to_vec();
        reserved[20] = 0x02; // the first submessageId
        assert_eq!(
            RtpsPacket::try_from(reserved.as_slice()),
            Err(RtpsParseError::ReservedSubmessageId { id: 0x02, offset: 20 })
        );
        // 0x00 is the HEADER_EXTENSION of RTPS 2.5: the first submessage or none.
        let mut misplaced = payload.to_vec();
        misplaced[36] = 0x00; // the INFO_TS at offset 36
        assert_eq!(
            RtpsPacket::try_from(misplaced.as_slice()),
            Err(RtpsParseError::MisplacedHeaderExtension { offset: 36 })
        );
        let mut wrong_length = payload.to_vec();
        wrong_length[20..22].copy_from_slice(&[0x00, 0x03]); // first, with flags L and E
        wrong_length[24..28].copy_from_slice(&131u32.to_le_bytes()); // its messageLength
        assert_eq!(
            RtpsPacket::try_from(wrong_length.as_slice()),
            Err(RtpsParseError::HeaderExtensionLengthMismatch { declared: 131, actual: 132 })
        );
        let mut overflow = payload.to_vec();
        overflow[22] = 200; // INFO_DST declares 200 bytes instead of 12
        assert_eq!(
            RtpsPacket::try_from(overflow.as_slice()),
            Err(RtpsParseError::SubmessageOverflow {
                id: 0x0e,
                offset: 20,
                declared: 200,
                available: 108,
            })
        );
        let mut short = payload[..124].to_vec();
        short[102] = 20; // the HEARTBEAT at offset 100 keeps 20 of its 28 bytes
        assert_eq!(
            RtpsPacket::try_from(short.as_slice()),
            Err(RtpsParseError::SubmessageTooShort {
                id: 0x07,
                offset: 100,
                expected: 28,
                actual: 20,
            })
        );
        let mut longer = payload.to_vec();
        longer.push(0); // one byte cannot hold a submessage header
        assert_eq!(
            RtpsPacket::try_from(longer.as_slice()),
            Err(RtpsParseError::Truncated { expected: 136, actual: 133 })
        );

        // In the frame, a refused message is not RTPS, and not a corruption
        // either: the datagram goes on to the next rules.
        let mut frame = raw.clone();
        frame[4 + 20 + 8 + 22] = 200;
        let flow = parse(LinkType::NULL, &frame).unwrap();
        assert_eq!(flow.application.as_ref().unwrap().protocol.label(), "Unknown");
        assert!(flow.corrupted.is_none());
    }
    // ANCHOR_END: rtps_refusals

    // ANCHOR: rtps_header_extension
    #[test]
    fn a_header_extension_right_after_the_header() {
        // No capture of the corpus carries a HEADER_EXTENSION. This one is put
        // by hand between the header and the first submessage of frame 9,
        // little-endian like the rest of the message, with flags L and C2.
        let raw = hex::decode(CYCLONE_FRAME_9_HEX).unwrap();
        let frame_9 = &raw[4 + 20 + 8..];
        let mut payload = frame_9[..20].to_vec();
        payload.extend_from_slice(&[0x00, 0x23, 8, 0]); // id, flags C2 | L | E, 8 bytes
        payload.extend_from_slice(&144u32.to_le_bytes()); // messageLength, in the order of E
        payload.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]); // a CRC-32C nobody computed
        payload.extend_from_slice(&frame_9[20..]);
        assert_eq!(payload.len(), 144);

        let packet = RtpsPacket::try_from(payload.as_slice()).unwrap();
        let message = packet.message().expect("a message, not a ping");
        assert_eq!(message.submessages.len(), 5);
        let extension = &message.submessages[0];
        assert_eq!(extension.kind, SubmessageKind::HeaderExtension);
        let SubmessageDetails::HeaderExtension(fields) = extension.details else {
            panic!("expected a HEADER_EXTENSION, got {:?}", extension.details);
        };
        assert_eq!(fields.message_length, Some(144)); // the length of the datagram
        // Read big-endian whatever E, and not verified: the message is accepted.
        assert_eq!(fields.checksum, Some(RtpsChecksum::Crc32c(0xdead_beef)));
        assert_eq!(fields.send_timestamp, None); // no flag T
        assert_eq!((fields.u_extension, fields.w_extension), (None, None));
        assert!(!fields.parameters);
        assert_eq!(extension.header_extension_parameters(), None);
        assert_eq!(message.submessages[1].kind, SubmessageKind::InfoDestination);

        // Flag P alone: a ParameterList, here its PID_SENTINEL only, kept raw.
        let mut payload = frame_9[..20].to_vec();
        payload.extend_from_slice(&[0x00, 0x81, 4, 0, 0x01, 0x00, 0x00, 0x00]);
        payload.extend_from_slice(&frame_9[20..]);
        let packet = RtpsPacket::try_from(payload.as_slice()).unwrap();
        let extension = &packet.message().unwrap().submessages[0];
        assert_eq!(extension.header_extension_parameters(), Some(&[0x01, 0x00, 0x00, 0x00][..]));

        // Every flag but P, on the INFO_DST of frame 9 turned HEADER_EXTENSION:
        // 4 + 8 + 4 + 8 + 16 bytes of fields, in a body of 12.
        let mut too_short = frame_9.to_vec();
        too_short[20..22].copy_from_slice(&[0x00, 0x7f]);
        assert_eq!(
            RtpsPacket::try_from(too_short.as_slice()),
            Err(RtpsParseError::SubmessageTooShort {
                id: 0x00,
                offset: 20,
                expected: 40,
                actual: 12,
            })
        );
    }
    // ANCHOR_END: rtps_header_extension

    // ANCHOR: rtps_spdp
    #[test]
    fn a_participant_announces_itself_through_spdp() {
        // Frame 3 of talker-listener-rtps.pcapng: the participant of frame 9
        // announces itself to the SPDP multicast group, an INFO_TS then a DATA.
        let raw = hex::decode(CYCLONE_FRAME_3_HEX).unwrap();
        let flow = parse(LinkType::NULL, &raw).unwrap();
        assert_eq!(flow.application.as_ref().unwrap().protocol.label(), "RTPS");
        let payload = flow.transport.as_ref().unwrap().payload.unwrap();
        let packet = RtpsPacket::try_from(payload).unwrap();
        let message = packet.message().expect("a message, not a ping");
        let data = &message.submessages[1];
        assert_eq!(data.kind, SubmessageKind::Data);

        // Decoded on demand, from the submessage: the writer 0x000100c2 is SPDP's.
        assert!(data.inline_qos().is_none()); // no flag Q
        let discovery = data.discovery().expect("an SPDP writer").unwrap();
        assert_eq!(discovery.topic, RtpsBuiltinTopic::Participant);
        assert_eq!(discovery.topic.name(), "DCPSParticipant");
        assert_eq!(discovery.encapsulation, RtpsEncapsulation::PlCdrLe);
        assert!(!discovery.secure && !discovery.key_only);

        let list = discovery.parameters;
        let guid = list.participant_guid().unwrap();
        assert_eq!(guid[..12], message.header.guid_prefix); // the sender itself
        assert_eq!(guid[12..], [0x00, 0x00, 0x01, 0xc1]); // ENTITYID_PARTICIPANT
        assert_eq!(list.vendor_id(), Some(0x0110)); // Cyclone DDS
        assert_eq!(list.protocol_version(), Some((2, 1)));
        assert_eq!(list.domain_id(), Some(0));
        assert_eq!(list.builtin_endpoint_set(), Some(0x0000_0c3f));
        let lease = list.participant_lease_duration().unwrap();
        assert_eq!((lease.seconds, lease.fraction), (10, 0));
        assert_eq!(list.entity_name(), None); // Cyclone DDS sends none
        // Where to reach the participant: its data, and its metatraffic.
        let locators: Vec<(RtpsLocatorRole, Option<Ipv4Addr>, u32)> = list
            .locators()
            .map(|(role, locator)| (role, locator.ipv4(), locator.port))
            .collect();
        let host = Some(Ipv4Addr::new(10, 0, 0, 46));
        assert_eq!(
            locators,
            [
                (RtpsLocatorRole::DefaultUnicast, host, 61_329),
                (RtpsLocatorRole::MetatrafficUnicast, host, 61_329),
            ]
        );

        // Every parameter in wire order, the PID_SENTINEL left out.
        let ids: Vec<u16> = list.iter().map(|parameter| parameter.id).collect();
        assert_eq!(
            ids,
            [0x002c, 0x0015, 0x0016, 0x0002, 0x0050, 0x0058, 0x000f, 0x0031, 0x0032, 0x8007, 0x8019]
        );
        // Bit 15: two PIDs of Cyclone DDS, which the specification does not name.
        let vendor: Vec<u16> = list
            .iter()
            .filter(|parameter| parameter.is_vendor_specific())
            .map(|parameter| parameter.id)
            .collect();
        assert_eq!(vendor, [0x8007, 0x8019]);
        assert!(list.iter().all(|parameter| !parameter.must_understand()));
        assert_eq!(list.get(0x8007).unwrap().name(), None);
        // A PID without an accessor: its value, borrowed. ROS 2 writes its
        // enclave in PID_USER_DATA, a sequence of 10 octets.
        let user_data = list.get(0x002c).unwrap();
        assert_eq!(user_data.name(), Some("PID_USER_DATA"));
        assert_eq!(user_data.u32_value(), Some(10));
        assert_eq!(&user_data.value[4..14], b"enclave=/;");
    }
    // ANCHOR_END: rtps_spdp

    // ANCHOR: rtps_sedp
    #[test]
    fn a_publication_announced_by_sedp_then_its_first_sample() {
        /// The UDP payload of a LINKTYPE_NULL frame the pipeline labels RTPS.
        fn datagram(raw: &[u8]) -> &[u8] {
            let flow = parse(LinkType::NULL, raw).unwrap();
            assert_eq!(flow.application.unwrap().protocol.label(), "RTPS");
            flow.transport.unwrap().payload.unwrap()
        }

        // Frame 57 of talker-listener-rtps.pcapng: the SEDP publications
        // writer, 0x000003c2, announces a writer of the participant.
        let raw = hex::decode(CYCLONE_FRAME_57_HEX).unwrap();
        let packet = RtpsPacket::try_from(datagram(&raw)).unwrap();
        let message = packet.message().unwrap();
        let discovery = message.submessages[1].discovery().expect("an SEDP writer").unwrap();
        assert_eq!(discovery.topic, RtpsBuiltinTopic::Publication);
        let list = discovery.parameters;
        assert_eq!(list.topic_name(), Some(&b"rt/chatter"[..]));
        assert_eq!(list.type_name(), Some(&b"std_msgs::msg::dds_::String_"[..]));
        let writer = list.endpoint_guid().unwrap();
        assert_eq!(writer[..12], message.header.guid_prefix);
        assert_eq!(writer[12..], [0x00, 0x00, 0x15, 0x03]); // a user writer, no key
        let reliability = list.reliability().unwrap();
        assert_eq!(reliability.kind, RtpsReliabilityKind::Reliable);
        assert!(reliability.max_blocking_time.unwrap().is_infinite());
        assert_eq!(list.durability(), None); // no PID_DURABILITY in the list

        // Frame 70: a DATA of that writer. A user writer: no discovery, and
        // a payload that is not a ParameterList.
        let raw = hex::decode(CYCLONE_FRAME_70_HEX).unwrap();
        let packet = RtpsPacket::try_from(datagram(&raw)).unwrap();
        let data = &packet.message().unwrap().submessages[1];
        let SubmessageDetails::Data { writer_id, .. } = data.details else {
            panic!("expected a DATA");
        };
        assert_eq!(writer_id.to_be_bytes(), writer[12..]);
        assert_eq!(data.discovery(), None);
        let payload = data.serialized_payload().expect("flag D").unwrap();
        assert_eq!(payload.encapsulation, RtpsEncapsulation::CdrLe);
        assert_eq!(payload.encapsulation.name(), Some("CDR_LE"));
        assert_eq!(payload.encapsulation.little_endian(), Some(true));
        assert_eq!(payload.options, 0);
        assert_eq!(payload.parameters(), None); // PL_CDR only

        // The crate stops at the bytes. The IDL of std_msgs/String reads
        // them as a CDR string: a u32 length, NUL included, then the text.
        assert_eq!(payload.data.len(), 20); // to the end of the submessage
        let length = u32::from_le_bytes(payload.data[..4].try_into().unwrap()) as usize;
        assert_eq!(&payload.data[4..4 + length], b"Hello World: 1\0");
    }
    // ANCHOR_END: rtps_sedp

    // ANCHOR: rtps_dds_refusals
    #[test]
    fn inline_qos_and_the_refusals_of_the_dds_layer() {
        /// The DATA of a message, which must still decode as RTPS.
        fn data_of(message: &[u8]) -> RtpsSubmessage<'_> {
            let packet = RtpsPacket::try_from(message).expect("still an RTPS message");
            packet.message().unwrap().submessages[1]
        }

        // Frame 29 of rtps.pcap: an RTI Connext participant leaves. Its SPDP
        // writer sends a DATA with flags Q and E, neither data nor key: the
        // inline QoS alone say which instance, and what happened to it.
        let raw = hex::decode(RTI_FRAME_29_HEX).unwrap();
        let flow = parse(LinkType::ETHERNET, &raw).unwrap();
        assert_eq!(flow.application.as_ref().unwrap().protocol.label(), "RTPS");
        let payload = flow.transport.as_ref().unwrap().payload.unwrap();
        let data = data_of(payload);
        assert_eq!(data.flags, 0x03);
        let qos = data.inline_qos().expect("flag Q").unwrap();
        assert!(qos.little_endian); // the byte order of the submessage
        let key = qos.key_hash().unwrap(); // the GUID of the participant
        assert_eq!(key[..12], payload[8..20]); // the guidPrefix of the header
        let status = qos.status_info().unwrap();
        assert_eq!(status.flags, 0x03);
        assert!(status.disposed() && status.unregistered() && !status.filtered());
        assert_eq!(data.serialized_payload(), None); // neither D nor K
        assert_eq!(data.discovery(), None);

        // The 88-byte message: the DATA at offset 32, its octetsToInlineQos
        // at 38, the inline QoS from 56 to the end, their PID_SENTINEL at 84.
        assert_eq!(payload.len(), 88);
        let mut pointer = payload.to_vec();
        pointer[38] = 64; // beyond the 52 bytes of the body
        assert_eq!(
            data_of(&pointer).inline_qos(),
            Some(Err(RtpsParseError::InvalidOctetsToInlineQos {
                octets_to_inline_qos: 64,
                body: 52,
            }))
        );
        let mut unterminated = payload.to_vec();
        unterminated[84] = 0x00; // PID_SENTINEL turned PID_PAD, its length 1 kept
        assert_eq!(
            data_of(&unterminated).inline_qos(),
            Some(Err(RtpsParseError::ParameterTruncated { offset: 28, expected: 1, actual: 0 }))
        );
        unterminated[86] = 0x00; // length 0: the list fits, and nothing ends it
        assert_eq!(
            data_of(&unterminated).inline_qos(),
            Some(Err(RtpsParseError::ParameterListUnterminated { length: 32 }))
        );
        let mut no_data = payload.to_vec();
        no_data[33] = 0x07; // flag D, and nothing after the inline QoS
        assert_eq!(
            data_of(&no_data).serialized_payload(),
            Some(Err(RtpsParseError::SerializedPayloadTooShort { actual: 0 }))
        );
        assert_eq!(
            data_of(&no_data).discovery(),
            Some(Err(RtpsParseError::SerializedPayloadTooShort { actual: 0 }))
        );

        // Frame 70 of talker-listener-rtps.pcapng, its writer id at 44 turned
        // into SPDP's: a CDR_LE payload is no discovery.
        let frame_70 = hex::decode(CYCLONE_FRAME_70_HEX).unwrap();
        let mut not_a_list = frame_70[4 + 20 + 8..].to_vec();
        not_a_list[44..48].copy_from_slice(&[0x00, 0x01, 0x00, 0xc2]);
        assert_eq!(
            data_of(&not_a_list).discovery(),
            Some(Err(RtpsParseError::NotAParameterList { encapsulation: 0x0001 }))
        );

        // None of them refuses the message: the frame is still RTPS, and
        // nothing is corrupted.
        let mut frame = raw.clone();
        frame[14 + 20 + 8 + 38] = 64;
        let flow = parse(LinkType::ETHERNET, &frame).unwrap();
        assert_eq!(flow.application.as_ref().unwrap().protocol.label(), "RTPS");
        assert!(flow.corrupted.is_none());
    }
    // ANCHOR_END: rtps_dds_refusals

    // ANCHOR: asterix_typed_values
    #[test]
    fn typed_values_are_decoded_on_demand() {
        // Frame 3 of cat_034_048.pcap: a CAT 048 block, then a CAT 034 block.
        let raw = hex::decode(CAT_034_048_FRAME_3_HEX).unwrap();
        let flow = parse(LinkType::ETHERNET, &raw).unwrap();
        assert_eq!(flow.application.as_ref().unwrap().protocol.label(), "ASTERIX");
        let payload = flow.transport.as_ref().unwrap().payload.unwrap();
        let packet = AsterixPacket::try_from(payload).unwrap();
        let shape: Vec<(u8, u16, usize)> = packet
            .blocks
            .iter()
            .map(|block| (block.category, block.length, block.records.len()))
            .collect();
        assert_eq!(shape, [(48, 55, 1), (34, 11, 1)]);

        let record = &packet.blocks[0].records[0];
        let report = cat048::TargetReport::from_record(record).expect("a CAT 048 record");
        let position = report.polar_position.unwrap();
        let velocity = report.polar_velocity.unwrap();
        let line = format!(
            "{} ({}) at {:.2} NM / {:.2}°, FL {}, {:.0} kt heading {:.1}°",
            report.aircraft_identification.unwrap().trimmed(),
            report.aircraft_address.unwrap(),
            position.range_nm(),
            position.azimuth_deg(),
            report.flight_level.unwrap().flight_level(),
            velocity.ground_speed_kt(),
            velocity.heading_deg()
        );
        assert_eq!(line, "THY9TX (4BAACD) at 194.82 NM / 128.76°, FL 360, 457 kt heading 263.6°");

        // Each decoder reads its own category only.
        assert!(cat034::ServiceMessage::from_record(record).is_none());
        let service = cat034::ServiceMessage::from_record(&packet.blocks[1].records[0]).unwrap();
        assert_eq!(service.message_type, Some(cat034::MessageType::SectorCrossing));
        assert_eq!(service.sector_azimuth_deg(), Some(135.0));

        // I048/020 is extended: one octet here (a0, FX = 0), six at most.
        assert_eq!(record.item("I048/020"), Some(&[0xa0][..]));
        let spec = record.uap().unwrap().item_by_id("I048/020").unwrap();
        assert_eq!(spec.format, ItemFormat::Extended(&[1, 1, 1, 1, 1, 1]));
    }
    // ANCHOR_END: asterix_typed_values

    // ANCHOR: asterix_cat001_uap
    #[test]
    fn a_cat001_record_picks_its_uap_from_its_own_bytes() {
        // Frame 772 of wireshark_8579_radardata.pcap: CAT 001, 002 and 001
        // blocks in one datagram.
        let raw = hex::decode(RADARDATA_FRAME_772_HEX).unwrap();
        let flow = parse(LinkType::ETHERNET, &raw).unwrap();
        assert_eq!(flow.application.as_ref().unwrap().protocol.label(), "ASTERIX");
        let packet =
            AsterixPacket::try_from(flow.transport.as_ref().unwrap().payload.unwrap()).unwrap();
        let categories: Vec<u8> = packet.blocks.iter().map(|block| block.category).collect();
        assert_eq!(categories, [1, 2, 1]);

        // TYP = 0 in I001/020: a plot, cut with the plot UAP, the one whose
        // selector would have switched to the track UAP.
        let plot = &packet.blocks[0].records[0];
        assert_eq!(plot.uap(), Some(&uap::CAT001));
        assert_eq!(uap::CAT001.selector, Some(UapSelector::Cat001TargetType));
        let report = cat001::TargetReport::from_record(plot).unwrap();
        let descriptor = report.descriptor.unwrap();
        assert!(!descriptor.track);
        assert_eq!(descriptor.detection, cat001::RadarDetection::Combined);
        let position = report.polar_position.unwrap(); // LSB 1/128 NM in CAT 001
        assert_eq!((position.range_nm(), position.azimuth_deg()), (57.25, 239.150_390_625));
        assert_eq!(report.mode_3a.unwrap().to_string(), "0304");
        assert_eq!(report.flight_level.unwrap().flight_level(), 350.0);
        assert_eq!(report.truncated_time_of_day_seconds(), Some(440.484_375));
        assert!(!report.mode_2.unwrap().validated); // military IFF, not validated
        assert!(report.track_number.is_none()); // a track item

        // The CAT 002 block in between: the north marker of the same radar.
        let marker = cat002::ServiceMessage::from_record(&packet.blocks[1].records[0]).unwrap();
        assert_eq!(marker.message_type, Some(cat002::MessageType::NorthMarker));
        assert_eq!(marker.antenna_rotation_period_seconds(), Some(9.304_687_5));
        let counts: Vec<(u8, u16)> = marker
            .plot_counts
            .iter()
            .map(|count| (count.identification, count.counter))
            .collect();
        assert_eq!(counts, [(1, 29), (2, 19), (3, 35)]); // primary, SSR, combined

        // The last block: a simulated test target, I001/020 in two extents.
        let test_target = &packet.blocks[2].records[0];
        assert_eq!(test_target.item("I001/020"), Some(&[0x51, 0x80][..]));
        assert_eq!(uap::CAT001.item(2).unwrap().format, ItemFormat::Extended(&[1, 1]));
    }
    // ANCHOR_END: asterix_cat001_uap

    // ANCHOR: asterix_system_track
    #[test]
    fn a_system_track_and_the_subfields_its_decoder_skips() {
        // Frame 1 of cat_062_065.pcap: two CAT 062 tracks, then a CAT 065
        // end of batch.
        let raw = hex::decode(CAT_062_065_FRAME_1_HEX).unwrap();
        let flow = parse(LinkType::ETHERNET, &raw).unwrap();
        assert_eq!(flow.application.as_ref().unwrap().protocol.label(), "ASTERIX");
        let packet =
            AsterixPacket::try_from(flow.transport.as_ref().unwrap().payload.unwrap()).unwrap();
        let shape: Vec<(u8, usize)> = packet
            .blocks
            .iter()
            .map(|block| (block.category, block.records.len()))
            .collect();
        assert_eq!(shape, [(62, 2), (65, 1)]);

        let record = &packet.blocks[0].records[0];
        let track = cat062::SystemTrack::from_record(record).unwrap();
        assert_eq!(track.track_number, Some(4713));
        assert_eq!(track.aircraft_identification.unwrap().trimmed(), "RYR174C"); // I062/380 ID
        assert_eq!(track.aircraft_address.unwrap().to_string(), "4CA7A8"); // I062/380 ADR
        let position = track.wgs84_position.unwrap();
        assert_eq!(
            (position.latitude_deg(), position.longitude_deg()),
            (41.167_123_317_718_506, 15.708_866_715_431_213)
        );
        assert_eq!(track.barometric_altitude.unwrap().flight_level(), 390.0);
        let measured = track.measured_information.unwrap(); // I062/340, the last sensor
        assert_eq!(measured.sensor.map(|sensor| (sensor.sac, sensor.sic)), Some((25, 12)));
        assert_eq!(measured.range_nm(), Some(147.726_562_5));

        // I062/080 is extended: four of its seven extents here.
        assert_eq!(record.item("I062/080"), Some(&[0x19, 0x03, 0x01, 0x08][..]));
        // A compound item, by subfield number: PSR age, 23 x 1/4 s; no TRK age.
        assert_eq!(record.subfield("I062/290", 2), Some(&[0x17][..]));
        assert_eq!(record.subfield("I062/290", 1), None);

        let end = cat065::ServiceStatus::from_record(&packet.blocks[1].records[0]).unwrap();
        assert_eq!(end.message_type, Some(cat065::MessageType::EndOfBatch));
        assert_eq!(end.batch_number, Some(1));
    }
    // ANCHOR_END: asterix_system_track

    // ANCHOR: asterix_status_messages
    #[test]
    fn status_of_a_ground_station_a_sensor_and_a_weather_picture() {
        /// The UDP payload of an Ethernet frame the pipeline labels ASTERIX.
        fn datagram(raw: &[u8]) -> &[u8] {
            let flow = parse(LinkType::ETHERNET, raw).unwrap();
            assert_eq!(flow.application.unwrap().protocol.label(), "ASTERIX");
            flow.transport.unwrap().payload.unwrap()
        }

        // Frame 1 of wireshark_9953_cat021023.pcap: CAT 023, an ADS-B service.
        let raw = hex::decode(CAT021023_FRAME_1_HEX).unwrap();
        let packet = AsterixPacket::try_from(datagram(&raw)).unwrap();
        let report = cat023::StatusReport::from_record(&packet.blocks[0].records[0]).unwrap();
        assert_eq!(report.report_type, Some(cat023::ReportType::ServiceStatus));
        let service_type = report.service.map(|service| service.service_type);
        assert_eq!(service_type, Some(2)); // ADS-B Ext Squitter
        assert_eq!(report.service_status, Some(4)); // normal
        assert_eq!(report.operational_range_nm, Some(255));

        // Frame 428 of the same stream: CAT 247, the editions it sends.
        let raw = hex::decode(CAT021023_FRAME_428_HEX).unwrap();
        let packet = AsterixPacket::try_from(datagram(&raw)).unwrap();
        let versions = cat247::VersionReport::from_record(&packet.blocks[0].records[0]).unwrap();
        let editions: Vec<(u8, u8, u8)> = versions
            .category_versions
            .iter()
            .map(|version| (version.category, version.main_version, version.sub_version))
            .collect();
        assert_eq!(editions, [(21, 0, 26), (23, 1, 20)]);

        // Frame 1105 of wireshark_8579_radardata.pcap: CAT 063, a sensor
        // operational but NOGO on every technology.
        let raw = hex::decode(RADARDATA_FRAME_1105_HEX).unwrap();
        let packet = AsterixPacket::try_from(datagram(&raw)).unwrap();
        let status = cat063::SensorStatus::from_record(&packet.blocks[0].records[0]).unwrap();
        assert_eq!(status.sensor.map(|sensor| (sensor.sac, sensor.sic)), Some((34, 26)));
        let configuration = status.configuration.unwrap();
        assert_eq!(configuration.connection, cat063::ConnectionStatus::Operational);
        assert!(configuration.psr_nogo && configuration.ssr_nogo && configuration.mode_s_nogo);
        assert!(configuration.ads_nogo && configuration.mlt_nogo);
        assert_eq!(status.time_stamping_bias_ms, Some(75));

        // Frame 1 of wireshark_9239_cat008only-2.pcap: CAT 008, the start of
        // a weather picture.
        let raw = hex::decode(CAT008ONLY_2_FRAME_1_HEX).unwrap();
        let packet = AsterixPacket::try_from(datagram(&raw)).unwrap();
        let weather = cat008::WeatherMessage::from_record(&packet.blocks[0].records[0]).unwrap();
        assert_eq!(weather.message_type, Some(cat008::MessageType::StartOfPicture));
        assert_eq!(weather.processing_status.map(|status| status.scaling_factor), Some(6));
    }
    // ANCHOR_END: asterix_status_messages

    // ANCHOR: asterix_beyond_tshark
    #[test]
    fn where_tshark_stops_the_specification_goes_on() {
        // Frame 30453 of wireshark_8579_radardata.pcap: a CAT 002 north marker
        // whose I002/050 takes two octets. tshark 4.6.6 reads one and calls
        // the frame malformed.
        let raw = hex::decode(RADARDATA_FRAME_30453_HEX).unwrap();
        let flow = parse(LinkType::ETHERNET, &raw).unwrap();
        assert_eq!(flow.application.as_ref().unwrap().protocol.label(), "ASTERIX");
        let packet =
            AsterixPacket::try_from(flow.transport.as_ref().unwrap().payload.unwrap()).unwrap();
        let record = &packet.blocks[0].records[0];
        let ids: Vec<&str> = record.items.iter().map(|item| item.id).collect();
        assert_eq!(ids, ["I002/010", "I002/000", "I002/030", "I002/050"]);
        assert_eq!(record.item("I002/050"), Some(&[0x0b, 0x02][..])); // FX 1, then FX 0
        assert_eq!(uap::CAT002.item(6).unwrap().format, ItemFormat::Variable);
    }
    // ANCHOR_END: asterix_beyond_tshark

    // ANCHOR: asterix_all_or_nothing
    #[test]
    fn one_failure_anywhere_and_the_datagram_is_not_asterix() {
        // The 66-byte payload of frame 3 of cat_034_048.pcap, after Ethernet,
        // IPv4 and UDP; its second block, CAT 034, starts at byte 55.
        let raw = hex::decode(CAT_034_048_FRAME_3_HEX).unwrap();
        let datagram = &raw[14 + 20 + 8..];
        assert!(AsterixPacket::try_from(datagram).is_ok());
        let second = 55;

        // Relabelled CAT 062, a decoded category: its UAP reads the FSPEC f0,
        // and FRN 2 is reserved in CAT 062.
        let mut relabelled = datagram.to_vec();
        relabelled[second] = 62;
        assert_eq!(
            AsterixPacket::try_from(relabelled.as_slice()),
            Err(AsterixError::UnknownFrn { category: 62, frn: 2 })
        );
        // Relabelled CAT 010, which has no UAP in the crate.
        relabelled[second] = 10;
        assert_eq!(
            AsterixPacket::try_from(relabelled.as_slice()),
            Err(AsterixError::UnsupportedCategory(10))
        );
        // LEN 56 for the first block: the extra byte opens a record.
        let mut longer = datagram.to_vec();
        longer[2] = 56;
        assert_eq!(
            AsterixPacket::try_from(longer.as_slice()),
            Err(AsterixError::TruncatedItem { item: "I048/020", needed: 1, actual: 0 })
        );
        // One trailing byte cannot hold a block header.
        let mut trailing = datagram.to_vec();
        trailing.push(0);
        assert_eq!(
            AsterixPacket::try_from(trailing.as_slice()),
            Err(AsterixError::Truncated { needed: 3, actual: 1 })
        );
        // Zero padding inside a block: a record of 00 announces no item.
        let mut padded = datagram.to_vec();
        padded[second + 2] += 1;
        padded.push(0);
        assert_eq!(
            AsterixPacket::try_from(padded.as_slice()),
            Err(AsterixError::EmptyRecord { category: 34 })
        );

        // In the frame, the refused datagram goes on to the next rules.
        let mut frame = raw.clone();
        frame[14 + 20 + 8 + second] = 10;
        let flow = parse(LinkType::ETHERNET, &frame).unwrap();
        assert_eq!(flow.application.as_ref().unwrap().protocol.label(), "Unknown");
        assert!(flow.corrupted.is_none());
    }
    // ANCHOR_END: asterix_all_or_nothing
}
