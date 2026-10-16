//! The examples of the link-layer chapters: the PPPoE session page, and the
//! total length of zero on the IPv4 page. Each `#[test]` is a chapter
//! snippet, delimited by `ANCHOR` comments that mdBook includes verbatim.
//!
//! Every frame is a real one from the crate's corpus, copied with its
//! capture file and frame number; the bytes were taken with a script and
//! checked against tshark's hex dump.

#[cfg(test)]
mod tests {
    use std::hash::{DefaultHasher, Hash, Hasher};

    use packet_parser::parse::data_link::pppoe::PPPOE_SESSION_ETHERTYPE;
    use packet_parser::{
        CorruptedLayerKind, InternetDetails, IpType, LinkType, NetworkProtocol, PacketFlow, parse,
    };

    /// Frame 1 of `pcaps_exemple/vlan/pppoe-over-qinq.pcap`: two 802.1Q tags
    /// (outer VID 3704, inner VID 2474), a PPPoE session 0x0f07 of length 66
    /// carrying PPP IPv4 (0x0021), and the SYN of a TCP connection
    /// 1.1.1.1:20394 -> 2.2.2.2:443.
    const QINQ_PPPOE_IPV4_SYN_HEX: &str = concat!(
        "00000000000100000000000081000e78810009aa886411000f07004200214500",
        "0040000040003f0635b301010101020202024faa01bbd7a8415500000000b002",
        "ffffeced0000020405a0010303060101080a012dd88c0000000004020000"
    );

    /// Frame 3 of the same capture: an ACK of the same connection, in the same
    /// direction and the same session, in a PPPoE length of 42.
    const QINQ_PPPOE_IPV4_ACK_HEX: &str = concat!(
        "00000000000100000000000081000e78810009aa886411000f07002a00214500",
        "0028000040003f0635cb01010101020202024faa01bbd7a84156fc90a2ff5010",
        "10008fda0000"
    );

    /// Frame 19 of the same capture: an ACK 2.2.2.2:443 -> 1.1.1.1:20394 whose
    /// PPPoE length (42) does not cover its 46-byte IPv4 packet; tshark flags
    /// it ("Possible bad payload length 42 != 48").
    const QINQ_PPPOE_SHORT_LENGTH_HEX: &str = concat!(
        "bcd17717750d00000000000081000e78810009aa886411000f07002a00214500",
        "002e1c464000ef06697e020202020101010101bb4faafc90b007d7a844995010",
        "086287270000000000000000"
    );

    /// Frame 10 415 of `pcaps_exemple/The-Ultimate-PCAP.pcapng`: VLAN 7, a
    /// PPPoE session 0x8f9e of length 149 carrying PPP IPv6 (0x0057), a
    /// DHCPv6 Solicit fe80::be05:43ff:fecc:c2a9 -> ff02::1:2, UDP 546 -> 547,
    /// then four bytes after the PPPoE length.
    const PPPOE_IPV6_DHCPV6_SOLICIT_HEX: &str = concat!(
        "442b03190344bc0543ccc2a981000007886411008f9e0095005760000000006b",
        "11fffe80000000000000be0543fffeccc2a9ff02000000000000000000000001",
        "000202220223006b21cc013f490000080002000000100004000003680001000a",
        "00030001bc0543ccc2a9000e00000006000a00170038001f0019001100140000",
        "0019002943ccc2a90000000000000000001a0019000000000000000000000000",
        "00000000000000000000000000fb4fb20e"
    );

    /// Frame 10 401 of the same capture: the same session and direction, an
    /// LCP Configure-Request (PPP 0xC021) in a PPPoE length of 16, then 24
    /// bytes up to the end of the 64-byte frame.
    const PPPOE_LCP_CONFIGURE_REQUEST_HEX: &str = concat!(
        "442b03190344bc0543ccc2a981000007886411008f9e0010c0210101000e0104",
        "05d4050601da28e10000000000000001000000000000bc0543cc00009b36c5c6"
    );

    /// Frame 10 409 of the same capture: the same session and direction, an
    /// IPCP Configure-Ack (PPP 0x8021) in a PPPoE length of 12.
    const PPPOE_IPCP_CONFIGURE_ACK_HEX: &str = concat!(
        "442b03190344bc0543ccc2a981000007886411008f9e000c80210201000a0306",
        "d90076d5000000000000000000000000000000000000000000000000fbd21df4"
    );

    /// Frame 47 790 of `pcaps_exemple/The-Ultimate-PCAP.pcapng`: Ethernet /
    /// IPv4 with a total length of 0 / TCP 56186 -> 443 carrying a TLS
    /// ClientHello record of 1 908 bytes, 1 967 bytes in a single frame.
    const IPV4_TSO_TLS_CLIENT_HELLO_HEX: &str = concat!(
        "04d59042861500e04c6866c1080045000000d92e400080060000c0a8016f6419",
        "e122db7a01bb6175ef73bf1c98c3501800ff075a000016030107740100077003",
        "035616ab096e58e74c3d5a2faccf4d2b34dabfba557cbe30c598905084787239",
        "8720b0c6717ae8402773b00a39e5b4012c603af9b30884427237cf5faf33ab1d",
        "56dd0022130113031302c02bc02fcca9cca8c02cc030c00ac009c013c014009c",
        "009d002f003501000705000000250023000020657874656e73696f6e2e66656d",
        "6574726963732e6772616d6d61726c792e696f00170000ff01000100000a0010",
        "000e11ec001d00170018001901000101000b00020100002300000010000e000c",
        "02683208687474702f312e310005000501000000000022000a00080403050306",
        "0302030033052f052d11ec04c0fe98920ef5c154290fe9573ec001c21419ae72",
        "fc307b5110e12826430c435615c75c6a7d13b322648044b266a902285734e9a0",
        "d4418854a947037540950a8776909e11381761ec4a2e98443e0c85caf8bcc455",
        "8e791ab2a897b4c4da947fa33fedd84f1d27b3a41191252b6f350064bf3b4374",
        "d77f7a9993293881cc8276f86c7bf6c39505d015dbca172196c52ab733e0e16b",
        "bfe12a902c2335d8cdb5a12f7cbc12b56b0ee2d0cc19992acd66452b7c8d2405",
        "32593178a4e21cea106a7836595a2958084466b78c620333123f20a16e75a03f",
        "3280f25b86893a98d5e6b7f5792ac64394d091810e60ae9c1743d594ba145958",
        "254057b792c5dba422e1e52db90426542ba4c23ca0bfb38d2f784db4a1826ff6",
        "67972246fddaaca726c61a900f8081c5ee290465f2b59b76adfff7ac11987785",
        "553c0f8a529e322ff7358405fa3da86042ae466e8d7863f58384746381517c89",
        "c3f8c71042167be394698432b57b42c5d406e2465258830bdfe00a16543cd295",
        "a3d86bbac91cb7e9b375a72c474fa84081c98004c76516863b1a616c75865152",
        "8831861b472c298db19b8ed6700488665598a585855b598af30c98ebb04a35c8",
        "a712440d850486317bfa53aa6f2a391536655a94722db35f91c77feff5ad10e0",
        "add9cca128f22cfe8221673866efbb1cee5b86dbd86a7917385eb85ce7b7c4bb",
        "17009baa12792369922935cd91283032890ce5cc0fd425dde8588fd78c2a6090",
        "da689cd43a93879330c0285043450024b05d6314a09cc525fa8b2acae63fb230",
        "c0621238d3649552ca529cb5a0a5409e694ca87de4b713f2576b179550a45de8",
        "5a614361468714a983e9a3e80c8d5af8230708175a8c71d233b8f624b110380a",
        "c0329a3f49785f4722d27a8c323aa0ee97b8a135bac92396ed2a6dfcc21af455",
        "2944e75b8e93cc1d16b0e684884ce785cf64c3c3d308383a660f279aa4c4b406",
        "5aa918958cb346bbecdc1e2728088710be188646662ba88b019f6f3038c232b1",
        "a569249116cbf27976bc54395fe86e17b15285630aa0a51aede00680567682f8",
        "3c1578438fc64d8957991bb02f01ac61ea60974974a9da3b96e7e83f249b13ba",
        "7b76f3f17c4391ce886a95eb396b5e70412fcc642cca93f7a50c7f1cc66f894b",
        "24a98465eb1c06eb129f0a9e81f173f92c79ddb0cfb4e8c57df99b87091d2c87",
        "93d0598ffec427745067f297b655a98c17dc49828a2165e153d0ebae87096df7",
        "837ef3623fdce8c643a7ce3d40a0dc07a57d244a626c2dbb61022db03cd4c01e",
        "74498b4ee4484eda8defdba061a01e17362604703873cc8d0b824ff127c29fc6",
        "b447852716e8755a127f4be0b75d286c27fb5c043136a68ba532aba33e9b9b66",
        "0683478b3a2b49b278bab0d9ba21b92a0a6db75dd0c618368a3ba80979f4e770",
        "8ab693ee678ff93464e21ab259121547864efbc73cd359a8ac020d54fb20ca0a",
        "721d96b1e35a98fd2c4797f27f15b095472503e852ad96cc06da1596bfa717e6",
        "4a21418c3425749ec1b640e4348d80670233879ba7d79844baa12e0b1531685f",
        "01866968735c5a281018708c19e898fd332fbce087fa98109066ac1e5111cf82",
        "a0b08b1cf1733697374b5526603af3387afdc68a0f266f2fb603eee962a9c542",
        "beffc7b9f1d8cf1b731a0be1955887caf92493dda197403fd274256283b70161",
        "58c6b7c066792f8a1291ca521b001d00205887caf92493dda197403fd2742562",
        "83b7016158c6b7c066792f8a1291ca521b00170041041f812a612e1399e5ae51",
        "2ddd9d6ddf745c712cc734a37fd3d14f7591f77cd75836ca06c8036dc39f0ab0",
        "75376d1d086c1243663f07206ec51b4cbf14108db76e002b0005040304030300",
        "0d0018001604030503060308040805080604010501060102030201002d000201",
        "01001c00024001001b000706000100020003fe0d01190000010003b40020312c",
        "0ae27a63a585ce3366bed23561f58306f9f5d302a683716998cd9e40f27c00ef",
        "605ec6614079e62c88f9da17de45e2d2c587c48cbad7c0a3ffb43ab49a96fdf8",
        "f3b325892cd2f3252edb4c3a627185c30ab67151b1bd5e6edc70b63051b8e493",
        "2d3ecd5e5aa2c917da08c3750ecf3f0460ababf0c5efb2d7ba312f364b1a411f",
        "5cd1ab2f7a51a8f341a440d86d268d45d20226cbb2840846e4319c2f2a92df14",
        "51592acd0f3080ec1cf6076e1fb0a80bfb95fa3ef5573e7067eda9c5cd655b78",
        "72ab3473a6e2921c14d70b2a9d87cd8773f024ab556f53f01e449f4b1ed3278c",
        "07bdb65c0d89be11ff0054dc39f70c34e9fc93cacebd587533deb7b25c3e199b",
        "49b3a4b0d94bbfa4d6768d154eccc3"
    );

    // ANCHOR: pppoe_peeled
    #[test]
    fn a_pppoe_session_carrying_ipv4_is_peeled_like_a_vlan_tag() {
        // Frame 1 of pppoe-over-qinq.pcap: two VLAN tags, EtherType 0x8864,
        // a PPPoE session carrying PPP IPv4, then a TCP SYN.
        let raw = hex::decode(QINQ_PPPOE_IPV4_SYN_HEX).unwrap();
        let flow = parse(LinkType::ETHERNET, &raw).unwrap();
        let ethernet = flow.data_link.as_ethernet().unwrap();

        // The tags are consumed first, then the session...
        let tags: Vec<u16> = ethernet.vlan_stack.iter().map(|tag| tag.id).collect();
        assert_eq!(tags, [3704, 2474]);
        let session = ethernet.pppoe.expect("a PPPoE session");
        assert_eq!(session.session_id, 0x0f07);
        assert_eq!(session.length, 66); // the PPP protocol field and the packet
        assert_eq!(session.ppp_protocol, 0x0021);
        assert_eq!(session.ppp_protocol_name(), Some("IPv4"));

        // ...so that `ethertype` and `payload` describe the packet PPP carries:
        // the 64 bytes after 14 + 2 x 4 + 6 + 2.
        assert_eq!(ethernet.ethertype.0, 0x0800);
        assert_eq!(flow.data_link.network_protocol(), NetworkProtocol::Ipv4);
        assert_eq!(ethernet.payload, &raw[30..]);
        assert_eq!(ethernet.payload.len(), 64);

        // From there on, the pipeline is the usual one.
        let internet = flow.internet.as_ref().expect("IPv4");
        assert_eq!(internet.source.unwrap().to_string(), "1.1.1.1");
        assert_eq!(internet.destination.unwrap().to_string(), "2.2.2.2");
        let transport = flow.transport.as_ref().expect("TCP");
        assert_eq!(transport.source_port, Some(20394));
        assert_eq!(transport.destination_port, Some(443));
        assert!(flow.corrupted.is_none());
    }
    // ANCHOR_END: pppoe_peeled

    // ANCHOR: pppoe_ipv6
    #[test]
    fn a_pppoe_session_carrying_ipv6_reaches_the_application_layer() {
        // Frame 10 415 of The-Ultimate-PCAP.pcapng: a subscriber's router asks
        // for an IPv6 prefix over its PPPoE session, under VLAN 7.
        let raw = hex::decode(PPPOE_IPV6_DHCPV6_SOLICIT_HEX).unwrap();
        let flow = parse(LinkType::ETHERNET, &raw).unwrap();
        let ethernet = flow.data_link.as_ethernet().unwrap();

        assert_eq!(ethernet.vlan.as_ref().map(|tag| tag.id), Some(7));
        let session = ethernet.pppoe.unwrap();
        assert_eq!((session.session_id, session.length), (0x8f9e, 149));
        assert_eq!(session.ppp_protocol_name(), Some("IPv6"));
        assert_eq!(flow.data_link.network_protocol(), NetworkProtocol::Ipv6);

        // The PPPoE length bounds the packet: the four bytes after it, at the
        // end of the 177-byte frame, are not handed to IPv6.
        assert_eq!(raw.len(), 14 + 4 + 6 + 149 + 4);
        assert_eq!(ethernet.payload, &raw[26..raw.len() - 4]);

        let internet = flow.internet.as_ref().expect("IPv6");
        assert_eq!(internet.protocol_name, "IPv6");
        assert_eq!(internet.source_type, Some(IpType::LinkLocal));
        assert_eq!(internet.destination.unwrap().to_string(), "ff02::1:2");
        let transport = flow.transport.as_ref().expect("UDP");
        assert_eq!(transport.source_port, Some(546));
        assert_eq!(transport.destination_port, Some(547));
        assert_eq!(flow.application.as_ref().unwrap().application_protocol, "DHCPv6");
    }
    // ANCHOR_END: pppoe_ipv6

    // ANCHOR: pppoe_control
    #[test]
    fn a_ppp_control_protocol_keeps_ethertype_0x8864() {
        // Frame 10 401 of The-Ultimate-PCAP.pcapng: an LCP Configure-Request
        // on session 0x8f9e, in a 64-byte frame.
        let raw = hex::decode(PPPOE_LCP_CONFIGURE_REQUEST_HEX).unwrap();
        let flow = parse(LinkType::ETHERNET, &raw).unwrap();
        let ethernet = flow.data_link.as_ethernet().unwrap();

        let session = ethernet.pppoe.unwrap();
        assert_eq!(session.ppp_protocol, 0xc021);
        assert_eq!(session.ppp_protocol_name(), Some("LCP"));

        // No IP packet to reach: the EtherType stays the session's...
        assert_eq!(ethernet.ethertype.0, PPPOE_SESSION_ETHERTYPE);
        assert_eq!(ethernet.ethertype.static_name(), Some("Pppoe Session Stage"));
        assert_eq!(flow.data_link.network_protocol(), NetworkProtocol::Other(0x8864));

        // ...and the payload is the PPP packet, after the protocol field and
        // within the PPPoE length (16): Configure-Request, identifier 1,
        // length 14. The 24 bytes that follow are left out.
        assert_eq!(&ethernet.payload[..4], [0x01, 0x01, 0x00, 0x0e]);
        assert_eq!(ethernet.payload.len(), 14);
        assert_eq!(raw.len(), 14 + 4 + 6 + 16 + 24);

        // Not decoded is not corrupt: no internet layer, nothing reported.
        assert!(flow.internet.is_none());
        assert!(flow.corrupted.is_none());
        assert!(ethernet.to_string().ends_with("PPPoE: session 0x8f9e, PPP LCP\n"));
    }
    // ANCHOR_END: pppoe_control

    // ANCHOR: pppoe_short_length
    #[test]
    fn a_pppoe_length_shorter_than_the_ip_packet_truncates_it() {
        // Frame 19 of pppoe-over-qinq.pcap: a PPPoE length of 42, and 46 bytes
        // in the frame after the PPP protocol field.
        let raw = hex::decode(QINQ_PPPOE_SHORT_LENGTH_HEX).unwrap();
        let flow = parse(LinkType::ETHERNET, &raw).unwrap();
        let ethernet = flow.data_link.as_ethernet().unwrap();

        assert_eq!(ethernet.pppoe.unwrap().length, 42);
        assert_eq!(raw.len() - 30, 46);
        assert_eq!(ethernet.payload.len(), 40); // 42 minus the protocol field

        // The IPv4 header announces 46 bytes, the PPPoE length gave it 40:
        // the session is kept, the internet layer is reported corrupted.
        assert!(flow.internet.is_none());
        let corrupted = flow.corrupted.expect("a corrupted internet layer");
        assert_eq!(corrupted.layer, CorruptedLayerKind::Internet);
        assert_eq!(
            corrupted.error,
            "IPv4 error: Invalid total length: expected 46 bytes (header: 20 + data: 26), \
             but got 40 bytes"
        );
    }
    // ANCHOR_END: pppoe_short_length

    // ANCHOR: pppoe_flow_identity
    #[test]
    fn the_pppoe_length_is_not_part_of_the_flow_identity() {
        fn hash_of(flow: &PacketFlow<'_>) -> u64 {
            let mut hasher = DefaultHasher::new();
            flow.hash(&mut hasher);
            hasher.finish()
        }
        fn session_id_and_length(flow: &PacketFlow<'_>) -> (u16, u16) {
            let session = flow.data_link.as_ethernet().unwrap().pppoe.unwrap();
            (session.session_id, session.length)
        }

        // Frames 1 and 3 of pppoe-over-qinq.pcap: the SYN and an ACK of the
        // same connection, in the same session, in PPPoE lengths 66 and 42.
        let raw_syn = hex::decode(QINQ_PPPOE_IPV4_SYN_HEX).unwrap();
        let raw_ack = hex::decode(QINQ_PPPOE_IPV4_ACK_HEX).unwrap();
        let syn = parse(LinkType::ETHERNET, &raw_syn).unwrap();
        let ack = parse(LinkType::ETHERNET, &raw_ack).unwrap();
        assert_eq!(session_id_and_length(&syn), (0x0f07, 66));
        assert_eq!(session_id_and_length(&ack), (0x0f07, 42));
        assert_eq!(syn, ack); // one flow
        assert_eq!(hash_of(&syn), hash_of(&ack));

        // Frames 10 401 and 10 409 of The-Ultimate-PCAP.pcapng: LCP and IPCP
        // of one session, both under EtherType 0x8864. The PPP protocol is
        // what tells them apart...
        let raw_lcp = hex::decode(PPPOE_LCP_CONFIGURE_REQUEST_HEX).unwrap();
        let raw_ipcp = hex::decode(PPPOE_IPCP_CONFIGURE_ACK_HEX).unwrap();
        let lcp = parse(LinkType::ETHERNET, &raw_lcp).unwrap();
        let ipcp = parse(LinkType::ETHERNET, &raw_ipcp).unwrap();
        assert_eq!(session_id_and_length(&lcp).0, session_id_and_length(&ipcp).0);
        assert_ne!(lcp, ipcp); // two flows

        // ...and the owned model, which has no session, cannot.
        assert_eq!(lcp.to_owned_flow(), ipcp.to_owned_flow());
    }
    // ANCHOR_END: pppoe_flow_identity

    // ANCHOR: pppoe_json
    #[test]
    fn the_session_is_not_serialized_yet() {
        let raw = hex::decode(QINQ_PPPOE_IPV4_SYN_HEX).unwrap();
        let flow = parse(LinkType::ETHERNET, &raw).unwrap();
        let json = serde_json::to_value(&flow).unwrap();

        // The JSON describes the packet PPP carries...
        assert_eq!(json["data_link"]["link_details"]["ethertype"], "IPv4");
        assert_eq!(json["protocol_internet"], "IPv4");
        assert_eq!(json["destination_port"], 443);
        // ...and holds no trace of the session.
        assert!(!serde_json::to_string(&flow).unwrap().contains("pppoe"));
        // The owned model, which cannot carry it, gives the same JSON.
        assert_eq!(serde_json::to_value(flow.to_owned_flow()).unwrap(), json);
    }
    // ANCHOR_END: pppoe_json

    // ANCHOR: ipv4_tso
    #[test]
    fn a_total_length_of_zero_runs_to_the_end_of_the_frame() {
        // Frame 47 790 of The-Ultimate-PCAP.pcapng: a TLS ClientHello captured
        // on the sending host before its network card segmented it (TSO).
        let raw = hex::decode(IPV4_TSO_TLS_CLIENT_HELLO_HEX).unwrap();
        assert_eq!(raw.len(), 1967);
        let flow = parse(LinkType::ETHERNET, &raw).unwrap();
        assert!(flow.corrupted.is_none()); // InvalidTotalLength before 11.6.0

        let internet = flow.internet.as_ref().expect("IPv4");
        let Some(InternetDetails::Ipv4(ipv4)) = &internet.details else {
            panic!("expected the IPv4 header in details");
        };
        assert_eq!(ipv4.total_length, 0); // the wire value, kept
        assert_eq!(ipv4.payload, &raw[14 + 20..]); // up to the end of the frame

        let transport = flow.transport.as_ref().expect("TCP");
        assert_eq!(transport.destination_port, Some(443));
        assert_eq!(transport.payload.map(<[u8]>::len), Some(1913));
        assert_eq!(flow.application.as_ref().unwrap().application_protocol, "TLS");
    }
    // ANCHOR_END: ipv4_tso
}
