//! The examples of the RDP and WireGuard chapters (`rdp.md`, `wireguard.md`).
//! Each `#[test]` is a chapter snippet, delimited by `ANCHOR` comments that
//! mdBook includes verbatim.
//!
//! Every frame comes from the crate's tracked corpus,
//! `pcaps_exemple/protocols/rdp/` and `pcaps_exemple/protocols/wireguard/`
//! (provenance in each folder's `SOURCE.md`); the bytes were extracted with
//! tshark, frame by frame.

#[cfg(test)]
mod tests {
    use packet_parser::errors::application::rdp::RdpParseError;
    use packet_parser::errors::application::wireguard::WireGuardParseError;
    use packet_parser::parse::application::protocols::copt::CotpPduType;
    use packet_parser::parse::application::protocols::rdp::{
        McsPduType, NegotiationResponse, RdpPacket, RdpPayload,
    };
    use packet_parser::parse::application::protocols::wireguard::{
        WireGuardMessage, WireGuardPacket,
    };
    use packet_parser::{DecodeAsProtocol, LinkType, ParseConfig, parse, parse_with};

    /// Frame 6 of `pcaps_exemple/protocols/rdp/rdp-x509.pcap` (Zeek test corpus):
    /// Ethernet / IPv4 / TCP 54990 -> 3389, the X.224 Connection Request of the
    /// client, with its cookie and a negotiation request.
    const RDP_COOKIE_REQUEST_HEX: &str = concat!(
        "0050568cfc100017c51015400800450000572f2e40008006481fc0a80101c0a8",
        "0102d6ce0d3d0bb104fedd658a035018010062a100000300002f2ae000000000",
        "00436f6f6b69653a206d737473686173683d4a4f484e2d504320200d0a010008",
        "0000000000",
    );

    /// Frame 4 of `rdp-proprietary-encryption.pcap`: TCP 1311 -> 3389, a
    /// Connection Request offering TLS.
    const RDP_TLS_REQUEST_HEX: &str = concat!(
        "001b2f06fa6200059a3c7800080045000057c8894000400622dcac1580100ae2",
        "1834051f0d3d4f99078e3a5fef895018fff03a6200000300002f2ae000000000",
        "00436f6f6b69653a206d737473686173683d465442434f5c4137300d0a010008",
        "0001000000",
    );

    /// Frame 5 of the same capture: TCP 3389 -> 1311, the Connection Confirm that
    /// refuses it.
    const RDP_NEGOTIATION_FAILURE_HEX: &str = concat!(
        "00059a3c7800001b2f06fa6208004500003bfb5f40007d06b3210ae21834ac15",
        "80100d3d051f3a5fef894f9907bd5018ffd0a8ed0000030000130ed000001234",
        "000300080002000000",
    );

    /// Frame 6 of `rdp-to-ssl.pcap`: TCP 3389 -> 49206, a Connection Confirm that
    /// selects CredSSP.
    const RDP_CREDSSP_SELECTED_HEX: &str = concat!(
        "0800274a2a0c080027126d8908004500003b0d2f4000800668dfc0a80196c0a8",
        "01c80d3dc0369b89a66c5565d42d50180100cbea0000030000130ed000001234",
        "000201080002000000",
    );

    /// Frame 8 of the same capture: TCP 49206 -> 3389, the client's next
    /// segment with a payload, a TLS record (its ClientHello).
    const RDP_CLIENT_HELLO_HEX: &str = concat!(
        "080027126d890800274a2a0c0800450000a11d70400080065838c0a801c8c0a8",
        "0196c0360d3d5565d42d9b89a67f5018010005df000016030100740100007003",
        "014d570ec58a9b7d325ed908de8cb2b4de50ec88184a1f6ec723c1d5a344a6cc",
        "34000018002f00350005000ac013c014c009c00a00320038001300040100002f",
        "00000012001000000d3139322e3136382e312e31353000050005010000000000",
        "0a0006000400170018000b00020100",
    );

    /// Frame 32 of `rdp-proprietary-encryption.pcap`: TCP 1312 -> 3389, an MCS
    /// Send Data Request in a TPKT of 94 bytes.
    const RDP_SEND_DATA_HEX: &str = concat!(
        "001b2f06fa6200059a3c7800080045000086d4df400040061657ac1580100ae2",
        "183405200d3d97261aea1af1f2015018ff7d739100000300005e02f080640007",
        "03eb705001020000480000008b689c55b7c81a58755f6260006995ae78bab756",
        "234acd65b0ecb8dcbb9ea69b6520eaecea70ae4adc82423bee7e0718577ac4be",
        "710f16a2bd1d5464598177440000000000000000",
    );

    /// Frame 43 of the same capture: a segment of 1 260 bytes that starts a TPKT
    /// of 1 421.
    const RDP_CUT_TPKT_HEX: &str = concat!(
        "001b2f06fa6200059a3c7800080045000514d524400040061184ac1580100ae2",
        "183405200d3d97261fa11af1f3ad5010ff12a64100000300058d02f080640007",
        "03eb70857e08080000ac9deee397203e0c1f634e7a04ab3c57408c4663a6dee5",
        "a90bfbc1de4b3d7028b761d6bc402859463904778a94b29ffe95aaef886e74a0",
        "0439c102c8474bf4307734d1478a814c559e8bbbb14a80ed0aaa369f22111edf",
        "da1b702469b24db587ca40bfbc05ddbd11c9044f9ef3b2bf532fa89c840acaa9",
        "6520c468e8b272193d6e2deaf34354e5c50a2ab6dfb5049a329a7ddee005273c",
        "af3c3fff441da338ce086cac0b1c1a4c28f06a4f09ea06c3df3b9221824c59ad",
        "96f738e00625df506809764b897b0afb1660fe8831d3cd347de758723007f652",
        "d9bd8c7bcd422b40e7776dc66dfd19d587d9a5d70095660045f2e35b9577bcab",
        "c2727d7edfd2ede67d3b038a1b329fc08b2f1bebab5695de11ce91aa7ffd3eba",
        "61ef4b31bfce68ad616c4191328c0a427e30a9182834a9404d5f1c740453bf66",
        "adbadc510b85850d90464db641e06bb025a173e1a665d208b643f91dd9f40fb8",
        "ba26d712ded0fff96c2a0680119f8f72091dccf399eb9c557c67b93b603e6796",
        "ed24aef0fc251b6b12eeb2391fcdefb67f3b0c7ad6802652766aa3edda5bee3c",
        "f7e02d8c6c349de3547d57a2ee4fa12232391047c13244408d95bdd15466e0a1",
        "53247301b01a65fb3abda2e8eea7bdb12cd61f9c851d4c830fc4a82c0981a119",
        "e4c5e900de40847e112d21cc550c2dabb8a49fe7d2f00b937a053901e77844b4",
        "ca221ed3b2ce560930bd6e623b4e08774a85faf1aa70041c89220d076486d943",
        "526f78b9d72b344fb90d49917c1eb521a3b39bab516a7ad81a8993e497264c33",
        "c4e16772e1200c751172adec46ab5d80b3befd0191d94185d747c22fe0650c04",
        "e0a9d87177b22010929b1bebd4bf670889faae3667afe937e815e366d5694e6c",
        "296c33dacee312199d606ea3e718e9f91ecfa809d275ecc4a420b4e9e19a296f",
        "7217b1c7bcbd434880d3aa8855ef0142177ab0921a4f00a9f59647d9df2f042f",
        "a86b717304b6fd4fd44dd8a31357224fb97c65b1f423199d1f203ea79bd1bf4c",
        "5b2bf18e9ba736d74f525d9e8f96902a9667f23dd10be40831148a1f8626d7e9",
        "73c229221354830215b2398d6f414d1bae09588c70887b74865109742a6c934e",
        "dd6538dad76ec9a5a699b68581d09ddb20c3073751a2dc86f07f8075b503b0c2",
        "841b23fd8d920f0d142f1c93278cde95c99ecd13f2f5422060019b34fd6b966f",
        "b6945fbb222dc140ce0aebcbd861bdbe1cb1e003e379270f3646a44b9891cabc",
        "efbf89c06a1507c7b08a58b12c00af61f10a3c802d4ccd9ac0e49e1d4adea58d",
        "36c432dc8f642d5826b3b7de12b16f22ebf400a82b86f58c9d239fa6b49bd69c",
        "31efe5094fb49ad6397b24b58e103fb709904e5578f8ac1530791bfe28ab82de",
        "99def7dc1964296bf1ddd7fd9275f51a1a4759700ae61adaf307c4089f2d65e7",
        "cc7c12b56c03992b25928d4967ed9472bea9116ff02face71679aea664d8a8ee",
        "94a18a201c57fa0d2356434341bd14633b42923ffdbe4720632fd0104a41bbb9",
        "882861452f1422e90454c7185e1218ac769dd872096ce08ba6bd17ad01674a0d",
        "668633d556c4073bd3b9eb1f859f726b44c0b81051b8ec36572c246f08caff87",
        "45af8cf4b48c7ae37f87bf9b127ad37542517f125c74ef8c6951fb23bb7c74a4",
        "72bfca89de6ef7265302430e09107958c72e4decb74a37a6adb16bf5a1a633f4",
        "2a2168d85bdd59b401fc7b7a37e144c2df8825a5cffd6a4c3d2fda93db55b0ce",
        "74d2",
    );

    /// Frame 44: the next segment, the last 161 bytes of that TPKT.
    const RDP_TPKT_CONTINUATION_HEX: &str = concat!(
        "001b2f06fa6200059a3c78000800450000c9d5254000400615ceac1580100ae2",
        "183405200d3d9726248d1af1f3ad5018ff123fa000000329904c9f8adc26e6c6",
        "eadf3ac628b925fd8a458ba33edbdf8af7688cfdaa81aa1220f31138580bebb5",
        "a95bd101f90876330a16ca9ab86c2d07d77bc7496129aa485dc45264b882c435",
        "e7529f8630e69a88c41be3ec5bd1dd28620a196cd844ed7bb044ece37f33c11c",
        "b6bfdde54bbe8c4de5d09fc3d8baa557d239131d58826ac14c6979da2963ec26",
        "1b54e52b7296bf5c32a908abb99a976bbafe15323a79cc",
    );

    /// Frame 1 of `pcaps_exemple/protocols/wireguard/wireshark_wireguard-ping-tcp.pcap`
    /// (Wireshark repository): Linux WireGuard, Ethernet / IPv4 / UDP 43462 -> 51820,
    /// a Handshake Initiation.
    const WG_INITIATION_HEX: &str = concat!(
        "a2e63494b5833a36e5bf5af80800458800b0024b0000401163560a0900010a09",
        "0002a9c6ca6c009c14c201000000d837d0305fcec7c8e5c8e2e3f7989eef60c2",
        "28d82329d602b6b1e2bb9d068f89cf9d4d4532780f6d27264f7b98701fdc27a4",
        "ec00aeb6becdbef2332f1b4084cadb93823935c012ae255e7b25eff13940c321",
        "fa6bd66a2a87b061db1430173e937f569349de2856dc5f2616763eeeafc0533b",
        "01dd965e7ec76976e28f683d671200000000000000000000000000000000",
    );

    /// Frame 2 of the same capture: UDP 51820 -> 43462, the Handshake Response.
    const WG_RESPONSE_HEX: &str = concat!(
        "3a36e5bf5af8a2e63494b5830800458800782a39000040113ba00a0900020a09",
        "0001ca6ca9c60064148a0200000006f47dabd837d030b18d5550bd4042a37a46",
        "823ac08db1ec66839bc0ca2d64bc15cd80232b66232faec24af8918de1060ff5",
        "c98e865d5f35f272214c5260110dc4c61e32cdd8542100000000000000000000",
        "000000000000",
    );

    /// Frame 3: UDP 43462 -> 51820, the initiator's first Transport Data.
    const WG_DATA_HEX: &str = concat!(
        "a2e63494b5833a36e5bf5af808004500009c024c0000401163f10a0900010a09",
        "0002a9c6ca6c008814ae0400000006f47dab0000000000000000a4ebc12ee3f9",
        "90da18033a0789c04e2700f6f5c271d42ac4b4d6262e666549b445a7436e829b",
        "ffb6ac65f05648bc0c391fe7c5884874376127164940188f03dba67af8388eaa",
        "b76c593628bf9dc7be03346d912e916dad862545454701364f2d2486d7ced4c8",
        "642ce547ddb26ef6a46b",
    );

    /// Frame 9: UDP 43462 -> 51820, a keepalive.
    const WG_KEEPALIVE_HEX: &str = concat!(
        "a2e63494b5833a36e5bf5af808004500003c0976000040115d270a0900010a09",
        "0002a9c6ca6c0028144e0400000006f47dab03000000000000001956e2b6651d",
        "d4f59cb23092a0d09671",
    );

    /// Frame 29 of `ndpi_protonvpn.pcap` (nDPI test corpus): a ProtonVPN client,
    /// UDP 57701 -> 443, a keepalive.
    const PROTONVPN_KEEPALIVE_HEX: &str = concat!(
        "525400123502080027b3e62e08004500003c820340004011d03b0a00020fd917",
        "034ce16501bb002831e5040000005a80d24e0000000000000000b3b5aae8b513",
        "782beb8c9b6ba0f31d8d",
    );

    /// Frame 300 of `ndpi_zoom2.pcap` (nDPI test corpus): Zoom, UDP 8801 -> 58117,
    /// a datagram that starts with `04 00 00 00`.
    const ZOOM_DATAGRAM_HEX: &str = concat!(
        "283737006dc8101331f1397608004500006dc87b40003111e44c90c3499ac0a8",
        "01b22261e3050059703e0400000001006f7254004f8379010540675e5ff0e0eb",
        "5dc2330050b424e5ac4aaac0b89f5e80a3b7dfe8c35a97a02fe356b7d22dc34d",
        "b57eb5def336d3d07de6be65ec7dc4189b14f25cbf9dd048029300",
    );

    // ANCHOR: rdp_connection_request
    #[test]
    fn rdp_on_port_3389_and_the_connection_request() {
        let raw = hex::decode(RDP_COOKIE_REQUEST_HEX).unwrap();
        let flow = parse(LinkType::ETHERNET, &raw).unwrap();
        assert_eq!(flow.application.as_ref().unwrap().application_protocol, "RDP");

        // The label is a classification; RdpPacket is the decode.
        let payload = flow.transport.as_ref().unwrap().payload.unwrap();
        let packet = RdpPacket::try_from(payload).unwrap();
        assert_eq!(packet.pdus.len(), 1); // one TPKT in the segment
        assert!(!packet.truncated);
        let pdu = &packet.pdus[0];
        assert_eq!(pdu.tpkt_length, 47);
        assert_eq!(pdu.cotp.pdu_type, CotpPduType::ConnectionRequest);
        assert_eq!(pdu.cotp.length_indicator, 42);
        assert_eq!((pdu.cotp.dst_ref, pdu.cotp.src_ref), (Some(0), Some(0)));
        assert_eq!(pdu.cotp.class, Some(0));

        let RdpPayload::ConnectionRequest { token, negotiation } = &pdu.payload else {
            panic!("expected a Connection Request, got {:?}", pdu.payload);
        };
        assert_eq!(*token, Some(&b"Cookie: mstshash=JOHN-PC  "[..])); // without CR LF
        assert_eq!(pdu.payload.cookie_user(), Some("JOHN-PC  "));
        let negotiation = negotiation.expect("a negotiation request");
        assert_eq!(negotiation.requested_protocols, 0);
        assert!(negotiation.standard_security_only());

        // Bytes 36-37 are the TCP destination port (Ethernet, IPv4 without
        // options). On 3390 the port guard stays closed...
        let mut moved = raw.clone();
        moved[36..38].copy_from_slice(&3390u16.to_be_bytes());
        let flow = parse(LinkType::ETHERNET, &moved).unwrap();
        assert_eq!(flow.application.as_ref().unwrap().application_protocol, "Unknown");

        // ... until the caller declares the port.
        let config = ParseConfig::new().decode_as(3390, DecodeAsProtocol::Rdp);
        let flow = parse_with(LinkType::ETHERNET, &moved, &config).unwrap();
        assert_eq!(flow.application.as_ref().unwrap().application_protocol, "RDP");
    }
    // ANCHOR_END: rdp_connection_request

    // ANCHOR: rdp_negotiation
    #[test]
    fn the_negotiation_decides_what_follows() {
        // A client offers TLS (rdp-proprietary-encryption.pcap, frame 4)...
        let raw = hex::decode(RDP_TLS_REQUEST_HEX).unwrap();
        let flow = parse(LinkType::ETHERNET, &raw).unwrap();
        let segment = flow.transport.as_ref().unwrap().payload.unwrap();
        let request = RdpPacket::try_from(segment).unwrap();
        let payload = &request.pdus[0].payload;
        assert_eq!(payload.cookie_user(), Some("FTBCO\\A70"));
        let RdpPayload::ConnectionRequest { negotiation: Some(offer), .. } = payload else {
            panic!("expected a negotiation request, got {payload:?}");
        };
        assert_eq!(offer.requested_protocols, 0x0000_0001);
        assert!(offer.tls() && !offer.credssp() && !offer.rdstls());

        // ... and the server refuses it (frame 5): failure code 2, which
        // tshark names "TLS not allowed by server".
        let raw = hex::decode(RDP_NEGOTIATION_FAILURE_HEX).unwrap();
        let flow = parse(LinkType::ETHERNET, &raw).unwrap();
        assert_eq!(flow.application.as_ref().unwrap().application_protocol, "RDP");
        let segment = flow.transport.as_ref().unwrap().payload.unwrap();
        let confirm = RdpPacket::try_from(segment).unwrap();
        assert_eq!(confirm.pdus[0].cotp.pdu_type, CotpPduType::ConnectionConfirm);
        assert_eq!(confirm.pdus[0].cotp.src_ref, Some(0x1234));
        assert_eq!(
            confirm.pdus[0].payload,
            RdpPayload::ConnectionConfirm {
                negotiation: Some(NegotiationResponse::Failure { failure_code: 2 })
            }
        );

        // Another server selects CredSSP (rdp-to-ssl.pcap, frame 6)...
        let raw = hex::decode(RDP_CREDSSP_SELECTED_HEX).unwrap();
        let flow = parse(LinkType::ETHERNET, &raw).unwrap();
        let segment = flow.transport.as_ref().unwrap().payload.unwrap();
        let confirm = RdpPacket::try_from(segment).unwrap();
        assert_eq!(
            confirm.pdus[0].payload,
            RdpPayload::ConnectionConfirm {
                negotiation: Some(NegotiationResponse::Accepted {
                    flags: 0x01,
                    selected_protocol: 2
                })
            }
        );

        // ... so the client's next segment with a payload (frame 8) is a TLS
        // record: on port 3389 it fails the TPKT check, and the blind TLS rule
        // labels it.
        let raw = hex::decode(RDP_CLIENT_HELLO_HEX).unwrap();
        let flow = parse(LinkType::ETHERNET, &raw).unwrap();
        let transport = flow.transport.as_ref().unwrap();
        assert_eq!(transport.destination_port, Some(3389));
        assert_eq!(flow.application.as_ref().unwrap().application_protocol, "TLS");
        assert_eq!(
            RdpPacket::try_from(transport.payload.unwrap()),
            Err(RdpParseError::InvalidTpkt { version: 0x16, reserved: 0x03 })
        );
    }
    // ANCHOR_END: rdp_negotiation

    // ANCHOR: rdp_mcs
    #[test]
    fn mcs_send_data_and_a_tpkt_cut_by_tcp() {
        // rdp-proprietary-encryption.pcap, frame 32: a Send Data Request,
        // whole in its segment.
        let raw = hex::decode(RDP_SEND_DATA_HEX).unwrap();
        let flow = parse(LinkType::ETHERNET, &raw).unwrap();
        assert_eq!(flow.application.as_ref().unwrap().application_protocol, "RDP");
        let segment = flow.transport.as_ref().unwrap().payload.unwrap();
        let packet = RdpPacket::try_from(segment).unwrap();
        assert!(!packet.truncated);
        let pdu = &packet.pdus[0];
        assert_eq!(pdu.tpkt_length, 94);
        assert_eq!(pdu.cotp.pdu_type, CotpPduType::Data);
        assert_eq!(pdu.cotp.end_of_tsdu, Some(true));
        let RdpPayload::Mcs(mcs) = &pdu.payload else {
            panic!("expected an MCS PDU, got {:?}", pdu.payload);
        };
        assert_eq!(mcs.kind, McsPduType::SendDataRequest);
        let send = mcs.send_data.expect("a Send Data is decoded");
        assert_eq!(send.initiator, 1008); // 7 on the wire, plus 1001
        assert_eq!(send.channel_id, 1003);
        assert_eq!(send.priority_and_segmentation, 0x70);
        assert_eq!(send.declared_length, Some(80));
        assert_eq!(send.data.len(), 80);

        // Frame 43: the segment holds 1 260 bytes of a TPKT of 1 421. It is
        // decoded on what is there, and marked.
        let raw = hex::decode(RDP_CUT_TPKT_HEX).unwrap();
        let flow = parse(LinkType::ETHERNET, &raw).unwrap();
        assert_eq!(flow.application.as_ref().unwrap().application_protocol, "RDP");
        let segment = flow.transport.as_ref().unwrap().payload.unwrap();
        let packet = RdpPacket::try_from(segment).unwrap();
        assert_eq!((segment.len(), packet.pdus[0].tpkt_length), (1260, 1421));
        assert!(packet.truncated);
        let RdpPayload::Mcs(mcs) = &packet.pdus[0].payload else {
            panic!("expected an MCS PDU, got {:?}", packet.pdus[0].payload);
        };
        let send = mcs.send_data.expect("a Send Data is decoded");
        assert_eq!(send.declared_length, Some(1406));
        assert_eq!(send.data.len(), 1245); // what this segment carries

        // Frame 44 carries the other 161 bytes, without a header of its own:
        // its first byte happens to be 3, but a reserved byte of 0x29 is not
        // a TPKT.
        let raw = hex::decode(RDP_TPKT_CONTINUATION_HEX).unwrap();
        let flow = parse(LinkType::ETHERNET, &raw).unwrap();
        assert_eq!(flow.application.as_ref().unwrap().application_protocol, "Unknown");
        assert_eq!(
            RdpPacket::try_from(flow.transport.as_ref().unwrap().payload.unwrap()),
            Err(RdpParseError::InvalidTpkt { version: 3, reserved: 0x29 })
        );
    }
    // ANCHOR_END: rdp_mcs

    // ANCHOR: wireguard_handshake
    #[test]
    fn a_wireguard_handshake_on_udp_51820() {
        let initiation_frame = hex::decode(WG_INITIATION_HEX).unwrap();
        let flow = parse(LinkType::ETHERNET, &initiation_frame).unwrap();
        assert_eq!(flow.transport.as_ref().unwrap().destination_port, Some(51820));
        assert_eq!(flow.application.as_ref().unwrap().application_protocol, "WireGuard");

        let datagram = flow.transport.as_ref().unwrap().payload.unwrap();
        let packet = WireGuardPacket::try_from(datagram).unwrap();
        assert_eq!((packet.message_type, packet.reserved), (1, [0; 3]));
        let WireGuardMessage::HandshakeInitiation(initiation) = &packet.message else {
            panic!("expected an initiation, got {:?}", packet.message);
        };
        assert_eq!(datagram.len(), 148);
        assert_eq!(initiation.sender_index, 0x30d0_37d8);
        // Fixed-size fields, borrowed from the datagram.
        assert_eq!(initiation.unencrypted_ephemeral.as_slice(), &datagram[8..40]);
        assert_eq!(initiation.mac1.as_slice(), &datagram[116..132]);
        assert_eq!(initiation.mac2, &[0; 16]); // no Cookie Reply came before

        // The response answers that index with one of its own.
        let response_frame = hex::decode(WG_RESPONSE_HEX).unwrap();
        let flow = parse(LinkType::ETHERNET, &response_frame).unwrap();
        let datagram = flow.transport.as_ref().unwrap().payload.unwrap();
        let packet = WireGuardPacket::try_from(datagram).unwrap();
        let WireGuardMessage::HandshakeResponse(response) = &packet.message else {
            panic!("expected a response, got {:?}", packet.message);
        };
        assert_eq!(datagram.len(), 92);
        assert_eq!(response.sender_index, 0xab7d_f406);
        assert_eq!(response.receiver_index, initiation.sender_index);
        assert_eq!(response.encrypted_nothing.as_slice(), &datagram[44..60]);
    }
    // ANCHOR_END: wireguard_handshake

    // ANCHOR: wireguard_transport_data
    #[test]
    fn transport_data_and_a_keepalive() {
        let frame = hex::decode(WG_DATA_HEX).unwrap();
        let flow = parse(LinkType::ETHERNET, &frame).unwrap();
        assert_eq!(flow.application.as_ref().unwrap().application_protocol, "WireGuard");
        let datagram = flow.transport.as_ref().unwrap().payload.unwrap();
        let packet = WireGuardPacket::try_from(datagram).unwrap();
        let WireGuardMessage::TransportData(data) = &packet.message else {
            panic!("expected Transport Data, got {:?}", packet.message);
        };
        assert_eq!(data.receiver_index, 0xab7d_f406); // the responder's index
        assert_eq!(data.counter, 0);
        assert_eq!(datagram.len(), 128);
        // 96 bytes of plaintext, a multiple of 16, then the 16-byte tag.
        assert_eq!(data.encrypted_packet.len(), 112);
        assert!(!data.is_keepalive());

        let frame = hex::decode(WG_KEEPALIVE_HEX).unwrap();
        let flow = parse(LinkType::ETHERNET, &frame).unwrap();
        let datagram = flow.transport.as_ref().unwrap().payload.unwrap();
        let packet = WireGuardPacket::try_from(datagram).unwrap();
        let WireGuardMessage::TransportData(keepalive) = &packet.message else {
            panic!("expected Transport Data, got {:?}", packet.message);
        };
        assert_eq!(keepalive.counter, 3);
        assert_eq!(keepalive.encrypted_packet.len(), 16); // the tag alone
        assert!(keepalive.is_keepalive());
    }
    // ANCHOR_END: wireguard_transport_data

    // ANCHOR: wireguard_detection
    #[test]
    fn three_rules_from_the_most_tolerant_to_the_strictest() {
        let label = |frame: &[u8], config: &ParseConfig| {
            let flow = parse_with(LinkType::ETHERNET, frame, config).unwrap();
            flow.application.as_ref().map(|application| application.application_protocol)
        };
        // Ethernet and IPv4 without options: the UDP ports are bytes 34-37,
        // the datagram starts at byte 42.
        let off_port = |frame: &[u8]| {
            let mut moved = frame.to_vec();
            moved[34..38].copy_from_slice(&[0x9c, 0x40, 0x9c, 0x41]); // 40000 -> 40001
            moved
        };
        let reserved = |frame: &[u8]| {
            let mut altered = frame.to_vec();
            altered[43..46].copy_from_slice(&[0x02, 0x78, 0x00]); // non-zero reserved bytes
            altered
        };
        let default = ParseConfig::new();
        let declared = ParseConfig::new().decode_as(40_001, DecodeAsProtocol::WireGuard);
        let keepalive = hex::decode(WG_KEEPALIVE_HEX).unwrap();
        let initiation = hex::decode(WG_INITIATION_HEX).unwrap();

        // As captured, on 51820, then moved to 40000 -> 40001: the port rule,
        // then the blind probe.
        assert_eq!(label(&keepalive, &default), Some("WireGuard"));
        assert_eq!(label(&off_port(&keepalive), &default), Some("WireGuard"));

        // Non-zero reserved bytes: 51820 still takes a handshake, but not
        // Transport Data, like tshark's heuristic.
        assert_eq!(label(&reserved(&initiation), &default), Some("WireGuard"));
        assert_eq!(label(&reserved(&keepalive), &default), Some("Unknown"));

        // The blind probe takes neither...
        assert_eq!(label(&off_port(&reserved(&initiation)), &default), Some("Unknown"));
        assert_eq!(label(&off_port(&reserved(&keepalive)), &default), Some("Unknown"));

        // ... and a declared port takes both: Decode As checks the shape only.
        assert_eq!(label(&off_port(&reserved(&initiation)), &declared), Some("WireGuard"));
        assert_eq!(label(&off_port(&reserved(&keepalive)), &declared), Some("WireGuard"));
    }
    // ANCHOR_END: wireguard_detection

    // ANCHOR: wireguard_blind_probe
    #[test]
    fn the_blind_probe_on_real_traffic() {
        // ProtonVPN on UDP 443: the QUIC short-header rule of that port wants
        // the 0x40 bit in the first byte, which no WireGuard type has, and the
        // blind probe, last of the UDP cascade, takes the keepalive.
        let frame = hex::decode(PROTONVPN_KEEPALIVE_HEX).unwrap();
        let flow = parse(LinkType::ETHERNET, &frame).unwrap();
        assert_eq!(flow.transport.as_ref().unwrap().destination_port, Some(443));
        assert_eq!(flow.application.as_ref().unwrap().application_protocol, "WireGuard");

        // Zoom: `04 00 00 00` and 81 bytes are the shape of Transport Data, and
        // tshark's heuristic accepts the datagram. The blind probe does not.
        let frame = hex::decode(ZOOM_DATAGRAM_HEX).unwrap();
        let flow = parse(LinkType::ETHERNET, &frame).unwrap();
        assert_eq!(flow.application.as_ref().unwrap().application_protocol, "Unknown");
        let datagram = flow.transport.as_ref().unwrap().payload.unwrap();
        let packet = WireGuardPacket::try_from(datagram).unwrap(); // the shape is there
        assert_eq!(packet.reserved, [0; 3]);
        let WireGuardMessage::TransportData(data) = &packet.message else {
            panic!("expected the shape of Transport Data, got {:?}", packet.message);
        };
        assert!(data.counter >= 1 << 60); // REKEY_AFTER_MESSAGES
        let plaintext = datagram.len() - 32; // minus the header and the tag
        assert_eq!(plaintext, 49); // not a multiple of 16, and below 552

        // A port the caller declares is WireGuard as soon as the shape is.
        let config = ParseConfig::new().decode_as(8801, DecodeAsProtocol::WireGuard);
        let flow = parse_with(LinkType::ETHERNET, &frame, &config).unwrap();
        assert_eq!(flow.application.as_ref().unwrap().application_protocol, "WireGuard");
    }
    // ANCHOR_END: wireguard_blind_probe

    // ANCHOR: wireguard_errors
    #[test]
    fn what_wireguard_packet_refuses() {
        let frame = hex::decode(WG_KEEPALIVE_HEX).unwrap();
        let flow = parse(LinkType::ETHERNET, &frame).unwrap();
        let keepalive = flow.transport.as_ref().unwrap().payload.unwrap();
        assert_eq!(
            WireGuardPacket::try_from(&keepalive[..31]),
            Err(WireGuardParseError::Truncated { expected: 32, actual: 31 })
        );

        let frame = hex::decode(WG_INITIATION_HEX).unwrap();
        let flow = parse(LinkType::ETHERNET, &frame).unwrap();
        let mut longer = flow.transport.as_ref().unwrap().payload.unwrap().to_vec();
        longer.push(0);
        assert_eq!(
            WireGuardPacket::try_from(longer.as_slice()),
            Err(WireGuardParseError::InvalidLength { message_type: 1, expected: 148, actual: 149 })
        );

        // The type byte of Cloudflare's official WARP client.
        let mut warp = keepalive.to_vec();
        warp[0] = 0xc4;
        let error = WireGuardPacket::try_from(warp.as_slice()).unwrap_err();
        assert_eq!(error, WireGuardParseError::UnknownMessageType(0xc4));
        assert_eq!(error.to_string(), "Unknown WireGuard message type 196");
    }
    // ANCHOR_END: wireguard_errors
}
