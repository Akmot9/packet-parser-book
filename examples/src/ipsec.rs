//! The examples of the IKE and ESP chapters. Every frame is a real one from
//! the crate's corpus, its bytes taken with tshark (`tshark -T json -x`),
//! with the capture file and the frame number in the comment above it.

#[cfg(test)]
mod tests {
    use packet_parser::errors::application::ike::IkeParseError;
    use packet_parser::errors::transport::esp::EspError;
    use packet_parser::parse::application::protocols::ike::{
        ExchangeType, IkePacket, PayloadType, UdpEncapsulation,
    };
    use packet_parser::parse::transport::protocols::{TransportProtocol, esp::EspPacket};
    use packet_parser::{
        DecodeAsProtocol, LinkType, ParseConfig, TransportDetails, parse, parse_with,
    };

    /// Frame 1 of `pcaps_exemple/protocols/ipsec/ikev2_s2s_ipsec_vpn_aes_gcm.pcapng`
    /// (Wireshark wiki, a site-to-site VPN): Ethernet / IPv4 / UDP 500 -> 500,
    /// the initiator's IKE_SA_INIT, 374 bytes.
    const IKEV2_SA_INIT_HEX: &str = concat!(
        "50000002000150000001000108004500019237b80000ff116ea00a0000010a00",
        "000201f401f4017e60d362f94c9887715a340000000000000000212022080000",
        "0000000001762200002800000024010100030300000c01000014800e01000300",
        "000802000005000000080400001328000048001300004b59d6332b28b9e9d8c9",
        "f16e1f49614e5ea32b06f928a872a9435a16c00f16b0ceb951c06a6c69d1e138",
        "3926e5e72ed73c04e412e0b8da0fcaf1800fef6531842b0000448e0fffb0d754",
        "b65d52da18adfdc1a9f2b8c9284ca26fafb389b925c318483a13cf7b62489b15",
        "d38281aabab28a84b301385b1e04b37797764c0aa79bce3143462b0000174349",
        "53434f2d44454c4554452d524541534f4e2900003b434953434f28434f505952",
        "494748542926436f7079726967687420286329203230303920436973636f2053",
        "797374656d732c20496e632e2900001c010040045332b489ab0b4e69d77aca54",
        "53cfe6bc1528d7982900001c0100400531c1256e8602c28d9ba17c9c07201b99",
        "06ed6bc92b0000080000402e000000144048b7d56ebce88525e7de7f00d6c2d3",
    );

    /// Frame 4 of the same capture: the responder's IKE_AUTH, UDP 500 -> 500.
    const IKEV2_IKE_AUTH_RESPONSE_HEX: &str = concat!(
        "500000010001500000020001080045000101578b0000ff114f5e0a0000020a00",
        "000101f401f400ed9c3362f94c9887715a34f05534eef373dc1b2e2023200000",
        "0001000000e52b0000c90000000000000000a313da87397423dd5648a1483d91",
        "b34eeed79295b89f69ca1dfb868e2e5d28f9f7834b2358940a4c57bc4f5c65c9",
        "dac3175905726607549ef6d42d8c05606bcce9f5d8af98ea44851c7a889e2bb2",
        "111f41665e0b077252cb3f65417e7e668cb8d537f6c08ef80dc7d6082fecd4b6",
        "c9711069cca44ea3f26fa0e9828c446f44d7ae7e93e265e4e36a3971b8746176",
        "82060fd99162609c4f49bad34f4c3d615709624025a35444a06c7b6e065684b1",
        "1bc60a848b5e0651b3bad3c6f40f02",
    );

    /// Frame 1 of `pcaps_exemple/protocols/ipsec/attachment_ikev1_main_mode.pcap`
    /// (Wireshark wiki): UDP 500 -> 500, the first IKEv1 main mode message.
    const IKEV1_MAIN_MODE_HEX: &str = concat!(
        "007076696600000c29d47370080045000098536b4000401157b10a013d9b0a01",
        "3d9c01f401f40084defab31615b5ec7a4faf0000000000000000011002000000",
        "00000000007c0d00003800000001000000010000002c01010001000000240101",
        "0000800b0001800c708080010007800e00808003000180020002800400020d00",
        "0014afcad71368a1f1c96b8696fc7757010000000014a9b9b1034f7e50a2513b",
        "47b100bb85a9",
    );

    /// Frame 5 of the same capture: the fifth main mode message, sent with
    /// the E flag once the keys are agreed.
    const IKEV1_ENCRYPTED_HEX: &str = concat!(
        "007076696600000c29d4737008004500006853734000401157d90a013d9b0a01",
        "3d9c01f401f400544537b31615b5ec7a4faf71cdf256f717b6e8051002010000",
        "00000000004ce8e4fab1304e637f199b726453526619cea379a8aadd75507372",
        "2dbc2c6cbc872ca140c3b79ec64a4bfe2a8ea8d34e5b",
    );

    /// Frame 42 of `pcaps_exemple/protocols/ipsec/ipsec_isakmp_esp.pcap` (nDPI
    /// test corpus): UDP 4500 -> 14500, the non-ESP marker, then an IKEv2
    /// INFORMATIONAL.
    const NAT_T_IKE_HEX: &str = concat!(
        "6038e0c535a07894b42404a008004500006ca5180000f71131ad6dedbbc1c0a8",
        "0264119438a400580bb700000000de648338c613aa68d8b3038904240d4b2e20",
        "2500000000000000004c2a0000307249ae95a1dd31844a69f8046dd89aa167d2",
        "8a139c9c0ae217f4d63e5cb8b81e4c526cff390679acabb28be2",
    );

    /// Frame 11 of the same capture: UDP 4500 -> 14500, an ESP packet.
    const NAT_T_ESP_HEX: &str = concat!(
        "6038e0c535a07894b42404a00800450000a08a17000038110b7b6dedbbc1c0a8",
        "0264119438a4008c0000cbb7a0c6000000012b0f39c7c851181d561b92e517e2",
        "f5fb89e08aed877ad0bee8aea56f8427a4f6fbc9d00b73579e82bcca2f17324f",
        "cac1485c7e786df1085c7426f80721f02b6eb548119a3bc00f62aa24e966cdf1",
        "2bb32f22a3b890980f6d1f7d142521a506106f068b77fce6e2e8d17f19bf9c35",
        "53e731c2e70485c64ecd1de209ee",
    );

    /// Frame 5 of `ikev2_s2s_ipsec_vpn_aes_gcm.pcapng`: Ethernet / IPv4,
    /// protocol 50, the first ESP packet of the VPN.
    const NATIVE_ESP_IPV4_HEX: &str = concat!(
        "50000002000150000001000108004500008c3a83000040322bbb0a0000010a00",
        "00025fbd60dc000000010000000000000001fe32d6d07bb84c7f20c1b8d9f819",
        "65bf648259aea99a61b0727baa0e95e33b1e2d3ec2598d60151077c0de271207",
        "489090d2eba6921d31ef30b2eb24189bb5fff2cb057e5835e9cb4d27f7f9bcea",
        "4ffd6581f0009065848457c9a8a2756672a8d2002f334d61675a",
    );

    /// Frame 6601 of `pcaps_exemple/The-Ultimate-PCAP.pcapng` (Johannes
    /// Weber): Ethernet / IPv6, next header 50, an ESP packet.
    const NATIVE_ESP_IPV6_HEX: &str = concat!(
        "085b0e3c115db40c25058e1086dd600000000098323f20030051601200000000",
        "000000000002200300516012000000000000000000043d71315500000001e93e",
        "e38f275f171b1dd517c01bed1c7b4286af3d685500ae9b16471809ac8870a844",
        "c2c14b5ae90d3914f1b0a90cf59c32f85cddb1b099ea83cd7dad58256248b126",
        "4acd6029c2e58ac9ce67f3c13ed78f35fd9c7fd456e2c288abcea768970521fd",
        "77fbef0402ee22e8c5dc6f6a3488c897e8acc1134a318a393aee788a0da08908",
        "8277a42c75b0fda21cdee1948ef0",
    );

    /// Frame 46989 of `pcaps_exemple/The-Ultimate-PCAP.pcapng`: UDP 4500 ->
    /// 4500, a NAT-keepalive.
    const NAT_KEEPALIVE_HEX: &str = concat!(
        "0070766966003cfa3003121008004500001dd20b40003f11366c645d07fac2f7",
        "040a119411940009aa5aff00000000000000000000000000",
    );

    /// Ethernet + IPv4 without options: the two UDP ports are bytes 34 to 37.
    fn move_to_port_4501(frame: &mut [u8]) {
        frame[34..38].copy_from_slice(&[0x11, 0x95, 0x11, 0x95]);
    }

    fn label(raw: &[u8], config: &ParseConfig) -> Option<&'static str> {
        let flow = parse_with(LinkType::ETHERNET, raw, config).unwrap();
        Some(flow.application?.application_protocol)
    }

    // ANCHOR: ike_sa_init
    #[test]
    fn an_ike_sa_init_on_udp_500() {
        let raw = hex::decode(IKEV2_SA_INIT_HEX).unwrap();
        let flow = parse(LinkType::ETHERNET, &raw).unwrap();

        // Port 500 and a message whose length covers the datagram: "IKE".
        assert_eq!(
            flow.application.as_ref().unwrap().application_protocol,
            "IKE"
        );

        let payload = flow.transport.as_ref().unwrap().payload.unwrap();
        let ike = IkePacket::from_udp(payload).unwrap();
        let header = ike.header;
        assert_eq!(header.initiator_spi, 0x62f9_4c98_8771_5a34);
        assert_eq!(header.responder_spi, 0); // not chosen yet
        assert_eq!((header.major_version(), header.minor_version()), (2, 0));
        assert_eq!(header.exchange(), Some(ExchangeType::IkeSaInit));
        assert!(header.initiator_flag() && !header.response_flag());
        assert_eq!((header.message_id, header.length), (0, 374));

        // The top-level chain: SA, KE, Nonce, two Vendor IDs, three
        // Notifications, a Vendor ID; the last one says "no next payload".
        assert_eq!(
            ike.payload_types().collect::<Vec<_>>(),
            [33, 34, 40, 43, 43, 41, 41, 41, 43]
        );
        assert_eq!(ike.payloads[0].kind, Some(PayloadType::SecurityAssociation));
        assert_eq!(ike.payloads[2].kind, Some(PayloadType::Nonce));
        assert_eq!(ike.payloads[3].length, 23); // generic header included
        assert_eq!(ike.payloads[3].body, b"CISCO-DELETE-REASON");
        assert_eq!(ike.payloads[8].next_payload, 0);
        assert!(ike.payloads.iter().all(|payload| !payload.critical));
        assert_eq!(ike.encrypted_body, None);
    }
    // ANCHOR_END: ike_sa_init

    // ANCHOR: ike_encrypted
    #[test]
    fn what_is_encrypted_stays_bytes() {
        // IKEv2, frame 4: the IKE_AUTH response is a single SK payload.
        let raw = hex::decode(IKEV2_IKE_AUTH_RESPONSE_HEX).unwrap();
        let flow = parse(LinkType::ETHERNET, &raw).unwrap();
        let payload = flow.transport.as_ref().unwrap().payload.unwrap();
        let auth = IkePacket::from_udp(payload).unwrap();
        assert_eq!(auth.header.initiator_spi, 0x62f9_4c98_8771_5a34); // same IKE SA
        assert_eq!(auth.header.responder_spi, 0xf055_34ee_f373_dc1b);
        assert_eq!(auth.header.exchange(), Some(ExchangeType::IkeAuth));
        assert!(auth.header.response_flag());
        assert_eq!(auth.payload_types().collect::<Vec<_>>(), [46]);
        let sk = &auth.payloads[0];
        assert_eq!(sk.kind, Some(PayloadType::Encrypted));
        assert_eq!(sk.next_payload, 43); // the first payload under the encryption
        assert_eq!(sk.length, 201);
        assert_eq!(auth.encrypted_body, Some(sk.body));
        assert_eq!(sk.body.len(), 197);

        // IKEv1, frames 1 and 5 of the main mode: in clear, then under the E flag.
        let raw = hex::decode(IKEV1_MAIN_MODE_HEX).unwrap();
        let flow = parse(LinkType::ETHERNET, &raw).unwrap();
        let payload = flow.transport.as_ref().unwrap().payload.unwrap();
        let first = IkePacket::from_udp(payload).unwrap();
        assert_eq!(first.header.major_version(), 1);
        assert_eq!(
            first.header.exchange(),
            Some(ExchangeType::IdentityProtection)
        );
        assert_eq!(first.payload_types().collect::<Vec<_>>(), [1, 13, 13]); // SA, two VIDs

        let raw = hex::decode(IKEV1_ENCRYPTED_HEX).unwrap();
        let flow = parse(LinkType::ETHERNET, &raw).unwrap();
        let payload = flow.transport.as_ref().unwrap().payload.unwrap();
        let fifth = IkePacket::from_udp(payload).unwrap();
        assert!(fifth.header.encryption_flag());
        assert_eq!(fifth.header.next_payload, 5); // Identification, under the encryption
        assert!(fifth.payloads.is_empty());
        assert_eq!(fifth.encrypted_body.map(<[u8]>::len), Some(76 - 28));
    }
    // ANCHOR_END: ike_encrypted

    // ANCHOR: ike_nat_t
    #[test]
    fn ike_on_udp_4500_follows_the_non_esp_marker() {
        let raw = hex::decode(NAT_T_IKE_HEX).unwrap();
        let flow = parse(LinkType::ETHERNET, &raw).unwrap();
        let transport = flow.transport.as_ref().unwrap();
        assert_eq!(
            (transport.source_port, transport.destination_port),
            (Some(4500), Some(14500))
        );
        assert_eq!(
            flow.application.as_ref().unwrap().application_protocol,
            "IKE"
        );

        let payload = transport.payload.unwrap();
        assert_eq!(&payload[..4], [0, 0, 0, 0]); // the non-ESP marker

        // Read bare, the marker becomes half of an initiator SPI, every field
        // slides by four bytes, and the length read is 0.
        assert_eq!(
            IkePacket::try_from(payload),
            Err(IkeParseError::LengthMismatch {
                declared: 0,
                actual: 80
            })
        );
        let Ok(UdpEncapsulation::Ike(message)) = UdpEncapsulation::classify(payload) else {
            panic!("expected the non-ESP marker");
        };
        assert_eq!(message.len(), 76);

        // from_udp tries the bare message, then what follows the marker.
        let ike = IkePacket::from_udp(payload).unwrap();
        assert_eq!(ike.header.initiator_spi, 0xde64_8338_c613_aa68);
        assert_eq!(ike.header.exchange(), Some(ExchangeType::Informational));
        assert_eq!(ike.header.length, 76);
        assert_eq!(ike.payload_types().collect::<Vec<_>>(), [46]);
    }
    // ANCHOR_END: ike_nat_t

    // ANCHOR: ike_decode_as
    #[test]
    fn ike_on_another_port_needs_decode_as() {
        let mut raw = hex::decode(NAT_T_IKE_HEX).unwrap();
        move_to_port_4501(&mut raw);

        // The same bytes, on a port the table does not guard: no IKE.
        assert_eq!(label(&raw, &ParseConfig::new()), Some("Unknown"));

        // Declared, the port is guarded too, and the content still decides.
        let config = ParseConfig::new().decode_as(4501, DecodeAsProtocol::Ike);
        assert_eq!(label(&raw, &config), Some("IKE"));
    }
    // ANCHOR_END: ike_decode_as

    // ANCHOR: esp_native
    #[test]
    fn native_esp_is_decoded_by_the_transport_layer() {
        let raw = hex::decode(NATIVE_ESP_IPV4_HEX).unwrap();
        let flow = parse(LinkType::ETHERNET, &raw).unwrap();

        let transport = flow.transport.as_ref().unwrap();
        assert_eq!(transport.protocol, TransportProtocol::Esp);
        assert_eq!(
            (transport.source_port, transport.destination_port),
            (None, None)
        );
        // Nothing readable stacks above: no payload, so no application probe.
        assert!(transport.payload.is_none());
        assert!(flow.application.is_none() && flow.corrupted.is_none());

        let Some(TransportDetails::Esp(esp)) = &transport.details else {
            panic!("expected the ESP header in details");
        };
        assert_eq!(esp.spi, 0x5fbd_60dc);
        assert_eq!(esp.sequence, 1);
        assert_eq!(esp.payload.len(), 112); // IV, ciphertext, trailer and ICV

        // The JSON names the protocol; the SPI, in details, is not serialized.
        let json = serde_json::to_value(flow.to_owned_flow()).unwrap();
        assert_eq!(json["protocol_transport"], "ESP");
        assert!(json.get("spi").is_none());

        // Over IPv6, next header 50 ends the extension walk: same layer.
        let raw = hex::decode(NATIVE_ESP_IPV6_HEX).unwrap();
        let flow = parse(LinkType::ETHERNET, &raw).unwrap();
        assert_eq!(flow.internet.as_ref().unwrap().protocol_name, "IPv6");
        let Some(TransportDetails::Esp(esp)) = &flow.transport.as_ref().unwrap().details else {
            panic!("expected the ESP header in details");
        };
        assert_eq!((esp.spi, esp.sequence), (0x3d71_3155, 1));
    }
    // ANCHOR_END: esp_native

    // ANCHOR: esp_unreadable
    #[test]
    fn an_unreadable_esp_packet_does_not_corrupt_the_flow() {
        let mut raw = hex::decode(NATIVE_ESP_IPV4_HEX).unwrap();
        raw[34..38].copy_from_slice(&[0, 0, 0, 0]); // SPI 0, reserved by RFC 4303

        let flow = parse(LinkType::ETHERNET, &raw).unwrap();
        let transport = flow.transport.as_ref().unwrap();
        assert_eq!(transport.protocol, TransportProtocol::Esp); // still named
        assert!(transport.details.is_none());
        assert!(flow.corrupted.is_none());

        // The reason is one call away, on the internet payload.
        let internet = flow.internet.as_ref().unwrap();
        assert_eq!(
            EspPacket::try_from(internet.payload),
            Err(EspError::ReservedSpi)
        );
    }
    // ANCHOR_END: esp_unreadable

    // ANCHOR: esp_nat_t
    #[test]
    fn esp_and_keepalives_on_udp_4500() {
        // Frame 11: an ESP packet, non-zero SPI first.
        let raw = hex::decode(NAT_T_ESP_HEX).unwrap();
        let flow = parse(LinkType::ETHERNET, &raw).unwrap();
        assert_eq!(
            flow.application.as_ref().unwrap().application_protocol,
            "ESP"
        );
        assert!(flow.inner.is_none()); // a label, not a tunnel: nothing to peel

        let payload = flow.transport.as_ref().unwrap().payload.unwrap();
        assert_eq!(
            UdpEncapsulation::classify(payload),
            Ok(UdpEncapsulation::Esp(payload))
        );
        let esp = EspPacket::try_from(payload).unwrap();
        assert_eq!((esp.spi, esp.sequence), (0xcbb7_a0c6, 1));
        assert_eq!(esp.payload.len(), payload.len() - 8);

        // Frame 46989 of the Ultimate PCAP: one byte, 0xFF.
        let raw = hex::decode(NAT_KEEPALIVE_HEX).unwrap();
        let flow = parse(LinkType::ETHERNET, &raw).unwrap();
        assert_eq!(
            flow.application.as_ref().unwrap().application_protocol,
            "NAT-keepalive"
        );

        let payload = flow.transport.as_ref().unwrap().payload.unwrap();
        assert_eq!(payload, [0xff]); // the Ethernet trailer is cut by IPv4
        assert_eq!(
            UdpEncapsulation::classify(payload),
            Ok(UdpEncapsulation::Keepalive)
        );
    }
    // ANCHOR_END: esp_nat_t

    // ANCHOR: esp_decode_as
    #[test]
    fn esp_on_another_port_needs_decode_as() {
        let mut raw = hex::decode(NAT_T_ESP_HEX).unwrap();
        move_to_port_4501(&mut raw);
        assert_eq!(label(&raw, &ParseConfig::new()), Some("Unknown"));

        let config = ParseConfig::new().decode_as(4501, DecodeAsProtocol::Esp);
        assert_eq!(label(&raw, &config), Some("ESP"));

        // A declaration names a protocol, and that protocol's probe decides.
        let config = ParseConfig::new().decode_as(4501, DecodeAsProtocol::Ike);
        assert_eq!(label(&raw, &config), Some("Unknown"));

        // The keepalive has no Decode As: off 4500, its byte is just a byte.
        let mut raw = hex::decode(NAT_KEEPALIVE_HEX).unwrap();
        move_to_port_4501(&mut raw);
        let config = ParseConfig::new().decode_as(4501, DecodeAsProtocol::Esp);
        assert_eq!(label(&raw, &config), Some("Unknown"));
    }
    // ANCHOR_END: esp_decode_as
}
