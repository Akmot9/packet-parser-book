//! Examples of the BACnet/IP and RADIUS chapters: two UDP protocols with a
//! port rule and a blind probe. Every frame comes from the crate's corpus,
//! extracted with tshark; the comment above each constant names the capture
//! (under `pcaps_exemple/` in the crate repository) and the frame number.

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use packet_parser::errors::application::bacnet::BacnetParseError;
    use packet_parser::errors::application::radius::RadiusParseError;
    use packet_parser::parse::application::protocols::bacnet::{
        ApduType, BacnetPacket, BvlcFunction, ConfirmedService, NpduMessage, UnconfirmedService,
    };
    use packet_parser::parse::application::protocols::radius::{
        AttributeType, RadiusAttribute, RadiusCode, RadiusPacket,
    };
    use packet_parser::{LinkType, parse};

    /// Frame 3 of `protocols/bacnet/iti_bacnet_test.pcap` (ITI, CC-BY-4.0):
    /// Ethernet / IPv4 / UDP 47808 -> 47808, a readProperty request from a
    /// host to a controller (the first query of nmap's `bacnet-info` script).
    const ITI_READ_PROPERTY_HEX: &str = concat!(
        "001907243cca3ca9f42122f808004500002d28af00008011fac30a0101a70a01",
        "01a5bac0bac0001959a1810a001101040005010c0c023fffff194b"
    );

    /// Frame 4 of the same capture: the ComplexACK that answers it.
    const ITI_COMPLEX_ACK_HEX: &str = concat!(
        "3ca9f42122f8001907243cca080045000033f3cc0000771138a00a0101a50a01",
        "01a7bac0bac0001f1770810a0017010030010c0c023fffff194b3ec4020001f4",
        "3f"
    );

    /// Frame 25 of the same capture: a Register-Foreign-Device.
    const ITI_REGISTER_FOREIGN_DEVICE_HEX: &str = concat!(
        "001907243cca3ca9f42122f80800450000222a1100008011f96c0a0101a70a01",
        "01a5bac0bac0000ef1e7810500060010"
    );

    /// Frame 26 of the same capture: the BVLC-Result that answers it.
    const ITI_BVLC_RESULT_HEX: &str = concat!(
        "3ca9f42122f8001907243cca080045000022f40c0000771138710a0101a50a01",
        "01a7bac0bac0000ef1cc810000060030"
    );

    /// Frame 10 of `protocols/bacnet/ndpi_bacnet.pcap` (nDPI test corpus,
    /// LGPL-3.0): a Who-Is in an Original-Broadcast-NPDU.
    const NDPI_WHO_IS_HEX: &str = concat!(
        "010203040506001a2b3c4d5e080045000028abd54000401191f7ccacb1ffccac",
        "b19fbac0bac00014fa0d810b000c0120ffff00ff1008"
    );

    /// Frame 22 of the same capture: a network-layer message.
    const NDPI_NETWORK_MESSAGE_HEX: &str = concat!(
        "010203040506001a2b3c4d5e080045000029fdb7400040114014ccacb1ffccac",
        "b19fbac0bac000150893810b000d01a0ffff00ff010000"
    );

    /// Frame 1 of `protocols/radius/radius.pcap` (Zeek test corpus, BSD
    /// 3-clause): Ethernet / IPv4 / UDP 1645 -> 1812, the Access-Request of a
    /// Cisco switch for an EAP user.
    const RADIUS_ACCESS_REQUEST_HEX: &str = concat!(
        "001d60b30184001906eab8c00800450000a700460000ff11a69b0a0000010a00",
        "0064066d071400933dca0105008becfe3d2fe4473ec6299095ee46aedf770406",
        "0a00000105060000c35c3d060000000f010e4a6f686e2e4d63477569726b1e13",
        "30302d31392d30362d45412d42382d38431f1330302d31342d32322d45392d35",
        "342d35450606000000020c06000005dc4f1302000011014a6f686e2e4d634775",
        "69726b501228c5beb8842486da70db51316f9d7889"
    );

    /// Frame 36702 of `The-Ultimate-PCAP.pcapng` (Johannes Weber): Ethernet /
    /// IPv6 / UDP 1812 -> 60664, an Access-Accept with Microsoft attributes.
    const ULTIMATE_ACCESS_ACCEPT_HEX: &str = concat!(
        "000c29b71d68000c29a826f786dd600e940200681140200104701f0b16b0020c",
        "29fffea826f7200104701f0b16b0020c29fffeb71d680714ecf800684ea80216",
        "0060788a984c129702448a9d665de2a0b1b5120c48656c6c6f2c20626f621a28",
        "000001370c22599456833f24252a2a00abd692adf84a9d9e2807e529a11d23f5",
        "cc80c6e830101a0c000001370706000000011a0c00000137080600000006"
    );

    /// Frame 14 of `protocols/radius/radius_localhost.pcap` (Zeek test
    /// corpus): captured on the loopback interface, LINKTYPE_NULL / IPv4 /
    /// UDP 1812 -> 52178, an Access-Reject.
    const LOCALHOST_ACCESS_REJECT_HEX: &str = concat!(
        "020000004500003085680000401100007f0000017f0000010714cbd2001cfe2f",
        "032b001442d5fe68699de5322f636f566bdd10f3"
    );

    // ANCHOR: bacnet_read_property
    #[test]
    fn bacnet_read_property_and_its_complex_ack() {
        // Frame 3: labelled by the port rule, then decoded from the payload.
        let raw = hex::decode(ITI_READ_PROPERTY_HEX).unwrap();
        let flow = parse(LinkType::ETHERNET, &raw).unwrap();
        assert_eq!(flow.application.as_ref().unwrap().application_protocol, "BACnet/IP");
        let transport = flow.transport.as_ref().unwrap();
        assert_eq!(transport.destination_port, Some(47808));

        let packet = BacnetPacket::try_from(transport.payload.unwrap()).unwrap();
        assert_eq!(packet.bvlc.kind, BvlcFunction::OriginalUnicastNpdu);
        assert_eq!((packet.bvlc.function, packet.bvlc.length), (0x0a, 17)); // the whole datagram
        assert_eq!(packet.forwarded_from, None);

        let npdu = packet.npdu.unwrap();
        assert_eq!((npdu.version, npdu.control), (1, 0x04));
        assert!(npdu.expecting_reply());
        assert_eq!(npdu.priority(), 0); // normal
        assert!(npdu.destination.is_none() && npdu.source.is_none());
        assert_eq!(npdu.hop_count, None); // no destination, no hop count

        let NpduMessage::Apdu(request) = npdu.message else {
            panic!("expected an APDU, got {:?}", npdu.message);
        };
        assert_eq!(request.kind, ApduType::ConfirmedRequest);
        assert_eq!(request.flags, 0); // not segmented
        assert_eq!(request.max_segments_and_apdu, Some(0x05)); // up to 1476 bytes, for tshark
        assert_eq!(request.invoke_id, Some(1));
        assert_eq!(request.service, Some(12));
        assert_eq!(request.confirmed_service(), Some(ConfirmedService::ReadProperty));
        // The object and the property asked for, tag-encoded, left as bytes.
        assert_eq!(request.data, &[0x0c, 0x02, 0x3f, 0xff, 0xff, 0x19, 0x4b]);

        // Frame 4: the answer carries the same invoke id and service.
        let raw = hex::decode(ITI_COMPLEX_ACK_HEX).unwrap();
        let flow = parse(LinkType::ETHERNET, &raw).unwrap();
        let payload = flow.transport.as_ref().unwrap().payload.unwrap();
        let packet = BacnetPacket::try_from(payload).unwrap();
        let npdu = packet.npdu.unwrap();
        assert!(!npdu.expecting_reply());
        let NpduMessage::Apdu(ack) = npdu.message else {
            panic!("expected an APDU, got {:?}", npdu.message);
        };
        assert_eq!(ack.kind, ApduType::ComplexAck);
        assert_eq!((ack.invoke_id, ack.service), (Some(1), Some(12)));
        assert_eq!(ack.max_segments_and_apdu, None); // a request field
        assert_eq!(ack.segment, None);
        assert_eq!(ack.data.len(), 14); // object and property again, then the value
    }
    // ANCHOR_END: bacnet_read_property

    // ANCHOR: bacnet_broadcast
    #[test]
    fn bacnet_who_is_and_a_network_message_broadcast_to_all_networks() {
        // Frame 10: a Who-Is for every device on every network.
        let raw = hex::decode(NDPI_WHO_IS_HEX).unwrap();
        let flow = parse(LinkType::ETHERNET, &raw).unwrap();
        assert_eq!(flow.application.as_ref().unwrap().application_protocol, "BACnet/IP");
        let payload = flow.transport.as_ref().unwrap().payload.unwrap();
        let packet = BacnetPacket::try_from(payload).unwrap();
        assert_eq!(packet.bvlc.kind, BvlcFunction::OriginalBroadcastNpdu);

        let npdu = packet.npdu.unwrap();
        assert_eq!(npdu.control, 0x20); // destination specifier
        let destination = npdu.destination.unwrap();
        assert_eq!(destination.network, 65535); // DNET 0xFFFF
        assert!(destination.address.is_empty()); // DLEN 0
        assert_eq!(npdu.source, None);
        assert_eq!(npdu.hop_count, Some(255)); // present with a destination

        let NpduMessage::Apdu(who_is) = npdu.message else {
            panic!("expected an APDU, got {:?}", npdu.message);
        };
        assert_eq!(who_is.kind, ApduType::UnconfirmedRequest);
        assert_eq!(who_is.invoke_id, None); // nothing to pair with
        assert_eq!(who_is.unconfirmed_service(), Some(UnconfirmedService::WhoIs));
        assert_eq!(who_is.confirmed_service(), None);
        assert!(who_is.data.is_empty()); // no device instance range

        // Frame 22: control 0xA0, a network-layer message instead of an APDU.
        let raw = hex::decode(NDPI_NETWORK_MESSAGE_HEX).unwrap();
        let flow = parse(LinkType::ETHERNET, &raw).unwrap();
        let payload = flow.transport.as_ref().unwrap().payload.unwrap();
        let packet = BacnetPacket::try_from(payload).unwrap();
        let npdu = packet.npdu.unwrap();
        assert_eq!((npdu.control, npdu.hop_count), (0xa0, Some(255)));
        let NpduMessage::Network { message_type, vendor_id, data } = npdu.message else {
            panic!("expected a network message, got {:?}", npdu.message);
        };
        assert_eq!(message_type, 0x01); // I-Am-Router-To-Network, for tshark
        assert_eq!(vendor_id, None); // only types 0x80 and above have one
        assert_eq!(data, &[0x00, 0x00]); // the network list, raw
    }
    // ANCHOR_END: bacnet_broadcast

    // ANCHOR: bacnet_bvlc_only
    #[test]
    fn bacnet_bvlc_functions_without_an_npdu() {
        // Frame 25: a device asks to be registered as a foreign device.
        let raw = hex::decode(ITI_REGISTER_FOREIGN_DEVICE_HEX).unwrap();
        let flow = parse(LinkType::ETHERNET, &raw).unwrap();
        assert_eq!(flow.application.as_ref().unwrap().application_protocol, "BACnet/IP");
        let payload = flow.transport.as_ref().unwrap().payload.unwrap();
        let packet = BacnetPacket::try_from(payload).unwrap();
        assert_eq!(packet.bvlc.kind, BvlcFunction::RegisterForeignDevice);
        assert_eq!(packet.bvlc.length, 6);
        assert_eq!(packet.npdu, None);
        assert_eq!(packet.body, &[0x00, 0x10]); // time-to-live, 16 seconds

        // Frame 26: the BVLC-Result. Its code is left in `body`, undecoded
        // (tshark reads 0x0030, Register-Foreign-Device NAK).
        let raw = hex::decode(ITI_BVLC_RESULT_HEX).unwrap();
        let flow = parse(LinkType::ETHERNET, &raw).unwrap();
        let payload = flow.transport.as_ref().unwrap().payload.unwrap();
        let packet = BacnetPacket::try_from(payload).unwrap();
        assert_eq!(packet.bvlc.kind, BvlcFunction::Result);
        assert_eq!(packet.npdu, None);
        assert_eq!(packet.body, &[0x00, 0x30]);
    }
    // ANCHOR_END: bacnet_bvlc_only

    // ANCHOR: bacnet_blind_probe
    #[test]
    fn bacnet_is_recognized_off_its_ports_and_refused_when_altered() {
        // Frame 3 moved to UDP 40000 -> 40001: no port rule applies, the
        // blind rule recognizes the datagram by its content.
        let mut raw = hex::decode(ITI_READ_PROPERTY_HEX).unwrap();
        raw[34..38].copy_from_slice(&[0x9c, 0x40, 0x9c, 0x41]);
        let flow = parse(LinkType::ETHERNET, &raw).unwrap();
        let transport = flow.transport.as_ref().unwrap();
        assert_eq!((transport.source_port, transport.destination_port), (Some(40000), Some(40001)));
        assert_eq!(flow.application.as_ref().unwrap().application_protocol, "BACnet/IP");

        // One altered byte: the decoder refuses the datagram, the label is not
        // given, and nothing is reported as corrupted.
        let start = raw.len() - 17; // where the BVLC header starts
        for (offset, value, error) in [
            (0, 0x82, BacnetParseError::InvalidBvlcType(0x82)),
            (3, 0x12, BacnetParseError::LengthMismatch { declared: 18, actual: 17 }),
            (4, 0x02, BacnetParseError::UnsupportedNpduVersion(2)),
        ] {
            let mut altered = raw.clone();
            altered[start + offset] = value;
            assert_eq!(BacnetPacket::try_from(&altered[start..]), Err(error));
            let flow = parse(LinkType::ETHERNET, &altered).unwrap();
            assert_eq!(flow.application.as_ref().unwrap().application_protocol, "Unknown");
            assert!(flow.corrupted.is_none());
        }
    }
    // ANCHOR_END: bacnet_blind_probe

    // ANCHOR: radius_access_request
    #[test]
    fn radius_access_request_of_a_switch() {
        let raw = hex::decode(RADIUS_ACCESS_REQUEST_HEX).unwrap();
        let flow = parse(LinkType::ETHERNET, &raw).unwrap();
        assert_eq!(flow.application.as_ref().unwrap().application_protocol, "RADIUS");
        let transport = flow.transport.as_ref().unwrap();
        assert_eq!((transport.source_port, transport.destination_port), (Some(1645), Some(1812)));

        let packet = RadiusPacket::try_from(transport.payload.unwrap()).unwrap();
        assert_eq!(packet.kind, RadiusCode::AccessRequest);
        assert_eq!((packet.code, packet.identifier, packet.length), (1, 5, 139));
        assert_eq!(packet.authenticator[..4], [0xec, 0xfe, 0x3d, 0x2f]);

        // Ten attributes in wire order, each value borrowed from the datagram.
        let types: Vec<u8> = packet.attributes.iter().map(|a| a.attribute_type).collect();
        assert_eq!(types, [4, 5, 61, 1, 30, 31, 6, 12, 79, 80]);
        assert_eq!(packet.attributes[0].kind, Some(AttributeType::NasIpAddress));

        // The first attribute of a type, read through the accessor that fits.
        let nas = packet.attribute(AttributeType::NasIpAddress).and_then(RadiusAttribute::as_ipv4);
        assert_eq!(nas, Some(Ipv4Addr::new(10, 0, 0, 1)));
        let port = packet.attribute(AttributeType::NasPort).and_then(RadiusAttribute::as_u32);
        assert_eq!(port, Some(50012));
        let user = packet.attribute(AttributeType::UserName).and_then(RadiusAttribute::as_text);
        assert_eq!(user, Some("John.McGuirk"));
        let station = packet
            .attribute(AttributeType::CallingStationId)
            .and_then(RadiusAttribute::as_text);
        assert_eq!(station, Some("00-14-22-E9-54-5E"));
        let mtu = packet.attribute(AttributeType::FramedMtu).and_then(RadiusAttribute::as_u32);
        assert_eq!(mtu, Some(1500));

        // EAP and the Message-Authenticator stay bytes; an accessor that does
        // not fit the value answers None.
        let eap = packet.attribute(AttributeType::EapMessage).unwrap();
        assert_eq!((eap.length, eap.value.len()), (19, 17));
        assert_eq!(eap.as_u32(), None);
        let authenticator = packet.attribute(AttributeType::MessageAuthenticator).unwrap();
        assert_eq!(authenticator.value.len(), 16);
        assert_eq!(packet.attribute(AttributeType::VendorSpecific), None);
    }
    // ANCHOR_END: radius_access_request

    // ANCHOR: radius_vendor_specific
    #[test]
    fn radius_access_accept_with_microsoft_vendor_attributes() {
        // Over IPv6 this time: the rule only looks at UDP.
        let raw = hex::decode(ULTIMATE_ACCESS_ACCEPT_HEX).unwrap();
        let flow = parse(LinkType::ETHERNET, &raw).unwrap();
        assert_eq!(flow.internet.as_ref().unwrap().protocol_name, "IPv6");
        assert_eq!(flow.application.as_ref().unwrap().application_protocol, "RADIUS");

        let payload = flow.transport.as_ref().unwrap().payload.unwrap();
        let packet = RadiusPacket::try_from(payload).unwrap();
        assert_eq!(packet.kind, RadiusCode::AccessAccept);
        assert_eq!((packet.identifier, packet.length), (22, 96)); // answers request 22
        let reply = packet.attribute(AttributeType::ReplyMessage);
        assert_eq!(reply.and_then(RadiusAttribute::as_text), Some("Hello, bob"));

        // Three Vendor-Specific attributes: the vendor id, then the bytes the
        // vendor defines, which the crate does not decode.
        let vendors: Vec<(u32, &[u8])> =
            packet.attributes.iter().filter_map(RadiusAttribute::vendor).collect();
        assert_eq!(vendors.len(), 3);
        assert!(vendors.iter().all(|(id, _)| *id == 311)); // Microsoft
        // Vendor type 7, length 6, value 1: MS-MPPE-Encryption-Policy, for tshark.
        assert_eq!(vendors[1].1, &[7, 6, 0, 0, 0, 1]);
        // vendor() answers only on a Vendor-Specific attribute.
        assert_eq!(packet.attributes[0].kind, Some(AttributeType::ReplyMessage));
        assert_eq!(packet.attributes[0].vendor(), None);
    }
    // ANCHOR_END: radius_vendor_specific

    // ANCHOR: radius_loopback_reject
    #[test]
    fn radius_access_reject_without_attributes_on_loopback() {
        // Captured on the loopback interface: LINKTYPE_NULL, then IPv4 and UDP.
        let raw = hex::decode(LOCALHOST_ACCESS_REJECT_HEX).unwrap();
        let flow = parse(LinkType::NULL, &raw).unwrap();
        assert_eq!(flow.application.as_ref().unwrap().application_protocol, "RADIUS");

        let payload = flow.transport.as_ref().unwrap().payload.unwrap();
        let packet = RadiusPacket::try_from(payload).unwrap();
        assert_eq!(packet.kind, RadiusCode::AccessReject);
        assert_eq!((packet.identifier, packet.length), (43, 20));
        assert!(packet.attributes.is_empty()); // the header alone is a packet
    }
    // ANCHOR_END: radius_loopback_reject

    // ANCHOR: radius_blind_probe
    #[test]
    fn radius_is_recognized_off_its_ports_and_refused_when_altered() {
        // Frame 1 moved to UDP 40000 -> 40001: the blind rule recognizes it.
        let mut raw = hex::decode(RADIUS_ACCESS_REQUEST_HEX).unwrap();
        raw[34..38].copy_from_slice(&[0x9c, 0x40, 0x9c, 0x41]);
        let flow = parse(LinkType::ETHERNET, &raw).unwrap();
        assert_eq!(flow.application.as_ref().unwrap().application_protocol, "RADIUS");

        // The authenticator and the values are not checked: nothing here knows
        // the shared secret.
        let start = raw.len() - 139; // where the RADIUS header starts
        let mut values = raw.clone();
        values[start + 4] ^= 0xff; // first byte of the authenticator
        values[start + 22] ^= 0xff; // first byte of the NAS-IP-Address value
        let flow = parse(LinkType::ETHERNET, &values).unwrap();
        assert_eq!(flow.application.as_ref().unwrap().application_protocol, "RADIUS");

        // The structure is checked: an unknown code, a length that is not the
        // datagram's, attributes that no longer tile it (a NAS-IP-Address one
        // byte longer makes the next attribute start on a length byte).
        for (offset, value, error) in [
            (0, 6, RadiusParseError::UnknownCode(6)),
            (3, 0x8a, RadiusParseError::LengthMismatch { declared: 138, actual: 139 }),
            (21, 7, RadiusParseError::AttributeTooShort { attribute_type: 6, length: 0 }),
        ] {
            let mut altered = raw.clone();
            altered[start + offset] = value;
            assert_eq!(RadiusPacket::try_from(&altered[start..]), Err(error));
            let flow = parse(LinkType::ETHERNET, &altered).unwrap();
            assert_eq!(flow.application.as_ref().unwrap().application_protocol, "Unknown");
            assert!(flow.corrupted.is_none());
        }
    }
    // ANCHOR_END: radius_blind_probe
}
