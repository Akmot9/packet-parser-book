//! The examples of the Packet Parser book. Each `#[test]` is a chapter
//! snippet, delimited by `ANCHOR` comments that mdBook includes verbatim.
//!
//! Run with `cargo test` from the `examples/` directory.

#![allow(clippy::unwrap_used)]

mod building_aaa;
mod defense_a;
mod defense_b;
mod internet_layer;
mod ipsec;
mod link_layer;
mod remote_vpn;
mod scada;
mod shared;

/// Frame 1 of the crate's README example: Ethernet / IPv4 / TCP 443 -> 49416,
/// a pure ACK with an empty payload.
pub const ETHERNET_IPV4_TCP_ACK_HEX: &str = concat!(
    "feaa81e86d1efeaa818ec864080045500034000000003d06206b36e6700d",
    "ac140a0201bbc1087d7f02aa4e2b998e80100081748300000101080a9373",
    "c9c207ef14e3"
);

/// Frame 4 of `pcaps_exemple/protocols/giop/corba.pcap` (nDPI test corpus):
/// Ethernet / IPv4 / TCP carrying a GIOP 1.2 big-endian Request `echo`.
pub const ETHERNET_IPV4_TCP_GIOP_REQUEST_HEX: &str = concat!(
    "000000000000000000000000080045000118a41d4000400695c07f0001017f00",
    "0101a6ddde43905fd45390db7ac980180101010d00000101080a0013705a0013",
    "704947494f5001020000000000d80000000003000000000000000000003c0000",
    "000000000001000000104d795f436f6d70726573735f506f6100000000000000",
    "011f5a056dca000000100000011f5a056dca00000000000000000000000565",
    "63686f0000000000000001000000070000002800000000000000010000001c00",
    "000018000000000000000001ddf68a6dc5c42000000000000000000000004100",
    "0202060402010503010205030707060102070705030105030703030103060602",
    "0206040102020201010407050207070306040605020202020205020205040100",
    "00000000000000"
);

/// Frame 25 of `pcaps_exemple/protocols/ptp/ptpv2.pcap` (Wireshark wiki, a
/// Hirschmann clock): Ethernet / IPv4 / UDP 319 -> 319 carrying a PTPv2 Sync.
pub const ETHERNET_IPV4_UDP_PTP_SYNC_HEX: &str = concat!(
    "01005e0001810080630009ba08004500004845a900000111cfccc0a80206e000",
    "0181013f013f003400001002002c000000000000000000000000000000000080",
    "63ffff0009ba000100730000000045b111590a657725"
);

/// Frame 1 of the same capture: the same clock sending a PTPv2 Pdelay_Req
/// straight over Ethernet, EtherType 0x88F7, without IP or UDP.
pub const ETHERNET_PTP_PDELAY_REQ_HEX: &str = concat!(
    "0180c200000e0080630009ba88f7020200360000000000000000000000000000",
    "0000008063ffff0009ba0002045e050f000045b111491c4178f4000000000000",
    "00000000"
);

#[cfg(test)]
mod tests {
    use super::*;
    use packet_parser::parse::application::protocols::giop::{
        GiopMessage, GiopMessageType, GiopPacket, TargetAddress,
    };
    use packet_parser::parse::application::protocols::ptp::{PtpPacket, PtpV2Body};
    use packet_parser::{
        CorruptedLayerKind, InternetDetails, LinkType, PacketFlow, ParseError, is_supported, parse,
    };

    // ANCHOR: parse_valid_frame
    #[test]
    fn parse_a_valid_ethernet_frame() -> Result<(), Box<dyn std::error::Error>> {
        let raw = hex::decode(ETHERNET_IPV4_TCP_ACK_HEX)?;

        // Always pass the LINKTYPE the capture declares.
        let flow = parse(LinkType::ETHERNET, &raw)?;

        let internet = flow.internet.as_ref().expect("IPv4 announced by the EtherType");
        assert_eq!(internet.protocol_name, "IPv4");
        assert_eq!(internet.source.unwrap().to_string(), "54.230.112.13");
        assert_eq!(internet.destination.unwrap().to_string(), "172.20.10.2");

        let transport = flow.transport.as_ref().expect("TCP announced by the IP header");
        assert_eq!(transport.source_port, Some(443));
        assert_eq!(transport.destination_port, Some(49416));

        // A pure ACK: the payload is empty, so there is nothing to classify.
        assert!(flow.application.is_none());
        assert!(flow.corrupted.is_none());
        Ok(())
    }
    // ANCHOR_END: parse_valid_frame

    // ANCHOR: unsupported_linktype
    #[test]
    fn an_unsupported_linktype_is_refused_before_reading_bytes() {
        let raw = hex::decode(ETHERNET_IPV4_TCP_ACK_HEX).unwrap();
        let bluetooth = LinkType::BLUETOOTH_HCI_H4_WITH_PHDR;

        assert!(!is_supported(bluetooth));
        assert!(matches!(
            parse(bluetooth, &raw),
            Err(ParseError::UnsupportedLinkType(LinkType(201)))
        ));
    }
    // ANCHOR_END: unsupported_linktype

    // ANCHOR: truncated_link_layer
    #[test]
    fn a_truncated_link_header_fails_the_parse() {
        let raw = hex::decode(ETHERNET_IPV4_TCP_ACK_HEX).unwrap();

        // Only the link layer can fail the parse: 10 bytes cannot hold the
        // 14-byte Ethernet header.
        let error = parse(LinkType::ETHERNET, &raw[..10]).unwrap_err();
        assert_eq!(
            error.to_string(),
            "Invalid link layer: LINKTYPE 1 packet is truncated: required bytes 14, actual bytes 10"
        );
    }
    // ANCHOR_END: truncated_link_layer

    // ANCHOR: corrupted_upper_layer
    #[test]
    fn a_recognized_but_invalid_upper_layer_is_reported_not_fatal() {
        let raw = hex::decode(ETHERNET_IPV4_TCP_ACK_HEX).unwrap();

        // Cut 6 bytes into the IPv4 header: the EtherType still says IPv4,
        // so the layer is recognized, but its bytes are invalid.
        let flow = parse(LinkType::ETHERNET, &raw[..20]).unwrap();

        assert!(flow.data_link.as_ethernet().is_some()); // kept
        assert!(flow.internet.is_none());
        let corrupted = flow.corrupted.expect("recognized layer with invalid bytes");
        assert_eq!(corrupted.layer, CorruptedLayerKind::Internet);
        assert_eq!(
            corrupted.error,
            "IPv4 error: Invalid IPv4 packet length: expected at least 20 bytes, got 6 bytes"
        );
    }
    // ANCHOR_END: corrupted_upper_layer

    // ANCHOR: unsupported_upper_layer
    #[test]
    fn an_unsupported_upper_layer_leaves_the_layer_none_without_corruption() {
        // Synthetic frame: two MAC addresses, EtherType 0x88B5 (the IEEE 802
        // local experimental EtherType, decoded by no one) and a few payload
        // bytes.
        let mut raw = hex::decode("0180c200000e001122334455").unwrap();
        raw.extend_from_slice(&[0x88, 0xb5, 0x02, 0x07, 0x04, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);

        let flow = parse(LinkType::ETHERNET, &raw).unwrap();

        // Not supported is not the same as corrupt: nothing above the link
        // layer could be reached, and nothing is reported as invalid.
        assert!(flow.internet.is_none());
        assert!(flow.transport.is_none());
        assert!(flow.application.is_none());
        assert!(flow.corrupted.is_none());
    }
    // ANCHOR_END: unsupported_upper_layer

    // ANCHOR: classification_vs_decode
    #[test]
    fn classification_is_a_label_the_protocol_parser_is_the_decode() {
        let raw = hex::decode(ETHERNET_IPV4_TCP_GIOP_REQUEST_HEX).unwrap();
        let flow = parse(LinkType::ETHERNET, &raw).unwrap();

        // The pipeline classifies the transport payload: a label, no decode.
        assert_eq!(flow.application.as_ref().unwrap().application_protocol, "GIOP");

        // The detailed parser decodes the same bytes.
        let payload = flow.transport.as_ref().unwrap().payload.unwrap();
        let packet = GiopPacket::try_from(payload).unwrap();
        assert_eq!(packet.header.minor_version, 2);
        assert_eq!(packet.header.message_type, GiopMessageType::Request);
        assert!(!packet.header.is_little_endian());
        assert_eq!(packet.header.message_length, 216);
        assert!(!packet.truncated);

        let GiopMessage::Request(request) = &packet.payload else {
            panic!("expected a Request, got {:?}", packet.payload);
        };
        assert_eq!(request.request_id, 0);
        assert_eq!(request.operation, "echo");
        assert_eq!(request.service_contexts.len(), 1);
        assert_eq!(request.stub_data.len(), 76);
        let TargetAddress::KeyAddr(key) = &request.target else {
            panic!("expected a KeyAddr target");
        };
        assert_eq!(key.len(), 60);
    }
    // ANCHOR_END: classification_vs_decode

    // ANCHOR: ptp_two_carriers
    #[test]
    fn ptp_is_a_label_on_udp_and_an_internet_layer_on_ethertype_88f7() {
        // Frame 25 of ptpv2.pcap: UDP 319 -> 319. The pipeline labels the
        // datagram; the protocol parser decodes it from the transport payload.
        let raw = hex::decode(ETHERNET_IPV4_UDP_PTP_SYNC_HEX).unwrap();
        let flow = parse(LinkType::ETHERNET, &raw).unwrap();
        assert_eq!(flow.application.as_ref().unwrap().application_protocol, "PTP");

        let payload = flow.transport.as_ref().unwrap().payload.unwrap();
        let PtpPacket::V2(sync) = PtpPacket::try_from_udp(payload).unwrap() else {
            panic!("expected a PTPv2 message");
        };
        assert_eq!(sync.header.message_type, 0); // Sync
        assert_eq!(sync.header.message_length, 44);
        assert_eq!(sync.header.sequence_id, 115);
        assert_eq!(sync.header.source_port_identity.port_number, 1);
        let PtpV2Body::Sync { origin_timestamp } = sync.body else {
            panic!("expected a Sync body, got {:?}", sync.body);
        };
        assert_eq!(origin_timestamp.seconds, 1_169_232_217);
        assert_eq!(origin_timestamp.nanoseconds, 174_421_797);
        assert_eq!(sync.tlvs.iter().count(), 0);
        assert!(sync.trailing.is_empty());

        // Frame 1 of the same capture: EtherType 0x88F7. No IP, no UDP: the
        // message is the internet layer, already decoded, and the flow has
        // neither a transport layer nor an application label.
        let raw = hex::decode(ETHERNET_PTP_PDELAY_REQ_HEX).unwrap();
        let flow = parse(LinkType::ETHERNET, &raw).unwrap();
        let internet = flow.internet.as_ref().unwrap();
        assert_eq!(internet.protocol_name, "PTP");
        assert!(internet.source.is_none() && internet.destination.is_none());
        assert!(flow.transport.is_none() && flow.application.is_none());
        assert!(flow.corrupted.is_none());

        let Some(InternetDetails::Ptp(PtpPacket::V2(pdelay_req))) = &internet.details
        else {
            panic!("expected a decoded PTPv2 message in details");
        };
        assert_eq!(pdelay_req.header.message_type, 2); // Pdelay_Req
        assert_eq!(pdelay_req.header.sequence_id, 1118);
        assert!(matches!(pdelay_req.body, PtpV2Body::PdelayReq { .. }));
        assert!(pdelay_req.trailing.is_empty());
    }
    // ANCHOR_END: ptp_two_carriers

    // ANCHOR: owned_and_json
    #[test]
    fn owned_flows_serialize_like_borrowed_ones() -> Result<(), Box<dyn std::error::Error>> {
        let raw = hex::decode(ETHERNET_IPV4_TCP_ACK_HEX)?;
        let flow = parse(LinkType::ETHERNET, &raw)?;

        // The owned form outlives the buffer; it drops payloads and details.
        let owned = flow.to_owned_flow();
        drop(raw);

        let json: serde_json::Value = serde_json::from_str(&serde_json::to_string(&owned)?)?;
        assert_eq!(json["data_link"]["link_type"], 1);
        assert_eq!(json["data_link"]["link_kind"], "ethernet");
        assert_eq!(json["source_ip"], "54.230.112.13");
        assert_eq!(json["protocol_transport"], "TCP");
        assert_eq!(json["destination_port"], 49416);
        Ok(())
    }
    // ANCHOR_END: owned_and_json

    #[test]
    fn the_ethernet_shortcut_assumes_ethernet() {
        let raw = hex::decode(ETHERNET_IPV4_TCP_ACK_HEX).unwrap();
        let shortcut = PacketFlow::try_from(raw.as_slice()).unwrap();
        let explicit = parse(LinkType::ETHERNET, &raw).unwrap();
        assert_eq!(shortcut, explicit);
    }
}
