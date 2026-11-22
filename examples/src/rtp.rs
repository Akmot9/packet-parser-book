//! Examples of the RTP and RTCP pages. Both frames come from one call of
//! `pcaps_exemple/protocols/sip/wireshark_aaa.pcap` in the crate repository
//! (see the folder's `SOURCE.md`): a soft phone of 2005 behind a home
//! router, from the Wireshark wiki. The bytes were extracted with tshark
//! 4.6.9.

#[cfg(test)]
mod tests {
    use packet_parser::errors::application::rtcp::RtcpError;
    use packet_parser::errors::application::rtp::RtpError;
    use packet_parser::parse::application::protocols::rtcp::{RtcpCompound, RtcpPacketType};
    use packet_parser::parse::application::protocols::rtp::RtpPacket;
    use packet_parser::{DecodeAsProtocol, LinkType, PacketFlow, ParseConfig, parse, parse_with};

    /// Frame 624 of `sip/wireshark_aaa.pcap`: 20 ms of G.711 A-law, Ethernet /
    /// IPv4 / UDP 30000 -> 40392.
    const RTP_PCMA_HEX: &str = concat!(
        "00305400345600e0ed016ebd0800450000c86bfc000080111668c0a80102d4f2",
        "212475309dc800b418de80086fae000004d83796cb71d5d5d5d5d5d5d5d5d5d5",
        "d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d51104",
        "1c181812121e1014176a131c18040405060101000705051913051b1910131905",
        "040407030203030000020d0d0d0001030d0c0d0000010203010606010f0e0e0c",
        "030007060003030607010406061b1f1c11696062151110146a13156069617d74",
        "525b59d7475c565255444b42755973785a7c6e68146a",
    );

    /// Frame 633 of the same capture: the phone's last RTCP datagram, a
    /// Sender Report, a Source Description and a Goodbye, UDP 30001 -> 40393.
    const RTCP_SR_SDES_BYE_HEX: &str = concat!(
        "00305400345600e0ed016ebd0800450000846c050000801116a3c0a80102d4f2",
        "212475319dc900702c8180c800063796cb7142c907ca5efac603000024c30000",
        "00090000060c81ca000b3796cb71011d31313839343239372d34343332613966",
        "38403139322e3136382e312e3206055349505053000081cb00063796cb711073",
        "657373696f6e2073687574646f776e000000",
    );

    fn label(flow: &PacketFlow<'_>) -> Option<&'static str> {
        flow.application.as_ref().map(|application| application.protocol.label())
    }

    fn payload<'a>(flow: &PacketFlow<'a>) -> &'a [u8] {
        flow.transport.as_ref().unwrap().payload.unwrap()
    }

    // ANCHOR: rtp_declared_port
    #[test]
    fn rtp_is_named_on_a_declared_port() {
        let raw = hex::decode(RTP_PCMA_HEX).unwrap();

        // No rule of the table names RTP: two fixed bits prove nothing.
        let flow = parse(LinkType::ETHERNET, &raw).unwrap();
        assert_eq!(label(&flow), Some("Unknown"));

        // The decoder reads the packet all the same.
        let packet = RtpPacket::try_from(payload(&flow)).unwrap();
        assert_eq!(packet.payload_type, 8);
        assert_eq!(packet.static_payload_name(), Some("PCMA"));
        assert!(!packet.marker);
        assert_eq!(packet.sequence_number, 28590);
        assert_eq!(packet.timestamp, 1240);
        assert_eq!(packet.ssrc, 0x3796_cb71);
        assert!(packet.csrc.is_empty());
        assert_eq!(packet.extension, None);
        // 160 samples at 8 000 Hz: 20 ms of sound, no padding.
        assert_eq!(packet.payload.len(), 160);
        assert_eq!(packet.padding_length, 0);

        // The caller knows the media port, from the SDP of the call: once
        // declared, the same frame is RTP.
        let config = ParseConfig::new().decode_as(40392, DecodeAsProtocol::Rtp);
        let flow = parse_with(LinkType::ETHERNET, &raw, &config).unwrap();
        assert_eq!(label(&flow), Some("RTP"));
    }
    // ANCHOR_END: rtp_declared_port

    // ANCHOR: rtp_refuses_rtcp
    #[test]
    fn rtp_refuses_an_rtcp_datagram() {
        let raw = hex::decode(RTCP_SR_SDES_BYE_HEX).unwrap();
        let flow = parse(LinkType::ETHERNET, &raw).unwrap();

        // The second byte of a Sender Report is 200: read as RTP, a marker
        // bit and payload type 72, which RFC 3551 reserves for that reason.
        assert_eq!(
            RtpPacket::try_from(payload(&flow)).unwrap_err(),
            RtpError::RtcpPayloadType(72)
        );

        // Even on a port declared RTP, the datagram is not RTP. The table
        // then names it by its content.
        let config = ParseConfig::new().decode_as(40393, DecodeAsProtocol::Rtp);
        let flow = parse_with(LinkType::ETHERNET, &raw, &config).unwrap();
        assert_eq!(label(&flow), Some("RTCP"));
    }
    // ANCHOR_END: rtp_refuses_rtcp

    // ANCHOR: rtcp_compound
    #[test]
    fn a_compound_rtcp_datagram() {
        let raw = hex::decode(RTCP_SR_SDES_BYE_HEX).unwrap();
        let flow = parse(LinkType::ETHERNET, &raw).unwrap();
        // No port, no Decode As: the blind rule reads the content.
        assert_eq!(label(&flow), Some("RTCP"));

        let compound = RtcpCompound::try_from(payload(&flow)).unwrap();
        let packets: Vec<_> = compound.packets().collect();
        let types: Vec<_> = packets.iter().map(|packet| packet.packet_type).collect();
        assert_eq!(
            types,
            [
                RtcpPacketType::SenderReport,
                RtcpPacketType::SourceDescription,
                RtcpPacketType::Goodbye,
            ]
        );
        // 28, 48 and 28 bytes: the three packets tile the 104 bytes.
        let lengths: Vec<_> = packets.iter().map(|packet| 4 + packet.body.len()).collect();
        assert_eq!(lengths, [28, 48, 28]);
        assert_eq!(compound.as_bytes().len(), 104);

        // The Sender Report: no report block, the sender and its counters.
        let report = &packets[0];
        assert_eq!(report.count, 0);
        assert_eq!(report.sender_ssrc(), Some(0x3796_cb71));
        let info = report.sender_info().unwrap();
        assert_eq!(info.ntp_timestamp >> 32, 1_120_470_986);
        assert_eq!(info.rtp_timestamp, 9411);
        assert_eq!((info.packet_count, info.octet_count), (9, 1548));

        // SDES and BYE carry a list of sources, not a sender: one each.
        assert_eq!(packets[1].count, 1);
        assert_eq!(packets[1].sender_ssrc(), None);
        assert_eq!(packets[1].sender_info(), None);
        assert_eq!(packets[2].count, 1);
        // The bodies are borrowed, not decoded: the reason of the Goodbye
        // is still in its bytes.
        assert!(packets[2].body.ends_with(b"session shutdown\0\0\0"));
    }
    // ANCHOR_END: rtcp_compound

    // ANCHOR: rtcp_refusals
    #[test]
    fn what_rtcp_refuses() {
        let raw = hex::decode(RTCP_SR_SDES_BYE_HEX).unwrap();
        let flow = parse(LinkType::ETHERNET, &raw).unwrap();
        let datagram = payload(&flow);

        // The lengths must tile the datagram: one byte less, and the
        // Goodbye runs past the end.
        assert_eq!(
            RtcpCompound::try_from(&datagram[..103]).unwrap_err(),
            RtcpError::TruncatedPacket { declared: 28, available: 27 }
        );

        // An RTP packet of the same call: its second byte, 8, is no RTCP
        // packet type.
        let raw = hex::decode(RTP_PCMA_HEX).unwrap();
        let flow = parse(LinkType::ETHERNET, &raw).unwrap();
        assert_eq!(
            RtcpCompound::try_from(payload(&flow)).unwrap_err(),
            RtcpError::UnknownPacketType(8)
        );
    }
    // ANCHOR_END: rtcp_refusals
}
