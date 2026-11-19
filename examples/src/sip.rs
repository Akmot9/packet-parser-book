//! Examples of the SIP page. Every frame is a real frame of
//! `pcaps_exemple/protocols/sip/` in the crate repository (see the folder's
//! `SOURCE.md`): `wireshark_aaa.pcap`, a soft phone of 2005 behind a home
//! router, from the Wireshark wiki, and `ndpi_sip_hello.pcapng`, from the
//! nDPI test corpus. The bytes were extracted with tshark 4.6.9.

#[cfg(test)]
mod tests {
    use packet_parser::errors::application::sip::SipError;
    use packet_parser::parse::application::protocols::sip::{SipMessage, SipStartLine};
    use packet_parser::{LinkType, PacketFlow, parse};

    /// Frame 649 of `sip/wireshark_aaa.pcap`: the server's `100 Trying` to a
    /// REGISTER, Ethernet / IPv4 / UDP 5060 -> 5060.
    const TRYING_HEX: &str = concat!(
        "00e0ed016ebd0030540034560800450001480000400037118ae5d4f22123c0a8",
        "010213c413c4013421c55349502f322e302031303020547279696e670d0a4361",
        "6c6c2d49443a2032393835383134372d34363562303735324032393835383035",
        "312d34363562303762320d0a435365713a20362052454749535445520d0a4672",
        "6f6d3a203c7369703a3335313034373233407369702e6379626572636974792e",
        "646b3e3b7461673d3635396162660d0a546f3a203c7369703a33353130343732",
        "33407369702e6379626572636974792e646b3e0d0a5669613a205349502f322e",
        "302f554450203139322e3136382e312e323b72656365697665643d38302e3233",
        "302e3231392e37303b72706f72743d353036303b6272616e63683d7a39684734",
        "624b6e70363635383832342d34363530353966313139322e3136382e312e320d",
        "0a436f6e74656e742d4c656e6774683a20300d0a0d0a",
    );

    /// Frame 193 of the same capture: the phone's keep-alive, five spaces,
    /// UDP 5060 -> 5060.
    const SPACES_KEEPALIVE_HEX: &str = concat!(
        "00305400345600e0ed016ebd0800450000216a520000801118bac0a80102d4f2",
        "212313c413c4000dc04b2020202020",
    );

    /// Frame 1 of `sip/ndpi_sip_hello.pcapng`: a keep-alive `hello`, UDP
    /// 5060 -> 5060, padded to the Ethernet minimum.
    const HELLO_KEEPALIVE_HEX: &str = concat!(
        "000000000000000200b19a8c080045000021f76e4000fd110c0a0aef9cebac1d",
        "265b13c413c4000d000068656c6c6f000000000000000000",
    );

    fn label(flow: &PacketFlow<'_>) -> Option<&'static str> {
        flow.application.as_ref().map(|application| application.protocol.label())
    }

    fn payload<'a>(flow: &PacketFlow<'a>) -> &'a [u8] {
        flow.transport.as_ref().unwrap().payload.unwrap()
    }

    // ANCHOR: sip_response
    #[test]
    fn a_response_and_its_headers() {
        let raw = hex::decode(TRYING_HEX).unwrap();
        let flow = parse(LinkType::ETHERNET, &raw).unwrap();
        assert_eq!(label(&flow), Some("SIP"));

        let message = SipMessage::try_from(payload(&flow)).unwrap();
        let SipStartLine::Response { status_code, reason, .. } = message.start_line else {
            panic!("expected a status line, got {:?}", message.start_line);
        };
        assert_eq!((status_code, reason), (100, "Trying"));
        assert!(!message.is_request());
        assert_eq!(message.status_code(), Some(100));

        // A response answers the request its CSeq names: here a REGISTER.
        assert_eq!(message.cseq.sequence, 6);
        assert_eq!(message.cseq.method, "REGISTER");
        assert_eq!(message.method(), "REGISTER");

        // The headers keep the order of the wire: this server puts Call-ID
        // first, Via fifth.
        let names: Vec<&str> = message.headers.iter().map(|(name, _)| name).collect();
        assert_eq!(names, ["Call-ID", "CSeq", "From", "To", "Via", "Content-Length"]);
        assert!(message.via.starts_with("SIP/2.0/UDP 192.168.1.2;received="));

        // `get` ignores case, and finds a long name by its compact form.
        assert_eq!(message.headers.get("i"), Some(message.call_id));
        assert_eq!(message.headers.get("CSEQ"), Some("6 REGISTER"));
        assert_eq!(message.headers.get("Contact"), None);

        // Content-Length: 0, so the body is empty.
        assert_eq!(message.content_length, Some(0));
        assert!(message.body.is_empty());
    }
    // ANCHOR_END: sip_response

    // ANCHOR: sip_keepalives
    #[test]
    fn keepalives_are_not_sip() {
        // Frame 193 of aaa.pcap: five spaces on UDP 5060.
        let raw = hex::decode(SPACES_KEEPALIVE_HEX).unwrap();
        let flow = parse(LinkType::ETHERNET, &raw).unwrap();
        assert_eq!(payload(&flow), b"     ");
        assert_eq!(
            SipMessage::try_from(payload(&flow)).unwrap_err(),
            SipError::MissingHeaderTerminator
        );
        assert_eq!(label(&flow), Some("Unknown"));

        // Frame 1 of sip_hello.pcapng: `hello`. The padding after the
        // datagram is not part of the payload.
        let raw = hex::decode(HELLO_KEEPALIVE_HEX).unwrap();
        let flow = parse(LinkType::ETHERNET, &raw).unwrap();
        assert_eq!(payload(&flow), b"hello");
        assert_eq!(label(&flow), Some("Unknown"));
    }
    // ANCHOR_END: sip_keepalives
}
