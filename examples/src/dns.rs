//! Examples of the DNS page. Every frame is a real frame of the crate's
//! corpus (`pcaps_exemple/` in the crate repository), extracted with tshark.

#[cfg(test)]
mod tests {
    use packet_parser::parse::application::protocols::dns::DnsPacket;
    use packet_parser::{LinkType, PacketFlow, parse};

    /// Frame 1 of `protocols/dns/dns_query_response.pcapng` (Chris Sanders):
    /// a query for the A record of wireshark.org, UDP 1060 -> 53.
    const DNS_QUERY_HEX: &str = concat!(
        "00055d21994c0016ce6e8b2408004500003b1f270000801167c1c0a80072cd98",
        "2517042400350027036d180f010000010000000000000977697265736861726b",
        "036f72670000010001",
    );

    /// Frame 2 of the same capture: the response, UDP 53 -> 1060.
    const DNS_RESPONSE_HEX: &str = concat!(
        "0016ce6e8b2400055d21994c08004500004b767d400032111e5bcd982517c0a8",
        "00720035042400373c20180f818000010001000000000977697265736861726b",
        "036f72670000010001c00c000100010000384000048079327a",
    );

    /// Frame 6 of `protocols/dns/dns_tcp.pcapng` (Chris Sanders): a query
    /// for every record of ripe.net, TCP 45818 -> 53.
    const DNS_TCP_QUERY_HEX: &str = concat!(
        "4ce67640db2daa0004000a0408004500005044ae400040065e6ac0a80b3ec0a8",
        "0b01b2fa0035cfe7844f19a6470c8018005c144700000101080a0cbcc0e228af",
        "ffd4001ab4c3010000010000000000000472697065036e65740000ff0001",
    );

    /// Frame 9891 of `The-Ultimate-PCAP.pcapng`: an mDNS announcement with
    /// no question, UDP 5353 -> 5353, to 224.0.0.251.
    const MDNS_ANNOUNCEMENT_HEX: &str = concat!(
        "01005e0000fb74811481c2d408004500006307c80000ff110b04c0a8071ae000",
        "00fb14e914e9004f9ebb000084000000000100000000055f64616370045f7463",
        "70056c6f63616c00000c000100000000001f1c6954756e65735f4374726c5f37",
        "334635333234303835323846323339c00c7ec5d479",
    );

    fn label(flow: &PacketFlow<'_>) -> Option<&'static str> {
        flow.application.as_ref().map(|application| application.protocol.label())
    }

    /// The same frame with other transport ports, as on the NTP page.
    fn with_ports(raw: &[u8], source: u16, destination: u16) -> Vec<u8> {
        let ports = 14 + usize::from(raw[14] & 0x0f) * 4;
        let mut moved = raw.to_vec();
        moved[ports..ports + 2].copy_from_slice(&source.to_be_bytes());
        moved[ports + 2..ports + 4].copy_from_slice(&destination.to_be_bytes());
        moved
    }

    // ANCHOR: dns_query_and_response
    #[test]
    fn a_response_repeats_the_question_and_points_back_to_its_name() {
        let raw = hex::decode(DNS_QUERY_HEX).unwrap();
        let flow = parse(LinkType::ETHERNET, &raw).unwrap();
        assert_eq!(label(&flow), Some("DNS")); // 1060 -> 53
        let query = DnsPacket::try_from(flow.transport.as_ref().unwrap().payload.unwrap()).unwrap();
        assert_eq!(query.header.transaction_id, 0x180f);
        assert_eq!(query.header.flags, 0x0100); // a query, recursion desired
        assert_eq!(query.header.counts, [1, 0, 0, 0]);
        assert_eq!(query.queries.queries[0].name, "wireshark.org");
        assert!(query.answers.is_none()); // an empty section is None

        let raw = hex::decode(DNS_RESPONSE_HEX).unwrap();
        let flow = parse(LinkType::ETHERNET, &raw).unwrap();
        let payload = flow.transport.as_ref().unwrap().payload.unwrap();
        let response = DnsPacket::try_from(payload).unwrap();
        assert_eq!(response.header.transaction_id, 0x180f);
        assert_eq!(response.header.counts, [1, 1, 0, 0]);
        // The answer's name is two bytes on the wire, c0 0c: a pointer to
        // offset 12, the name of the question.
        assert_eq!(payload[31..33], [0xc0, 0x0c]);
        let answer = &response.answers.as_ref().unwrap()[0];
        assert_eq!(answer.name, "wireshark.org");
        assert_eq!((answer.ttl, answer.data_length), (14400, 4));
        assert_eq!(answer.address, [128, 121, 50, 122]); // the record data, raw

        // Off port 53 the blind rule still finds it: its sections end where
        // the datagram ends, and its counts are not all zero.
        let moved = with_ports(&raw, 40000, 40001);
        assert_eq!(label(&parse(LinkType::ETHERNET, &moved).unwrap()), Some("DNS"));
    }
    // ANCHOR_END: dns_query_and_response

    // ANCHOR: dns_over_tcp
    #[test]
    fn dns_over_tcp_starts_with_a_length() {
        let raw = hex::decode(DNS_TCP_QUERY_HEX).unwrap();
        let flow = parse(LinkType::ETHERNET, &raw).unwrap();
        assert_eq!(label(&flow), Some("DNS")); // 45818 -> 53

        let payload = flow.transport.as_ref().unwrap().payload.unwrap();
        assert_eq!(payload[..2], [0x00, 0x1a]); // 26: the message that follows
        assert_eq!(payload.len(), 2 + 26);
        let query = DnsPacket::try_from_tcp(payload).unwrap();
        assert_eq!(query.queries.queries[0].name, "ripe.net");
        // The datagram form takes the length for a transaction id, and
        // refuses the flags it reads two bytes too late.
        assert!(DnsPacket::try_from(payload).is_err());

        // There is no blind rule on TCP: off port 53 the segment is unknown.
        let moved = with_ports(&raw, 40000, 40001);
        assert_eq!(label(&parse(LinkType::ETHERNET, &moved).unwrap()), Some("Unknown"));
    }
    // ANCHOR_END: dns_over_tcp

    // ANCHOR: mdns_terminal_port
    #[test]
    fn mdns_and_llmnr_ports_are_terminal() {
        let raw = hex::decode(MDNS_ANNOUNCEMENT_HEX).unwrap();
        let flow = parse(LinkType::ETHERNET, &raw).unwrap();
        assert_eq!(label(&flow), Some("mDNS")); // 5353 -> 5353

        // One answer and no question: unicast DNS refuses it, mDNS does not.
        let payload = flow.transport.as_ref().unwrap().payload.unwrap();
        assert!(DnsPacket::try_from(payload).is_err());
        let announcement = DnsPacket::try_from_mdns(payload).unwrap();
        assert_eq!(announcement.header.counts, [0, 1, 0, 0]);
        let record = &announcement.answers.as_ref().unwrap()[0];
        assert_eq!(record.name, "_dacp._tcp.local");
        assert_eq!(record.ttl, 0); // a goodbye: the service is going away
        // Off port 5353 nothing labels it: the blind rule is the strict form.
        let moved = with_ports(&raw, 40000, 40001);
        assert_eq!(label(&parse(LinkType::ETHERNET, &moved).unwrap()), Some("Unknown"));

        // The wireshark.org response on the LLMNR port: its RA bit falls in
        // the bits LLMNR reserves, the probe refuses it, and the port is
        // terminal. No later rule is tried, and the flow has no application.
        let raw = hex::decode(DNS_RESPONSE_HEX).unwrap();
        let moved = with_ports(&raw, 5355, 1060);
        let flow = parse(LinkType::ETHERNET, &moved).unwrap();
        assert!(flow.transport.is_some());
        assert!(flow.application.is_none());
    }
    // ANCHOR_END: mdns_terminal_port
}
