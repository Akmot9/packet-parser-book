//! Examples of the application chapter's own sections: NTP, Modbus/TCP and
//! UMAS, PostgreSQL. Every frame is a real frame of the crate's corpus
//! (`pcaps_exemple/` in the crate repository), extracted with tshark.

#[cfg(test)]
mod tests {
    use packet_parser::parse::application::protocols::modbus_tcp::ModbusTcpPacket;
    use packet_parser::parse::application::protocols::ntp::{NtpPacket, Refid};
    use packet_parser::parse::application::protocols::postgresql::{
        PostgreSqlMessageBody, PostgreSqlMessageType, PostgreSqlPacket,
    };
    use packet_parser::parse::application::protocols::umas::{UmasFunction, UmasPacket};
    use packet_parser::{DecodeAsProtocol, LinkType, PacketFlow, ParseConfig, parse, parse_with};

    /// Frame 1 of `protocols/iec104/iti_JavaRMI_and_IEC_Misc.pcap` (ITI): a
    /// Java client's NTPv4 request, Ethernet / IPv4 / UDP 1027 -> 123.
    const NTP_JAVA_REQUEST_HEX: &str = concat!(
        "00e0ab011018001c11405d8c08004500004c000000003b11a5790ad10d91c0a8",
        "011e0403007b0038fdb223000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000002500000000",
    );

    /// Frame 2 of `protocols/iec104/iti_JavaRMI_and_IEC_Misc.pcap`: the
    /// stratum 1 server's reply, UDP 123 -> 1027.
    const NTP_SHM_REPLY_HEX: &str = concat!(
        "001c11405d8c00e0ab01101808004500004c13bc400040114cbdc0a8011e0ad1",
        "0d91007b0403003889ee240100ed00000000006bd0b953484d00cbce6bc97b89",
        "4dc10000002500000000cc3c245b1152c685cc3c245b115a3524",
    );

    /// Frame 3 of `protocols/ntp/tcpdump_ntp.pcap` (tcpdump test corpus): a
    /// chrony request, Ethernet / IPv4 / UDP 42818 -> 123, with a SHA-1 MAC.
    const NTP_CHRONY_REQUEST_HEX: &str = concat!(
        "001213141516001213141517080045000064169140004011daa3c0a86402c0a8",
        "6401a742007b005049b623000020000000000000000000000000000000000000",
        "0000dcf25be5794d206a6b70caf9b1a9f9d9ae9d0aa81b8971a7000000088b7e",
        "640979156264f3faa5ae979656dd86502431",
    );

    /// Frame 1 of `protocols/modbus/Modbus.pcap`: a Read Holding Registers
    /// request, Ethernet / IPv4 / TCP 2074 -> 502.
    const MODBUS_READ_HEX: &str = concat!(
        "001cc05f490a000ae4c5830a0800450000348bfd400080061068c0a86e83c0a8",
        "6e8a081a01f641d2eac6e1153ace5018fcc60032000000d10000000601030001",
        "0001",
    );

    /// Frame 170 of `protocols/modbus/MODBUS-TestDataPart2.pcap` (ITI): a
    /// scanner's request with function code 0x41, TCP 2582 -> 502.
    const MODBUS_USER_FUNCTION_HEX: &str = concat!(
        "00c0a8f2bffb000c296b2d28080045000034fd52400080064256c0a842eba6a1",
        "10e60a1601f6f1ece05a8a75f8135018fa9f97e1000000000000000601410000",
        "0000",
    );

    /// Frame 40035 of `The-Ultimate-PCAP.pcapng`: an Active Directory LDAP
    /// bindResponse, Ethernet / VLAN 80 / IPv6 / TCP 389 -> 49961.
    const LDAP_BIND_RESPONSE_HEX: &str = concat!(
        "3cfa30031230000c29a9e4e38100005086dd600d4a45008206402a006020ad0b",
        "838000000000000000102a006020ad0b8381fd70e2f9f0319dc40185c329afc2",
        "4adac5adcf1950181fff2936000030840000006802010961840000005f0a0131",
        "0400045838303039303330433a204c6461704572723a20445349442d30433039",
        "303641422c20636f6d6d656e743a204163636570745365637572697479436f6e",
        "74657874206572726f722c2064617461203532652c20763466376300",
    );

    /// Frame 6 of `protocols/umas/umas.pcap` (nDPI): a Modicon PLC's UMAS
    /// reply, Ethernet / IPv4 / TCP 502 -> 7718.
    const UMAS_REPLY_HEX: &str = concat!(
        "3c970e9154ab00005414f24f08004500006003c700004006761fc0a83ffdc0a8",
        "3f6401f61e268310cfbe4684fc15501810006d3e0000000000000032005a00fe",
        "10ff5a010100000070020000270009000800000000000e313430204350552033",
        "3131203130010101000000001100",
    );

    /// Frame 6 of `protocols/postgresql/psql-login.pcap` (Zeek): the
    /// server's one-byte answer to SSLRequest, Ethernet / IPv4 / TCP
    /// 5432 -> 35304.
    const POSTGRESQL_SSL_ANSWER_HEX: &str = concat!(
        "0000000000000000000000000800450000354ad240004006f1ee7f0000017f00",
        "0001153889e800bfd256aaf2fcb48018020054c200000101080a51ec8b1d51ec",
        "8b1b4e",
    );

    /// Frame 12 of `protocols/postgresql/psql-login.pcap`: psql's
    /// SASLInitialResponse, TCP 35304 -> 5432.
    const POSTGRESQL_SASL_INITIAL_HEX: &str = concat!(
        "00000000000000000000000008004500006b5b8e40004006e0fc7f0000017f00",
        "000189e81538aaf2fd0000bfd26f801802008bda00000101080a51ec8b2051ec",
        "8b1f7000000036534352414d2d5348412d32353600000000206e2c2c6e3d2c72",
        "3d5538784939575938597363524173567737347978324c7434",
    );

    fn label(flow: &PacketFlow<'_>) -> Option<&'static str> {
        flow.application.as_ref().map(|application| application.application_protocol)
    }

    // ANCHOR: with_ports
    /// The same frame with other transport ports: Ethernet, IPv4 (header
    /// length in the low nibble of byte 14), then TCP or UDP, whose first
    /// four bytes are the two ports. `parse` verifies no checksum, so nothing
    /// else changes.
    fn with_ports(raw: &[u8], source: u16, destination: u16) -> Vec<u8> {
        let ports = 14 + usize::from(raw[14] & 0x0f) * 4;
        let mut moved = raw.to_vec();
        moved[ports..ports + 2].copy_from_slice(&source.to_be_bytes());
        moved[ports + 2..ports + 4].copy_from_slice(&destination.to_be_bytes());
        moved
    }
    // ANCHOR_END: with_ports

    // ANCHOR: ntp_lenient_on_port_123
    #[test]
    fn ntp_is_lenient_on_port_123_and_strict_elsewhere() {
        let raw = hex::decode(NTP_CHRONY_REQUEST_HEX).unwrap();
        let flow = parse(LinkType::ETHERNET, &raw).unwrap();
        assert_eq!(label(&flow), Some("NTP")); // 42818 -> 123: the decoder alone

        let payload = flow.transport.as_ref().unwrap().payload.unwrap();
        assert_eq!(payload.len(), 48 + 24); // the header, then a key id and a SHA-1 digest
        let request = NtpPacket::try_from(payload).unwrap();
        assert_eq!(request.flags, (0, 4, 3)); // leap indicator 0, version 4, mode 3: client
        assert_eq!(request.precision, 32); // what chrony puts in its client requests
        // chrony fills Receive and Transmit with random values: here Receive
        // falls in 2093 and Transmit in 1992.
        assert!(request.receive_timestamp.to_rfc3339().starts_with("2093-03-22"));
        assert!(request.transmit_timestamp.to_rfc3339().starts_with("1992-10-31"));

        // The same bytes off port 123: the blind probe also wants Receive
        // not after Transmit, and refuses them.
        let moved = with_ports(&raw, 42818, 40001);
        let flow = parse(LinkType::ETHERNET, &moved).unwrap();
        assert_eq!(label(&flow), Some("Unknown"));
    }
    // ANCHOR_END: ntp_lenient_on_port_123

    // ANCHOR: ntp_era_and_clocks
    #[test]
    fn ntp_timestamps_have_an_era_and_two_clocks() {
        // The Java client's request. Its one timestamp, Transmit, counts 37
        // seconds with the high bit clear: era 1, which starts in 2036.
        let raw = hex::decode(NTP_JAVA_REQUEST_HEX).unwrap();
        let flow = parse(LinkType::ETHERNET, &raw).unwrap();
        assert_eq!(label(&flow), Some("NTP"));
        let request = NtpPacket::try_from(flow.transport.as_ref().unwrap().payload.unwrap()).unwrap();
        assert_eq!(request.stratum, 0);
        assert_eq!(request.transmit_timestamp.to_rfc3339(), "2036-02-07T06:28:53+00:00");
        // An all-zero timestamp is "unknown", and comes out as the Unix epoch.
        assert_eq!(request.receive_timestamp.to_rfc3339(), "1970-01-01T00:00:00+00:00");

        // The server's reply. Its clock source is SHM, ntpd's shared memory
        // driver, which the RFC's list of codes does not name.
        let raw = hex::decode(NTP_SHM_REPLY_HEX).unwrap();
        let flow = parse(LinkType::ETHERNET, &raw).unwrap();
        assert_eq!(label(&flow), Some("NTP"));
        let reply = NtpPacket::try_from(flow.transport.as_ref().unwrap().payload.unwrap()).unwrap();
        assert_eq!(reply.flags, (0, 4, 4)); // mode 4: server
        assert_eq!(reply.stratum, 1);
        assert_eq!(reply.precision, -19);
        assert_eq!(reply.root_dispersion >> 16, 107); // 16.16 seconds: 107.8 s, not bounded
        assert_eq!(reply.reference_id, Refid::ClockSource(*b"SHM\0"));
        assert_eq!(reply.reference_id.to_string(), "SHM");

        // Originate is the client's Transmit, copied back: 2036 on the
        // client's clock, after the 2008 of the server's Receive. Only
        // Receive and Transmit share a clock.
        assert_eq!(reply.originate_timestamp, request.transmit_timestamp);
        assert!(reply.originate_timestamp > reply.receive_timestamp);
        assert_eq!(reply.receive_timestamp.to_rfc3339(), "2008-07-31T11:45:31.067669303+00:00");
        assert!(reply.receive_timestamp <= reply.transmit_timestamp);

        // Both datagrams are NTP for the blind probe too, off port 123.
        for (hex_frame, source, destination) in
            [(NTP_JAVA_REQUEST_HEX, 1027, 40001), (NTP_SHM_REPLY_HEX, 40001, 1027)]
        {
            let moved = with_ports(&hex::decode(hex_frame).unwrap(), source, destination);
            assert_eq!(label(&parse(LinkType::ETHERNET, &moved).unwrap()), Some("NTP"));
        }
    }
    // ANCHOR_END: ntp_era_and_clocks

    // ANCHOR: modbus_lenient_on_port_502
    #[test]
    fn modbus_is_lenient_on_port_502_and_strict_elsewhere() {
        // A Read Holding Registers request: a common function code, and the
        // four bytes of data it imposes.
        let raw = hex::decode(MODBUS_READ_HEX).unwrap();
        let flow = parse(LinkType::ETHERNET, &raw).unwrap();
        assert_eq!(label(&flow), Some("ModbusTCP"));
        let payload = flow.transport.as_ref().unwrap().payload.unwrap();
        let packet = ModbusTcpPacket::try_from(payload).unwrap();
        let [mbap] = packet.mbaps.as_slice() else {
            panic!("one MBAP, got {}", packet.mbaps.len());
        };
        assert_eq!(mbap.transaction_identifier, 209);
        assert_eq!((mbap.protocol_identifier, mbap.length, mbap.unit_identifier), (0, 6, 1));
        assert_eq!(mbap.pdu.function_code, 0x03);
        assert_eq!(mbap.pdu.pdu_data, [0x00, 0x01, 0x00, 0x01]); // address 1, quantity 1

        let moved = with_ports(&raw, 2074, 40001);
        assert_eq!(label(&parse(LinkType::ETHERNET, &moved).unwrap()), Some("ModbusTCP"));

        // A scanner's probe with function code 0x41, of the user-defined
        // range: a valid envelope, which only port 502 accepts.
        let raw = hex::decode(MODBUS_USER_FUNCTION_HEX).unwrap();
        let flow = parse(LinkType::ETHERNET, &raw).unwrap();
        assert_eq!(label(&flow), Some("ModbusTCP"));
        let moved = with_ports(&raw, 2582, 40001);
        assert_eq!(label(&parse(LinkType::ETHERNET, &moved).unwrap()), Some("Unknown"));
    }
    // ANCHOR_END: modbus_lenient_on_port_502

    // ANCHOR: modbus_ldap_lookalike
    #[test]
    fn an_ldap_message_has_the_envelope_of_modbus_not_its_label() {
        let raw = hex::decode(LDAP_BIND_RESPONSE_HEX).unwrap();
        let flow = parse(LinkType::ETHERNET, &raw).unwrap();
        let payload = flow.transport.as_ref().unwrap().payload.unwrap();

        // 30 84 00 00 00 68: a BER SEQUENCE with a four-byte length, read as
        // transaction 0x3084, protocol 0 and a length that fills the segment;
        // then the messageID INTEGER, 02 01, read as unit 2 and function 1.
        let packet = ModbusTcpPacket::try_from(payload).unwrap();
        let [mbap] = packet.mbaps.as_slice() else {
            panic!("one MBAP, got {}", packet.mbaps.len());
        };
        assert_eq!(mbap.transaction_identifier, 0x3084);
        assert_eq!(usize::from(mbap.length) + 6, payload.len());
        assert_eq!((mbap.unit_identifier, mbap.pdu.function_code), (2, 1));

        // On TCP 389 only the blind probe can label it, and it refuses.
        assert_eq!(label(&flow), Some("Unknown"));
    }
    // ANCHOR_END: modbus_ldap_lookalike

    // ANCHOR: umas_decode_as
    #[test]
    fn umas_keeps_its_label_off_port_a_declared_modbus_port_does_not() {
        let raw = hex::decode(UMAS_REPLY_HEX).unwrap();
        let flow = parse(LinkType::ETHERNET, &raw).unwrap();
        assert_eq!(label(&flow), Some("UMAS")); // 502 -> 7718: UMAS comes before ModbusTCP

        let umas = UmasPacket::try_from(flow.transport.as_ref().unwrap().payload.unwrap()).unwrap();
        assert_eq!(umas.mbap.pdu.function_code, 0x5A);
        assert_eq!(umas.session_id, 0x00);
        assert_eq!(umas.function, UmasFunction::Reply); // 0xFE
        assert!(umas.data.windows(14).any(|bytes| bytes == b"140 CPU 311 10")); // the PLC's model

        // Off port 502 the UMAS probe is the same: still UMAS.
        let moved = with_ports(&raw, 40001, 7718);
        assert_eq!(label(&parse(LinkType::ETHERNET, &moved).unwrap()), Some("UMAS"));

        // A port declared as Modbus/TCP is tried before the table, with the
        // tolerant decoder: the label is the declared protocol.
        let config = ParseConfig::new().decode_as(40001, DecodeAsProtocol::ModbusTcp);
        let flow = parse_with(LinkType::ETHERNET, &moved, &config).unwrap();
        assert_eq!(label(&flow), Some("ModbusTCP"));
    }
    // ANCHOR_END: umas_decode_as

    // ANCHOR: postgresql_ssl_answer
    #[test]
    fn a_one_byte_ssl_answer_needs_the_port() {
        let raw = hex::decode(POSTGRESQL_SSL_ANSWER_HEX).unwrap();
        let flow = parse(LinkType::ETHERNET, &raw).unwrap();
        assert_eq!(label(&flow), Some("PostgreSQL")); // 5432 -> 35304

        let payload = flow.transport.as_ref().unwrap().payload.unwrap();
        assert_eq!(payload, b"N"); // TLS refused
        let packet = PostgreSqlPacket::try_from(payload).unwrap();
        let [message] = packet.messages.as_slice() else {
            panic!("one message, got {}", packet.messages.len());
        };
        assert_eq!(message.message_type, PostgreSqlMessageType::SslResponse);
        assert_eq!(message.body, PostgreSqlMessageBody::SslResponse { accepted: false });

        // One byte proves nothing: off port 5432 the blind probe leaves it.
        let moved = with_ports(&raw, 5433, 35304);
        assert_eq!(label(&parse(LinkType::ETHERNET, &moved).unwrap()), Some("Unknown"));

        // A declared port gets the port rule's probe.
        let config = ParseConfig::new().decode_as(5433, DecodeAsProtocol::PostgreSql);
        let flow = parse_with(LinkType::ETHERNET, &moved, &config).unwrap();
        assert_eq!(label(&flow), Some("PostgreSQL"));
    }
    // ANCHOR_END: postgresql_ssl_answer

    // ANCHOR: postgresql_password_message
    #[test]
    fn a_scram_p_message_is_proof_on_any_port() {
        let raw = hex::decode(POSTGRESQL_SASL_INITIAL_HEX).unwrap();
        let flow = parse(LinkType::ETHERNET, &raw).unwrap();
        assert_eq!(label(&flow), Some("PostgreSQL")); // 35304 -> 5432

        let payload = flow.transport.as_ref().unwrap().payload.unwrap();
        assert_eq!(payload[0], b'p');
        let packet = PostgreSqlPacket::try_from(payload).unwrap();
        let [message] = packet.messages.as_slice() else {
            panic!("one message, got {}", packet.messages.len());
        };
        assert_eq!(message.message_type, PostgreSqlMessageType::PasswordOrSaslResponse);
        assert_eq!(message.length, 54);
        assert!(matches!(message.body, PostgreSqlMessageBody::Raw(_)));
        // The mechanism, the length of the initial response, then SCRAM's
        // client-first-message: no user name (psql sends it in the
        // StartupMessage), and the client's nonce.
        assert!(message.payload.starts_with(b"SCRAM-SHA-256\0"));
        assert!(message.payload.windows(8).any(|bytes| bytes == b"n,,n=,r="));

        // The SCRAM form is strong evidence: the blind probe keeps the label
        // off port 5432.
        let moved = with_ports(&raw, 35304, 5433);
        assert_eq!(label(&parse(LinkType::ETHERNET, &moved).unwrap()), Some("PostgreSQL"));
    }
    // ANCHOR_END: postgresql_password_message
}
