//! Parsers added by the caller (13.0.0) and rule files (13.1.0): the
//! [Custom parsers and rules](../../src/custom_parsers.md) chapter.
//!
//! ACME and DEMO are made up: no real protocol has their bytes.

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use packet_parser::{
        ApplicationParser, ApplicationProtocol, CustomTransports, LinkType, PacketFlow, ParseConfig,
        PayloadContext, RuleSet, parse, parse_with,
    };

    use crate::ETHERNET_IPV4_TCP_GIOP_REQUEST_HEX;

    /// An Ethernet / IPv4 / UDP frame from port 40000 to `destination_port`.
    fn udp_frame(destination_port: u16, payload: &[u8]) -> Vec<u8> {
        let udp_length = u16::try_from(8 + payload.len()).unwrap();
        let mut frame = vec![2, 0, 0, 0, 0, 2, 2, 0, 0, 0, 0, 1, 0x08, 0x00];
        frame.extend_from_slice(&[0x45, 0]);
        frame.extend_from_slice(&(20 + udp_length).to_be_bytes());
        frame.extend_from_slice(&[0, 1, 0x40, 0, 64, 17, 0, 0, 192, 0, 2, 1, 192, 0, 2, 2]);
        frame.extend_from_slice(&40_000_u16.to_be_bytes());
        frame.extend_from_slice(&destination_port.to_be_bytes());
        frame.extend_from_slice(&udp_length.to_be_bytes());
        frame.extend_from_slice(&[0, 0]);
        frame.extend_from_slice(payload);
        frame
    }

    /// The label of a flow.
    fn protocol(flow: &PacketFlow<'_>) -> Option<ApplicationProtocol> {
        flow.application.as_ref().map(|application| application.protocol)
    }

    /// An ACME request: magic, version 1, type 1, a length of 12, an id.
    const ACME_REQUEST: &[u8] = b"ACME\x01\x01\x00\x0c\xde\xad\xbe\xef";

    // ANCHOR: acme_parser
    /// ACME: datagrams on UDP 47000 that start with `ACME`.
    struct Acme;

    impl ApplicationParser for Acme {
        fn label(&self) -> &'static str {
            "ACME"
        }

        fn transports(&self) -> CustomTransports {
            CustomTransports::Udp // TCP and UDP by default
        }

        fn ports(&self) -> &[u16] {
            &[47_000] // any port by default
        }

        fn matches(&self, payload: &[u8], _context: &PayloadContext) -> bool {
            payload.starts_with(b"ACME")
        }

        fn fields(&self, payload: &[u8], _context: &PayloadContext) -> Vec<(String, String)> {
            match payload.get(5) {
                Some(kind) => vec![("type".to_string(), kind.to_string())],
                None => Vec::new(),
            }
        }
    }
    // ANCHOR_END: acme_parser

    // ANCHOR: acme_registered
    #[test]
    fn an_added_parser_names_what_the_table_left_unknown() {
        let frame = udp_frame(47_000, ACME_REQUEST);
        let flow = parse(LinkType::ETHERNET, &frame).unwrap();
        assert_eq!(protocol(&flow), Some(ApplicationProtocol::Unknown));

        let config = ParseConfig::new().with_parser(Arc::new(Acme)).unwrap();
        let flow = parse_with(LinkType::ETHERNET, &frame, &config).unwrap();
        assert_eq!(protocol(&flow), Some(ApplicationProtocol::Custom("ACME")));
        assert_eq!(protocol(&flow).unwrap().label(), "ACME");

        // The fields are read on demand, when a packet is shown.
        let fields = config.custom_fields(&flow).unwrap();
        assert_eq!(fields, [("type".to_string(), "1".to_string())]);

        // The port list is a guard: on another port the parser is not called.
        let elsewhere = udp_frame(47_001, ACME_REQUEST);
        let flow = parse_with(LinkType::ETHERNET, &elsewhere, &config).unwrap();
        assert_eq!(protocol(&flow), Some(ApplicationProtocol::Unknown));
    }
    // ANCHOR_END: acme_registered

    // ANCHOR: never_takes_a_frame
    /// A parser that accepts every payload, on every transport and port.
    struct Everything;

    impl ApplicationParser for Everything {
        fn label(&self) -> &'static str {
            "EVERYTHING"
        }

        fn matches(&self, _payload: &[u8], _context: &PayloadContext) -> bool {
            true
        }
    }

    #[test]
    fn an_added_parser_never_takes_a_frame_from_the_crate() {
        let config = ParseConfig::new().with_parser(Arc::new(Everything)).unwrap();

        // The GIOP request of corba.pcap stays GIOP: the table named it.
        let raw = hex::decode(ETHERNET_IPV4_TCP_GIOP_REQUEST_HEX).unwrap();
        let flow = parse_with(LinkType::ETHERNET, &raw, &config).unwrap();
        assert_eq!(protocol(&flow), Some(ApplicationProtocol::Giop));
        assert_eq!(config.custom_fields(&flow), None);

        // A label of the crate is refused, whatever its case.
        struct FakeDns;
        impl ApplicationParser for FakeDns {
            fn label(&self) -> &'static str {
                "dns"
            }
            fn matches(&self, _payload: &[u8], _context: &PayloadContext) -> bool {
                false
            }
        }
        assert!(ParseConfig::new().with_parser(Arc::new(FakeDns)).is_err());
    }
    // ANCHOR_END: never_takes_a_frame

    // ANCHOR: label_read_back
    #[test]
    fn a_stored_label_reads_back_with_its_configuration() {
        let mut config = ParseConfig::new().with_parser(Arc::new(Acme)).unwrap();

        // `FromStr` knows the labels of the crate, not those of a configuration.
        assert_eq!("DNS".parse::<ApplicationProtocol>(), Ok(ApplicationProtocol::Dns));
        assert!("ACME".parse::<ApplicationProtocol>().is_err());

        // The configuration knows both. The comparison is exact, case included.
        assert_eq!(config.application_protocol("DNS"), Ok(ApplicationProtocol::Dns));
        assert_eq!(config.application_protocol("ACME"), Ok(ApplicationProtocol::Custom("ACME")));
        assert!(config.application_protocol("acme").is_err());

        // A parser removed since the export: the label no longer reads back.
        config.remove_parser("ACME");
        assert!(config.application_protocol("ACME").is_err());
    }
    // ANCHOR_END: label_read_back

    // ANCHOR: acme_rules
    const ACME_RULES: &str = r#"
version = 1

[[rule]]
label = "ACME"
transport = "udp"
ports = [47000]
min_length = 12

[[rule.pattern]]
offset = 0
bytes = "41 43 4D 45"   # "ACME"

[[rule.pattern]]
offset = 4
bytes = "01"
mask = "0F"             # version 1 in the low nibble

[[rule.field]]
name = "type"
offset = 5
type = "u8"
values = { 1 = "request", 2 = "response", 0x7F = "error" }

[[rule.field]]
name = "length"
offset = 6
type = "u16be"

[[rule.field]]
name = "id"
offset = 8
type = "hex"
length = 4
"#;

    #[test]
    fn a_rule_file_names_and_shows_a_protocol_without_code() {
        let rules = RuleSet::from_toml(ACME_RULES).unwrap();
        assert_eq!(rules.labels().collect::<Vec<_>>(), ["ACME"]);
        let config = ParseConfig::new().with_rules(&rules).unwrap();

        let frame = udp_frame(47_000, ACME_REQUEST);
        let flow = parse_with(LinkType::ETHERNET, &frame, &config).unwrap();
        assert_eq!(protocol(&flow), Some(ApplicationProtocol::Custom("ACME")));
        let fields = config.custom_fields(&flow).unwrap();
        let shown: Vec<String> = fields.iter().map(|(name, value)| format!("{name}: {value}")).collect();
        assert_eq!(shown, ["type: request (1)", "length: 12", "id: DE AD BE EF"]);

        // Version 2 in the low nibble: the second pattern fails.
        let mut version_2 = ACME_REQUEST.to_vec();
        version_2[4] = 0x02;
        let frame = udp_frame(47_000, &version_2);
        let flow = parse_with(LinkType::ETHERNET, &frame, &config).unwrap();
        assert_eq!(protocol(&flow), Some(ApplicationProtocol::Unknown));
    }
    // ANCHOR_END: acme_rules

    // ANCHOR: weak_rule
    #[test]
    fn a_rule_on_a_port_and_one_byte_is_refused() {
        // 8 bits of pattern: a random payload would match once in 256.
        let weak = "version = 1\n\n[[rule]]\nlabel = \"ACME\"\nports = [47000]\n\n\
                    [[rule.pattern]]\noffset = 0\nbytes = \"41\"\n";
        let error = RuleSet::from_toml(weak).unwrap_err();
        assert_eq!(error.line(), Some(3));
        assert!(error.message().starts_with("signature trop faible : 8 bits"));

        // A typo is an unknown key, refused where it is.
        let typo = ACME_RULES.replace("mask = \"0F\"", "masq = \"0F\"");
        let error = RuleSet::from_toml(&typo).unwrap_err();
        assert!(error.to_string().starts_with("ligne 17, colonne 1 : "));
    }
    // ANCHOR_END: weak_rule
}
