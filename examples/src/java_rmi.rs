//! Examples of the Java RMI page. Every frame is a real frame of
//! `pcaps_exemple/protocols/java_rmi/jdk11-loopback.pcap` in the crate
//! repository: two OpenJDK 11 JVMs on the loopback, with a registry on TCP
//! 1099 and an exported object on TCP 50050 (see the folder's `SOURCE.md`).
//! The bytes were extracted with tshark.

#[cfg(test)]
mod tests {
    use packet_parser::errors::application::java_rmi::JavaRmiError;
    use packet_parser::parse::application::protocols::java_rmi::{
        JAVA_RMI_REGISTRY_INTERFACE_HASH, JavaRmiPacket, JavaRmiReturnType, JavaRmiWellKnownObject,
    };
    use packet_parser::{DecodeAsProtocol, LinkType, PacketFlow, ParseConfig, parse, parse_with};

    /// Frame 33 of `java_rmi/jdk11-loopback.pcap`: the client's
    /// `Registry.list()`, Ethernet / IPv4 / TCP 36568 -> 1099.
    const REGISTRY_LIST_HEX: &str = concat!(
        "00000000000000000000000008004500005dd89b4000400663fd7f0000017f00",
        "00018ed8044b23c176518d92ad6d80180200fe5100000101080ab4de876cb4de",
        "876b50aced000577220000000000000000000000000000000000000000000000",
        "00000144154dc9d4e63bdf",
    );

    /// Frame 35 of the same capture: the registry's Return to `list()`, TCP
    /// 1099 -> 36568.
    const REGISTRY_LIST_RETURN_HEX: &str = concat!(
        "0000000000000000000000000800450000865ecc40004006dda37f0000017f00",
        "0001044b8ed88d92ad6d23c1767a80180200fe7a00000101080ab4de876db4de",
        "876c51aced0005770f01bfcb98ab000001a1e8ed9c5b8006757200135b4c6a61",
        "76612e6c616e672e537472696e673badd256e7e91d7b47020000707870000000",
        "0274000773746174696f6e7400066a6d78726d69",
    );

    /// Frame 38 of the same capture: `Registry.lookup("station")`, TCP
    /// 36568 -> 1099.
    const REGISTRY_LOOKUP_HEX: &str = concat!(
        "000000000000000000000000080045000067d89d4000400663f17f0000017f00",
        "00018ed8044b23c1767b8d92adc080180200fe5b00000101080ab4de8781b4de",
        "877d50aced000577220000000000000000000000000000000000000000000000",
        "00000244154dc9d4e63bdf74000773746174696f6e",
    );

    /// Frame 60 of the same capture: `Station.add(2, 3)` on the exported
    /// object, TCP 53372 -> 50050.
    const STATION_ADD_HEX: &str = concat!(
        "000000000000000000000000080045000065c8d64000400673ba7f0000017f00",
        "0001d07cc38257ef4df1e6c6ecb380180200fe5900000101080ab4de87aab4de",
        "87aa50aced0005772a18ab9a4555f8f98abfcb98ab000001a1e8ed9c5b8001ff",
        "ffffff94a9af306652c3a60000000200000003",
    );

    /// Frame 61 of the same capture: the Return of `add`, TCP 50050 -> 53372.
    const STATION_ADD_RETURN_HEX: &str = concat!(
        "00000000000000000000000008004500004e67e940004006d4be7f0000017f00",
        "0001c382d07ce6c6ecb357ef4e2280180200fe4200000101080ab4de87abb4de",
        "87aa51aced0005771301bfcb98ab000001a1e8ed9c5b800a00000005",
    );

    /// Frame 36 of the same capture: a Ping before the client reuses its
    /// registry connection, TCP 36568 -> 1099.
    const REGISTRY_PING_HEX: &str = concat!(
        "000000000000000000000000080045000035d89c4000400664247f0000017f00",
        "00018ed8044b23c1767a8d92adbf80180200fe2900000101080ab4de877db4de",
        "876d52",
    );

    /// Frame 54 of the same capture: a Ping on the object's connection, TCP
    /// 53372 -> 50050.
    const STATION_PING_HEX: &str = concat!(
        "000000000000000000000000080045000035c8d34000400673ed7f0000017f00",
        "0001d07cc38257ef4dbce6c6ec8980180200fe2900000101080ab4de87aab4de",
        "87a252",
    );

    /// Frame 45 of the same capture: the object's ProtocolAck, TCP
    /// 50050 -> 53372.
    const STATION_PROTOCOL_ACK_HEX: &str = concat!(
        "00000000000000000000000008004500004467e340004006d4ce7f0000017f00",
        "0001c382d07ce6c6eb5a57ef4bea80180200fe3800000101080ab4de879eb4de",
        "879e4e00093132372e302e302e310000d07c",
    );

    /// Frame 8 of the same capture: the EndpointIdentifier the client sends
    /// after the registry's ProtocolAck, TCP 36556 -> 1099.
    const CLIENT_ENDPOINT_HEX: &str = concat!(
        "00000000000000000000000008004500004336d24000400605e17f0000017f00",
        "00018ecc044b1e5b2a3cff8edb3380180200fe3700000101080ab4de863ab4de",
        "863a00093132372e302e302e3100000000",
    );

    /// Frame 329 of the same capture: a stream header with the unknown
    /// protocol `0x4e`, written by hand for the capture, TCP 58428 -> 1099.
    const UNKNOWN_PROTOCOL_HEX: &str = concat!(
        "00000000000000000000000008004500003b7c7a40004006c0407f0000017f00",
        "0001e43c044b71ff8b37094c0a1880180200fe2f00000101080ab4dea8a7b4de",
        "a8a74a524d4900024e",
    );

    /// Frame 331 of the same capture: the registry's answer to frame 329,
    /// TCP 1099 -> 58428.
    const PROTOCOL_NOT_SUPPORTED_HEX: &str = concat!(
        "000000000000000000000000080045000035afa5400040068d1b7f0000017f00",
        "0001044be43c094c0a1871ff8b3e80180200fe2900000101080ab4dea8a8b4de",
        "a8a74f",
    );

    fn label(flow: &PacketFlow<'_>) -> Option<&'static str> {
        flow.application.as_ref().map(|application| application.protocol.label())
    }

    fn payload<'a>(flow: &PacketFlow<'a>) -> &'a [u8] {
        flow.transport.as_ref().unwrap().payload.unwrap()
    }

    // ANCHOR: java_rmi_registry_call
    #[test]
    fn a_registry_call_names_its_method() {
        let raw = hex::decode(REGISTRY_LIST_HEX).unwrap();
        let flow = parse(LinkType::ETHERNET, &raw).unwrap();
        assert_eq!(label(&flow), Some("Java RMI")); // 36568 -> 1099
        let packet = JavaRmiPacket::try_from(payload(&flow)).unwrap();
        assert_eq!(packet.to_string(), "Call Registry.list");
        let JavaRmiPacket::Call(call) = packet else {
            panic!("expected a Call, got {packet:?}");
        };
        // Object 0 in the null space: the registry of any server.
        assert_eq!(call.object.object_number, 0);
        assert!(call.object.space.is_zero());
        assert_eq!(call.object.well_known(), Some(JavaRmiWellKnownObject::Registry));
        // A 1.1 stub: an operation number and the interface hash.
        assert_eq!(call.operation, 1);
        assert_eq!(call.hash, JAVA_RMI_REGISTRY_INTERFACE_HASH);
        assert_eq!(
            call.well_known_method(),
            Some((JavaRmiWellKnownObject::Registry, "list"))
        );
        assert!(call.arguments.is_empty()); // list() takes none

        // Frame 35: the Return. A type and a UID, then the value.
        let raw = hex::decode(REGISTRY_LIST_RETURN_HEX).unwrap();
        let flow = parse(LinkType::ETHERNET, &raw).unwrap();
        assert_eq!(label(&flow), Some("Java RMI")); // 1099 -> 36568
        let JavaRmiPacket::Return(ret) = JavaRmiPacket::try_from(payload(&flow)).unwrap() else {
            panic!("expected a Return");
        };
        assert_eq!(ret.return_type, JavaRmiReturnType::Normal);
        assert_eq!(ret.ack_id.unique, 0xbfcb_98ab_u32 as i32);
        assert_eq!(ret.ack_id.time, 1_794_909_248_603); // 2026-11-17 09:54:08.603 UTC
        assert_eq!(ret.ack_id.count, 0x8006_u16 as i16);
        // The value stays serialized: a TC_ARRAY of String, the two names bound.
        assert_eq!(ret.value[0], 0x75);
        assert!(ret.value.ends_with(b"\x74\x00\x07station\x74\x00\x06jmxrmi"));

        // Frame 38: the lookup of the first name. Its argument is a serialized
        // String: TC_STRING, a two-byte length, the bytes.
        let raw = hex::decode(REGISTRY_LOOKUP_HEX).unwrap();
        let flow = parse(LinkType::ETHERNET, &raw).unwrap();
        let JavaRmiPacket::Call(call) = JavaRmiPacket::try_from(payload(&flow)).unwrap() else {
            panic!("expected a Call");
        };
        assert_eq!(call.operation, 2);
        assert_eq!(
            call.well_known_method(),
            Some((JavaRmiWellKnownObject::Registry, "lookup"))
        );
        assert_eq!(call.arguments, b"\x74\x00\x07station");
    }
    // ANCHOR_END: java_rmi_registry_call

    // ANCHOR: java_rmi_method_call
    #[test]
    fn an_application_call_is_named_by_its_hash() {
        let raw = hex::decode(STATION_ADD_HEX).unwrap();
        let flow = parse(LinkType::ETHERNET, &raw).unwrap();
        // 53372 -> 50050, a port no rule knows: the blind rule takes a Call.
        assert_eq!(label(&flow), Some("Java RMI"));
        let packet = JavaRmiPacket::try_from(payload(&flow)).unwrap();
        assert!(packet.is_self_identifying());
        let JavaRmiPacket::Call(call) = packet else {
            panic!("expected a Call, got {packet:?}");
        };
        // An exported object: a random number, in the space of the server's JVM.
        assert_eq!(call.object.object_number, 0x18ab_9a45_55f8_f98a);
        assert_eq!(call.object.well_known(), None);
        // A 1.2 stub: operation -1, and the hash names the method.
        assert_eq!(call.operation, -1);
        assert_eq!(call.hash, 0x94a9_af30_6652_c3a6_u64 as i64);
        assert_eq!(call.well_known_method(), None);
        assert_eq!(
            packet.to_string(),
            "Call object 1777684100513593738 operation -1 hash 0x94a9af306652c3a6"
        );
        // The block is 42 bytes: the 34 of the call header, then two int.
        assert_eq!(payload(&flow)[6], 42);
        assert_eq!(call.arguments, [0, 0, 0, 2, 0, 0, 0, 3]);

        // Frame 61: the Return, 5, in the same block as its header.
        let raw = hex::decode(STATION_ADD_RETURN_HEX).unwrap();
        let flow = parse(LinkType::ETHERNET, &raw).unwrap();
        assert_eq!(label(&flow), Some("Java RMI")); // 50050 -> 53372
        let JavaRmiPacket::Return(ret) = JavaRmiPacket::try_from(payload(&flow)).unwrap() else {
            panic!("expected a Return");
        };
        assert_eq!(ret.return_type, JavaRmiReturnType::Normal);
        assert_eq!(ret.value, [0, 0, 0, 5]);
        // Both UIDs come from the server's JVM: the same unique and time.
        assert_eq!(ret.ack_id.unique, call.object.space.unique);
        assert_eq!(ret.ack_id.time, call.object.space.time);
    }
    // ANCHOR_END: java_rmi_method_call

    // ANCHOR: java_rmi_port_and_blind
    #[test]
    fn a_one_byte_message_needs_port_1099_or_a_decode_as() {
        // Frame 36: a Ping on the registry connection, 36568 -> 1099.
        let raw = hex::decode(REGISTRY_PING_HEX).unwrap();
        let flow = parse(LinkType::ETHERNET, &raw).unwrap();
        assert_eq!(payload(&flow), [0x52]);
        assert_eq!(JavaRmiPacket::try_from(payload(&flow)), Ok(JavaRmiPacket::Ping));
        assert_eq!(label(&flow), Some("Java RMI"));

        // Frame 54: the same byte on the object's connection, 53372 -> 50050.
        // One byte proves nothing: the blind rule leaves it.
        let raw = hex::decode(STATION_PING_HEX).unwrap();
        let flow = parse(LinkType::ETHERNET, &raw).unwrap();
        assert_eq!(payload(&flow), [0x52]);
        assert_eq!(label(&flow), Some("Unknown"));

        // A declared port gets the probe of the 1099 rule.
        let config = ParseConfig::new().decode_as(50050, DecodeAsProtocol::JavaRmi);
        let flow = parse_with(LinkType::ETHERNET, &raw, &config).unwrap();
        assert_eq!(label(&flow), Some("Java RMI"));

        // Frame 45: the object's ProtocolAck, 50050 -> 53372. A type byte and
        // free fields: off 1099, only the declared port labels it.
        let raw = hex::decode(STATION_PROTOCOL_ACK_HEX).unwrap();
        assert_eq!(label(&parse(LinkType::ETHERNET, &raw).unwrap()), Some("Unknown"));
        let flow = parse_with(LinkType::ETHERNET, &raw, &config).unwrap();
        assert_eq!(label(&flow), Some("Java RMI"));
        let packet = JavaRmiPacket::try_from(payload(&flow)).unwrap();
        assert!(!packet.is_self_identifying());
        let JavaRmiPacket::ProtocolAck(endpoint) = packet else {
            panic!("expected a ProtocolAck, got {packet:?}");
        };
        // The client as the server sees it: its address and its port.
        assert_eq!(endpoint.hostname_str(), Some("127.0.0.1"));
        assert_eq!(endpoint.port, 53372);
    }
    // ANCHOR_END: java_rmi_port_and_blind

    // ANCHOR: java_rmi_errors
    #[test]
    fn what_the_decoder_refuses() {
        // Frame 8: the client's EndpointIdentifier, 36556 -> 1099. No type
        // byte: it starts with the length of the hostname, 9.
        let raw = hex::decode(CLIENT_ENDPOINT_HEX).unwrap();
        let flow = parse(LinkType::ETHERNET, &raw).unwrap();
        assert_eq!(payload(&flow)[..2], [0x00, 0x09]);
        assert_eq!(
            JavaRmiPacket::try_from(payload(&flow)),
            Err(JavaRmiError::UnknownMessageType(0))
        );
        assert_eq!(label(&flow), Some("Unknown")); // even on 1099

        // Frame 329: a stream header with the protocol 0x4e, 58428 -> 1099.
        let raw = hex::decode(UNKNOWN_PROTOCOL_HEX).unwrap();
        let flow = parse(LinkType::ETHERNET, &raw).unwrap();
        assert_eq!(payload(&flow), b"JRMI\x00\x02\x4e");
        let error = JavaRmiPacket::try_from(payload(&flow)).unwrap_err();
        assert_eq!(error, JavaRmiError::UnknownProtocol(0x4e));
        assert_eq!(error.to_string(), "Unknown Java RMI protocol 0x4e");
        assert_eq!(label(&flow), Some("Unknown"));

        // Frame 331: the registry refuses it with one byte, labelled on 1099.
        let raw = hex::decode(PROTOCOL_NOT_SUPPORTED_HEX).unwrap();
        let flow = parse(LinkType::ETHERNET, &raw).unwrap();
        assert_eq!(
            JavaRmiPacket::try_from(payload(&flow)),
            Ok(JavaRmiPacket::ProtocolNotSupported)
        );
        assert_eq!(label(&flow), Some("Java RMI"));
    }
    // ANCHOR_END: java_rmi_errors
}
