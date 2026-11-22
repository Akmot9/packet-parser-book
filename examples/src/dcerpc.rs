//! Examples of the DCE/RPC page. Both frames come from
//! `pcaps_exemple/The-Ultimate-PCAP.pcapng` in the crate repository: a
//! Windows client asks the endpoint mapper of a server, on TCP 135, where a
//! service listens. The bytes were extracted with tshark 4.6.9.

#[cfg(test)]
mod tests {
    use packet_parser::errors::application::dcerpc::DceRpcError;
    use packet_parser::parse::application::protocols::dcerpc::{
        DCERPC_COMMON_HEADER_LENGTH, DceRpcPdu, DceRpcPduType,
    };
    use packet_parser::{LinkType, PacketFlow, parse};

    /// Frame 40261: a Bind to the endpoint mapper, Ethernet / VLAN / IPv6 /
    /// TCP 49984 -> 135, a PDU of 160 bytes.
    const BIND_HEX: &str = concat!(
        "3cfa30031230000c29c37feb8100005186dd60037ec900b406402a006020ad0b",
        "8381fd70e2f9f0319dc42a006020ad0b83800000000000000010c340008712be",
        "51c26b2ddf7b50180405a787000005000b0310000000a000000002000000d016",
        "d0160000000003000000000001000883afe11f5dc91191a408002b14a0fa0300",
        "0000045d888aeb1cc9119fe808002b10486002000000010001000883afe11f5d",
        "c91191a408002b14a0fa0300000033057171babe37498319b5dbef9ccc360100",
        "0000020001000883afe11f5dc91191a408002b14a0fa030000002c1cb76c1298",
        "4045030000000000000001000000",
    );

    /// Frame 40263: the Request that follows, operation 3 of the endpoint
    /// mapper (`ept_map`), a PDU of 168 bytes.
    const REQUEST_HEX: &str = concat!(
        "3cfa30031230000c29c37feb8100005186dd60037ec900bc06402a006020ad0b",
        "8381fd70e2f9f0319dc42a006020ad0b83800000000000000010c340008712be",
        "52626b2ddfe750180404e8f100000500000310000000a8000000020000009000",
        "0000010003000100000000000000000000000000000000000000000000000200",
        "0000000000004b000000000000004b000000050013000d354251e3064bd111ab",
        "0400c04fc2dcd204000200000013000d045d888aeb1cc9119fe808002b104860",
        "02000200000001000b0200000001000702000087010009040000000000000000",
        "00000000000000000000000000000000000004000000",
    );

    fn label(flow: &PacketFlow<'_>) -> Option<&'static str> {
        flow.application.as_ref().map(|application| application.protocol.label())
    }

    fn payload<'a>(flow: &PacketFlow<'a>) -> &'a [u8] {
        flow.transport.as_ref().unwrap().payload.unwrap()
    }

    // ANCHOR: dcerpc_bind
    #[test]
    fn a_bind_and_its_common_header() {
        let raw = hex::decode(BIND_HEX).unwrap();
        let flow = parse(LinkType::ETHERNET, &raw).unwrap();
        assert_eq!(label(&flow), Some("DCE/RPC"));

        let pdu = DceRpcPdu::try_from(payload(&flow)).unwrap();
        assert_eq!(pdu.version_minor, 0);
        assert_eq!(pdu.pdu_type, DceRpcPduType::Bind);
        assert_eq!(pdu.pdu_type.as_u8(), 11);
        // One fragment holds the whole PDU: first and last at once.
        assert_eq!(pdu.flags, 0x03);
        assert!(pdu.is_first_fragment() && pdu.is_last_fragment());
        // The label says little-endian, ASCII, IEEE: what Windows sends.
        assert_eq!(pdu.data_representation, [0x10, 0, 0, 0]);
        assert!(pdu.little_endian);
        assert_eq!((pdu.frag_length, pdu.auth_length), (160, 0));
        assert_eq!(pdu.call_id, 2);

        // The body is what follows the 16 bytes of the header: here the
        // three presentation contexts, borrowed and not decoded.
        assert_eq!(pdu.body.len(), 160 - DCERPC_COMMON_HEADER_LENGTH);
        assert!(!pdu.is_truncated());
        assert!(pdu.rest().is_empty());
        // Only a Request has an operation number.
        assert_eq!(pdu.request(), None);
    }
    // ANCHOR_END: dcerpc_bind

    // ANCHOR: dcerpc_request
    #[test]
    fn a_request_and_its_operation() {
        let raw = hex::decode(REQUEST_HEX).unwrap();
        let flow = parse(LinkType::ETHERNET, &raw).unwrap();
        assert_eq!(label(&flow), Some("DCE/RPC"));

        let pdu = DceRpcPdu::try_from(payload(&flow)).unwrap();
        assert_eq!(pdu.pdu_type, DceRpcPduType::Request);
        // The same call identifier as the Bind: one association.
        assert_eq!(pdu.call_id, 2);

        let request = pdu.request().unwrap();
        // 144 bytes of stub data, in presentation context 1, the second
        // one the Bind offered.
        assert_eq!(request.alloc_hint, 144);
        assert_eq!(request.context_id, 1);
        // Operation 3 of the endpoint mapper is ept_map. The crate gives
        // the number; the name belongs to the interface.
        assert_eq!(request.opnum, 3);
        assert_eq!(pdu.body.len(), 8 + 144);
    }
    // ANCHOR_END: dcerpc_request

    // ANCHOR: dcerpc_refusals
    #[test]
    fn what_dcerpc_refuses() {
        let raw = hex::decode(BIND_HEX).unwrap();
        let flow = parse(LinkType::ETHERNET, &raw).unwrap();
        let bind = payload(&flow);

        // Less than the common header.
        assert_eq!(
            DceRpcPdu::try_from(&bind[..10]).unwrap_err(),
            DceRpcError::TooShort { expected: 16, actual: 10 }
        );
        // The same bytes read one byte late: no version 0.11.
        assert_eq!(
            DceRpcPdu::try_from(&bind[1..]).unwrap_err(),
            DceRpcError::UnsupportedVersion { major: 0, minor: 11 }
        );

        // A segment that stops before the end of its fragment is still a
        // PDU: the header is whole, the body is cut.
        let pdu = DceRpcPdu::try_from(&bind[..100]).unwrap();
        assert!(pdu.is_truncated());
        assert_eq!(pdu.body.len(), 84);
    }
    // ANCHOR_END: dcerpc_refusals
}
