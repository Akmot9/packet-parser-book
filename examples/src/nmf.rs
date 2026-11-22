//! Examples of the NMF page. Every frame is a real frame of
//! `pcaps_exemple/protocols/nmf/terrain_nmf_censure.pcap` in the crate
//! repository (see the folder's `SOURCE.md`): a field capture of the
//! maintainer, censored before it was published. Addresses, ports and the
//! URI were rewritten; record types, sizes and the segmentation are the
//! original ones. The bytes were extracted with tshark 4.6.9.

#[cfg(test)]
mod tests {
    use packet_parser::errors::application::nmf::NmfError;
    use packet_parser::parse::application::protocols::nmf::{NmfMode, NmfRecord, NmfSegment};
    use packet_parser::{DecodeAsProtocol, LinkType, PacketFlow, ParseConfig, parse, parse_with};

    /// Frame 4: the preamble a client opens its session with, Ethernet /
    /// IPv4 / TCP 50000 -> 50001, 51 bytes of payload.
    const PREAMBLE_HEX: &str = concat!(
        "02000000000102000000000208004500005b554c40002006814dc0000201c000",
        "0202c350c3514a6b653cb0e4a43050184029c2e10000000100010202296e6574",
        "2e7463703a2f2f686f73742f7878787878787878787878787878787878787878",
        "78787878787803080c",
    );

    /// Frame 5: the server's answer, one byte, behind a VLAN tag and padded
    /// to the Ethernet minimum, TCP 50001 -> 50000.
    const PREAMBLE_ACK_HEX: &str = concat!(
        "02000000000202000000000181002001080045380029525e400020068435c000",
        "0202c0000201c351c350b0e4a4304a6b656f50180100943500000b0000000000",
    );

    fn label(flow: &PacketFlow<'_>) -> Option<&'static str> {
        flow.application.as_ref().map(|application| application.protocol.label())
    }

    fn payload<'a>(flow: &PacketFlow<'a>) -> &'a [u8] {
        flow.transport.as_ref().unwrap().payload.unwrap()
    }

    // ANCHOR: nmf_preamble
    #[test]
    fn a_preamble_and_its_records() {
        let raw = hex::decode(PREAMBLE_HEX).unwrap();
        let flow = parse(LinkType::ETHERNET, &raw).unwrap();
        assert_eq!(label(&flow), Some("NMF"));

        let segment = NmfSegment::try_from(payload(&flow)).unwrap();
        let records: Vec<_> = segment.records().collect();
        let [version, mode, via, encoding, end] = records[..] else {
            panic!("expected five records, got {records:?}");
        };
        assert_eq!(version, NmfRecord::Version { major: 1, minor: 0 });
        assert_eq!(mode, NmfRecord::Mode(NmfMode::Duplex));
        // The URI the session is bound to: 41 bytes, censored to x's.
        let NmfRecord::Via(uri) = via else { panic!("expected a Via, got {via:?}") };
        assert!(uri.starts_with("net.tcp://host/"));
        assert_eq!(uri.len(), 41);
        // 8: binary XML with a session dictionary, the default of net.tcp.
        assert_eq!(encoding, NmfRecord::KnownEncoding(8));
        assert_eq!(end, NmfRecord::PreambleEnd);

        // The record type is the first byte of each record.
        let types: Vec<u8> = records.iter().map(NmfRecord::record_type).collect();
        assert_eq!(types, [0x00, 0x01, 0x02, 0x03, 0x0C]);
    }
    // ANCHOR_END: nmf_preamble

    // ANCHOR: nmf_one_byte
    #[test]
    fn a_one_byte_record_needs_a_declared_port() {
        let raw = hex::decode(PREAMBLE_ACK_HEX).unwrap();
        let flow = parse(LinkType::ETHERNET, &raw).unwrap();
        // The padding after the segment is not part of the payload.
        assert_eq!(payload(&flow), [0x0B]);

        // The decoder reads it, but one byte is no signature: the blind
        // rule leaves it alone.
        let segment = NmfSegment::try_from(payload(&flow)).unwrap();
        assert_eq!(segment.records().next(), Some(NmfRecord::PreambleAck));
        assert_eq!(label(&flow), Some("Unknown"));

        // On a port the caller declares, every segment that splits into
        // records is NMF.
        let config = ParseConfig::new().decode_as(50001, DecodeAsProtocol::Nmf);
        let flow = parse_with(LinkType::ETHERNET, &raw, &config).unwrap();
        assert_eq!(label(&flow), Some("NMF"));
    }
    // ANCHOR_END: nmf_one_byte

    // ANCHOR: nmf_refusals
    #[test]
    fn what_nmf_refuses() {
        let raw = hex::decode(PREAMBLE_HEX).unwrap();
        let flow = parse(LinkType::ETHERNET, &raw).unwrap();
        let preamble = payload(&flow);

        // A Version record is three bytes.
        assert_eq!(
            NmfSegment::try_from(&preamble[..2]).unwrap_err(),
            NmfError::TruncatedRecord { record_type: 0x00, expected: 3, actual: 2 }
        );
        // A Via cut inside its URI: 43 bytes announced, 20 in the segment.
        assert_eq!(
            NmfSegment::try_from(&preamble[5..25]).unwrap_err(),
            NmfError::TruncatedRecord { record_type: 0x02, expected: 43, actual: 20 }
        );
        // The same bytes read from the URI on: `n` is no record type.
        assert_eq!(
            NmfSegment::try_from(&preamble[7..]).unwrap_err(),
            NmfError::UnknownRecordType(b'n')
        );
        assert_eq!(NmfSegment::try_from(&preamble[..0]).unwrap_err(), NmfError::Empty);
    }
    // ANCHOR_END: nmf_refusals
}
