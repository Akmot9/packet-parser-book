//! Examples of the TLS page. Every frame is a real frame of the crate's
//! corpus (`pcaps_exemple/` in the crate repository), extracted with tshark.
//! The capture is `protocols/tls/tls12-dsb.pcapng`, from the Wireshark test
//! suite: a TLS 1.2 session to example.com, captured as raw IP.

#[cfg(test)]
mod tests {
    use packet_parser::parse::application::protocols::tls::{
        TlsContentType, TlsPacket, parse_tls_records,
    };
    use packet_parser::{LinkType, PacketFlow, parse};

    /// Frame 1: the Client Hello, IPv4 / TCP 46800 -> 443, 229 bytes.
    const TLS_CLIENT_HELLO_HEX: &str = concat!(
        "45000119e1ea40004006180f0a0900025db8d822b6d001bbfbc2e052de551ae0",
        "801800e540f100000101080ac8fafa0d880626a616030100e0010000dc0303f6",
        "7a28b386b31c620d76c0026fdd9888edbe6bf0f5b715b2caca158f84ae9d6600",
        "0038c02cc030009fcca9cca8ccaac02bc02f009ec024c028006bc023c0270067",
        "c00ac0140039c009c0130033009d009c003d003c0035002f00ff0100007b0000",
        "0010000e00000b6578616d706c652e636f6d000b000403000102000a000c000a",
        "001d0017001e00190018337400000010000b000908687474702f312e31001600",
        "0000170000000d0030002e040305030603080708080809080a080b0804080508",
        "06040105010601030302030301020103020202040205020602",
    );

    /// Frame 2: the Server Hello and the start of the Certificate record,
    /// TCP 443 -> 46800, 1448 bytes.
    const TLS_SERVER_HELLO_HEX: &str = concat!(
        "450005dc3371000037060ac65db8d8220a09000201bbb6d0de551ae0fbc2e137",
        "8010011ddc7a00000101080a880626c8c8fafa0d16030300700200006c030375",
        "d016e23ae727d77c98266e8ef9dcf47db447ae88cf19a8444f574e4752440120",
        "51873a30ac90644894cb114763dc1f4eee3a3b859f517cf662b87e74a1b72fe9",
        "c02f000024ff0100010000000000000b0004030001020010000b000908687474",
        "702f312e31001700001603030ab80b000ab4000ab10005f6308205f2308204da",
        "a00302010202100e64c5fbc236ade14b172aeb41c78cb0300d06092a864886f7",
        "0d01010b05003070310b300906035504061302555331153013060355040a130c",
        "446967694365727420496e6331193017060355040b13107777772e6469676963",
        "6572742e636f6d312f302d060355040313264469676943657274205348413220",
        "48696768204173737572616e636520536572766572204341301e170d31353131",
        "30333030303030305a170d3138313132383132303030305a3081a5310b300906",
        "0355040613025553311330110603550408130a43616c69666f726e6961311430",
        "120603550407130b4c6f7320416e67656c6573313c303a060355040a1333496e",
        "7465726e657420436f72706f726174696f6e20666f722041737369676e656420",
        "4e616d657320616e64204e756d6265727331133011060355040b130a54656368",
        "6e6f6c6f6779311830160603550403130f7777772e6578616d706c652e6f7267",
        "30820122300d06092a864886f70d01010105000382010f003082010a02820101",
        "00b340962f61633e25c197ad6545fbef1342b32c9986f4b5800b76dc06382c1f",
        "a362555a3676deae5dfce2e5b4e6ec5dcaeecadf5016242ceefc9ab68cf6a8b3",
        "ac7a087b2a1fad5fe7fa965925ab90b0f8c23f13042674680fc6782a958a5f42",
        "f20eed52a6eb682389e543f86d121b62427ba805f359c45ed6c5cc46c04b19b9",
        "2d4a7172241e5e554493ab78a1474da5dc075a9c67f41168122fd32871bcad72",
        "053c1675d4f87258ba19f1dc09edf118c6922f7dbc160b378d8aef1b6f4fb9e0",
        "7a5498bfb5b6cfbbaa937f0a7f1f56eba9d8e1dbd539d8185bd1f26433d0d6c4",
        "23ff09ab6d71cedacfc1179c23be2caf2f921c3f90088958f2b1e1106f832ef7",
        "9f0203010001a38202503082024c301f0603551d230418301680145168ff90af",
        "0207753cccd9656462a212b859723b301d0603551d0e04160414a64f601e1f2d",
        "d1e7f123a02a9516e4e89aea6e483081810603551d11047a3078820f7777772e",
        "6578616d706c652e6f7267820b6578616d706c652e636f6d820b6578616d706c",
        "652e656475820b6578616d706c652e6e6574820b6578616d706c652e6f726782",
        "0f7777772e6578616d706c652e636f6d820f7777772e6578616d706c652e6564",
        "75820f7777772e6578616d706c652e6e6574300e0603551d0f0101ff04040302",
        "05a0301d0603551d250416301406082b0601050507030106082b060105050703",
        "0230750603551d1f046e306c3034a032a030862e687474703a2f2f63726c332e",
        "64696769636572742e636f6d2f736861322d68612d7365727665722d67342e63",
        "726c3034a032a030862e687474703a2f2f63726c342e64696769636572742e63",
        "6f6d2f736861322d68612d7365727665722d67342e63726c304c0603551d2004",
        "453043303706096086480186fd6c0101302a302806082b06010505070201161c",
        "68747470733a2f2f7777772e64696769636572742e636f6d2f43505330080606",
        "67810c01020230818306082b0601050507010104773075302406082b06010505",
        "0730018618687474703a2f2f6f6373702e64696769636572742e636f6d304d06",
        "082b060105050730028641687474703a2f2f636163657274732e646967696365",
        "72742e636f6d2f446967694365727453484132486967684173737572616e6365",
        "53657276657243412e637274300c0603551d130101ff04023000300d06092a86",
        "4886f70d01010b0500038201010084a89a11a7d8bd0b267e52247bb2559dea30",
        "895108876fa9ed10ea5b3e0bc72d47044edd4537c7cabc387fb66a1c",
    );

    /// Frame 3: the rest of the Certificate record and what follows it,
    /// TCP 443 -> 46800, 1765 bytes.
    const TLS_CERTIFICATE_REST_HEX: &str = concat!(
        "4500071933720000370609885db8d8220a09000201bbb6d0de552088fbc2e137",
        "8018011d46f100000101080a880626c8c8fafa0d65426a73742e5a9785d0cc92",
        "e22e3889d90d69fa1b9bf0c16232654f3d98dbdad666da2a5656e31133ece0a5",
        "154cea7549f45def15f5121ce6f8fc9b04214bcf63e77cfcaadcfa43d0c0bbf2",
        "89ea916dcb858e6a9fc8f994bf553d4282384d08a4a70ed3654d3361900d3f80",
        "bf823e11cb8f3fce7994691bf2da4bc897b811436d6a2532b9b2ea2262860da3",
        "727d4fea573c653b2f2773fc7c16fb0d03a40aed01aba423c68d5f8a21154292",
        "c034a220858858988919b11e20ed13205c045564ce9db365fdf68f5e99392115",
        "e271aa6a88820004b5308204b130820399a003020102021004e1e7a4dc5cf2f3",
        "6dc02b42b85d159f300d06092a864886f70d01010b0500306c310b3009060355",
        "04061302555331153013060355040a130c446967694365727420496e63311930",
        "17060355040b13107777772e64696769636572742e636f6d312b302906035504",
        "03132244696769436572742048696768204173737572616e636520455620526f",
        "6f74204341301e170d3133313032323132303030305a170d3238313032323132",
        "303030305a3070310b300906035504061302555331153013060355040a130c44",
        "6967694365727420496e6331193017060355040b13107777772e646967696365",
        "72742e636f6d312f302d06035504031326446967694365727420534841322048",
        "696768204173737572616e63652053657276657220434130820122300d06092a",
        "864886f70d01010105000382010f003082010a0282010100b6e02fc22406c86d",
        "045fd7ef0a6406b27d22266516ae42409bcedc9f9f76073ec330558719b94f94",
        "0e5a941f5556b4c2022aafd098ee0b40d7c4d03b72c8149eef90b111a9aed2c8",
        "b8433ad90b0bd5d595f540afc81ded4d9c5f57b786506899f58adad2c7051fa8",
        "97c9dca4b182842dc6ada59cc71982a6850f5e44582a378ffd35f10b0827325a",
        "f5bb8b9ea4bd51d027e2dd3b4233a30528c4bb28cc9aac2b230d78c67be65e71",
        "b74a3e08fb81b71616a19d23124de5d79208ac75a49cbacd17b21e4435657f53",
        "2539d11c0a9a631b199274680a37c2c25248cb395aa2b6e15dc1dda020b821a2",
        "93266f144a2141c7ed6d9bf2482ff303f5a26892532f5ee30203010001a38201",
        "493082014530120603551d130101ff040830060101ff020100300e0603551d0f",
        "0101ff040403020186301d0603551d250416301406082b060105050703010608",
        "2b06010505070302303406082b0601050507010104283026302406082b060105",
        "050730018618687474703a2f2f6f6373702e64696769636572742e636f6d304b",
        "0603551d1f044430423040a03ea03c863a687474703a2f2f63726c342e646967",
        "69636572742e636f6d2f4469676943657274486967684173737572616e636545",
        "56526f6f7443412e63726c303d0603551d200436303430320604551d2000302a",
        "302806082b06010505070201161c68747470733a2f2f7777772e646967696365",
        "72742e636f6d2f435053301d0603551d0e041604145168ff90af0207753cccd9",
        "656462a212b859723b301f0603551d23041830168014b13ec36903f8bf4701d4",
        "98261a0802ef63642bc3300d06092a864886f70d01010b05000382010100188a",
        "958903e66ddf5cfc1d68ea4a8f83d6512f8d6b44169eac63f5d26e6c84998baa",
        "8171845bed344eb0b7799229cc2d806af08e20e179a4fe034713eaf586ca5971",
        "7df404966bd359583dfed331255c183884a3e69f82fd8c5b98314ecd789e1afd",
        "85cb49aaf2278b9972fc3eaad5410bdad536a1bf1c6e47497f5ed9487c03d9fd",
        "8b49a098264240ebd69211a4640a5754c4f51dd6025e6baceec4809a1272fa56",
        "93d7ffbf30850630bf0b7f4eff57059d24ed85c32bfba675a8ac2d16ef7d7927",
        "b2ebc29d0b07eaaa85d301a3202841594328d281e3aaf6ec7b3b77b640628005",
        "414501ef17063edec0339b67d3612e7287e469fc120057401e70f51ec9b41603",
        "03014d0c0001490300174104fb5c93ed9700db294c16461eb391da54575bd35b",
        "d92abd5a0f388b0792923d0bea1f8582d2879300696fa3a5ba27eb697d0b95c7",
        "d5eec198076d31a074eff27b08040100008e3c4e564864e309b1370215ee6faa",
        "e1976d80ab29bd4be33e356cc60bf72df302036139568e70a1ebe305a90e454e",
        "510ea110062e8e48432df06879f3989cf4df5b73df91c28a3afa98807c7d9c74",
        "03875ff00152f2822441dd7cd8e15e282444b332cad0ccaee04f95f1dd12a789",
        "37369faca239f28477e02eda9d6791151e47ed1eb461e0f7fd5d57a2aed32a7a",
        "81e3e2912570263c1076cd983a9b14baa638d67f852d82802d385a8129231664",
        "8ecc7b33eaa7ee17ad7484c70d8f9bf565839b4b0ffd837d9d003dccc876295c",
        "82caffe2ac63b2aad1adf590409aa680539650c2572488ca11b74cbe4ea5c53c",
        "a5b7a4f6a9cfe2267c686813a301831816030300040e000000",
    );

    fn label(flow: &PacketFlow<'_>) -> Option<&'static str> {
        flow.application.as_ref().map(|application| application.protocol.label())
    }

    /// The same raw IP packet with other TCP ports: the IPv4 header length is
    /// in the low nibble of byte 0, and the two ports follow the header.
    fn with_ports(raw: &[u8], source: u16, destination: u16) -> Vec<u8> {
        let ports = usize::from(raw[0] & 0x0f) * 4;
        let mut moved = raw.to_vec();
        moved[ports..ports + 2].copy_from_slice(&source.to_be_bytes());
        moved[ports + 2..ports + 4].copy_from_slice(&destination.to_be_bytes());
        moved
    }

    // ANCHOR: tls_client_hello
    #[test]
    fn a_client_hello_is_a_record_and_nothing_more() {
        let raw = hex::decode(TLS_CLIENT_HELLO_HEX).unwrap();
        let flow = parse(LinkType::RAW, &raw).unwrap();
        assert_eq!(label(&flow), Some("TLS")); // 46800 -> 443

        let payload = flow.transport.as_ref().unwrap().payload.unwrap();
        let record = TlsPacket::try_from(payload).unwrap();
        assert_eq!(record.content_type, TlsContentType::Handshake);
        // The record says 3.1, TLS 1.0: a TLS 1.2 client writes it there for
        // old middleboxes. The version it offers is inside the handshake.
        assert_eq!(record.version.to_string(), "TLS 1.0");
        assert_eq!(record.length, 224);
        assert_eq!(payload.len(), 5 + 224); // one record fills the segment

        // The handshake is not decoded. Its bytes are there: type 1, Client
        // Hello, then the version 3.3, and further on the server name.
        assert_eq!(record.payload[0], 1);
        assert_eq!(record.payload[4..6], [3, 3]);
        assert!(record.payload.windows(11).any(|w| w == b"example.com"));

        // The rule has no port: the same segment is TLS anywhere.
        let moved = with_ports(&raw, 40000, 40001);
        assert_eq!(label(&parse(LinkType::RAW, &moved).unwrap()), Some("TLS"));
    }
    // ANCHOR_END: tls_client_hello

    // ANCHOR: tls_record_cut
    #[test]
    fn a_record_cut_by_the_segment_hides_the_next_segment() {
        // The server answers with two records. The first fits in the segment.
        let raw = hex::decode(TLS_SERVER_HELLO_HEX).unwrap();
        let flow = parse(LinkType::RAW, &raw).unwrap();
        assert_eq!(label(&flow), Some("TLS"));
        let payload = flow.transport.as_ref().unwrap().payload.unwrap();
        assert_eq!(payload.len(), 1448);
        let records = parse_tls_records(payload);
        assert_eq!(records.len(), 1); // the Server Hello, 5 + 112 bytes
        assert_eq!(records[0].length, 112);

        // The second starts right after it and declares more than is left.
        let next = &payload[117..];
        assert_eq!(next[0], 22); // a handshake record: the Certificate
        let declared = usize::from(u16::from_be_bytes([next[3], next[4]]));
        assert!(declared > next.len() - 5);
        assert!(TlsPacket::try_from(next).is_err());

        // Its end is in the next segment, which starts in the middle of a
        // certificate: no record header, no label.
        let raw = hex::decode(TLS_CERTIFICATE_REST_HEX).unwrap();
        let flow = parse(LinkType::RAW, &raw).unwrap();
        assert_eq!(label(&flow), Some("Unknown"));
    }
    // ANCHOR_END: tls_record_cut
}
