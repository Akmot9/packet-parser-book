//! The examples of the internet-layer chapters: GOOSE, LLDP and PROFINET,
//! which travel straight over Ethernet and are decoded by the internet
//! layer, and the blind probe of `Internet::try_from`.
//!
//! Every frame is a real one from the crate's corpus, copied byte for byte
//! with tshark; the comment above each constant names the capture and the
//! frame number.

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use packet_parser::errors::internet::profinet::ProfinetPacketError;
    use packet_parser::parse::internet::protocols::goose::DataKind;
    use packet_parser::parse::internet::protocols::lldp::{
        CHASSIS_ID_MAC_ADDRESS, SystemCapabilities,
    };
    use packet_parser::parse::internet::protocols::profinet::{
        DCP_SERVICE_IDENTIFY, DCP_SERVICE_SET, DCP_SERVICE_TYPE_REQUEST, FrameId, ProfinetPacket,
        validate_frame,
    };
    use packet_parser::{
        CorruptedLayerKind, Internet, InternetDetails, LinkType, MacAddress, NetworkProtocol, parse,
    };

    /// Frame 1 of `pcaps_exemple/protocols/goose/iti_GOOSE.pcap` (ITI,
    /// CC-BY-4.0): a GE F650 relay publishing its `gcb01` message, Ethernet
    /// without VLAN tag, EtherType 0x88B8.
    const GOOSE_F650_HEX: &str = concat!(
        "01a0f4082f7700a0f4082f7788b80001009100000000618186801a4745446576",
        "696365463635302f4c4c4e3024474f2467636230318103009c40821847454465",
        "76696365463635302f4c4c4e3024474f4f534531830b463635305f474f4f5345",
        "318408386ebbf34217280a85010186010a8701008801018901008a0108ab2083",
        "01008403030000830100840303000083010084030300008301008403030000"
    );

    /// Frame 1 of `pcaps_exemple/protocols/goose/iti_GOOSE_DEMO.pcap` (ITI,
    /// CC-BY-4.0): a simulator on VLAN 10, APPID 0x2000, ten booleans.
    const GOOSE_DEMO_VLAN_10_HEX: &str = concat!(
        "010ccd0100010017a4dd981e8100800a88b82000006c00000000616280033131",
        "31810500000027108203323232830333333384084ddda51adbe76d0085050000",
        "00000186050000000001870100880500000000018901008a05000000000aab1e",
        "830100830100830100830100830100830100830100830100830100830100"
    );

    /// Frame 29 of
    /// `pcaps_exemple/protocols/profinet/cisagov_profinet_io_cm_mixed_1.pcap`
    /// (CISA, BSD-3-Clause): the LLDP announcement of a Siemens SCALANCE X208
    /// switch, EtherType 0x88CC.
    const LLDP_SCALANCE_HEX: &str = concat!(
        "0180c200000e000e8cef75c988cc0214077369656d656e732d783230382d7377",
        "69746368040907706f72742d303034060200140c325369656d656e7320414720",
        "53494d41544943205337204d554c5449504f5254205343414c414e4345205820",
        "3230302046414d0e040080008010140501000000000200000004082b06010401",
        "81c06efe08000ecf0200000000fe0a000ecf05000e8cef75c5fe0900120f0103",
        "6c0000100000"
    );

    /// Frame 2165 of `pcaps_exemple/The-Ultimate-PCAP.pcapng` (Johannes
    /// Weber): the LLDP announcement of a Cisco C2960 switch, with an IPv4
    /// and an IPv6 management address.
    const LLDP_CISCO_HEX: &str = concat!(
        "0180c200000e00211bae319988cc02070400211bae31800406054769302f3106",
        "0200780a1943434e502d4c41422d53312e77656265726e65747a2e6e65740cf3",
        "436973636f20494f5320536f6674776172652c20433239363020536f66747761",
        "7265202843323936302d4c414e424153454b392d4d292c2056657273696f6e20",
        "31352e302832295345392c2052454c4541534520534f46545741524520286663",
        "31290a546563686e6963616c20537570706f72743a20687474703a2f2f777777",
        "2e636973636f2e636f6d2f74656368737570706f72740a436f70797269676874",
        "2028632920313938362d3230313520627920436973636f2053797374656d732c",
        "20496e632e0a436f6d70696c6564205475652030312d4465632d31352030373a",
        "30372062792070726f645f72656c5f7465616d08124769676162697445746865",
        "726e6574302f310e0400040004100c0501c0a8790a0300000000001018110220",
        "030051601201210000000000000010030000000000fe0900120f010380000000",
        "0000"
    );

    /// Frame 5 of `pcaps_exemple/protocols/profinet/miguelob_pn.pcapng`
    /// (miguelob/ICS-Hacking, GPL-3.0): RT_CLASS_1 cyclic I/O data, Frame ID
    /// 0x8000, under a VLAN 0 tag.
    const PROFINET_RT_CLASS_1_HEX: &str = concat!(
        "2863369f1c6b00d0241c27c28100c00088928000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "00000000000000000000a3c03500"
    );

    /// Frame 14 of the same capture: a low-priority alarm, Frame ID 0xFE01,
    /// VLAN 0.
    const PROFINET_ALARM_HEX: &str = concat!(
        "00d0241c27c22863369f1c6b8100a0008892fe01001400001401fffefffe0004",
        "cf81fd24002a010e72020007012400000280090c8181440000000000"
    );

    /// Frame 34 of
    /// `pcaps_exemple/protocols/profinet/cisagov_profinet_io_cm_mixed_1.pcap`:
    /// a PTCP delay request, Frame ID 0xFF40.
    const PROFINET_PTCP_DELAY_HEX: &str = concat!(
        "0180c200000e00099143e0688892ff40000000000000000000000000001c0000",
        "000000000c0600099143e06800000000000000000000000000000000"
    );

    /// Frame 28 of `pcaps_exemple/protocols/profinet/cisagov_profinet_io_cm.pcap`
    /// (CISA, BSD-3-Clause): the last fragment of an RT frame, Frame ID 0xFF83.
    const PROFINET_FRAGMENT_HEX: &str = concat!(
        "1234123412400012341234018892ff830705ccfc000000020001000600000101",
        "0002000d00000101010b002001000000060100180100000000000001a64dd1e3",
        "83c0074a693c320541232ea7"
    );

    /// Frame 2 of `pcaps_exemple/protocols/profinet/iti_ChangeIPUsingDCP.pcap`
    /// (ITI, CC-BY-4.0, from the Wireshark wiki): the DCP Identify response
    /// of the station `X208-BORD`, six blocks.
    const PROFINET_DCP_IDENTIFY_RESPONSE_HEX: &str = concat!(
        "000c29ba09ea08000693cf328892feff0501010000010000005e0205001c0000",
        "0101010202010202020302040205033d0501050205030504ffff020100050000",
        "494e43000202000b0000583230382d424f524400020300060000002a0a010204",
        "0004000001000102000e0001c0a80006ffffff00c0a80001"
    );

    /// Frame 3 of the same capture: the DCP Set request that gives the
    /// station a new IP address, one IP block with its BlockQualifier.
    const PROFINET_DCP_SET_REQUEST_HEX: &str = concat!(
        "08000693cf32000c29ba09ea8892fefd040001000001000000120102000e0001",
        "c0a8000affffff00c0a80001000000000000000000000000"
    );

    /// Frame 3 of `pcaps_exemple/protocols/profinet/miguelob_pn_dcp.pcapng`
    /// (miguelob/ICS-Hacking, GPL-3.0): an Identify request captured on its
    /// way out, 32 bytes, not padded; DCPDataLength announces 4 bytes of
    /// blocks and 2 follow.
    const PROFINET_DCP_SHORT_HEX: &str =
        "010ecf00000000e04c680628810000008892fefe05000000000100010004ffff";

    /// Frame 24183 of `pcaps_exemple/The-Ultimate-PCAP.pcapng`: an IS-IS CSNP
    /// in an IEEE 802.3 frame with an LLC header (`FE FE 03`), carried in an
    /// IEEE 802.3br express mPacket (LINKTYPE 274).
    const ISIS_OVER_LLC_MPACKET_HEX: &str = concat!(
        "55555555555555d50180c20000150025456017c00076fefe0383210100190100",
        "000073000000000005000000000000000000ffffffffffffffff0950045a0000",
        "0000000100000000001ab6520000000000000001010000000003ed0a03d30000",
        "000000040000000000133bdb04ad00000000000500000000000e888f048e0000",
        "0000000501000000001002c2c091b8cc"
    );

    // ANCHOR: goose_frame
    #[test]
    fn goose_is_an_internet_layer_that_keeps_its_pdu() {
        let raw = hex::decode(GOOSE_F650_HEX).unwrap();
        let flow = parse(LinkType::ETHERNET, &raw).unwrap();
        assert_eq!(flow.data_link.network_protocol(), NetworkProtocol::Goose);
        // EtherType 0x88B8 right after the MAC addresses: no VLAN tag.
        let ethernet = flow.data_link.as_ethernet().unwrap();
        assert!(ethernet.vlan.is_none());

        // No IP, no UDP: the frame is the internet layer, without addresses,
        // and nothing is parsed above it.
        let internet = flow.internet.as_ref().unwrap();
        assert_eq!(internet.protocol_name, "GOOSE");
        assert!(internet.source.is_none() && internet.destination.is_none());
        assert!(internet.payload_protocol.is_none() && internet.payload.is_empty());
        assert!(flow.transport.is_none() && flow.application.is_none());
        assert!(flow.corrupted.is_none());

        let Some(InternetDetails::Goose(goose)) = &internet.details else {
            panic!("expected a decoded GOOSE frame in details");
        };
        assert_eq!((goose.app_id, goose.length), (0x0001, 145));
        assert!(!goose.simulation_bit());

        let pdu = &goose.pdu;
        assert_eq!(pdu.gocb_ref, "GEDeviceF650/LLN0$GO$gcb01");
        assert_eq!(pdu.data_set, "GEDeviceF650/LLN0$GOOSE1");
        assert_eq!(pdu.go_id, Some("F650_GOOSE1"));
        assert_eq!(pdu.time_allowed_to_live, 40_000); // milliseconds
        assert_eq!((pdu.st_num, pdu.sq_num), (1, 10));
        assert_eq!((pdu.simulation, pdu.conf_rev, pdu.nds_com), (false, 1, false));
        // tshark: Jan  2, 2000 02:46:11.258165836 UTC
        assert_eq!(pdu.timestamp.seconds, 946_781_171);
        assert_eq!(pdu.timestamp.nanoseconds(), 258_165_836);
        assert!(!pdu.timestamp.clock_not_synchronized());

        // allData: eight values, a boolean then a bit string, four times.
        assert_eq!((pdu.num_dat_set_entries, pdu.all_data.len()), (8, 8));
        assert_eq!(pdu.all_data[0].kind, Some(DataKind::Boolean));
        assert_eq!(pdu.all_data[0].as_bool(), Some(false));
        assert_eq!(pdu.all_data[1].kind, Some(DataKind::BitString));
        assert_eq!(pdu.all_data[1].value, [0x03, 0x00, 0x00]); // 3 unused bits, then the bits
        assert_eq!(pdu.all_data[1].as_bool(), None);
        assert_eq!(pdu.security, None);
    }
    // ANCHOR_END: goose_frame

    // ANCHOR: goose_vlan_probe_corruption
    #[test]
    fn goose_under_a_vlan_tag_probed_blindly_and_cut_short() {
        // Frame 1 of iti_GOOSE_DEMO.pcap: the link layer consumes the VLAN
        // tag, and the EtherType it hands over is GOOSE's.
        let raw = hex::decode(GOOSE_DEMO_VLAN_10_HEX).unwrap();
        let flow = parse(LinkType::ETHERNET, &raw).unwrap();
        let vlan = flow.data_link.as_ethernet().and_then(|ethernet| ethernet.vlan.as_ref());
        assert_eq!(vlan.map(|tag| tag.id), Some(10));
        assert_eq!(flow.data_link.network_protocol(), NetworkProtocol::Goose);

        let internet = flow.internet.as_ref().unwrap();
        let Some(InternetDetails::Goose(goose)) = &internet.details else {
            panic!("expected a decoded GOOSE frame in details");
        };
        assert_eq!(goose.app_id, 0x2000);
        let pdu = &goose.pdu;
        assert_eq!((pdu.gocb_ref, pdu.data_set, pdu.go_id), ("111", "222", Some("333")));
        // Its integers take five bytes, a zero then four: 00 00 00 27 10.
        assert_eq!(pdu.time_allowed_to_live, 10_000);
        assert_eq!((pdu.num_dat_set_entries, pdu.all_data.len()), (10, 10));
        assert!(pdu.all_data.iter().all(|value| value.as_bool() == Some(false)));

        // In JSON, the flow names the internet layer and the EtherType.
        let json = serde_json::to_value(flow.to_owned_flow()).unwrap();
        assert_eq!(json["protocol_internet"], "GOOSE");
        assert_eq!(json["data_link"]["network_protocol"]["kind"], "goose");
        assert_eq!(json["data_link"]["link_details"]["ethertype"], "GOOSE");
        assert!(json["source_ip"].is_null());

        // Without the EtherType, the probing Internet::try_from finds it too.
        let probed = Internet::try_from(flow.data_link.network_payload()).unwrap();
        assert_eq!(probed.protocol_name, "GOOSE");

        // One byte short, the Length field no longer covers the frame: the
        // EtherType announced GOOSE, so the internet layer is corrupted.
        let flow = parse(LinkType::ETHERNET, &raw[..raw.len() - 1]).unwrap();
        assert!(flow.internet.is_none());
        let corrupted = flow.corrupted.unwrap();
        assert_eq!(corrupted.layer, CorruptedLayerKind::Internet);
        assert_eq!(
            corrupted.error,
            "GOOSE error: GOOSE length 108 does not match the 107 bytes after the EtherType"
        );
    }
    // ANCHOR_END: goose_vlan_probe_corruption

    // ANCHOR: lldp_announcement
    #[test]
    fn lldp_keeps_every_tlv_and_reads_the_announcement() {
        // Frame 29 of cisagov_profinet_io_cm_mixed_1.pcap: a Siemens
        // SCALANCE X208 switch announces itself on EtherType 0x88CC.
        let raw = hex::decode(LLDP_SCALANCE_HEX).unwrap();
        let flow = parse(LinkType::ETHERNET, &raw).unwrap();
        assert_eq!(flow.data_link.network_protocol(), NetworkProtocol::Lldp);
        let internet = flow.internet.as_ref().unwrap();
        assert_eq!(internet.protocol_name, "LLDP");
        assert!(internet.source.is_none() && internet.payload_protocol.is_none());
        assert!(flow.transport.is_none() && flow.application.is_none());
        assert!(flow.corrupted.is_none());

        let Some(InternetDetails::Lldp(lldp)) = &internet.details else {
            panic!("expected a decoded LLDPDU in details");
        };
        // Every TLV in wire order, End of LLDPDU included; nothing after it.
        let types: Vec<u8> = lldp.tlvs.iter().map(|tlv| tlv.tlv_type).collect();
        assert_eq!(types, [1, 2, 3, 6, 7, 8, 127, 127, 127, 0]);
        assert_eq!(lldp.tlvs[3].type_name(), "System Description");
        assert!(lldp.padding.is_empty());

        // The three mandatory TLVs: chassis and port IDs locally assigned
        // (subtype 7), readable as text, and the time to live in seconds.
        assert_eq!(lldp.chassis_id.subtype, 7);
        assert_eq!(lldp.chassis_id.as_text(), Some("siemens-x208-switch"));
        assert_eq!((lldp.port_id.subtype, lldp.port_id.as_text()), (7, Some("port-004")));
        assert_eq!(lldp.time_to_live, 20);

        // The optional TLVs, through accessors.
        assert_eq!(lldp.system_name(), None);
        assert_eq!(
            lldp.system_description(),
            Some("Siemens AG SIMATIC S7 MULTIPORT SCALANCE X 200 FAM")
        );
        let capabilities = lldp.system_capabilities().unwrap();
        assert_eq!(capabilities.capabilities, SystemCapabilities::STATION_ONLY);
        assert!(capabilities.is_enabled(SystemCapabilities::STATION_ONLY));

        let addresses: Vec<_> = lldp.management_addresses().collect();
        assert_eq!(addresses.len(), 1);
        assert_eq!(addresses[0].ip(), Some(IpAddr::V4(Ipv4Addr::UNSPECIFIED)));
        // Interface numbering 2 (ifIndex), interface 4, and an 8-byte OID.
        assert_eq!((addresses[0].interface_subtype, addresses[0].interface_number), (2, 4));
        assert_eq!(addresses[0].oid.len(), 8);

        let organizations: Vec<_> = lldp
            .organization_tlvs()
            .map(|tlv| (tlv.organization(), tlv.subtype))
            .collect();
        assert_eq!(
            organizations,
            [(Some("PROFINET"), 2), (Some("PROFINET"), 5), (Some("IEEE 802.3"), 1)]
        );
    }
    // ANCHOR_END: lldp_announcement

    // ANCHOR: lldp_ids_addresses_corruption
    #[test]
    fn lldp_ids_management_addresses_and_a_cut_lldpdu() {
        // Frame 2165 of The-Ultimate-PCAP.pcapng: a Cisco C2960.
        let raw = hex::decode(LLDP_CISCO_HEX).unwrap();
        let flow = parse(LinkType::ETHERNET, &raw).unwrap();
        let internet = flow.internet.as_ref().unwrap();
        let Some(InternetDetails::Lldp(lldp)) = &internet.details else {
            panic!("expected a decoded LLDPDU in details");
        };

        // The subtype says how to read an ID; the accessors do not check it.
        assert_eq!(lldp.chassis_id.subtype, CHASSIS_ID_MAC_ADDRESS);
        assert_eq!(
            lldp.chassis_id.as_mac(),
            Some(MacAddress([0x00, 0x21, 0x1b, 0xae, 0x31, 0x80]))
        );
        assert_eq!((lldp.port_id.subtype, lldp.port_id.as_text()), (5, Some("Gi0/1")));
        assert_eq!(lldp.time_to_live, 120);
        assert_eq!(lldp.system_name(), Some("CCNP-LAB-S1.webernetz.net"));
        assert_eq!(lldp.port_description(), Some("GigabitEthernet0/1"));
        assert_eq!(lldp.tlv(6).map(|tlv| tlv.value.len()), Some(243)); // System Description

        let ips: Vec<IpAddr> = lldp.management_addresses().filter_map(|a| a.ip()).collect();
        assert_eq!(
            ips,
            [
                "192.168.121.10".parse::<IpAddr>().unwrap(),
                "2003:51:6012:121::10".parse().unwrap()
            ]
        );
        let capabilities = lldp.system_capabilities().unwrap();
        assert!(capabilities.is_enabled(SystemCapabilities::BRIDGE));
        assert!(!capabilities.is_enabled(SystemCapabilities::ROUTER));

        // Without the EtherType, the probing Internet::try_from finds it too.
        let probed = Internet::try_from(flow.data_link.network_payload()).unwrap();
        assert_eq!(probed.protocol_name, "LLDP");

        // Cut in the middle of the System Description: the EtherType
        // announced LLDP, so the internet layer is corrupted.
        let flow = parse(LinkType::ETHERNET, &raw[..100]).unwrap();
        assert!(flow.internet.is_none());
        let corrupted = flow.corrupted.unwrap();
        assert_eq!(corrupted.layer, CorruptedLayerKind::Internet);
        assert_eq!(
            corrupted.error,
            "LLDP error: LLDP TLV type 6 at offset 48 declares 243 bytes, 36 remain"
        );
    }
    // ANCHOR_END: lldp_ids_addresses_corruption

    // ANCHOR: profinet_rt_frames
    #[test]
    fn every_rt_frame_is_valid_by_its_frame_id() {
        // Four real frames that 11.5.0 reported as corrupted.
        let frames = [
            (PROFINET_RT_CLASS_1_HEX, 0x8000, FrameId::RtClass1Unicast), // cyclic data, VLAN 0
            (PROFINET_ALARM_HEX, 0xFE01, FrameId::AlarmLow),
            (PROFINET_PTCP_DELAY_HEX, 0xFF40, FrameId::PtcpDelay),
            (PROFINET_FRAGMENT_HEX, 0xFF83, FrameId::Fragment),
        ];
        for (frame, frame_id, class) in frames {
            let raw = hex::decode(frame).unwrap();
            let flow = parse(LinkType::ETHERNET, &raw).unwrap();
            assert_eq!(flow.data_link.network_protocol(), NetworkProtocol::Profinet);
            let internet = flow.internet.as_ref().unwrap();
            assert_eq!(internet.protocol_name, "Profinet");
            assert!(internet.source.is_none() && internet.details.is_none());
            assert!(flow.transport.is_none() && flow.corrupted.is_none());

            // What the internet layer checked: the Frame ID and its class.
            let payload = flow.data_link.network_payload();
            assert_eq!(validate_frame(payload), Ok(class));
            // Not a DCP frame: the DCP decoder does not apply, and says so.
            assert_eq!(
                ProfinetPacket::try_from(payload),
                Err(ProfinetPacketError::NotDcp(frame_id))
            );
        }
    }
    // ANCHOR_END: profinet_rt_frames

    // ANCHOR: profinet_dcp_blocks
    #[test]
    fn dcp_messages_are_decoded_block_by_block() {
        // Frame 2 of iti_ChangeIPUsingDCP.pcap: the Identify response of
        // X208-BORD. Its first block is DeviceOptions, not the name.
        let raw = hex::decode(PROFINET_DCP_IDENTIFY_RESPONSE_HEX).unwrap();
        let flow = parse(LinkType::ETHERNET, &raw).unwrap();
        assert!(flow.corrupted.is_none());
        let dcp = ProfinetPacket::try_from(flow.data_link.network_payload()).unwrap();
        assert_eq!(dcp.frame_id, FrameId::IdentifyResp);
        assert_eq!((dcp.service_id, dcp.service_type), (DCP_SERVICE_IDENTIFY, 1));
        assert_eq!((dcp.xid, dcp.dcp_data_length), (0x0100_0001, 94));
        let blocks: Vec<(u8, u8, u16)> = dcp
            .blocks
            .iter()
            .map(|block| (block.option, block.suboption, block.block_length))
            .collect();
        assert_eq!(blocks, [(2, 5, 28), (2, 1, 5), (2, 2, 11), (2, 3, 6), (2, 4, 4), (1, 2, 14)]);
        // In a response, each block starts with a BlockInfo, kept apart.
        assert_eq!(dcp.blocks[2].qualifier, Some(0));
        assert_eq!(dcp.blocks[2].data, b"X208-BORD"); // 11 bytes, minus BlockInfo
        assert_eq!(dcp.name_of_station, "X208-BORD"); // taken from block 2/2
        assert_eq!(dcp.blocks[5].qualifier, Some(1));
        assert_eq!(dcp.blocks[5].data, [192, 168, 0, 6, 255, 255, 255, 0, 192, 168, 0, 1]);
        // The fields kept for compatibility describe the first block.
        assert_eq!((dcp.option, dcp.suboption, dcp.dcp_block_length), (2, 5, 28));

        // Frame 3: the Set request that gives it 192.168.0.10. A Set request
        // block starts with a BlockQualifier; the message carries no name.
        let raw = hex::decode(PROFINET_DCP_SET_REQUEST_HEX).unwrap();
        let flow = parse(LinkType::ETHERNET, &raw).unwrap();
        let dcp = ProfinetPacket::try_from(flow.data_link.network_payload()).unwrap();
        assert_eq!(dcp.frame_id, FrameId::GetReqSetReqGetRespSetResp);
        assert_eq!((dcp.service_id, dcp.service_type), (DCP_SERVICE_SET, DCP_SERVICE_TYPE_REQUEST));
        assert_eq!(dcp.blocks.len(), 1);
        assert_eq!((dcp.blocks[0].option, dcp.blocks[0].suboption), (1, 2));
        assert_eq!(dcp.blocks[0].qualifier, Some(1));
        assert_eq!(dcp.blocks[0].data, [192, 168, 0, 10, 255, 255, 255, 0, 192, 168, 0, 1]);
        assert_eq!(dcp.name_of_station, "");
    }
    // ANCHOR_END: profinet_dcp_blocks

    // ANCHOR: profinet_dcp_overflow
    #[test]
    fn a_dcp_message_shorter_than_its_length_is_corrupted() {
        // Frame 3 of miguelob_pn_dcp.pcapng: DCPDataLength announces 4 bytes
        // of blocks, the frame ends 2 bytes later. tshark calls it malformed.
        let raw = hex::decode(PROFINET_DCP_SHORT_HEX).unwrap();
        let flow = parse(LinkType::ETHERNET, &raw).unwrap();
        assert!(flow.internet.is_none());
        let corrupted = flow.corrupted.unwrap();
        assert_eq!(corrupted.layer, CorruptedLayerKind::Internet);
        assert_eq!(
            corrupted.error,
            "Profinet error: DCP data length 4 exceeds the 2 bytes after the header"
        );
        assert_eq!(
            validate_frame(flow.data_link.network_payload()),
            Err(ProfinetPacketError::DcpDataOverflow { declared: 4, available: 2 })
        );
    }
    // ANCHOR_END: profinet_dcp_overflow

    // ANCHOR: blind_probe_is_a_guess
    #[test]
    fn the_blind_probe_is_a_guess_not_a_verdict() {
        // Frame 24183 of The-Ultimate-PCAP.pcapng: IS-IS over LLC in an
        // 802.3br express mPacket. Its length field (0x0076) is no EtherType:
        // nothing is announced, so the pipeline parses nothing above.
        let raw = hex::decode(ISIS_OVER_LLC_MPACKET_HEX).unwrap();
        let flow = parse(LinkType::IEEE802_3BR, &raw).unwrap();
        assert_eq!(flow.data_link.network_protocol(), NetworkProtocol::Other(0x0076));
        assert!(flow.internet.is_none() && flow.corrupted.is_none());

        // Probed without that context, the same bytes pass for PROFINET: the
        // LLC header FE FE 03 reads as the Frame ID of a DCP Identify
        // request, a Get service, and a DCP header that holds.
        let payload = flow.data_link.network_payload();
        assert_eq!(&payload[..3], [0xfe, 0xfe, 0x03]);
        let probed = Internet::try_from(payload).unwrap();
        assert_eq!(probed.protocol_name, "Profinet");
        let dcp = ProfinetPacket::try_from(payload).unwrap();
        assert_eq!(dcp.frame_id, FrameId::IdentifyReq);
        assert_eq!(dcp.service_id, 3); // Get

        // A cyclic PROFINET frame, the reverse: valid by its Frame ID, but
        // two bytes are no proof, and the probe does not recognize it.
        let raw = hex::decode(PROFINET_RT_CLASS_1_HEX).unwrap();
        let flow = parse(LinkType::ETHERNET, &raw).unwrap();
        assert!(Internet::try_from(flow.data_link.network_payload()).is_err());
    }
    // ANCHOR_END: blind_probe_is_a_guess
}
