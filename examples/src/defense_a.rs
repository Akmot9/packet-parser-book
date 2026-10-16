//! The examples of the DIS and STANAG 5066 SIS chapters, two protocols of the
//! defense lot. Every frame is real, taken from the crate's tracked corpus:
//! each constant names its capture file and frame number.

#[cfg(test)]
mod tests {
    use packet_parser::errors::application::dis::DisParseError;
    use packet_parser::errors::application::stanag5066::Stanag5066ParseError;
    use packet_parser::parse::application::protocols::dis::{self, DisBody, DisPacket};
    use packet_parser::parse::application::protocols::stanag5066::{self, SisPdu, SisPrimitive};
    use packet_parser::{DecodeAsProtocol, LinkType, ParseConfig, parse, parse_with};

    /// Frame 1 of `pcaps_exemple/protocols/dis/wireshark_12043_dis_v7_transmitter.pcap`
    /// (Wireshark issue 12043): Ethernet / IPv4 / UDP 3000 -> 3000 carrying one
    /// DIS v7 Transmitter PDU of 104 bytes.
    const DIS_V7_TRANSMITTER_HEX: &str = concat!(
        "ffffffffffff005056285ee70800450000841ec90000801159dcc0a8011cffff",
        "ffff0bb80bb80070dc89070119047b3278cf00680000fa80f01bfffefffe0700",
        "0000010000000100000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000005f5e10046c35000c387",
        "000000000003000100010000000000000000"
    );

    /// Frame 29 of `pcaps_exemple/protocols/dis/dis_voice_sample.pcap` (Wireshark
    /// `test/captures`): Ethernet / IPv4 / UDP 3388 -> 6993 carrying one DIS v6
    /// Signal PDU of 1 056 bytes, 1 024 mu-law samples.
    const DIS_V6_SIGNAL_HEX: &str = concat!(
        "ffffffffffff001143e6859108004500043ca08000008011c722ac1122fdffff",
        "ffff0d3c1b510428cc9b06011a040002bb0e042000007dfd00fd000100020001",
        "000000001f4020000400fefefffdfcff7c78777cff7e7fff7c7dffff7d7dfcfb",
        "fe7efefafaf9fbfdfdfbf9fcfdfaf7fafcfbfcfcfefefe7ffefffdfbfaf8f5f6",
        "f9f7f9fbfbfafafaf6f8fafbfcfaf9f5f4f2f1f0f2f8fcfcf7f5f7f3efeff1f1",
        "f0f3f5f7f5f5f4efeff6f6f2f4f4efeeeff3f8f9f6f6f5f2f3f3f0f5f6f1eeef",
        "f0eff2f0f0f5f8f7f2efedecececebedeeedebeaedefeff2f5efeff2f1eeeef0",
        "f2f3f1efeeefedebebecededefefeeececeef0f2f6f7f5f3f2f0efeeedeeefef",
        "f0f4f4f2f3f2efefefefedeff4f4efedeef2efebecededececeff1f2f5f4edec",
        "efeeeeeff2f0efedeeeff0f0eeeeeff0efeef0f0efeff0f2f1f1f2f6f5efeeee",
        "eeefefeeeef0efeeeef0f2f5f7f5f4f7f5f2f5f5efeff0eeeeefedeef2f0f0f5",
        "f1f0f0eeedeff0f7f8f7fbfbf6f7f9f2eeefefedeceeefeef4faf6f0ecfa72f4",
        "f4756f6d79796f7372757979fcf6f6f0f4fe7d7e7d7d7e7873767b7577fd7b76",
        "7efafd7efaf7fcfbf8f7f6f7f8fc7e7fff7d7ef9f87ffbf97dfef9ff79f9effd",
        "7bf8fe7078fb7a7cf4f6fcfbfd7efffe7e7e7b7c7a767a7ffbf9f8f77f777a7f",
        "7a7bf9f6f8f3f4fdfef7f2f5f6f5f9faf5eeeef4fbfafc7dfbf6f9f9f9fd7e7f",
        "fefcfc7b757172767afdf9f9fcf8f3f7f8fbfe7eff7e7779787478faf87dfff9",
        "7d7cfb7d7375777375fdfc767579736f757dfffcfcfbfb7c79fef9faf9f87a77",
        "7d7c736f6f6d6f777b76757dfe7b7afafb777472747a7dff7c7dfe7e77777a6f",
        "6c74796f6e6e6c6e6f757979fefa79727ef979757a746d717674757876757978",
        "7a7a717174757577716b6a6b6b6b6d72726f70757b797c7f7f7b73726f6d6f72",
        "706f6f706f6b696a6a6a6868696a6c6c6d70736f6f6e6c6b69696c6e6d6e726e",
        "6f706d6b696c6d6b69676768696e6d6c787b6d6c716c67676a696768655f5e60",
        "5f5d5c5a575f473b3d3e40414245494f585a5c5a595e645c5756555353595952",
        "4e4d4e4d4f545252545d6ff5ebedece5e1e1ebf07d6d6b695f5e5c5e5f62675b",
        "53525d6bf9e1e4e6dddbdbdde5eceae5e6eef9777cefe9e9f3f7f2efece7e4ea",
        "eeebe6e2e2e5eceff3f6f37c707579f9f5f2f5f8f0eee8e8f2fa7e7cff7d7376",
        "fbf1f2f8f1efede9effbfefdfbfdfd7cf6eefafbf8fdf9f2f5fdfdfdf7effe79",
        "f6efeeeef0f5efeef4f7f9f3ebe8e9ebeeeaeaecebedede8e8fb71fbf3f6f3ea",
        "e4e1dde0e4dfe1e2e9edeff5ecf27978fceef4fbece3e2edefe6e2dddee5e8e5",
        "e7f2f5ebe7edefecece6eaf67c77f8f87e77f6e7e8e7eaeae0dee4f57befdfe1",
        "e9e5e4e3e3edf4f5edee77727ff6edeeefeae9e4e1e9e9e4e2e7eeececede7e8",
        "f1ece7ecf2f8fdf0f6f5ef7eefe5eaee7cfdeaece9e3dfdfdddcdfe2eafe79fd",
        "fd7e7c7efceee7ebf5faf0eceae8eae6dfe5eefbeee2e5eff4e5dfe3eafcf4ed",
        "f87a73727aeee8e2e1df"
    );

    /// Frame 1 of `pcaps_exemple/protocols/dis/wireshark_3492_dis_test2.pcap`
    /// (Wireshark issue 3492): Ethernet / IPv4 / UDP 2725 -> 6993 carrying a DIS
    /// v4 Set Data PDU whose length field says 48 bytes, in a 160-byte datagram.
    const DIS_V4_SET_DATA_HEX: &str = concat!(
        "00248c0a2f94001372d0a1450800450000bce10a00008011d70bc0a80064c0a8",
        "00660aa51b5100a893c0040b13054f2545f60030000000c8001f000100c8000b",
        "000100000beb00000000000000040000000300094eda00000001000000be0000",
        "000200094ed700000003000001220000000400094f570000014040265ddddddd",
        "d689401c000000000000000001a5000001314224cccd4193333300a43c020101",
        "010100094f5800000040303132333435363700094f5900000080414243444546",
        "47484950515253545556"
    );

    /// Frame 25 of `pcaps_exemple/protocols/stanag5066/S5066-HFChat-1.pcap`
    /// (Wireshark wiki): the S_BIND_REQUEST of an HF Chat client, TCP 2749 -> 5066.
    const SIS_BIND_REQUEST_HEX: &str = concat!(
        "0090f5037e5c001319ab0f3f0800450000312f9240007e069863c3a97069c0a8",
        "40160abd13ca6d327047705530845018fffff816000090eb00000401511400"
    );

    /// Frame 26 of the same capture: the node's S_BIND_ACCEPTED, TCP 5066 -> 2749.
    const SIS_BIND_ACCEPTED_HEX: &str = concat!(
        "001319ab0f3f0090f5037e5c0800450000312d314000800698c4c0a84016c3a9",
        "706913ca0abd705530846d3270505018fff6ff27000090eb000004035000fa"
    );

    /// Frame 28 of the same capture: the first 18 bytes of a 35-byte
    /// S_UNIDATA_INDICATION, TCP 5066 -> 2749.
    const SIS_INDICATION_FIRST_SEGMENT_HEX: &str = concat!(
        "001319ab0f3f0090f5037e5c08004500003a2dcc400080069820c0a84016c3a9",
        "706913ca0abd7055308d6d3270505018fff6792f000090eb00001e1505e56464",
        "0215e56464010011"
    );

    /// Frame 30 of the same capture: the next segment of that direction, the
    /// 17-byte U_PDU of the indication.
    const SIS_INDICATION_CONTINUATION_HEX: &str = concat!(
        "001319ab0f3f0090f5037e5c0800450000392dcd400080069820c0a84016c3a9",
        "706913ca0abd7055309f6d3270505018fff6f6a800003c303e2048656c6c6f20",
        "74686572652e0a"
    );

    /// Frame 3 of `pcaps_exemple/protocols/stanag5066/wireshark_10827_sis_acp142.pcap`
    /// (Wireshark issue 10827, on the loopback): an S_UNIDATA_REQUEST carrying a
    /// 38-byte ACP 142 U_PDU, TCP 41778 -> 5066.
    const SIS_ACP142_REQUEST_HEX: &str = concat!(
        "00000000000000000000000008004500006beca4400040064fe67f0000017f00",
        "0001a33213ca702b642c2f79d6d280180802fe5f00000101080a141b88c2141b",
        "889190eb0000321402ea3242022c0000000026000000002000002001020006ab",
        "c10a324201013eeca554a5efac000100000a32420200000000"
    );

    /// Frame 4 of the same capture: a 6 195-byte TCP segment that holds three
    /// S_UNIDATA_REQUESTs of 2 065 bytes each.
    const SIS_THREE_REQUESTS_HEX: &str = concat!(
        "000000000000000000000000080045001867eca54000400637e97f0000017f00",
        "0001a33213ca702b64632f79d6d280180802165c00000101080a141b88cc141b",
        "88cc90eb00080c1402ea3242022c000000080000010000200007fa01000001d7",
        "9f0a324201013eeca5aced000573720027533434303645436f6d707265737365",
        "6444617461547970652e436f6d70726573736564446174610000000000000037",
        "0200024c0015636f6d70726573736564436f6e74656e74496e666f7400304c53",
        "3434303645436f6d7072657373656444617461547970652f436f6d7072657373",
        "6564436f6e74656e74496e666f3b4c0014636f6d7072657373696f6e416c676f",
        "726974686d7400394c533434303645436f6d7072657373656444617461547970",
        "652f436f6d7072657373696f6e416c676f726974686d4964656e746966696572",
        "3b78720020636f6d2e6f626a7379732e61736e316a2e72756e74696d652e4173",
        "6e31536571fc6d43304f3affd902000078720025636f6d2e6f626a7379732e61",
        "736e316a2e72756e74696d652e41736e315365714f72536574fc6d4330e2409f",
        "1902000078720021636f6d2e6f626a7379732e61736e316a2e72756e74696d65",
        "2e41736e3154797065fc6d4330d6aadde50300015a0001617870007702000173",
        "720020636f6d2e6f626a7379732e61736e316a2e72756e74696d652e41736e31",
        "546167e1c931d7eca7a474030000787077080001000000000000787704000000",
        "00787372002e533434303645436f6d7072657373656444617461547970652e43",
        "6f6d70726573736564436f6e74656e74496e666f00000000000000370200024c",
        "00076143686f6963657400384c533434303645436f6d70726573736564446174",
        "61547970652f436f6d70726573736564436f6e74656e74496e666f5f6143686f",
        "6963653b4c0011636f6d70726573736564436f6e74656e7474002a4c636f6d2f",
        "6f626a7379732f61736e316a2f72756e74696d652f41736e314f637465745374",
        "72696e673b7871007e000300770200017371007e000777080001000000000000",
        "787704000000007873720036533434303645436f6d7072657373656444617461",
        "547970652e436f6d70726573736564436f6e74656e74496e666f5f6143686f69",
        "6365000000000000003702000078720023636f6d2e6f626a7379732e61736e31",
        "6a2e72756e74696d652e41736e3143686f6963655f9dac02a107cdde03000078",
        "71007e000500770200017371007e000777080001000000000000787704000000",
        "007877060001000000017372002e533434303645436f6d707265737365644461",
        "7461547970652e436f6e74656e74547970655f53686f7274466f726d00000000",
        "0000003702000078720024636f6d2e6f626a7379732e61736e316a2e72756e74",
        "696d652e41736e31496e74656765720d8f4f497accadf50300007871007e0005",
        "00770200017371007e0007770800010000000000007877040000000078770a00",
        "010000000000000000787873720028636f6d2e6f626a7379732e61736e316a2e",
        "72756e74696d652e41736e314f63746574537472696e67e955d7fe7f5c0d6d03",
        "00007871007e000500770200017371007e000777080001000000000000787704",
        "000000007877020001757200025b42acf317f8060854e00200007870000027ce",
        "7801a596437025808245631b2f763ae6cb8bed746cdbe9a063dbeed8b66ddb56",
        "c7b6d9713233bbf9ebbfbb55a74ed559debc40ea13d680390908c436437e165e",
        "23680c482088dd1812039cdd1f9c23001c54f07f330852f8a77230c24f53333b",
        "672b732b33c762387f1839334b5b33c712584c681165617505533c13a4ffaf03",
        "e0552d8d9c9d247fff36950407b3a26021fb4fce8aee8f04646165650502d980",
        "ac2c2c81e0600552ac12ff65853f384e00045814542035dad21e7d770f29bef3",
        "4356fa9d9e313566b9f586f18d33b9870aa05d699c24216430b27b4e1c418fe6",
        "a7f5b4f7dee19878e344e278ff128c74941d5e7e72dfce6cf83fd5af8d88ab51",
        "c68075c918e2bb1d031c629e31fd31aac1c024d8400133da80d14623b1d89aaf",
        "40ecc58c59a6fa3c29f8ed07546df89247aa06cceb99dfa069d50ede8cb077d0",
        "889ae8d152ac2f9948f70ef62e07e60a8fda9f9b1b7ffa1b602ce08593c166d9",
        "9566c323613929ef6af1177f873c96140dd8bb0d321968e6317b0b4549977102",
        "a58c4d213d7b7638c3503a49fff34004ee7e59bdc1a0118eeef5087fb02edc02",
        "fd332ec41a2afe229c86b0074f3589d3373ab8e45318b117ad67fa2daa0ff5de",
        "5c32aee279db67a8626b1ab24422bd320fa77746ed2c7c24bcb97230070dddb5",
        "8f38b18d95a38668819c4ca14103483ce95b5ec501c10cfaf17c6a57cb2f2524",
        "9935a966f977f9e04059663b3bf22a9cd5aeb4429cc8ac62dca9b4a3cbc7fc5c",
        "21f89301565af030756d2da5bb03028fdc973503734fd27948fec331d65f55c8",
        "e748938040e11f3fa227ac5f2a74f4d1428191b5fd6662260bdc51d732e93690",
        "2be9939aabffd819e7c44cb51cd1e77e6f7821e2c85addef79e1eca681e1a796",
        "0cc148b513fae2c9c1eb6eb2c57db00b7dd11a80caeea501ca878a1d89fd4fd4",
        "54947a140fa6fa0ceedd8fbb3ca9a5269cf2a7586f0928e720ada68736d6ce29",
        "25520b85c72dbe8ab1d87c511fda341e68fa3c0fdf75be70975b1db11b099f3d",
        "56f8de94ecee65e14e96d7b4c29de55ecead2b0e4ee97d27eb9f39f97b1714c0",
        "871f3a2a08536207ebfeda7b8a12ed9b889e29cc4910153ec25bd777304787fd",
        "c34a68c5a5c55bef10e605e5bd1fbb301141c7177d6b0e060aa6b96635cf9bd2",
        "308de2bc43b4c2aa0cb5815acf407a5df77131263a1118cf588a07c7782f697e",
        "b61b7fe95f1e3595b162337d27b17a855d97cfd1a7845656dec901a078bcb1c8",
        "255a060d7b2e2e5da70ebac058cd0dd41b115390eb00080c1402ea3242022c00",
        "0000080000020000200007fa01000002d6140a324201013eeca56153a5c7b303",
        "4cc9f63f65c77ff502430ee5f2e5cb130761d59e18726dd556befa2a77dd7f36",
        "157fb0aed79010a483f5bbddc679bf97c1f2cbbacfcf4b4c3f122d49f53443f3",
        "be4d5dc33ee8d02c8f10dc253bb58d3659e4b6ddd0ac0335872e2d48f5f1cb42",
        "228cd27327705a93beeb943bc8717b91551025ba095c0945bd7d259c6065f14c",
        "09f55de586183fe5c2cab79c27140b7fbfd76807f5b414afa6e138fecb8a0122",
        "0d322b7dfc4bbee351426a76677e30adaa514883e1707ffcd574fdb7c351a38c",
        "4de9329be74988fc5f41e86625b36c55a99901e33102c7af4a3ba51cac0bfc0f",
        "55949af07e82b275780bddb7f98153b133be1b821981d36aa7c447156a96ab0f",
        "d6eb1c48fbdd5c9acbd27a377aed46a9e75b41ab16426eb982e9874ebd61b9bb",
        "deed85efe90c31de8e756e7479f873f445bd63c96483ebeb90732792c1334cff",
        "9b4e3809bdd001a352426d5723a8f8960ddad53fc1c4e1b25bda96d7aed4d546",
        "916502dea111ef5fb8a35e645c5fb23538d3ec8df584bcd5c08cf071de871a6b",
        "3459529035efc3e67434f5a4d996f02809fb85db56f81de260e4671d6d9fb10a",
        "3fe28cf326dc495498631e77f4c00fbe2992891d549a10cd44ba8ae2832f6955",
        "29cffb9b52413bc0cce9938790454dd1c9ea9b59216d1b66f365e6ae0ee272e7",
        "fe4df859fb6ea2e81e35e46073999e3e43b11fe97e79a8c03f6232d8379ba92d",
        "5ca9e71f1cd893f699f1d1dead36228d2ac0551d4136f7bdd9432cd8d51506b7",
        "fa8ef3e666cdad187200af5d4e9b669d8044eda2b3953c6085b1719ace00ebe6",
        "835d9f42ab89886092ed377e4d0875a1a53542c6a46aa3701f0f18eb971d4aa8",
        "3d7d39d4aa45e623cd16bbf83b6839c0cf55bd3c439ef1ad697898980101ba18",
        "153b531c36ae22ffda7d1591dcc512e30cc45a332836af17550ae7be5acf2d16",
        "18d215ff437137fcd80b7588e8f29139a82cf285a64126cfbc6b3ab87784c60b",
        "716129bf6491a3d986fed8c1160e1cfb94e8ba05e683c65ecbcebd3e6daf518d",
        "29d21bdde162159b9cc5032851c1a560122d0d5e9be269eba27c9cb844c8bd77",
        "93e19c3d9683b64a6aeaeecc1524641669d69c0f513808a7abd19d02d7f74fc7",
        "3669ede063e6a36e4fb58c1d4de89185104682ca73bfbe3317bafbb87d54c51c",
        "2c38b957917ef3ad3233ab8c49b8992ddc4dac563f2b9ebbf3dfc4cfc8530fc3",
        "65b7f291d5bf6443c81c997a4af6f0f7d1b72fb185cc336f93938aea0d847387",
        "55bcd2387863ea3bc74e66dbfb3c31a7448e9bd0039b6dc629bfd612bac54cf4",
        "35e38d406b773dcb031867fd75757b4ea9f312a7645f3816827d035e53c771da",
        "fd9a0019e871caaac5589b078c619785c62d38497299094d5891c488921073b5",
        "a8fedbc3aec41ad485525e1ac6cde7561036651c33115e93750419ce05efd840",
        "8f284b31b7c043519d31a5d72fa33fac92b50265a4b361f6c88d425f7c87982c",
        "06d43973c78e2b13768b68de45a12ab86f74d7ce8d00b10a1cd90bb4c046cb1f",
        "2a3938446c98a623f9138cfbd2733ca361fc816234b3cad7a678822c36110758",
        "69d05914090728f517097ec430e08ad76e31db55fe5543b331db4901b97e7d09",
        "7c628fb4e3b3b6d416014177f74d95c6e318d14806ce1a4184ebda1c338b8664",
        "28e68158efc8d292d0f73ffa91f8fdc3ef31218cd79667e147da0cb683aab2bf",
        "211f10b736ae451caac6faa7e2debf05d3e0778c2456f2e305a4a570e142ae16",
        "4b4b3d93a90d32653ccb4676f17f57ad145a035e1b3bf01d93d557f519f470d0",
        "02fb41541dd53813551c091fafe92f58c4e395ef3f75492e8f2bcb97a9ca1d4e",
        "629f079c241675bef90a6768b593e935acc44df5ef6d3518424505b99f4182de",
        "a9c79a8c3965bd81aaa5b19e20a726cc4c7d840a0b7a3f6aca8ba9e3328faaa7",
        "1936f2b8992c62cf937b90dc4b499e001b879676355a323bbe87ed24b975e037",
        "fb4b52268219c65d2343cc379e8c50fbe76e547674f680a7fd5008ce8f47083c",
        "342dbd445c23d22648bdc370db650a247acb0523cacf751a753ff1d8527782cb",
        "10daea94999aa398fa528632510e25eb7fc30dedaf71892347946f4806fac49e",
        "32733f8c6fb162761fecd43d3308742191ec8bf712dd8b8339736bdbde1a86d1",
        "1d223d4e3509e7b3f56bfd4b2b2d127814cbd2e307fdca1254da4f2381a32599",
        "38f3592624b7991e1cf1d68b9d559a7352cfe835773e08b7e62576a0364ca9f5",
        "44ce6d0677a64975f9309f2043945973b6f6671cd04a505e9d064e12b8e86f73",
        "eb2b84dae9b951b2dfaf69e6b0465a6de6449977304030c54595c5d954713276",
        "5d6b7733adba32ea2731665e80ff8f8b8631e00d008a95d222478b1285f3950b",
        "9e9f94f0b0379a1ac2836d167c26f96f9826f97b4b9bc75790780421ebd25e9b",
        "acd71b73eec6112c563eca3f61410febe24994e4d018bbfb60bf53568e88e0e6",
        "51ac251b0cf1d7288d28b4b8ca91cb183fa805a6d246e99f54f0423cbaa9432e",
        "a39abc027fa12d38230672b37a1ee7d70f54826c14430c7db03c49f6fa51ec86",
        "00ebb71f2e56e5ed8de378c9c194e5c8ea4d2690a20f9a142c599e67b01fb782",
        "eb955a0a9df82a9f332d84cac2b25a909a31f0090b69b0a7b76ea54fd1b581cc",
        "63c20a984f8b641000345091541078991e5b2e240572308d6fad6be245e37e42",
        "81d91ea0ef24ed62b20bc0409b4887686f8d4ea76e4f3150769deecb15fdd321",
        "2efdca962fdcf303a346366bdbfe60dca39cf7046a386f6b748586d06f565e15",
        "e2e6944b31b8219a748a65c56fd332bff52ccc05765adfef86d0cfad0240b9cf",
        "a1da147790eb00080c1402ea3242022c000000080000030000200007fa010000",
        "03b7e90a324201013eeca5ff2344e594a6832209a6283b0497e49b8f741f0d8c",
        "21921cd7b3c57c6f71e06eb82c3d850eaaad46e33e461530cd0d1a08b9ed74f2",
        "3445a5fa251b82a7accf31bd9910e87cbece9ed6d4b5ea26509e30d6330b0129",
        "18de3aa3d625de0075b49eef1361d7a9abaaa796e40c38888277d73813085c55",
        "6f026a4494a4f02eba1fdeeca7963ad1a52668eac70e2c05758adfb8632a6e3c",
        "765f537be751171387e27c09b1c71bb6d1f6209c6b360eda3ed5c311b7b6160d",
        "8ac390cd023f1d19f5fe79273e5ce5be55f1470b939a5dc4377139ca7e9d145d",
        "bb889fbe3b480e7afbc153185f31df17bf93bbdbc3ba7851091f52798622cb45",
        "e7678332a2a07b1ec159adbd29e4392fc7bb477d9c1929fe5a5a3b4125c477cd",
        "945c8e04658a1b11a64365a212e76c5e847f8e73dfdf0b08b68ae9b137d3e629",
        "a0bcb95ec2d3ea43842a57a3b8859fe78f4774508d42f882750402c972cfaefa",
        "f0ef3e5ea44473b96e49bc2605a4215455cfe0021edc62fce3d422c0d6ccb1c7",
        "e43368d05d21ed082ec88b2b263da371f5a4e637f3740a111511a8b175a23b3b",
        "8cc9d578c7be368ef3f645424a38b4c86937b65696ae64306e78099d628eaea2",
        "ce448eb6f913eb8ff5dbe444f0a387035ec0b8756ea35e3a381ddabd33cf65b7",
        "b9059c7ce72461b813fbc3e21d2e8c0f3831dcbd6d057e4c77e10894e045ea1a",
        "ead3843fbd6b3355cbca989f1f172e9c5eabe05b908631ba641cfb7aee15ea91",
        "733f4da31ec2c3a6e42d37cb07e2d75b197a5e468dfb148d1f31689a702ee858",
        "28d681d9aa459b69f1617228885a1320b9a7fdba6bb9b97de84819d02b84a64d",
        "93bed4a54bb7e1d898939c540cda8f5a4420ecea191208fe39b4db280c09daef",
        "4d56ac9235b727453fe837c124c46537fbf84d5fe8cf6225cb8265256bb6d741",
        "576ddc9b4c81795238b0f497e82424c8f33efae55bb47c4268621e8bd07dd9ac",
        "07fb07621232800c0c00eb53474cf116599a7e57be1ef6bf0f6b3d41e97743b8",
        "6ae963735f5bd6e73301f9d3a2970aba4cc3ec457cd5c0ac1e92ab75b3e90d85",
        "a0a0a57b7e139c2e7bb22bcabc48c24db5d6ce4eb1fdaf2e755bf99d8e67cdcf",
        "d92cbc17a77d0fb0d2b9fbc027774ce6f75f56dc1b607e90dc09e802bec318d3",
        "64d00dba1d3a2a3648584f60fed4290e4103142aa12757215a6fbb8e85db2ceb",
        "27eb2a244431966a15163b659e9076909aa6096092c342d76b4dc2f19c1626f5",
        "478aba3cbd7eddc069ca9b92b0b01e5e9ae1d24c14a252f57fa77ab0b4662f0d",
        "1bda5b01a994588c5c36b9a377e8010d5a52d52167680dea410713c53bf736de",
        "aa8386f0073492c062ace068a33b567b876025f7942eecea9452b8d60f5b70b4",
        "f183a64beefaa2d41e9e7dde9f246a9ccd990187b42f580f98dabd349c1df9f1",
        "c01aaa5dd5faf11b15659f4416202bc6a09683ffac7865d48c6fe892deb83de2",
        "a05d64f8904900c537fe14e2b274c5a9742394d81f5469fd9553c7eda6a4aea1",
        "75bcc88f6134e934129c80f7b7ad069dec3759e727bd0142d5ecb9f50a30d66a",
        "8df7527d036238e84c07064f1930b56b60a2e78e8e633fb8f8b0d217d603b34b",
        "4c879c95841b29127c99adb99c22b5c96807ab65e28a456534135dcf960912df",
        "1de532a97802e451bd1e09df26b9e7c659aec9189f298c84e4136173b88de2a8",
        "414281ba0134d3feb757884b7766ba1ce7615263aaa8266afb0f4597b7b1a47e",
        "104d9a17260f7a8e3efffd6d683a57e04bcf68e219c7542ba661c7bf3bf990ce",
        "d33f2d08580e178352a46618662b169285729862055e98f7d768729b280b379d",
        "0c7dd5ff22fdf6634446bc6b5827eeb572854bb4f50537c9defe89bf16619977",
        "5e61615009333d5efc8d9ff142dadb6af16bbd58ff75cfb5880d54cd70b42a9b",
        "39910417cf7ebd0ece54dcbeba0924d2890d4958b3831881632f6d2573d51d5c",
        "8718adc4a2cdac600b8616ead1f34d163deed7ca0cbe47ab726b1517bb1a4e31",
        "d409803e305b999205be886e382f7404285cc7107467ee566d46c5491f7489bc",
        "395ebe35d86fe5f49f823868d04ebc9d8219a67d46855850afed0a684505cc64",
        "31837a957bacd7a97398c7972f0fe65438052b83d34397ec6fa0002f8b8fd69b",
        "fa4a57e9392b544c33c426966b82f6483c51b4cbb5cb0ede96a850851049ac58",
        "0e0d9f83127f972786cea192d7590fa349dc75b908ada95b91e4fff87efde2a4",
        "0e142d7ea36d4fb8e93ad8fda7f15ba807310f56eeab0cc6f25b7135fab6f54e",
        "1e4237deadd9c33cd3b23c600c96475e33ff6bfc65a197479e27ed041eb43f8e",
        "600e6e1e661adf8a217e25bf776aa43a818f3bb46bdcf9b124e485e1fe826e72",
        "1323afb25ec0000d9ad16e8503a7f32b1aeea1391672da9c1f780482a29c50a4",
        "a38f318d85689193e3c9d84310f7690dbba25d7a8a3d30d2cdde95a2009bf2d7",
        "eb4dc0294a284e0015bdc51fd4ef9a2050d7b1f2fe0e4a03ee7195a31faab09e",
        "0fdad9b75bfcd6f2b8f752c1f4ae0b1f00037a4fdcffac229ea83a0be51cf0f7",
        "236847db916eb3b810eee1d8f36f12b45e63db60cb64abc16711bd12359ab890",
        "52ba0f8ec7b48832f7ab791f825b2fedac7f4ca26f3b153748885ddd5f6526d7",
        "77beef833f81ce5a1a46c3ecddbec1518ef09a7c760da688715d6dc4b4931ffe",
        "117fa41f4958f5d4f8d677fdafb9a64ec4b5a644a4083d049fb7981eb63d3f72",
        "3ad0a718b5ae1565a71d5fc0a801510adbbabeb5a41831238b8c6c97e7eccdee",
        "a8e73323c40c098dca8c5880378781eb266e7ffb1289b981a90f3a0340338fb4",
        "5814546a863c1c2ac7f1a5f2f7489a6018f463480c"
    );

    // ANCHOR: dis_transmitter_port_3000
    #[test]
    fn a_v7_transmitter_on_udp_3000() {
        let raw = hex::decode(DIS_V7_TRANSMITTER_HEX).unwrap();
        let flow = parse(LinkType::ETHERNET, &raw).unwrap();

        // UDP 3000, the customary DIS port: the port rule and its lenient read.
        let transport = flow.transport.as_ref().unwrap();
        assert_eq!(transport.destination_port, Some(3000));
        assert_eq!(flow.application.as_ref().unwrap().application_protocol, "DIS");

        // The PDU fills the datagram, so the strict read accepts it too.
        let packet = DisPacket::try_from(transport.payload.unwrap()).unwrap();
        assert_eq!(packet.pdus.len(), 1);
        assert!(packet.trailing.is_empty());

        let pdu = &packet.pdus[0];
        assert_eq!(pdu.pdu_type, dis::PduType::Transmitter);
        let header = pdu.header;
        assert_eq!(header.protocol_version, 7); // IEEE 1278.1-2012
        assert_eq!(header.exercise_id, 1);
        assert_eq!(header.pdu_type, 25);
        assert_eq!(header.protocol_family, 4); // radio communications
        assert_eq!(header.length, 104);
        assert_eq!(pdu.raw.len(), 104);
        assert_eq!(header.status(), Some(0)); // the PDU Status of version 7
        assert!(header.absolute_timestamp());
        assert_eq!(header.timestamp_units(), 1_033_452_647); // 28 min 52.46 s past the hour

        let DisBody::Transmitter {
            entity_id,
            radio_id,
            radio_entity_type,
            transmit_state,
            frequency_hz,
            bandwidth_hz,
            power_dbm,
            modulation_type,
            crypto_system,
            ..
        } = pdu.body
        else {
            panic!("expected a Transmitter body, got {:?}", pdu.body);
        };
        assert_eq!(
            (entity_id.site, entity_id.application, entity_id.entity),
            (64128, 61467, 65534)
        );
        assert_eq!(radio_id, 65534);
        assert_eq!((radio_entity_type.kind, radio_entity_type.category), (7, 1)); // radio, voice
        assert_eq!(transmit_state, 1); // on, not transmitting
        assert_eq!(frequency_hz, 100_000_000);
        assert_eq!(bandwidth_hz, 25_000.0);
        assert_eq!(power_dbm, -270.0);
        // Angle modulation, FM, generic radio, in tshark's words.
        assert_eq!(
            (modulation_type.major, modulation_type.detail, modulation_type.system),
            (3, 1, 1)
        );
        assert_eq!(crypto_system, 0);
    }
    // ANCHOR_END: dis_transmitter_port_3000

    // ANCHOR: dis_blind_probe
    #[test]
    fn a_signal_off_port_3000_is_labelled_by_the_blind_probe() {
        let raw = hex::decode(DIS_V6_SIGNAL_HEX).unwrap();
        let flow = parse(LinkType::ETHERNET, &raw).unwrap();

        // UDP 3388 -> 6993: no rule has a port for it. The blind probe labels
        // it, because its PDUs tile the datagram exactly.
        let transport = flow.transport.as_ref().unwrap();
        assert_eq!(
            (transport.source_port, transport.destination_port),
            (Some(3388), Some(6993))
        );
        assert_eq!(flow.application.as_ref().unwrap().application_protocol, "DIS");

        let payload = transport.payload.unwrap();
        let packet = DisPacket::try_from(payload).unwrap();
        let pdu = &packet.pdus[0];
        assert_eq!(pdu.pdu_type, dis::PduType::Signal);
        assert_eq!(pdu.header.protocol_version, 6); // IEEE 1278.1A-1998
        assert_eq!(usize::from(pdu.header.length), payload.len()); // 1 056 bytes
        assert_eq!(pdu.header.status(), None); // no PDU Status before version 7
        assert!(!pdu.header.absolute_timestamp());
        assert_eq!(pdu.header.timestamp_units(), 89_479); // 0.15 s

        let DisBody::Signal {
            entity_id,
            radio_id,
            encoding_scheme,
            sample_rate,
            data_length,
            samples,
            data,
            ..
        } = pdu.body
        else {
            panic!("expected a Signal body, got {:?}", pdu.body);
        };
        assert_eq!(
            (entity_id.site, entity_id.application, entity_id.entity),
            (32253, 253, 1)
        );
        assert_eq!(radio_id, 2);
        assert_eq!(encoding_scheme, 0x0001); // tshark: encoded audio, 8-bit mu-law
        assert_eq!((sample_rate, samples), (8000, 1024));
        assert_eq!(data_length, 8192); // in bits: 1 024 bytes of samples
        assert_eq!(data.len(), 1024);
    }
    // ANCHOR_END: dis_blind_probe

    // ANCHOR: dis_strict_and_lenient
    #[test]
    fn a_length_shorter_than_the_datagram_needs_the_lenient_read() {
        let raw = hex::decode(DIS_V4_SET_DATA_HEX).unwrap();

        // UDP 2725 -> 6993: no port rule applies, and the strict read of the
        // blind probe refuses the 112 bytes after the declared 48.
        let flow = parse(LinkType::ETHERNET, &raw).unwrap();
        assert_eq!(flow.application.as_ref().unwrap().application_protocol, "Unknown");

        let payload = flow.transport.as_ref().unwrap().payload.unwrap();
        assert_eq!(payload.len(), 160);
        assert_eq!(
            DisPacket::try_from(payload),
            Err(DisParseError::UnexpectedTrailingBytes { trailing: 112 })
        );

        // The lenient read takes the PDU its length delimits and keeps the rest.
        let packet = DisPacket::try_from_lenient(payload).unwrap();
        assert_eq!(packet.pdus.len(), 1);
        let pdu = &packet.pdus[0];
        assert_eq!(pdu.pdu_type, dis::PduType::SetData);
        assert_eq!(pdu.header.protocol_version, 4);
        assert_eq!(pdu.header.protocol_family, 5); // simulation management
        assert_eq!(pdu.header.length, 48);
        assert!(matches!(pdu.body, DisBody::Opaque(body) if body.len() == 36));
        assert_eq!(packet.trailing.len(), 112);

        // Declaring the port selects the lenient read, as port 3000 does.
        let config = ParseConfig::new().decode_as(6993, DecodeAsProtocol::Dis);
        let flow = parse_with(LinkType::ETHERNET, &raw, &config).unwrap();
        assert_eq!(flow.application.as_ref().unwrap().application_protocol, "DIS");
    }
    // ANCHOR_END: dis_strict_and_lenient

    // ANCHOR: sis_bind
    #[test]
    fn a_bind_request_and_its_acceptance() {
        let raw = hex::decode(SIS_BIND_REQUEST_HEX).unwrap();
        let flow = parse(LinkType::ETHERNET, &raw).unwrap();
        let transport = flow.transport.as_ref().unwrap();
        assert_eq!(transport.destination_port, Some(5066));
        assert_eq!(flow.application.as_ref().unwrap().application_protocol, "STANAG 5066");

        let payload = transport.payload.unwrap();
        assert_eq!(&payload[..2], &[0x90, 0xeb]); // the preamble
        let request = SisPdu::try_from(payload).unwrap();
        assert_eq!(request.pdu_type, stanag5066::PduType::BindRequest);
        assert_eq!(request.header.version, 0);
        assert_eq!(request.header.primitive_size, 4); // type included
        assert_eq!(request.header.pdu_type, 1);
        assert!(!request.truncated);
        // 5 bytes of header and 4 of primitive: the whole segment.
        assert_eq!(request.consumed(), 9);
        assert_eq!(request.consumed(), payload.len());

        let SisPrimitive::Bind {
            sap_id,
            rank,
            service_type,
        } = request.primitive
        else {
            panic!("expected a Bind primitive, got {:?}", request.primitive);
        };
        assert_eq!((sap_id, rank), (5, 1)); // SAP 5: HF Chat, for tshark
        assert_eq!(service_type.transmission_mode, 1); // ARQ
        assert_eq!(service_type.delivery_confirmation, 1); // by the node
        assert!(service_type.in_order_delivery);
        assert!(!service_type.extended);

        // Frame 26, the node's answer: SAP 5 is bound, with an MTU of 250 bytes.
        let raw = hex::decode(SIS_BIND_ACCEPTED_HEX).unwrap();
        let flow = parse(LinkType::ETHERNET, &raw).unwrap();
        let payload = flow.transport.as_ref().unwrap().payload.unwrap();
        let accepted = SisPdu::try_from(payload).unwrap();
        assert_eq!(accepted.pdu_type, stanag5066::PduType::BindAccepted);
        assert_eq!(
            accepted.primitive,
            SisPrimitive::BindAccepted {
                sap_id: 5,
                mtu: 250
            }
        );
    }
    // ANCHOR_END: sis_bind

    // ANCHOR: sis_unidata_request
    #[test]
    fn a_unidata_request_carrying_acp_142() {
        let raw = hex::decode(SIS_ACP142_REQUEST_HEX).unwrap();
        let flow = parse(LinkType::ETHERNET, &raw).unwrap();
        assert_eq!(flow.application.as_ref().unwrap().application_protocol, "STANAG 5066");

        let payload = flow.transport.as_ref().unwrap().payload.unwrap();
        let request = SisPdu::try_from(payload).unwrap();
        assert_eq!(request.pdu_type, stanag5066::PduType::UnidataRequest);
        assert_eq!(request.header.primitive_size, 50);
        assert!(!request.truncated);
        assert_eq!(request.consumed(), payload.len()); // 55 bytes

        let SisPrimitive::Unidata {
            priority,
            reason,
            destination_sap_id,
            destination,
            service_type,
            minimum_retransmissions,
            time_to_live,
            source,
            u_pdu_size,
            u_pdu,
            ..
        } = request.primitive
        else {
            panic!("expected a Unidata primitive, got {:?}", request.primitive);
        };
        assert_eq!((priority, reason), (Some(0), None)); // a request has no reason
        assert_eq!(destination_sap_id, 2); // for tshark, the STANAG 4406 annex E client
        assert_eq!(destination.to_string(), "10.50.66.2");
        assert_eq!((destination.size, destination.group), (7, false));
        assert_eq!(destination.address, 0x0a32_4202);
        assert_eq!(service_type.unwrap().transmission_mode, 2); // non-ARQ
        assert_eq!((minimum_retransmissions, time_to_live), (Some(0), Some(0)));
        assert!(source.is_none()); // only indications name a source
        assert_eq!((u_pdu_size, u_pdu.len()), (38, 38));
        // The U_PDU stays raw: an ACP 142 message behind a client transport
        // header whose application identifier is 0x2000.
        assert_eq!(&u_pdu[4..6], &[0x20, 0x00]);
    }
    // ANCHOR_END: sis_unidata_request

    // ANCHOR: sis_port_guard
    #[test]
    fn off_tcp_5066_an_s_pdu_needs_decode_as() {
        let mut raw = hex::decode(SIS_ACP142_REQUEST_HEX).unwrap();
        // Rewrite the TCP destination port, after 14 bytes of Ethernet and 20
        // of IPv4, from 5066 to 5067; `parse` does not verify the checksum.
        raw[36..38].copy_from_slice(&5067u16.to_be_bytes());

        let flow = parse(LinkType::ETHERNET, &raw).unwrap();
        let transport = flow.transport.as_ref().unwrap();
        assert_eq!(
            (transport.source_port, transport.destination_port),
            (Some(41778), Some(5067))
        );
        // Still an S_PDU, but off port 5066 no rule probes it.
        assert!(SisPdu::try_from(transport.payload.unwrap()).is_ok());
        assert_eq!(flow.application.as_ref().unwrap().application_protocol, "Unknown");

        let config = ParseConfig::new().decode_as(5067, DecodeAsProtocol::Stanag5066);
        let flow = parse_with(LinkType::ETHERNET, &raw, &config).unwrap();
        assert_eq!(flow.application.as_ref().unwrap().application_protocol, "STANAG 5066");
    }
    // ANCHOR_END: sis_port_guard

    // ANCHOR: sis_split_pdu
    #[test]
    fn a_split_s_pdu_is_decoded_on_its_first_segment() {
        let raw = hex::decode(SIS_INDICATION_FIRST_SEGMENT_HEX).unwrap();
        let flow = parse(LinkType::ETHERNET, &raw).unwrap();
        assert_eq!(flow.application.as_ref().unwrap().application_protocol, "STANAG 5066");

        let payload = flow.transport.as_ref().unwrap().payload.unwrap();
        let indication = SisPdu::try_from(payload).unwrap();
        assert_eq!(indication.pdu_type, stanag5066::PduType::UnidataIndication);
        // 5 + 30 = 35 bytes announced, 18 in this segment.
        assert_eq!(indication.header.primitive_size, 30);
        assert_eq!(payload.len(), 18);
        assert!(indication.truncated);
        assert_eq!(indication.consumed(), 18);

        // The fixed fields are all in this segment, the U_PDU is not.
        let SisPrimitive::Unidata {
            priority,
            destination_sap_id,
            destination,
            transmission_mode,
            source_sap_id,
            source,
            u_pdu_size,
            u_pdu,
            ..
        } = indication.primitive
        else {
            panic!("expected a Unidata primitive, got {:?}", indication.primitive);
        };
        assert_eq!((priority, destination_sap_id), (Some(0), 5));
        assert_eq!(destination.to_string(), "5.100.100.2");
        assert_eq!((transmission_mode, source_sap_id), (Some(1), Some(5))); // ARQ
        assert_eq!(source.unwrap().to_string(), "5.100.100.1");
        assert_eq!(u_pdu_size, 17);
        assert!(u_pdu.is_empty());

        // Frame 30, the next segment: the 17 bytes of the U_PDU. Without a
        // preamble they are not an S_PDU, and the segment stays "Unknown".
        let raw = hex::decode(SIS_INDICATION_CONTINUATION_HEX).unwrap();
        let flow = parse(LinkType::ETHERNET, &raw).unwrap();
        let payload = flow.transport.as_ref().unwrap().payload.unwrap();
        assert_eq!(payload, b"<0> Hello there.\n");
        assert_eq!(
            SisPdu::try_from(payload),
            Err(Stanag5066ParseError::InvalidPreamble(*b"<0"))
        );
        assert_eq!(flow.application.as_ref().unwrap().application_protocol, "Unknown");
    }
    // ANCHOR_END: sis_split_pdu

    // ANCHOR: sis_consumed
    #[test]
    fn consumed_walks_the_s_pdus_of_a_segment() {
        let raw = hex::decode(SIS_THREE_REQUESTS_HEX).unwrap();
        let flow = parse(LinkType::ETHERNET, &raw).unwrap();
        assert_eq!(flow.application.as_ref().unwrap().application_protocol, "STANAG 5066");
        let payload = flow.transport.as_ref().unwrap().payload.unwrap();
        assert_eq!(payload.len(), 6195);

        // `try_from` decodes the first S_PDU; `consumed` says where the next
        // one starts.
        let mut rest = payload;
        let mut lengths = Vec::new();
        while !rest.is_empty() {
            let pdu = SisPdu::try_from(rest).unwrap();
            assert_eq!(pdu.pdu_type, stanag5066::PduType::UnidataRequest);
            assert!(!pdu.truncated);
            let SisPrimitive::Unidata {
                destination,
                u_pdu_size,
                u_pdu,
                ..
            } = pdu.primitive
            else {
                panic!("expected a Unidata primitive, got {:?}", pdu.primitive);
            };
            assert_eq!(destination.to_string(), "10.50.66.2");
            assert_eq!((u_pdu_size, u_pdu.len()), (2048, 2048));
            lengths.push(pdu.consumed());
            rest = &rest[pdu.consumed()..];
        }
        assert_eq!(lengths, [2065, 2065, 2065]);
    }
    // ANCHOR_END: sis_consumed
}
