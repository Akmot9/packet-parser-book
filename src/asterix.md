# ASTERIX

Recognized by structure alone, a route of the [dispatch table](./application.md#three-detection-routes).

ASTERIX (EUROCONTROL-SPEC-0149), the exchange format of air traffic surveillance data, is the first protocol of the crate with **neither a magic nor a port**: no IANA port (Wireshark suggests 8600, the maintainer's capture runs on 8611 and 8612), and it usually travels as UDP multicast. What it has is structure. A datagram is a sequence of data blocks (`CAT`, `LEN`, records), and each record is cut item by item along the UAP of its category: fixed, extensible (FX), repetitive, compound and explicit (SP/RE) items.

`CAT + LEN` alone match far too many things, so the probe asks for everything: every data block must be of a decoded category (CAT 048 monoradar plots and tracks, CAT 034 service messages from the same radar, CAT 021 ADS-B in its 2.x editions), and its records must split exactly along the UAP up to the last byte. One block of another category (CAT 062, say) fails the whole datagram. On the reference corpus, the probe labels exactly the 303 frames `tshark -Y asterix` sees, and no other. CAT 021 editions 0.2x, whose UAP is entirely different, are not decoded: nothing in the bytes tells them apart.
