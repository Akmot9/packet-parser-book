#!/usr/bin/env python3
"""Generate the book's SVG diagrams.

They follow the visual language of the original FigJam images (src/images/*.png):
one colour per layer, byte grids with real bytes, a black-titled struct, rounded
arrows with chevron heads, orange for the field the next step branches on, all on
a cream card so they read the same in the light and dark mdBook themes.

The bytes are built here with valid checksums. Every value printed in a struct is
what packet_parser returns for those bytes: when the crate changes, check them
again, edit this file and run `python3 tools/diagrams.py`.
"""

from pathlib import Path
import struct

IMAGES = Path(__file__).resolve().parent.parent / "src" / "images"

# Palette sampled from the FigJam PNGs
DARK = "#1E1E1E"
GREY = "#757575"
GREY_LIGHT = "#B3B3B3"
BLUE = "#3DADFF"
BLUE_LIGHT = "#C2E5FF"
GREEN = "#66D575"
GREEN_LIGHT = "#CDF4D3"
YELLOW = "#FFC943"
YELLOW_LIGHT = "#FFECBD"
ORANGE = "#FF9E42"
ORANGE_DARK = "#EB7500"
FRAME_FILL = "#FFEAD6"
FRAME_LINE = "#FF9E42"
SUCCESS = "#3E9B4F"
ARROW_DARK = "#3A3A3A"
WHITE = "#FFFFFF"

# Grid lines: (between fields, inside the strong payload rows)
LINES = {BLUE_LIGHT: ("#8EC6EE", "#2F97E3"), GREEN_LIGHT: ("#93D9A0", "#4DBE5E"),
         YELLOW_LIGHT: ("#E9CF86", "#E0AE2E")}
RED = "#D56666"
NONE_FILL = "#4A4A4A"
HATCH = "url(#hatch)"

SANS = "Inter, ui-sans-serif, system-ui, -apple-system, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif"
MONO = "ui-monospace, SFMono-Regular, Menlo, Consolas, 'DejaVu Sans Mono', monospace"

W = 900
CW, RH = 96, 60          # byte cell width, row height
CAP_Y, HEX_Y = 19, 49    # caption and hex baselines inside a row
ARROW_DY = 28            # an arrow crossing a row runs between caption and hex
FIELD_H, GAP, TITLE_H = 56, 4, 56


# --------------------------------------------------------------------------- packets

def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def addr(a: str) -> bytes:
    return bytes(int(x) for x in a.split("."))


def ipv4(src, dst, proto, payload, ident):
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), ident, 0x4000, 64, proto, 0,
                      addr(src), addr(dst))
    return hdr[:10] + struct.pack("!H", checksum(hdr)) + hdr[12:] + payload


def tcp(src, dst, sport, dport, seq, flags, options=b"", data=b"", ack=0, window=0xFAF0):
    hdr = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, ((20 + len(options)) // 4) << 4, flags,
                      window, 0, 0) + options
    pseudo = addr(src) + addr(dst) + struct.pack("!BBH", 0, 6, len(hdr) + len(data))
    return hdr[:16] + struct.pack("!H", checksum(pseudo + hdr + data)) + hdr[18:] + data


def ethernet(dst, src, payload, ethertype=0x0800):
    return bytes.fromhex(dst.replace(":", "") + src.replace(":", "")) + struct.pack("!H", ethertype) + payload


# The same Linux TCP SYN runs through the internet, transport and tunnel chapters.
# Options: MSS 1460, SACK permitted, timestamps, NOP, window scale 7.
SYN_OPTIONS = bytes.fromhex("020405b40402080a000a3b1c0000000001030307")
SYN_TCP = tcp("192.168.0.104", "192.168.0.1", 54321, 80, 0x8F3A210C, 0x02, SYN_OPTIONS)
SYN_IP = ipv4("192.168.0.104", "192.168.0.1", 6, SYN_TCP, ident=0x1C46)
SYN_FRAME = ethernet("02:42:c0:a8:00:01", "02:42:c0:a8:00:68", SYN_IP)

VXLAN_HEADER = bytes.fromhex("0800000000006400")  # I flag, VNI 100
_vxlan_udp_payload = VXLAN_HEADER + SYN_FRAME
VXLAN_UDP = struct.pack("!HHHH", 51234, 4789, 8 + len(_vxlan_udp_payload), 0) + _vxlan_udp_payload
VXLAN_PACKET = ethernet("52:54:00:00:00:02", "52:54:00:00:00:01",
                        ipv4("10.0.0.1", "10.0.0.2", 17, VXLAN_UDP, ident=0x5A11))

# A minimal TLS 1.2 ClientHello in a TLS 1.0 record
_suites = bytes.fromhex("c02bc02fc02cc030")
_hello = (b"\x03\x03" + bytes(range(32)) + b"\x00" + struct.pack("!H", len(_suites)) + _suites
          + b"\x01\x00" + struct.pack("!H", 0))
_handshake = b"\x01" + struct.pack("!I", len(_hello))[1:] + _hello
TLS_RECORD = b"\x16\x03\x01" + struct.pack("!H", len(_handshake)) + _handshake



def udp(src, dst, sport, dport, data):
    hdr = struct.pack("!HHHH", sport, dport, 8 + len(data), 0)
    pseudo = addr(src) + addr(dst) + struct.pack("!BBH", 0, 17, 8 + len(data))
    return hdr[:6] + struct.pack("!H", checksum(pseudo + hdr + data)) + data


# A DNS query for example.com (A, IN), from the host of the SYN to its resolver: the packet of
# the first diagrams of the book, small enough to be drawn byte by byte
DNS_QUERY = bytes.fromhex("1a2b01000001000000000000") + b"\x07example\x03com\x00" + bytes.fromhex("00010001")
DNS_FRAME = ethernet("02:42:c0:a8:00:01", "02:42:c0:a8:00:68",
                     ipv4("192.168.0.104", "192.168.0.1", 17, udp("192.168.0.104", "192.168.0.1", 51000, 53, DNS_QUERY),
                          ident=0x3c1d))
# A MAC address whose OUI is in the crate's table (Siemens)
SIEMENS_MAC = bytes.fromhex("e0dca04d2e91")

# The book's other examples, already used in the getting started chapter and by examples/
ACK_FRAME = bytes.fromhex(
    "feaa81e86d1efeaa818ec864080045500034000000003d06206b36e6700d"
    "ac140a0201bbc1087d7f02aa4e2b998e80100081748300000101080a9373"
    "c9c207ef14e3")
LLDP_FRAME = bytes.fromhex("0180c200000e00112233445588cc0207040011223344 55".replace(" ", ""))
SYN_FIN_FRAME = SYN_FRAME[:14 + 33] + b"\x03" + SYN_FRAME[14 + 34:]

# pcaps_exemple/protocols/giop/corba.pcap (nDPI test corpus), frame 4: the TCP payload,
# a GIOP 1.2 big-endian Request "echo"
GIOP_FRAME4 = bytes.fromhex(
    "47494f5001020000000000d80000000003000000000000000000003c000000000000000100000010"
    "4d795f436f6d70726573735f506f6100000000000000011f5a056dca000000100000011f5a056dca"
    "0000000000000000000000056563686f000000000000000100000007000000280000000000000001"
    "0000001c00000018000000000000000001ddf68a6dc5c42000000000000000000000004100020206"
    "04020105030102050307070601020707050301050307030301030606020206040102020201010407"
    "05020707030604060502020202020502020504010000000000000000")
# frame 19: the GIOP header of a little-endian Request, at offset 32 of a MIOP datagram
GIOP_FRAME19_HEADER = bytes.fromhex("47494f5001020100d8000000")

def hexs(data: bytes) -> str:
    return " ".join(f"{b:02X}" for b in data)


# --------------------------------------------------------------------------- drawing

class Svg:
    def __init__(self, height, title, desc):
        self.h = height
        self.out = [
            f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {height}" width="{W}" '
            f'height="{height}" role="img" aria-labelledby="t d">',
            f"<title id=\"t\">{title}</title>",
            f"<desc id=\"d\">{desc}</desc>",
            f'<rect x="12" y="12" width="{W - 24}" height="{height - 24}" rx="18" fill="{FRAME_FILL}" '
            f'stroke="{FRAME_LINE}" stroke-width="2.5"/>',
        ]

    def define_hatch(self):
        self.out.insert(3, '<defs><pattern id="hatch" patternUnits="userSpaceOnUse" width="9" height="9" '
                           'patternTransform="rotate(45)"><rect width="9" height="9" fill="#FFF4D6"/>'
                           '<line x1="0" y1="0" x2="0" y2="9" stroke="#E9CF86" stroke-width="5"/></pattern></defs>')

    def add(self, s):
        self.out.append(s)

    def text(self, x, y, s, size, fill=DARK, weight=400, anchor="middle", family=SANS, opacity=None):
        op = f' fill-opacity="{opacity}"' if opacity is not None else ""
        self.add(f'<text x="{x}" y="{y}" font-family="{family}" font-size="{size}" font-weight="{weight}" '
                 f'fill="{fill}"{op} text-anchor="{anchor}">{s}</text>')

    def rect(self, x, y, w, h, fill, rx=0, stroke=None, sw=1.5, dash=None):
        st = f' stroke="{stroke}" stroke-width="{sw}"' if stroke else ""
        da = f' stroke-dasharray="{dash}"' if dash else ""
        r = f' rx="{rx}"' if rx else ""
        self.add(f'<rect x="{x}" y="{y}" width="{w}" height="{h}"{r} fill="{fill}"{st}{da}/>')

    def line(self, x1, y1, x2, y2, color, sw=1, dash=None):
        da = f' stroke-dasharray="{dash}"' if dash else ""
        self.add(f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" stroke="{color}" stroke-width="{sw}"{da}/>')

    def outline(self, x, y, w, h):
        self.rect(x, y, w, h, "none", rx=5, stroke=DARK, sw=3.5)

    def chevron(self, x, y, direction, color, size=9):
        dx, dy = {"left": (1, 0), "right": (-1, 0), "up": (0, 1), "down": (0, -1)}[direction]
        # the two arms go back along the arrow, spread perpendicular to it
        a = (x + size * dx + size * dy, y + size * dy + size * dx)
        b = (x + size * dx - size * dy, y + size * dy - size * dx)
        self.add(f'<polyline points="{a[0]},{a[1]} {x},{y} {b[0]},{b[1]}" fill="none" stroke="{color}" '
                 f'stroke-width="3.5" stroke-linecap="round" stroke-linejoin="round"/>')

    def arrow(self, points, color, radius=14, head=True):
        """Polyline of horizontal and vertical segments with rounded corners, chevron at the end."""
        d = f"M {points[0][0]} {points[0][1]}"
        for i in range(1, len(points) - 1):
            (x0, y0), (x1, y1), (x2, y2) = points[i - 1], points[i], points[i + 1]
            r = min(radius, abs(x1 - x0 + y1 - y0) / 2, abs(x2 - x1 + y2 - y1) / 2)
            ux, uy = _unit(x1 - x0, y1 - y0)
            vx, vy = _unit(x2 - x1, y2 - y1)
            d += f" L {x1 - ux * r} {y1 - uy * r} Q {x1} {y1} {x1 + vx * r} {y1 + vy * r}"
        d += f" L {points[-1][0]} {points[-1][1]}"
        self.add(f'<path d="{d}" fill="none" stroke="{color}" stroke-width="3.5" stroke-linecap="round" '
                 f'stroke-linejoin="round"/>')
        if head:
            (xa, ya), (xb, yb) = points[-2], points[-1]
            direction = ("right" if xb > xa else "left") if ya == yb else ("down" if yb > ya else "up")
            self.chevron(xb, yb, direction, color)

    def save(self, name):
        path = IMAGES / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("\n".join(self.out + ["</svg>"]) + "\n")
        print(f"wrote {path.relative_to(IMAGES.parent.parent)}")


def _unit(dx, dy):
    return ((dx > 0) - (dx < 0), (dy > 0) - (dy < 0))


def byte_grid(svg, gx, gy, rows, light, strong, highlight=ORANGE, cols=4, strong_ink=WHITE):
    """Draw a 32-bit-per-row byte grid; return the y of each row and the grid bottom.

    rows: ("fields", [(col, n, caption, hex, highlighted or a fill)]),
          ("bytes", hex, caption_or_None, fill) for undivided rows,
          ("ellipsis", text, fill, height).
    """
    field_line, strong_line = LINES[light]
    width = cols * CW
    ys, y = [], gy
    for row in rows:
        ys.append(y)
        y += row[3] if row[0] == "ellipsis" else RH
    bottom = y
    svg.add(f'<clipPath id="g"><rect x="{gx}" y="{gy}" width="{width}" height="{bottom - gy}" rx="12"/></clipPath>')
    svg.add('<g clip-path="url(#g)">')
    for row, y in zip(rows, ys):
        if row[0] == "fields":
            for col, n, cap, hx, hl in row[1]:
                x = gx + col * CW
                fill = hl if isinstance(hl, str) else highlight if hl else light
                svg.rect(x, y, n * CW, RH, fill, stroke=field_line)
                for k in range(1, n):  # byte separators below the caption
                    svg.line(x + k * CW, y + 26, x + k * CW, y + RH, field_line)
                svg.text(x + n * CW / 2, y + CAP_Y, cap, 13.5, weight=500, opacity=0.62)
                for k, b in enumerate(hx.split()):
                    svg.text(x + k * CW + CW / 2, y + HEX_Y, b, 20, weight=500,
                             opacity=0.45 if fill == HATCH else None)
        elif row[0] == "bytes":
            _, hx, cap, fill = row
            ink, sep = (strong_ink, strong_line) if fill == strong else (DARK, field_line)
            svg.rect(gx, y, width, RH, fill)
            for k in range(1, cols):
                svg.line(gx + k * CW, y + 26 if cap else y, gx + k * CW, y + RH, sep)
            if cap:
                svg.text(gx + width / 2, y + CAP_Y, cap, 13.5, fill=ink, weight=500,
                         opacity=0.85 if ink == WHITE else 0.62)
            hex_y = y + HEX_Y if cap else y + RH / 2 + 7
            for k, b in enumerate(hx.split()):
                svg.text(gx + k * CW + CW / 2, hex_y, b, 20, fill=ink, weight=500)
        else:
            _, label, fill, h = row
            ink, sep = (strong_ink, strong_line) if fill == strong else (DARK, field_line)
            svg.rect(gx, y, width, h, fill)
            svg.line(gx, y, gx + width, y, sep, dash="4 4")
            svg.text(gx + width / 2, y + h // 2 + 5, label, 14, fill=ink, weight=500, opacity=0.9 if ink == WHITE else 0.7)
    svg.add("</g>")
    svg.rect(gx, gy, width, bottom - gy, "none", rx=12, stroke=DARK, sw=3.5)
    return ys, bottom


def struct_box(svg, x, w, title, fields):
    """Black-titled struct; fields = [(name, value, fill, ink, center_y)], top to bottom."""
    top = fields[0][4] - FIELD_H / 2 - GAP - TITLE_H - GAP
    bottom = fields[-1][4] + FIELD_H / 2 + GAP
    svg.rect(x, top, w, bottom - top, DARK, rx=10)
    svg.text(x + w / 2, top + GAP + TITLE_H / 2 + 7, title, 20, fill=WHITE, weight=600)
    prev = top + GAP + TITLE_H
    for name, value, fill, ink, cy in fields:
        f_top = min(cy - FIELD_H / 2, prev + GAP)  # close any gap with the previous field
        svg.rect(x + 4, f_top, w - 8, cy + FIELD_H / 2 - f_top, fill, rx=6)
        svg.text(x + w / 2, cy - 3, name, 16, fill=ink, weight=600)
        svg.text(x + w / 2, cy + 18, value, 14, fill=ink, family=MONO, opacity=0.8)
        prev = cy + FIELD_H / 2


# --------------------------------------------------------------------------- diagrams

def ipv4_diagram():
    gx, gy = 60, 84
    hdr = SYN_IP[:20]
    h = lambda a, b: hexs(hdr[a:b])  # noqa: E731
    rows = [
        ("fields", [(0, 1, "Ver · IHL", h(0, 1), False), (1, 1, "DSCP · ECN", h(1, 2), False),
                    (2, 2, "Total length", h(2, 4), False)]),
        ("fields", [(0, 2, "Identification", h(4, 6), False), (2, 2, "Flags · offset", h(6, 8), False)]),
        ("fields", [(0, 1, "TTL", h(8, 9), False), (1, 1, "Protocol", h(9, 10), True),
                    (2, 2, "Header checksum", h(10, 12), False)]),
        ("fields", [(0, 4, "Source address", h(12, 16), False)]),
        ("fields", [(0, 4, "Destination address", h(16, 20), False)]),
        ("bytes", hexs(SYN_IP[20:24]), "Payload · TCP segment", BLUE),
        ("bytes", hexs(SYN_IP[24:28]), None, BLUE),
        ("ellipsis", f"… {len(SYN_IP) - 28} more bytes, up to Total length ({len(SYN_IP)})", BLUE, 40),
    ]
    height = gy + 5 * RH + 2 * RH + 40 + 34
    svg = Svg(height, "From IPv4 bytes to the Internet struct",
              "A 60-byte IPv4 packet drawn 32 bits per row. The Protocol byte 06 becomes payload_protocol "
              "Some(Tcp), the source and destination address words become source 192.168.0.104 and "
              "destination 192.168.0.1, and the 40 bytes after the 20-byte header become payload.")
    svg.text(gx, gy - 20, "IPv4 packet", 22, weight=600, anchor="start")
    svg.text(gx + 4 * CW, gy - 20, "32 bits per row", 14, anchor="end", opacity=0.55)
    ys, _ = byte_grid(svg, gx, gy, rows, BLUE_LIGHT, BLUE)
    right = gx + 4 * CW
    svg.outline(gx + CW, ys[2], CW, RH)
    svg.outline(gx, ys[3], 4 * CW, RH)
    svg.outline(gx, ys[4], 4 * CW, RH)

    sx = 610
    proto_y, src_y, dst_y, pay_y = ys[2] + ARROW_DY, ys[3] + RH / 2, ys[4] + RH / 2, ys[5] + RH / 2
    struct_box(svg, sx, 240, "Internet", [
        ("payload_protocol", "Some(Tcp)", ORANGE, DARK, proto_y),
        ("source", "192.168.0.104", BLUE_LIGHT, DARK, src_y),
        ("destination", "192.168.0.1", BLUE_LIGHT, DARK, dst_y),
        ("payload", "&amp;[u8] · 40 bytes", BLUE, WHITE, pay_y),
    ])
    svg.arrow([(sx - 12, proto_y), (gx + 2 * CW + 8, proto_y)], ORANGE_DARK)
    for y, color in ((src_y, GREY), (dst_y, GREY), (pay_y, ARROW_DARK)):
        svg.arrow([(sx - 12, y), (right + 10, y)], color)
    svg.save("network/ipv4_struct.svg")


def tcp_diagram():
    gx, gy = 60, 230
    seg = SYN_TCP
    h = lambda a, b: hexs(seg[a:b])  # noqa: E731
    header_len = (seg[12] >> 4) * 4
    rows = [
        ("fields", [(0, 2, "Source port", h(0, 2), True), (2, 2, "Destination port", h(2, 4), True)]),
        ("fields", [(0, 4, "Sequence number", h(4, 8), False)]),
        ("fields", [(0, 4, "Acknowledgment number", h(8, 12), False)]),
        ("fields", [(0, 1, "Offset · Rsv", h(12, 13), False), (1, 1, "Flags", h(13, 14), False),
                    (2, 2, "Window", h(14, 16), False)]),
        ("fields", [(0, 2, "Checksum", h(16, 18), False), (2, 2, "Urgent pointer", h(18, 20), False)]),
        ("bytes", h(20, 24), "Options", GREEN_LIGHT),
        ("ellipsis", f"… {header_len - 24} more option bytes, up to Offset × 4 = {header_len}", GREEN_LIGHT, 40),
    ]
    grid_bottom = gy + 6 * RH + 40
    pay_top = grid_bottom + 18
    pay_h = 48
    height = pay_top + pay_h + 34
    svg = Svg(height, "From TCP bytes to the Transport struct",
              "The 40-byte TCP SYN carried by the IPv4 packet of the previous diagram, 32 bits per row. "
              "The two port fields become source_port 54321 and destination_port 80, the Flags byte 02 is "
              "SYN, the data offset A says the header is 40 bytes long with its options, and the payload "
              "after it is empty.")
    svg.text(gx, 84, "TCP segment", 22, weight=600, anchor="start")
    svg.text(gx, 110, "the payload of the IPv4 packet · 32 bits per row", 14, anchor="start", opacity=0.55)
    ys, _ = byte_grid(svg, gx, gy, rows, GREEN_LIGHT, GREEN)
    right = gx + 4 * CW
    svg.outline(gx, ys[0], 2 * CW, RH)
    svg.outline(gx + 2 * CW, ys[0], 2 * CW, RH)
    svg.outline(gx + CW, ys[3], CW, RH)
    # empty payload, after the header
    svg.rect(gx, pay_top, 4 * CW, pay_h, "none", rx=10, stroke=GREEN, sw=2.5, dash="7 6")
    svg.text(gx + 2 * CW, pay_top + 30, "payload: nothing, a SYN carries no data", 14, opacity=0.7, weight=500)

    sx, sw = 610, 240
    src_y = gy - 30
    dst_y = ys[0] + RH / 2
    flags_y = ys[3] + ARROW_DY
    det_y, pay_y = dst_y + 60, dst_y + 120
    struct_box(svg, sx, sw, "Transport", [
        ("protocol", "Tcp, from the IP header", GREEN_LIGHT, DARK, src_y - 60),
        ("source_port", "Some(54321)", ORANGE, DARK, src_y),
        ("destination_port", "Some(80)", ORANGE, DARK, dst_y),
        ("details", "Some(Tcp(..)) · SYN", GREEN_LIGHT, DARK, det_y),
        ("payload", "Some(&amp;[]) · empty", GREEN, DARK, pay_y),
    ])
    svg.arrow([(sx - 12, src_y), (gx + CW, src_y), (gx + CW, gy - 8)], ORANGE_DARK)
    svg.arrow([(sx - 12, dst_y), (right + 10, dst_y)], ORANGE_DARK)
    svg.arrow([(sx - 12, det_y), (right + 46, det_y), (right + 46, flags_y), (gx + 2 * CW + 8, flags_y)], GREY)
    svg.arrow([(sx - 12, pay_y), (right + 86, pay_y), (right + 86, pay_top + pay_h / 2),
               (right + 10, pay_top + pay_h / 2)], ARROW_DARK)
    svg.save("transport/tcp_struct.svg")


def tunnel_diagram():
    # (label, length, fill, ink) for each header of the wire packet
    parts = [("Ethernet", 14, GREY, WHITE), ("IPv4", 20, BLUE, WHITE), ("UDP", 8, GREEN, DARK),
             ("VXLAN", 8, YELLOW, DARK), ("Ethernet", 14, GREY, WHITE), ("IPv4", 20, BLUE, WHITE),
             ("TCP SYN", 40, GREEN, DARK)]
    assert sum(p[1] for p in parts) == len(VXLAN_PACKET)
    x0, x1, sy, sh = 60, 840, 92, 58
    narrow = 66  # UDP and VXLAN are drawn wider than their 8 bytes, so that their name fits
    scale = (x1 - x0 - 2 * narrow) / (len(VXLAN_PACKET) - 16)
    height = 780
    svg = Svg(height, "A VXLAN packet parsed into two PacketFlow levels",
              "One 124-byte wire packet: Ethernet, IPv4 10.0.0.1 to 10.0.0.2, UDP 51234 to 4789, VXLAN, then "
              "a full inner Ethernet frame carrying the TCP SYN of the previous chapters. The outer PacketFlow "
              "reads the first four headers and is labelled VXLAN; its inner field holds a second PacketFlow "
              "for the encapsulated frame. flatten() returns both, outermost first.")
    svg.text(x0, 64, "One wire packet, two flows", 22, weight=600, anchor="start")
    svg.text(x1, 64, f"{len(VXLAN_PACKET)} bytes", 14, anchor="end", opacity=0.55)
    svg.add(f'<clipPath id="s"><rect x="{x0}" y="{sy}" width="{x1 - x0}" height="{sh}" rx="10"/></clipPath>')
    svg.add('<g clip-path="url(#s)">')
    x, edges = x0, [x0]
    for label, n, fill, ink in parts:
        w = narrow if n == 8 else n * scale
        svg.rect(x, sy, w, sh, fill, stroke="#00000033", sw=1)
        svg.text(x + w / 2, sy + 26, label, 15, fill=ink, weight=600)
        svg.text(x + w / 2, sy + 45, f"{n}", 13, fill=ink, opacity=0.8)
        x += w
        edges.append(x)
    svg.add("</g>")
    svg.rect(x0, sy, x1 - x0, sh, "none", rx=10, stroke=DARK, sw=3.5)
    split = edges[4]
    svg.line(split, sy - 8, split, sy + sh + 8, ORANGE_DARK, sw=3, dash="5 4")

    # brackets: which bytes each level reads
    by = sy + sh + 16
    for a, b, label in ((x0, split, "read by the outer flow"), (split, x1, "peeled, parsed again into inner")):
        svg.add(f'<path d="M {a + 4} {by} v 10 H {b - 4} v -10" fill="none" stroke="{DARK}" '
                f'stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/>')
        svg.text((a + b) / 2, by + 32, label, 14, weight=500, opacity=0.7)

    top, rw, rh = 250, 300, FIELD_H
    outer = [("data_link", "Ethernet", GREY_LIGHT, DARK),
             ("internet", "IPv4 10.0.0.1 → 10.0.0.2", BLUE_LIGHT, DARK),
             ("transport", "UDP 51234 → 4789", GREEN_LIGHT, DARK),
             ("application", "\"VXLAN\"", YELLOW, DARK),
             ("inner", "Some(Box&lt;PacketFlow&gt;)", ORANGE, DARK)]
    inner = [("data_link", "Ethernet (inner frame)", GREY_LIGHT, DARK),
             ("internet", "IPv4 192.168.0.104 → 192.168.0.1", BLUE_LIGHT, DARK),
             ("transport", "TCP 54321 → 80", GREEN_LIGHT, DARK),
             ("application", "None: empty payload", YELLOW_LIGHT, DARK),
             ("inner", "None", GREY_LIGHT, DARK)]

    def flow(x, y, title, fields):
        h = TITLE_H + len(fields) * (rh + GAP) + GAP * 2
        svg.rect(x, y, rw, h, DARK, rx=10)
        svg.text(x + rw / 2, y + GAP + TITLE_H / 2 + 7, title, 20, fill=WHITE, weight=600)
        centers = []
        fy = y + GAP + TITLE_H + GAP
        for name, value, fill, ink in fields:
            svg.rect(x + 4, fy, rw - 8, rh, fill, rx=6)
            svg.text(x + rw / 2, fy + rh / 2 - 3, name, 16, fill=ink, weight=600)
            svg.text(x + rw / 2, fy + rh / 2 + 18, value, 14, fill=ink, family=MONO, opacity=0.8)
            centers.append(fy + rh / 2)
            fy += rh + GAP
        return centers, y + h

    ox, ix = 60, 540
    oc, obottom = flow(ox, top, "PacketFlow", outer)
    itop = top + rh + GAP
    ic, ibottom = flow(ix, itop, "PacketFlow (inner)", inner)
    # bracket → flow
    svg.arrow([((x0 + split) / 2, by + 44), ((x0 + split) / 2, top - 6)], GREY)
    svg.arrow([((split + x1) / 2, by + 44), ((split + x1) / 2, itop - 6)], GREY)
    # inner → the inner flow
    svg.arrow([(ox + rw + 6, oc[4]), (ix - 60, oc[4]), (ix - 60, itop + GAP + TITLE_H / 2),
               (ix - 10, itop + GAP + TITLE_H / 2)], ORANGE_DARK)

    fy = max(obottom, ibottom) + 34
    svg.text(x0, fy, "flow.flatten()", 15, family=MONO, weight=600, anchor="start")
    svg.text(x0 + 160, fy, "→  [ &amp;outer, &amp;inner ]   outermost first, one entry when there is no tunnel",
             14, family=MONO, anchor="start", opacity=0.75)
    svg.text(x0, fy + 26, "Nesting stops at MAX_TUNNEL_DEPTH = 4 levels.", 14, anchor="start", opacity=0.6)
    svg.h = fy + 50
    svg.out[0] = svg.out[0].replace(f'0 0 {W} {height}"', f'0 0 {W} {svg.h}"').replace(
        f'height="{height}"', f'height="{svg.h}"')
    svg.out[3] = svg.out[3].replace(f'height="{height - 24}"', f'height="{svg.h - 24}"')
    svg.save("tunnels/vxlan_flows.svg")


def dispatch_diagram():
    height = 470
    svg = Svg(height, "How one rule of the dispatch table labels a payload",
              "The transport payload, here a TLS ClientHello on TCP 54322 to 443, goes through the rules of "
              "the table in order. Each rule has three gates: the transport guard, the port guard, then the "
              "content probe, run at most once per payload. The first rule whose three gates pass gives the "
              "label, TLS here. A failed gate moves on to the next rule; after the last one the label is "
              "Unknown. An empty payload is not probed and application stays None.")
    svg.text(60, 62, "One rule of the table", 22, weight=600, anchor="start")
    svg.text(60, 88, "RULES are tried in order, the first match wins. Decode As ports go first, through the "
             "same gates.", 14, anchor="start", opacity=0.6)

    cy = 216
    # input
    bx, bw, bh = 40, 160, 104
    svg.rect(bx, cy - bh / 2, bw, bh, GREY, rx=8)
    svg.text(bx + bw / 2, cy - 22, "transport payload", 15, fill=WHITE, weight=600)
    svg.text(bx + bw / 2, cy + 4, "TCP 54322 → 443", 13, fill=WHITE, family=MONO, opacity=0.9)
    svg.text(bx + bw / 2, cy + 28, hexs(TLS_RECORD[:5]), 13, fill=WHITE, family=MONO, opacity=0.9)

    gates = [(316, "transport", "guard", ("Tcp, Udp or Any,", "as the RFC allows")),
             (486, "port", "guard", ("port AND content,", "never the port alone")),
             (656, "content", "probe", ("once per payload,", "at most 18 KiB read"))]
    r = 56
    for x, l1, l2, (n1, n2) in gates:
        svg.add(f'<path d="M {x} {cy - r} L {x + r} {cy} L {x} {cy + r} L {x - r} {cy} Z" fill="{BLUE}" '
                f'stroke="{BLUE}" stroke-width="8" stroke-linejoin="round"/>')
        svg.text(x, cy - 3, l1, 15, fill=WHITE, weight=600)
        svg.text(x, cy + 16, l2, 15, fill=WHITE, weight=600)
        svg.text(x, cy - r - 30, n1, 13, opacity=0.7, weight=500)
        svg.text(x, cy - r - 13, n2, 13, opacity=0.7)

    loop_x, bus_y = 222, cy + r + 66
    svg.arrow([(bx + bw + 6, cy), (gates[0][0] - r - 12, cy)], GREY)
    for (xa, *_), (xb, *_) in zip(gates, gates[1:]):
        svg.arrow([(xa + r + 10, cy), (xb - r - 12, cy)], SUCCESS)
        svg.text((xa + r + xb - r) / 2, cy - 16, "yes", 13, fill=SUCCESS, weight=600)
    # match → label
    lx, lw, lh = 752, 118, 84
    svg.arrow([(gates[-1][0] + r + 10, cy), (lx - 10, cy)], SUCCESS)
    svg.text((gates[-1][0] + r + lx) / 2, cy - 16, "yes", 13, fill=SUCCESS, weight=600)
    svg.rect(lx, cy - lh / 2, lw, lh, YELLOW, rx=8)
    svg.text(lx + lw / 2, cy + 2, "\"TLS\"", 22, weight=700)
    svg.text(lx + lw / 2, cy + 24, "the label", 13, opacity=0.65)

    # no → next rule
    for i, (x, *_) in enumerate(gates):
        svg.line(x, cy + r + 10, x, bus_y, GREY, sw=3.5)
        svg.text(x + 10, cy + r + 34, "no, failure memoized" if i == 2 else "no", 13, fill=GREY,
                 weight=600, anchor="start")
    svg.arrow([(gates[-1][0], bus_y), (loop_x, bus_y), (loop_x, cy), (loop_x + 16, cy)], GREY, head=False)
    svg.text((gates[0][0] + gates[-1][0]) / 2, bus_y + 22, "next rule", 14, fill=GREY, weight=600)

    # outcomes without a label from a rule
    oy, oh = bus_y + 52, 52
    svg.arrow([(bx + bw / 2, cy + bh / 2 + 6), (bx + bw / 2, oy - 10)], GREY)
    svg.text(bx + bw / 2 + 10, cy + bh / 2 + 40, "empty", 13, fill=GREY, weight=600, anchor="start")
    svg.rect(bx, oy, bw, oh, GREY_LIGHT, rx=8)
    svg.text(bx + bw / 2, oy + 22, "None", 16, weight=700, family=MONO)
    svg.text(bx + bw / 2, oy + 41, "not probed", 13, opacity=0.65)
    ux = loop_x + 28
    svg.arrow([(loop_x, bus_y), (loop_x, oy + oh / 2), (ux - 10, oy + oh / 2)], GREY)
    svg.text(loop_x + 10, bus_y + 40, "no rule left", 13, fill=GREY, weight=600, anchor="start")
    svg.rect(ux, oy, 190, oh, YELLOW_LIGHT, rx=8)
    svg.text(ux + 95, oy + 22, "\"Unknown\"", 16, weight=700, family=MONO)
    svg.text(ux + 95, oy + 41, "after the last rule", 13, opacity=0.65)
    svg.save("application/dispatch_rule.svg")


def span_struct(svg, x, w, title, fields):
    """Struct whose fields cover explicit spans: [(name, value, fill, ink, top, bottom)]."""
    top = fields[0][4] - GAP - TITLE_H - GAP
    svg.rect(x, top, w, fields[-1][5] + GAP - top, DARK, rx=10)
    svg.text(x + w / 2, top + GAP + TITLE_H / 2 + 7, title, 20, fill=WHITE, weight=600)
    for name, value, fill, ink, f_top, f_bottom in fields:
        cy = (f_top + f_bottom) / 2
        svg.rect(x + 4, f_top + GAP / 2, w - 8, f_bottom - f_top - GAP, fill, rx=6)
        svg.text(x + w / 2, cy - 3, name, 16, fill=ink, weight=600)
        svg.text(x + w / 2, cy + 18, value, 14, fill=ink, family=MONO, opacity=0.8)


def outcomes_diagram():
    height = 590
    svg = Svg(height, "The outcomes of parse",
              "parse returns Err only when the link layer fails: an unsupported LINKTYPE or a truncated link "
              "header. Otherwise it returns a PacketFlow, in one of four shapes: every layer decoded (a TCP "
              "pure ACK, no application); an unsupported protocol above the link layer, the upper layers None "
              "and nothing corrupted (LLDP); a recognized layer with invalid bytes, None and reported in "
              "corrupted (an IPv4 header cut after 6 bytes); a readable header no conforming stack sends, kept "
              "and reported (TCP with SYN and FIN).")
    svg.text(40, 62, "What parse returns", 22, weight=600, anchor="start")
    svg.text(40, 88, "Only the link layer can fail the parse. Above it, a layer is decoded, absent, or reported.",
             14, anchor="start", opacity=0.6)
    # parse → Err
    px, py, pw, ph = 250, 116, 320, 56
    svg.rect(px, py, pw, ph, GREY, rx=8)
    svg.text(px + pw / 2, py + ph / 2 + 6, "parse(link_type, bytes)", 17, fill=WHITE, family=MONO, weight=600)
    ex, ew = 680, 180
    svg.rect(ex, py - 10, ew, ph + 20, RED, rx=8)
    svg.text(ex + ew / 2, py + 16, "Err(ParseError)", 16, fill=WHITE, weight=700, family=MONO)
    svg.text(ex + ew / 2, py + 38, "unsupported LINKTYPE", 13, fill=WHITE, opacity=0.95)
    svg.text(ex + ew / 2, py + 56, "truncated link header", 13, fill=WHITE, opacity=0.95)
    svg.arrow([(px + pw + 6, py + ph / 2), (ex - 10, py + ph / 2)], RED)
    svg.text((px + pw + ex) / 2, py + ph / 2 - 12, "link layer", 13, fill=RED, weight=600)

    cw, gap, cx0, ctop = 196, 12, 40, 262
    centers = [cx0 + i * (cw + gap) + cw / 2 for i in range(4)]
    bus = ctop - 34
    svg.add(f'<path d="M {px + pw / 2} {py + ph + 6} V {bus} M {centers[0]} {bus} H {centers[-1]}" fill="none" '
            f'stroke="{SUCCESS}" stroke-width="3.5" stroke-linecap="round"/>')
    svg.text(px + pw / 2 + 12, py + ph + 30, "Ok(PacketFlow)", 14, fill=SUCCESS, weight=700, family=MONO,
             anchor="start")
    for c in centers:
        svg.arrow([(c, bus), (c, ctop - 8)], SUCCESS)

    filled = lambda name, value, fill, ink=DARK: (name, value, fill, ink)  # noqa: E731
    none = lambda name, why="None": (name, why, NONE_FILL, "#E6E6E6")  # noqa: E731
    cards = [
        ("Decoded", "a TCP pure ACK", [
            filled("data_link", "Ethernet", GREY_LIGHT), filled("internet", "IPv4", BLUE_LIGHT),
            filled("transport", "TCP 443 → 49416", GREEN_LIGHT), none("application", "None: empty payload"),
            none("corrupted")]),
        ("Not supported", "EtherType 0x88CC (LLDP)", [
            filled("data_link", "Ethernet", GREY_LIGHT), none("internet"), none("transport"),
            none("application"), none("corrupted")]),
        ("Corrupted", "IPv4 cut after 6 bytes", [
            filled("data_link", "Ethernet", GREY_LIGHT), none("internet"), none("transport"),
            none("application"), filled("corrupted", "Internet: IPv4 error", RED, WHITE)]),
        ("Anomaly", "TCP with SYN and FIN", [
            filled("data_link", "Ethernet", GREY_LIGHT), filled("internet", "IPv4", BLUE_LIGHT),
            filled("transport", "TCP 54321 → 80", GREEN_LIGHT), none("application", "None: not probed"),
            filled("corrupted", "Transport: SYN+FIN", RED, WHITE)]),
    ]
    rh, th = 46, 54
    for i, (title, example, rows) in enumerate(cards):
        x = cx0 + i * (cw + gap)
        h = th + len(rows) * (rh + GAP) + GAP
        svg.rect(x, ctop, cw, h, DARK, rx=10)
        svg.text(x + cw / 2, ctop + 24, title, 17, fill=WHITE, weight=600)
        svg.text(x + cw / 2, ctop + 43, example, 12.5, fill=WHITE, opacity=0.7)
        fy = ctop + th
        for name, value, fill, ink in rows:
            svg.rect(x + 4, fy, cw - 8, rh, fill, rx=6)
            svg.text(x + cw / 2, fy + 18, name, 12.5, fill=ink, weight=600, opacity=0.75)
            svg.text(x + cw / 2, fy + 36, value, 13, fill=ink, family=MONO)
            fy += rh + GAP
    svg.save("getting_started/parse_outcomes.svg")


def giop_header_diagram():
    gx, gy = 60, 120
    hdr = GIOP_FRAME19_HEADER
    h = lambda a, b: hexs(hdr[a:b])  # noqa: E731
    size = int.from_bytes(hdr[8:12], "little")
    wrong = int.from_bytes(hdr[8:12], "big")
    rows = [
        ("fields", [(0, 4, 'Magic "GIOP"', h(0, 4), False)]),
        ("fields", [(0, 1, "Major", h(4, 5), False), (1, 1, "Minor", h(5, 6), False),
                    (2, 1, "Flags", h(6, 7), True), (3, 1, "Type", h(7, 8), False)]),
        ("fields", [(0, 4, "Message size", h(8, 12), False)]),
        ("ellipsis", f"CDR body: {size} bytes, in the same byte order", YELLOW, 40),
    ]
    height = 456
    svg = Svg(height, "The GIOP header, and why the byte order matters",
              "The 12-byte GIOP header of frame 19 of corba.pcap, a little-endian Request inside a MIOP "
              "datagram: magic GIOP, version 1.2, flags 01, type 0 (Request), message size D8 00 00 00. Bit 0 of "
              f"the flags says little-endian, so the size is {size} bytes. Read big-endian, as the first version "
              f"of the parser did, the same bytes say {wrong} and the message was rejected.")
    svg.text(gx, 62, "GIOP header", 22, weight=600, anchor="start")
    svg.text(gx, 88, "frame 19 of corba.pcap: a Request inside a MIOP datagram · 32 bits per row", 14,
             anchor="start", opacity=0.55)
    ys, bottom = byte_grid(svg, gx, gy, rows, YELLOW_LIGHT, YELLOW, strong_ink=DARK)
    right = gx + 4 * CW
    svg.outline(gx + 2 * CW, ys[1], CW, RH)
    svg.outline(gx, ys[2], 4 * CW, RH)

    bx, bw, bh = 570, 290, 96
    ok_cy = ys[1] + ARROW_DY + 10
    bad_cy = ys[2] + RH + 64
    svg.rect(bx, ok_cy - bh / 2, bw, bh, GREEN, rx=8)
    svg.text(bx + bw / 2, ok_cy - 14, f"{size} bytes", 20, weight=700)
    svg.text(bx + bw / 2, ok_cy + 8, "little-endian, as Flags bit 0 says", 13.5, opacity=0.8)
    svg.text(bx + bw / 2, ok_cy + 30, f"0x{size:08X}", 14, family=MONO, opacity=0.8)
    svg.rect(bx, bad_cy - bh / 2, bw, bh, RED, rx=8)
    svg.text(bx + bw / 2, bad_cy - 14, f"{wrong:,} bytes".replace(",", " "), 20, fill=WHITE, weight=700)
    svg.text(bx + bw / 2, bad_cy + 8, "big-endian, as the first version read it", 13.5, fill=WHITE, opacity=0.9)
    svg.text(bx + bw / 2, bad_cy + 30, f"0x{wrong:08X}: rejected", 14, fill=WHITE, family=MONO, opacity=0.9)
    # Flags decide how the size is read
    svg.arrow([(gx + 3 * CW - 4, ys[1] + ARROW_DY), (bx - 10, ys[1] + ARROW_DY)], ORANGE_DARK)
    fork = right + 50
    size_y = ys[2] + RH / 2
    svg.arrow([(right + 6, size_y), (fork, size_y), (fork, ok_cy + 26), (bx - 10, ok_cy + 26)], GREY)
    svg.arrow([(right + 6, size_y), (fork, size_y), (fork, bad_cy), (bx - 10, bad_cy)], GREY)
    svg.save("giop/giop_header.svg")


def giop_cdr_diagram():
    gx, gy = 60, 120
    body = GIOP_FRAME4[12:]
    h = lambda a, b: hexs(body[a:b])  # noqa: E731
    key_len = int.from_bytes(body[12:16], "big")
    op_at = 16 + key_len
    op_len = int.from_bytes(body[op_at:op_at + 4], "big")
    assert body[op_at + 4:op_at + 4 + op_len] == b"echo\0"
    pad_at = op_at + 4 + op_len
    ctx_at = pad_at + (-(op_at + 4 + op_len)) % 4
    rows = [
        ("fields", [(0, 4, "request_id · ulong", h(0, 4), False)]),
        ("fields", [(0, 1, "flags", h(4, 5), False), (1, 3, "reserved", h(5, 8), False)]),
        ("fields", [(0, 2, "Target · short", h(8, 10), True), (2, 2, "padding to 4", h(10, 12), HATCH)]),
        ("fields", [(0, 4, "object key length · ulong", h(12, 16), False)]),
        ("ellipsis", f"{key_len} bytes of object key", YELLOW_LIGHT, 40),
        ("fields", [(0, 4, "operation length · ulong", h(op_at, op_at + 4), False)]),
        ("fields", [(0, 4, '"echo"', h(op_at + 4, op_at + 8), False)]),
        ("fields", [(0, 1, "NUL", h(op_at + 8, op_at + 9), False),
                    (1, 3, "padding to 4", h(pad_at, ctx_at), HATCH)]),
        ("fields", [(0, 4, "service context count · ulong", h(ctx_at, ctx_at + 4), False)]),
        ("ellipsis", "… a 40-byte context, then 76 bytes of stub data", YELLOW_LIGHT, RH),
    ]
    height = gy + 9 * RH + 40 + 76
    svg = Svg(height, "The CDR body of a GIOP 1.2 Request",
              "The body of frame 4 of corba.pcap, a big-endian GIOP 1.2 Request, 32 bits per row. CDR aligns "
              "every primitive on its size: the 2-byte Target discriminant is followed by 2 bytes of padding "
              "before the object key length, and the operation name echo with its NUL is followed by 3 bytes "
              "of padding before the service context count. The GiopRequest fields come out as request_id 0, "
              "response_flags 3, target KeyAddr of 60 bytes, operation echo, one service context and 76 bytes "
              "of stub data.")
    svg.define_hatch()
    svg.text(gx, 62, "GIOP 1.2 Request body", 22, weight=600, anchor="start")
    svg.text(gx, 88, "frame 4 of corba.pcap · big-endian CDR, 32 bits per row", 14, anchor="start", opacity=0.55)
    ys, bottom = byte_grid(svg, gx, gy, rows, YELLOW_LIGHT, YELLOW, strong_ink=DARK)
    right = gx + 4 * CW
    svg.outline(gx, ys[2], 2 * CW, RH)
    # legend
    svg.rect(gx, bottom + 22, 34, 22, HATCH, rx=4, stroke="#E9CF86")
    svg.text(gx + 46, bottom + 38, "padding: CDR aligns each primitive on its own size", 14, anchor="start",
             opacity=0.7)

    sx, sw = 610, 240
    fields = [
        ("request_id", "0", YELLOW_LIGHT, DARK, ys[0], ys[1]),
        ("response_flags", "3", YELLOW_LIGHT, DARK, ys[1], ys[2]),
        ("target", f"KeyAddr({key_len} bytes)", ORANGE, DARK, ys[2], ys[5]),
        ("operation", '"echo"', YELLOW_LIGHT, DARK, ys[5], ys[8]),
        ("service_contexts", "1 entry, id 7", YELLOW_LIGHT, DARK, ys[8], ys[9]),
        ("stub_data", "76 bytes", YELLOW, DARK, ys[9], bottom),
    ]
    span_struct(svg, sx, sw, "GiopRequest", fields)
    svg.arrow([(sx - 12, ys[0] + RH / 2), (right + 10, ys[0] + RH / 2)], GREY)
    svg.arrow([(sx - 12, ys[1] + ARROW_DY), (gx + CW + 8, ys[1] + ARROW_DY)], GREY)
    svg.arrow([(sx - 12, ys[2] + ARROW_DY), (gx + 2 * CW + 8, ys[2] + ARROW_DY)], ORANGE_DARK)
    svg.arrow([(sx - 12, ys[6] + RH / 2), (right + 10, ys[6] + RH / 2)], GREY)
    svg.arrow([(sx - 12, ys[8] + RH / 2), (right + 10, ys[8] + RH / 2)], GREY)
    svg.arrow([(sx - 12, ys[9] + RH / 2), (right + 10, ys[9] + RH / 2)], ARROW_DARK)
    svg.save("giop/giop_cdr.svg")


def tryfrom_diagram():
    height = 640
    svg = Svg(height, "The shape of a parser: one TryFrom, one straight line",
              "FooPacket, the example of the chapter, on synthetic bytes 10 01 00 08 DE AD BE EF. The TryFrom "
              "runs a length pre-check, then one extract per constrained field in wire order, then the "
              "cross-field checks, and builds the struct: version 1, message type 1, length 8, a 4-byte "
              "payload. Each step can return a typed FooError. Below, the files each part lives in.")
    svg.text(40, 62, "One TryFrom, one straight line", 22, weight=600, anchor="start")
    svg.text(40, 88, "FooPacket, the example of this chapter, on synthetic bytes", 14, anchor="start", opacity=0.55)
    cy = 214
    bx, bw, bh = 40, 130, 96
    svg.rect(bx, cy - bh / 2, bw, bh, GREY, rx=8)
    svg.text(bx + bw / 2, cy - 18, "packet: &amp;[u8]", 15, fill=WHITE, weight=600)
    svg.text(bx + bw / 2, cy + 6, "10 01 00 08", 14, fill=WHITE, family=MONO, opacity=0.9)
    svg.text(bx + bw / 2, cy + 28, "DE AD BE EF", 14, fill=WHITE, family=MONO, opacity=0.9)
    steps = [(280, "length", "pre-check", "validate_foo_min_length", "too short"),
             (442, "extract_*", "per field", "extract_foo_version", "bad version"),
             (604, "cross-field", "checks", "validate_foo_announced_length", "length ≠ announced")]
    r = 52
    for i, (x, l1, l2, fn, err) in enumerate(steps):
        svg.add(f'<path d="M {x} {cy - r} L {x + r} {cy} L {x} {cy + r} L {x - r} {cy} Z" fill="{BLUE}" '
                f'stroke="{BLUE}" stroke-width="8" stroke-linejoin="round"/>')
        svg.text(x, cy - 3, l1, 14.5, fill=WHITE, weight=600)
        svg.text(x, cy + 15, l2, 14.5, fill=WHITE, weight=600)
        # function names are staggered: side by side they would touch
        svg.text(x, cy - r - (34 if i == 1 else 14), fn, 12, family=MONO, opacity=0.7)
    svg.arrow([(bx + bw + 6, cy), (steps[0][0] - r - 12, cy)], GREY)
    for (xa, *_), (xb, *_) in zip(steps, steps[1:]):
        svg.arrow([(xa + r + 10, cy), (xb - r - 12, cy)], SUCCESS)
    ox, ow, oh = 714, 146, 124
    svg.arrow([(steps[-1][0] + r + 10, cy), (ox - 10, cy)], SUCCESS)
    svg.rect(ox, cy - oh / 2, ow, oh, GREEN, rx=8)
    svg.text(ox + ow / 2, cy - 36, "Ok(FooPacket)", 14.5, weight=700, family=MONO)
    for k, line in enumerate(("version: 1", "message_type: 1", "length: 8", "payload: 4 bytes")):
        svg.text(ox + 12, cy - 11 + k * 19, line, 13, family=MONO, anchor="start", opacity=0.85)
    # errors
    ey, eh = cy + r + 64, 62
    for x, *_, err in steps:
        svg.arrow([(x, cy + r + 10), (x, ey - 10)], RED)
        svg.text(x + 10, cy + r + 38, err, 13, fill=RED, weight=600, anchor="start")
    svg.rect(200, ey, 520, eh, RED, rx=8)
    svg.text(460, ey + 25, "Err(FooError)", 16, fill=WHITE, weight=700, family=MONO)
    svg.text(460, ey + 46, "typed, with the offending values: InvalidLength { expected: 8, actual: 3 }", 13,
             fill=WHITE, opacity=0.95)
    # files
    fy0 = ey + eh + 40
    svg.text(40, fy0, "Where each part lives", 15, weight=600, anchor="start")
    files = [(BLUE, WHITE, "src/checks/application/foo.rs", "validate_* and extract_*"),
             (RED, WHITE, "src/errors/application/foo.rs", "enum FooError, with thiserror"),
             (GREEN, DARK, "src/parse/application/protocols/foo.rs", "FooPacket and its TryFrom"),
             (YELLOW, DARK, "src/parse/dispatch.rs", "a ProbeId and one line in RULES"),
             (GREY, WHITE, "pcaps_exemple/protocols/foo/", "a real capture and its SOURCE.md")]
    for i, (fill, ink, path, what) in enumerate(files):
        x = 40 + (i % 2) * 414
        y = fy0 + 16 + (i // 2) * 52
        svg.rect(x, y, 22, 40, fill, rx=5)
        svg.text(x + 34, y + 17, path, 13.5, family=MONO, weight=600, anchor="start")
        svg.text(x + 34, y + 35, what, 13, anchor="start", opacity=0.65)
    svg.save("adding_a_protocol/tryfrom_line.svg")


def engine_diagram():
    cx, bw = 405, 330
    bx = cx - bw / 2
    ox, ow = 626, 244
    loop_x = 196
    gap = 30
    # (key, height) of each stage, top to bottom
    layout = [("parse", 48), ("select", 48), ("decode", 56), ("decoded", 56), ("l3", 56), ("l4", 56),
              ("anomaly", 76), ("l7", 146), ("flow", 78)]
    ys, y = {}, 112
    for key, h in layout:
        ys[key] = (y, h)
        y += h + gap
    height = y - gap + 40
    svg = Svg(height, "The parsing engine",
              "parse selects a link decoder from the LINKTYPE, and returns Err only when there is none or when "
              "it fails. The decoder produces a DecodedLink: the link layer, the announced network protocol and "
              "the L3 bytes. From there one pipeline runs for every format: the internet layer, then the "
              "transport layer, each of them None when nothing is announced and reported in corrupted when its "
              "bytes are invalid. An anomalous TCP segment leaves on a cold path: transport kept, reported, no "
              "application. Otherwise the application stage looks for an IP-level tunnel, then a UDP tunnel, "
              "then runs the dispatch table, and labels STP from the link layer last. A tunnel sends its inner "
              "packet back to DecodedLink one level deeper, at most four levels. The timing counters l2_ns to "
              "l7_ns cover the stages they are drawn on.")
    svg.text(40, 62, "The parsing engine", 22, weight=600, anchor="start")
    svg.text(40, 88, "One pipeline for every LINKTYPE, run again for each tunnel level.", 14, anchor="start",
             opacity=0.6)

    def box(key, fill, ink, title, sub=None, badge=None, mono=False):
        y, h = ys[key]
        svg.rect(bx, y, bw, h, fill, rx=8)
        ty = y + h / 2 - 4 if sub else y + h / 2 + 6
        svg.text(cx, ty, title, 16, fill=ink, weight=600, family=MONO if mono else SANS)
        if sub:
            svg.text(cx, y + h / 2 + 16, sub, 13, fill=ink, opacity=0.85)
        if badge:
            svg.text(bx + bw - 10, y + 15, badge, 11.5, fill=ink, family=MONO, anchor="end", opacity=0.65)

    def mid(key):
        y, h = ys[key]
        return y + h / 2

    def down(a, b, color=GREY, label=None):
        ya = ys[a][0] + ys[a][1]
        svg.arrow([(cx, ya + 6), (cx, ys[b][0] - 8)], color)
        if label:
            svg.text(cx + 10, ya + 21, label, 12.5, fill=color, weight=600, anchor="start")

    def side(key, fill, ink, lines, label=None, color=GREY):
        y = mid(key)
        h = 22 + 20 * len(lines)
        svg.rect(ox, y - h / 2, ow, h, fill, rx=8, stroke=None if fill != WHITE else "#E9C9A6")
        for k, (text_, tint) in enumerate(lines):
            # a coloured card has a title line; a white one lists equal cases
            svg.text(ox + ow / 2, y - h / 2 + 26 + 20 * k, text_, 12.5 if fill != WHITE else 11.5, fill=tint or ink,
                     weight=600 if k == 0 and fill != WHITE else 400,
                     family=MONO if text_.startswith("Err") else SANS)
        svg.arrow([(bx + bw + 6, y), (ox - 10, y)], color)
        if label:
            svg.text((bx + bw + ox) / 2 - 4, y - 14, label, 12, fill=color, weight=600)

    box("parse", GREY, WHITE, "parse(link_type, bytes)", mono=True)
    box("select", GREY_LIGHT, DARK, "decoder_for(link_type)", mono=True)
    box("decode", GREY, WHITE, "link decoder", "Ethernet · NULL · RAW · SLL · SLL2 · 802.3br", "l2_ns")
    box("decoded", DARK, WHITE, "DecodedLink", "LinkLayer · NetworkProtocol · L3 bytes")
    box("l3", BLUE, WHITE, "internet layer", "Internet::try_from_network_parts", "l3_ns")
    box("l4", GREEN, DARK, "transport layer", "Transport::try_from_parts", "l4_ns")
    # anomaly test, a diamond like the other decisions of the book
    ay, ah = ys["anomaly"]
    r = ah / 2
    svg.add(f'<path d="M {cx} {ay} L {cx + r + 30} {ay + r} L {cx} {ay + ah} L {cx - r - 30} {ay + r} Z" '
            f'fill="{BLUE}" stroke="{BLUE}" stroke-width="6" stroke-linejoin="round"/>')
    svg.text(cx, ay + r - 2, "TCP", 13.5, fill=WHITE, weight=600)
    svg.text(cx, ay + r + 15, "anomaly?", 13.5, fill=WHITE, weight=600)
    ly, lh = ys["l7"]
    svg.rect(bx, ly, bw, lh, YELLOW, rx=8)
    svg.text(cx, ly + 25, "application, in this order", 16, weight=600)
    svg.text(bx + bw - 10, ly + 15, "l7_ns", 11.5, family=MONO, anchor="end", opacity=0.65)
    steps = ["1   IP tunnel: GRE, IP-in-IP", "2   UDP tunnel: CAPWAP, VXLAN, Geneve, GTP-U",
             "3   Decode As, then RULES, else \"Unknown\"", "4   still no label: STP, from the link layer"]
    for k, line in enumerate(steps):
        svg.text(bx + 16, ly + 54 + 23 * k, line, 12.5, anchor="start", opacity=0.9)
    fy, fh = ys["flow"]
    svg.rect(bx, fy, bw, fh, DARK, rx=10)
    svg.text(cx, fy + 27, "PacketFlow", 18, fill=WHITE, weight=600)
    svg.text(cx, fy + 49, "data_link · internet · transport", 13, fill=WHITE, family=MONO, opacity=0.8)
    svg.text(cx, fy + 67, "application · inner · corrupted", 13, fill=WHITE, family=MONO, opacity=0.8)

    for a, b in (("parse", "select"), ("select", "decode"), ("decode", "decoded"), ("decoded", "l3"),
                 ("l3", "l4"), ("l4", "anomaly")):
        down(a, b)
    down("anomaly", "l7", label="no")
    down("l7", "flow")

    side("select", RED, WHITE, [("Err(UnsupportedLinkType)", None), ("no decoder: no byte is read", None)],
         color=RED)
    side("decode", RED, WHITE, [("Err(InvalidLinkLayer)", None), ("truncated, bad version…", None)], color=RED)
    side("l3", WHITE, DARK, [("unknown protocol → internet: None", None),
                             ("invalid bytes → corrupted: Internet", RED)])
    side("l4", WHITE, DARK, [("nothing announced → transport: None", None),
                             ("invalid bytes → corrupted: Transport", RED)])
    side("anomaly", ORANGE, DARK, [("cold path", None), ("transport kept, reported", None),
                                   ("application: None", None)], "yes", ORANGE_DARK)
    # the cold path returns its PacketFlow directly
    cold_bottom = mid("anomaly") + (22 + 60) / 2
    svg.arrow([(ox + ow / 2, cold_bottom + 6), (ox + ow / 2, mid("flow")), (bx + bw + 10, mid("flow"))],
              ORANGE_DARK)
    # a tunnel runs the same pipeline on the inner packet, one level deeper
    tun_y = ly + 54 + 23 * 0.5
    svg.arrow([(bx - 6, tun_y), (loop_x, tun_y), (loop_x, mid("decoded")), (bx - 10, mid("decoded"))],
              ORANGE_DARK)
    lx = loop_x - 16
    lyc = (tun_y + mid("decoded")) / 2
    svg.add(f'<text x="{lx}" y="{lyc}" font-family="{SANS}" font-size="13.5" font-weight="600" fill="{ORANGE_DARK}" '
            f'text-anchor="middle" transform="rotate(-90 {lx} {lyc})">tunnel: inner = the same pipeline, '
            f'one level deeper</text>')
    svg.add(f'<text x="{lx - 20}" y="{lyc}" font-family="{SANS}" font-size="12.5" fill="{DARK}" fill-opacity="0.6" '
            f'text-anchor="middle" transform="rotate(-90 {lx - 20} {lyc})">at most 4 levels, then classified as '
            f'an ordinary payload</text>')
    svg.save("packet/parsing_engine.svg")



# --------------------------------------------------------------------------- the first chapters
# These replace the original FigJam PNGs: same compositions, current names, real bytes.

LAYER = {  # strong, light, ink on strong
    "link": (GREY, GREY_LIGHT, WHITE), "internet": (BLUE, BLUE_LIGHT, WHITE),
    "transport": (GREEN, GREEN_LIGHT, DARK), "application": (YELLOW, YELLOW_LIGHT, DARK),
    "inner": (ORANGE, "#FFE0C2", DARK), "corrupted": (RED, "#F2C9C9", WHITE),
}
DNS_SPANS = [("link", "Ethernet", 14), ("internet", "IPv4", 20), ("transport", "UDP", 8), ("application", "DNS", 29)]


def frame_layers(spans):
    """Layer key of each byte, from (key, name, length) spans."""
    return [key for key, _, n in spans for _ in range(n)]


def hex_grid(svg, x0, y0, data, cols, cw, ch, fill_of, ink_of, size=17, clip="h", rows=None, text_y=None):
    """A grid of bytes, one per cell; `fill_of(i)`/`ink_of(i)` colour byte i. Returns the bottom y."""
    rows = rows or -(-len(data) // cols)
    w, h = cols * cw, rows * ch
    svg.add(f'<clipPath id="{clip}"><rect x="{x0}" y="{y0}" width="{w}" height="{h}" rx="12"/></clipPath>')
    svg.add(f'<g clip-path="url(#{clip})">')
    for i in range(rows * cols):
        x, y = x0 + (i % cols) * cw, y0 + (i // cols) * ch
        if i < len(data):
            svg.rect(x, y, cw, ch, fill_of(i), stroke="#00000026", sw=1)
            svg.text(x + cw / 2, y + (text_y or ch / 2 + 6), f"{data[i]:02X}", size, fill=ink_of(i), weight=500)
        else:
            svg.rect(x, y, cw, ch, "#F4DCC4", stroke="#00000014", sw=1)
    svg.add("</g>")
    svg.rect(x0, y0, w, h, "none", rx=12, stroke=DARK, sw=3.5)
    return y0 + h


def flow_stack(svg, x, y, w, rows, title="PacketFlow", rh=52, sub_size=12.5):
    """The black PacketFlow stack: rows = [(label, layer key, sublabel or None)]. Returns row centers, bottom."""
    h = TITLE_H + len(rows) * (rh + GAP) + GAP
    svg.rect(x, y, w, h, DARK, rx=10)
    svg.text(x + w / 2, y + GAP + TITLE_H / 2 + 7, title, 20, fill=WHITE, weight=600)
    centers, fy = [], y + GAP + TITLE_H
    for label, key, sub in rows:
        strong, _, ink = LAYER[key]
        svg.rect(x + 4, fy, w - 8, rh, strong, rx=6)
        if sub:
            svg.text(x + w / 2, fy + rh / 2 - 3, label, 16, fill=ink, weight=600)
            svg.text(x + w / 2, fy + rh / 2 + 16, sub, sub_size, fill=ink, family=MONO, opacity=0.85)
        else:
            svg.text(x + w / 2, fy + rh / 2 + 6, label, 16, fill=ink, weight=600)
        centers.append(fy + rh / 2)
        fy += rh + GAP
    return centers, y + h


def chip(svg, x, cy, w, fill, ink, text_, sub=None, h=40, mono_sub=True):
    svg.rect(x, cy - h / 2, w, h, fill, rx=6)
    if sub:
        svg.text(x + w / 2, cy - 4, text_, 12, fill=ink, weight=600, opacity=0.85)
        svg.text(x + w / 2, cy + 13, sub, 13, fill=ink, family=MONO if mono_sub else SANS)
    else:
        svg.text(x + w / 2, cy + 5, text_, 14.5, fill=ink, weight=600)


def raw_packet_diagram():
    data = DNS_FRAME
    x0, y0, cols, cw, ch = 60, 112, 12, 65, 46
    height = y0 + 6 * ch + 44
    svg = Svg(height, "A packet, as captured",
              f"The {len(data)} bytes of a DNS query for example.com, as a capture stores them, one byte per "
              "cell and twelve per row: nothing in the bytes themselves says where a protocol starts.")
    svg.text(x0, 62, "A packet, as captured", 22, weight=600, anchor="start")
    svg.text(x0, 88, f"{len(data)} bytes: a DNS query for example.com, one byte per cell", 14, anchor="start",
             opacity=0.6)
    hex_grid(svg, x0, y0, data, cols, cw, ch, lambda i: GREY, lambda i: WHITE)
    svg.save("packet/raw_packet.svg")


def layered_packet_diagram():
    data = DNS_FRAME
    keys = frame_layers(DNS_SPANS)
    assert len(keys) == len(data)
    x0, y0, cols, cw, ch = 60, 112, 12, 65, 46
    bottom = y0 + 6 * ch
    height = bottom + 110
    svg = Svg(height, "Each protocol owns a span of bytes",
              "The same DNS query, each byte coloured by the protocol it belongs to: 14 bytes of Ethernet, 20 of "
              "IPv4, 8 of UDP, then the 29 bytes of the DNS message.")
    svg.text(x0, 62, "Each protocol owns a span of bytes", 22, weight=600, anchor="start")
    svg.text(x0, 88, "the same packet, coloured by layer", 14, anchor="start", opacity=0.6)
    hex_grid(svg, x0, y0, data, cols, cw, ch, lambda i: LAYER[keys[i]][0], lambda i: LAYER[keys[i]][2])
    cx = x0
    for key, name, n in DNS_SPANS:
        strong, _, ink = LAYER[key]
        chip(svg, cx, bottom + 50, 180, strong, ink, f"{name} · {n} bytes")
        cx += 200
    svg.save("packet/layered_packet.svg")


def nesting_diagram():
    height = 400
    svg = Svg(height, "Protocols are nested",
              "The DNS query as nested boxes: the Ethernet frame carries an IPv4 packet, which carries a UDP "
              "datagram, which carries the DNS message. Each layer is a header followed by the next layer.")
    svg.text(40, 62, "Protocols are nested", 22, weight=600, anchor="start")
    svg.text(40, 88, "each layer is a header, then the layer it carries", 14, anchor="start", opacity=0.6)
    boxes = [("link", "DATA LINK", "Ethernet · 14 bytes", 40, 860, 120, 360),
             ("internet", "INTERNET", "IPv4 · 20 bytes", 210, 840, 145, 335),
             ("transport", "TRANSPORT", "UDP · 8 bytes", 380, 820, 170, 310),
             ("application", "APPLICATION", "DNS · 29 bytes", 545, 800, 195, 285)]
    for i, (key, name, sub, x1, x2, y1, y2) in enumerate(boxes):
        strong, light, _ = LAYER[key]
        svg.rect(x1, y1, x2 - x1, y2 - y1, light if i < 3 else strong, rx=12, stroke=strong if i < 3 else "#E0AE2E",
                 sw=4)
        right = boxes[i + 1][3] if i < 3 else x2
        cxl = (x1 + right) / 2
        svg.text(cxl, (y1 + y2) / 2 - 2, name, 16, weight=600)
        svg.text(cxl, (y1 + y2) / 2 + 18, sub, 13, opacity=0.7)
    svg.save("packet/nesting.svg")


def packetflow_layers_diagram():
    rows = [("data_link", "link", None), ("internet", "internet", None), ("transport", "transport", None),
            ("application", "application", None), ("inner", "inner", None), ("corrupted", "corrupted", None)]
    chips = [["Ethernet", "Linux SLL", "RAW IP", "…"], ["IPv4", "IPv6", "ARP", "Profinet"],
             ["TCP", "UDP", "ICMP", "ICMPv6"], ["DNS", "TLS", "S7Comm", "…"], ["GRE", "VXLAN", "GTP-U", "…"],
             ["Internet", "Transport"]]
    sy, rh = 112, 52
    height = sy + TITLE_H + len(rows) * (rh + GAP) + GAP + 40
    svg = Svg(height, "The layers of a PacketFlow",
              "PacketFlow has one field per layer: data_link, always present, then internet, transport and "
              "application, each optional, and the formats or protocols each can hold. inner holds the packet a "
              "tunnel carries (GRE, VXLAN, GTP-U...), corrupted names the layer whose bytes were invalid.")
    svg.text(60, 62, "The layers of a PacketFlow", 22, weight=600, anchor="start")
    svg.text(60, 88, "data_link is always there; every other field is an Option", 14, anchor="start", opacity=0.6)
    centers, _ = flow_stack(svg, 60, sy, 240, rows, rh=rh)
    for cy, (_, key, _), names in zip(centers, rows, chips):
        strong, _, ink = LAYER[key]
        for k, name in enumerate(names):
            chip(svg, 340 + k * 128, cy, 116, strong, ink, name, h=38)
    svg.save("packet/packetflow_layers.svg")


def flow_identity_diagram():
    rows = [("data_link", "link", None), ("internet", "internet", None), ("transport", "transport", None),
            ("application", "application", None)]
    cells = [(("source_mac", "02:42:c0:a8:00:68"), "Ethernet", ("destination_mac", "02:42:c0:a8:00:01")),
             (("source", "192.168.0.104"), "IPv4", ("destination", "192.168.0.1")),
             (("source_port", "51000"), "UDP", ("destination_port", "53")),
             (None, "DNS", None)]
    sy, rh = 112, 60
    bottom = sy + TITLE_H + len(rows) * (rh + GAP) + GAP
    height = bottom + 70
    svg = Svg(height, "The flow identity",
              "What PartialEq, Eq and Hash compare, on the DNS query: the source and destination of each layer and "
              "its protocol, MAC addresses, IP addresses, ports, and the application label. Payloads and details "
              "are left out, so two packets of the same conversation compare equal.")
    svg.text(60, 62, "The flow identity", 22, weight=600, anchor="start")
    svg.text(60, 88, "what PartialEq, Eq and Hash compare, on the DNS query", 14, anchor="start", opacity=0.6)
    centers, _ = flow_stack(svg, 60, sy, 220, rows, rh=rh)
    for cy, (_, key, _), (src, proto, dst) in zip(centers, rows, cells):
        strong, light, ink = LAYER[key]
        if src:
            chip(svg, 320, cy, 190, light, DARK, *src, h=48)
        chip(svg, 530, cy, 110, strong, ink, proto, h=48)
        if dst:
            chip(svg, 660, cy, 190, light, DARK, *dst, h=48)
    svg.text(60, bottom + 30, "Payloads and details are left out: two packets of the same conversation compare "
             "equal.", 13.5, anchor="start", opacity=0.7)
    svg.text(60, bottom + 50, "inner and corrupted take part too.", 13.5, anchor="start", opacity=0.7)
    svg.save("packet/flow_identity.svg")


def layer_structs_diagram():
    rows = [("data_link", "link", "LinkLayer"), ("internet", "internet", "Option&lt;Internet&gt;"),
            ("transport", "transport", "Option&lt;Transport&gt;"),
            ("application", "application", "Option&lt;Application&gt;"),
            ("inner", "inner", "Option&lt;Box&lt;PacketFlow&gt;&gt;"),
            ("corrupted", "corrupted", "Option&lt;CorruptedLayer&gt;")]
    structs = [("LinkLayer", "link", [("link_type()", True), ("network_protocol()", True), ("kind() / as_ethernet()", True),
                                      ("network_payload()", False)]),
               ("Internet", "internet", [("source, destination", True), ("source_type, …", True),
                                         ("protocol_name", True), ("payload_protocol", True), ("payload", False),
                                         ("details", False)]),
               ("Transport", "transport", [("protocol", True), ("source_port", True), ("destination_port", True),
                                           ("payload", False), ("details", False)]),
               ("Application", "application", [("application_protocol", True)])]
    sx, sw, sy, rh = 300, 300, 112, 44
    by = sy + TITLE_H + len(rows) * (rh + GAP) + GAP + 80
    bw, bgap, bx0, frh = 196, 12, 40, 34
    tallest = max(len(f) for _, _, f in structs)
    height = by + TITLE_H + tallest * (frh + GAP) + GAP + 70
    svg = Svg(height, "The structs behind each layer",
              "Each field of PacketFlow is a struct of its own. LinkLayer exposes the LINKTYPE, the announced "
              "network protocol, the format-specific view and the L3 bytes; Internet the addresses, their type, "
              "the protocol name and the announced transport protocol; Transport the protocol and the ports; "
              "Application the label. payload, network_payload and details are not part of the flow identity.")
    svg.define_hatch()
    svg.text(40, 62, "The structs behind each layer", 22, weight=600, anchor="start")
    svg.text(40, 88, "the summary each layer exposes; details holds the full parsed header", 14, anchor="start",
             opacity=0.6)
    centers, sbottom = flow_stack(svg, sx, sy, sw, rows, rh=rh, sub_size=12)
    tops = []
    for i, (title, key, fields) in enumerate(structs):
        x = bx0 + i * (bw + bgap)
        strong, light, ink = LAYER[key]
        h = TITLE_H + len(fields) * (frh + GAP) + GAP
        svg.rect(x, by, bw, h, DARK, rx=10)
        svg.text(x + bw / 2, by + GAP + TITLE_H / 2 + 7, title, 18, fill=WHITE, weight=600)
        fy = by + GAP + TITLE_H
        for name, identity in fields:
            svg.rect(x + 4, fy, bw - 8, frh, light if identity else HATCH, rx=5)
            svg.text(x + bw / 2, fy + frh / 2 + 5, name, 13, family=MONO, opacity=1 if identity else 0.6)
            fy += frh + GAP
        tops.append(x + bw / 2)
    # from the bottom of the stack to each struct, on two lanes so that no line crosses another
    starts = [sx + 60, sx + 120, sx + 180, sx + 240]
    lanes = [sbottom + 26, sbottom + 50, sbottom + 50, sbottom + 26]
    for x_start, lane, x_end in zip(starts, lanes, tops):
        svg.arrow([(x_start, sbottom + 6), (x_start, lane), (x_end, lane), (x_end, by - 8)], GREY)
    ly = by + TITLE_H + tallest * (frh + GAP) + GAP + 36
    svg.rect(40, ly - 15, 30, 20, HATCH, rx=4, stroke="#E9CF86")
    svg.text(80, ly, "not part of the flow identity, not serialized", 13.5, anchor="start", opacity=0.7)
    svg.save("packet/layer_structs.svg")


def payload_chain_diagram():
    rows = [("data_link", "link", None), ("internet", "internet", None), ("transport", "transport", None),
            ("application", "application", None)]
    sx, sw, sy, rh = 330, 240, 112, 60
    height = sy + TITLE_H + len(rows) * (rh + GAP) + GAP + 44
    svg = Svg(height, "Each layer is parsed from the payload of the previous one",
              "The link layer has a network payload and announces the network protocol: the internet layer is "
              "parsed from them. The internet layer has a payload and announces the transport protocol: the "
              "transport layer is parsed from them. The transport payload and its ports go to the application "
              "probes.")
    svg.text(40, 62, "Each layer is parsed from the payload of the previous one", 22, weight=600, anchor="start")
    svg.text(40, 88, "and each layer announces what the next one is", 14, anchor="start", opacity=0.6)
    centers, bottom = flow_stack(svg, sx, sy, sw, rows, rh=rh)
    boxes = [(1, "network_payload()", "+ network_protocol", "link"), (-1, "payload", "+ payload_protocol", "internet"),
             (1, "payload", "+ ports, to the probes", "transport")]
    for i, (side_, name, sub, key) in enumerate(boxes):
        _, light, _ = LAYER[key]
        strong = LAYER[key][0]
        y = centers[i]
        w = 210
        x = sx + sw + 80 if side_ > 0 else sx - 80 - w
        svg.rect(x, y - 30, w, 60, light, rx=8, stroke=strong, sw=3)
        svg.text(x + w / 2, y - 4, name, 15, family=MONO, weight=600)
        svg.text(x + w / 2, y + 16, sub, 12.5, family=MONO, opacity=0.75)
        # the layer has it...
        if side_ > 0:
            svg.arrow([(sx + sw + 6, y), (x - 10, y)], ARROW_DARK)
            svg.text((sx + sw + x) / 2, y - 10, "has", 13, weight=600, opacity=0.7)
            # ...and the next layer is parsed from it
            svg.arrow([(x + w / 2, y + 36), (x + w / 2, centers[i + 1]), (sx + sw + 10, centers[i + 1])], GREY)
        else:
            svg.arrow([(sx - 6, y), (x + w + 10, y)], ARROW_DARK)
            svg.text((sx + x + w) / 2, y - 10, "has", 13, weight=600, opacity=0.7)
            svg.arrow([(x + w / 2, y + 36), (x + w / 2, centers[i + 1]), (sx - 10, centers[i + 1])], GREY)
    svg.save("packet/payload_chain.svg")


def tryfrom_card(name, title, subtitle, data, cols, ok_label, err_label, notes, desc):
    x0, y0, cw, ch = 60, 112, 65, 46
    rows = -(-len(data) // cols)
    gbottom = y0 + rows * ch
    cy = gbottom + 120
    height = cy + 210
    svg = Svg(height, title, desc)
    svg.text(x0, 62, title, 22, weight=600, anchor="start")
    svg.text(x0, 88, subtitle, 14, anchor="start", opacity=0.6)
    hex_grid(svg, x0, y0, data, cols, cw, ch, lambda i: GREY, lambda i: WHITE)
    bx, bw, bh = 60, 170, 90
    svg.rect(bx, cy - bh / 2, bw, bh, GREY, rx=8)
    svg.text(bx + bw / 2, cy + 6, "&amp;[u8]", 18, fill=WHITE, weight=600, family=MONO)
    # the grid is the input
    svg.arrow([(x0 - 6, gbottom - ch), (x0 - 26, gbottom - ch), (x0 - 26, cy), (bx - 8, cy)], GREY, radius=12)
    dx, r = 450, 66
    svg.arrow([(bx + bw + 6, cy), (dx - r - 12, cy)], GREY)
    svg.text((bx + bw + dx - r) / 2, cy - 12, "TryFrom", 14, weight=600, opacity=0.8)
    svg.add(f'<path d="M {dx} {cy - r} L {dx + r} {cy} L {dx} {cy + r} L {dx - r} {cy} Z" fill="{BLUE}" '
            f'stroke="{BLUE}" stroke-width="8" stroke-linejoin="round"/>')
    svg.text(dx, cy + 6, "validation", 16, fill=WHITE, weight=600)
    for k, note in enumerate(notes):
        svg.text(dx, cy - r - 34 + 18 * k, note, 12.5, opacity=0.7)
    ox, ow = 620, 240
    svg.arrow([(dx + r + 10, cy), (ox - 10, cy)], SUCCESS)
    svg.rect(ox, cy - bh / 2, ow, bh, GREEN, rx=8)
    svg.text(ox + ow / 2, cy + 6, ok_label, 16, weight=700, family=MONO)
    ey = cy + r + 50
    svg.arrow([(dx, cy + r + 10), (dx, ey - 10)], RED)
    svg.rect(dx - 150, ey, 300, 56, RED, rx=8)
    svg.text(dx, ey + 34, err_label, 15, fill=WHITE, weight=700, family=MONO)
    svg.save(name)


def tryfrom_diagrams():
    tryfrom_card("data_validation/tryfrom.svg", "Every struct is a TryFrom&lt;&amp;[u8]&gt;",
                 "the 20 bytes of an IPv4 header in, a typed struct or a typed error out", SYN_IP[:20], 10,
                 "Ok(Ipv4Packet)", "Err(Ipv4Error)", ["length, then each field in wire order,", "then the cross-field checks"],
                 "The 20 bytes of the IPv4 header of the book's SYN go through Ipv4Packet::try_from: a validation "
                 "of the length, then of each field in wire order, then of the fields together. It returns an "
                 "Ipv4Packet or a typed Ipv4Error.")
    tryfrom_card("datalink/validation.svg", "DataLink::try_from",
                 "the first bytes of an Ethernet frame in, a DataLink or a DataLinkError out", SYN_FRAME[:24], 12,
                 "Ok(DataLink)", "Err(DataLinkError)", ["at least 14 bytes,", "+ 4 per VLAN tag consumed"],
                 "The first bytes of the Ethernet frame carrying the book's SYN go through DataLink::try_from: at "
                 "least 14 bytes, re-checked for each VLAN tag. It returns a DataLink or a DataLinkError.")


def ethernet_frame_diagram():
    rows = [("Destination MAC", "6 bytes", "0 – 5", DARK, WHITE, False),
            ("Source MAC", "6 bytes", "6 – 11", DARK, WHITE, False),
            ("VLAN tag (802.1Q), optional", "4 bytes each", "", "none", DARK, True),
            ("EtherType", "2 bytes", "12 – 13", ORANGE, DARK, False),
            ("Payload", "variable", "14 –", GREY, WHITE, False)]
    x, w, y0, rh = 250, 400, 128, 62
    height = y0 + len(rows) * rh + 70
    svg = Svg(height, "The Ethernet II frame",
              "An Ethernet II frame: the destination MAC address (bytes 0 to 5), the source MAC address (6 to 11), "
              "the EtherType (12 and 13), then the payload from byte 14. Each 802.1Q VLAN tag inserts 4 bytes "
              "before the EtherType, which shifts it and the payload.")
    svg.text(60, 62, "The Ethernet II frame", 22, weight=600, anchor="start")
    svg.text(60, 88, "destination first; each VLAN tag adds 4 bytes before the EtherType", 14, anchor="start",
             opacity=0.6)
    svg.text(x - 30, y0 - 8, "size", 12.5, anchor="end", opacity=0.55)
    svg.text(x + w + 30, y0 - 8, "bytes, untagged", 12.5, anchor="start", opacity=0.55)
    for k, (name, size, offs, fill, ink, dashed) in enumerate(rows):
        y = y0 + k * rh
        if dashed:
            svg.rect(x, y + 4, w, rh - 8, "none", rx=8, stroke=ORANGE_DARK, sw=2.5, dash="7 6")
        else:
            svg.rect(x, y + 4, w, rh - 8, fill, rx=8)
        svg.text(x + w / 2, y + rh / 2 + 6, name, 17, fill=ink, weight=600, opacity=0.75 if dashed else None)
        svg.text(x - 30, y + rh / 2 + 6, size, 15, anchor="end", opacity=0.8)
        if offs:
            svg.text(x + w + 30, y + rh / 2 + 6, offs, 15, anchor="start", family=MONO, opacity=0.8)
    svg.save("datalink/ethernet_frame.svg")


def mac_address_diagram():
    mac = SIEMENS_MAC
    height = 470
    svg = Svg(height, "A MAC address",
              "The 6 bytes of a MAC address, e0:dc:a0:4d:2e:91: the first three are the Organizationally Unique "
              "Identifier (OUI) of the manufacturer, here Siemens, the last three the NIC-specific part. Bit 0 of "
              "the first byte is the I/G bit: 0, so the address is unicast. display_with_oui() gives "
              "Siemens:4d:2e:91.")
    svg.text(60, 62, "A MAC address", 22, weight=600, anchor="start")
    svg.text(60, 88, "6 bytes: who made the interface, then which interface", 14, anchor="start", opacity=0.6)
    x0, y0, cw, chh = 210, 130, 80, 70
    for i, b in enumerate(mac):
        fill, ink = (ORANGE, DARK) if i < 3 else (DARK, WHITE)
        svg.rect(x0 + i * (cw + 4), y0, cw, chh, fill, rx=8)
        svg.text(x0 + i * (cw + 4) + cw / 2, y0 + chh / 2 + 8, f"{b:02X}", 24, fill=ink, weight=600)
    left_c, right_c = x0 + 1.5 * cw + 4, x0 + 4.5 * cw + 12
    for cx, l1, l2, l3 in ((left_c, "3 bytes", "Organizationally Unique Identifier", "(OUI): the manufacturer"),
                           (right_c, "3 bytes", "NIC-specific part,", "assigned by the manufacturer")):
        svg.text(cx, y0 + chh + 34, l1, 15, weight=600)
        svg.text(cx, y0 + chh + 58, l2, 14, opacity=0.8)
        svg.text(cx, y0 + chh + 78, l3, 14, opacity=0.8)
    # the I/G bit of the first byte
    by = y0 + chh + 120
    bits = f"{mac[0]:08b}"
    svg.text(60, by + 22, f"byte 0x{mac[0]:02X}", 14, anchor="start", family=MONO, opacity=0.7)
    for k, bit in enumerate(bits):
        fill = ORANGE if k == 7 else "#F4DCC4"
        svg.rect(210 + k * 38, by, 34, 34, fill, rx=5)
        svg.text(210 + k * 38 + 17, by + 23, bit, 16, family=MONO, weight=600)
    svg.text(210 + 8 * 38 + 14, by + 22, "bit 0, I/G: 0 → unicast, is_multicast() is false", 14, anchor="start",
             opacity=0.8)
    svg.text(60, by + 84, 'display_with_oui()  →  "Siemens:4d:2e:91"', 16, anchor="start", family=MONO,
             weight=600)
    svg.save("datalink/mac_address.svg")


def ethernet_struct_diagram():
    data = SYN_FRAME[:48]
    x0, y0, cols, cw, ch = 60, 150, 12, 45, 52
    def fill_of(i):
        return GREY_LIGHT if i < 12 else ORANGE if i < 14 else GREY
    def ink_of(i):
        return DARK if i < 14 else WHITE
    height = 470
    svg = Svg(height, "From the frame to the DataLink struct",
              "The first 48 bytes of the Ethernet frame carrying the book's SYN, twelve per row. Bytes 0 to 5 "
              "become destination_mac 02:42:c0:a8:00:01, bytes 6 to 11 source_mac 02:42:c0:a8:00:68, bytes 12 and "
              "13 the EtherType 0x0800 (IPv4), and everything from byte 14 the 60-byte payload.")
    svg.text(x0, 70, "From the frame to the DataLink struct", 22, weight=600, anchor="start")
    svg.text(x0, 96, "the frame of the book's SYN, twelve bytes per row", 14, anchor="start", opacity=0.6)
    bottom = hex_grid(svg, x0, y0, data, cols, cw, ch, fill_of, ink_of, size=15, text_y=38)
    svg.outline(x0, y0, 6 * cw, ch)
    svg.outline(x0 + 6 * cw, y0, 6 * cw, ch)
    svg.outline(x0, y0 + ch, 2 * cw, ch)
    svg.text(x0 + 6 * cw, bottom + 26, "… 26 more bytes of payload", 13, opacity=0.6)
    sx, sw = 676, 190
    fields = [("destination_mac", "02:42:c0:a8:00:01", GREY_LIGHT, DARK, 200),
              ("source_mac", "02:42:c0:a8:00:68", GREY_LIGHT, DARK, 260),
              ("ethertype", "IPv4 (0x0800)", ORANGE, DARK, 320),
              ("payload", "&amp;[u8] · 60 bytes", GREY, WHITE, 380)]
    struct_box(svg, sx, sw, "DataLink", fields)
    right = x0 + cols * cw
    # the EtherType arrow runs in the upper part of row 1, above the bytes
    svg.arrow([(sx - 8, 200), (sx - 22, 200), (sx - 22, 126), (x0 + 3 * cw, 126), (x0 + 3 * cw, y0 - 8)], GREY)
    svg.arrow([(sx - 8, 260), (sx - 36, 260), (sx - 36, y0 + ch / 2), (right + 8, y0 + ch / 2)], GREY)
    svg.arrow([(sx - 8, 320), (sx - 50, 320), (sx - 50, y0 + ch + 14), (x0 + 2 * cw + 8, y0 + ch + 14)], ORANGE_DARK)
    svg.arrow([(sx - 8, 380), (sx - 64, 380), (sx - 64, y0 + 3 * ch + ch / 2), (right + 8, y0 + 3 * ch + ch / 2)],
              ARROW_DARK)
    svg.save("datalink/ethernet_struct.svg")


if __name__ == "__main__":
    ipv4_diagram()
    tcp_diagram()
    tunnel_diagram()
    dispatch_diagram()
    outcomes_diagram()
    giop_header_diagram()
    giop_cdr_diagram()
    tryfrom_diagram()
    engine_diagram()
    raw_packet_diagram()
    layered_packet_diagram()
    nesting_diagram()
    packetflow_layers_diagram()
    flow_identity_diagram()
    layer_structs_diagram()
    payload_chain_diagram()
    tryfrom_diagrams()
    ethernet_frame_diagram()
    mac_address_diagram()
    ethernet_struct_diagram()
