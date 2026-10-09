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


if __name__ == "__main__":
    ipv4_diagram()
    tcp_diagram()
    tunnel_diagram()
    dispatch_diagram()
    outcomes_diagram()
    giop_header_diagram()
    giop_cdr_diagram()
    tryfrom_diagram()
