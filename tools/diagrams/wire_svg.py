"""Generate the book's "bytes -> struct" diagrams in the style of the existing
SVGs (tcp_struct.svg, ptp_header.svg): a 32-bit-per-row byte grid on the left,
the decoded struct as a dark card on the right, arrows between them.

A diagram is a dict:

    {
      "out": "images/application/ike_header.svg",
      "title": "IKEv2 header: IKE_SA_INIT request",
      "subtitle": "frame 1 of ikev2_s2s_ipsec_vpn_aes_gcm.pcapng, UDP 500 ...",
      "desc": "one full sentence for <desc>",
      "palette": "app" | "transport",       # cream or green body fields
      "fields": [
         {"label": "Initiator SPI", "hex": "62f94c9887715a34", "color": "orange"},
         {"label": "...", "hex": "...", "color": "body"|"orange"|"yellow"|"green"|"cream", "emph": True, "cont": "label of continued rows"},
         {"skip": "… 16 more option bytes"},     # a 40 px ellipsis row (row start only)
      ],
      "payload": "payload: 346 bytes of payloads",   # dashed box under the grid (optional)
      "card": {"title": "IkeHeader", "width": 250, "y": 48,
               "fields": [{"name": "initiator_spi", "value": "0x62f9...", "color": "orange",
                           "arrow": 0, "arrow_color": "orange"|"gray"|"dark"}, ...]},
    }

`arrow` is the index of the grid field (or "payload") the card field points
at. Byte grid: x=60, 96 px per byte, 60 px per row, four bytes per row.
"""

import html

FONT = "Inter, ui-sans-serif, system-ui, -apple-system, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif"
MONO = "ui-monospace, SFMono-Regular, Menlo, Consolas, 'DejaVu Sans Mono', monospace"

COLORS = {
    "orange": "#FF9E42",
    "yellow": "#FFC943",
    "cream": "#FFECBD",
    "green": "#CDF4D3",
    "dark": "#1E1E1E",
    "payload": "#66D575",
}
ARROWS = {"orange": "#EB7500", "gray": "#757575", "dark": "#3A3A3A"}

GX, GY, BYTE_W, ROW_H, SKIP_H = 60, 230, 96, 60, 40
GRID_W = 4 * BYTE_W
CARD_X = 610
STROKE = "#93D9A0"


def esc(s):
    return html.escape(str(s), quote=True)


def text(x, y, s, size, weight=400, fill="#1E1E1E", opacity=None, anchor="start", mono=False):
    op = f' fill-opacity="{opacity}"' if opacity is not None else ""
    return (f'<text x="{x}" y="{y}" font-family="{MONO if mono else FONT}" font-size="{size}" '
            f'font-weight="{weight}" fill="{fill}"{op} text-anchor="{anchor}">{esc(s)}</text>')


def wrap(s, width):
    words, lines, cur = s.split(), [], ""
    for w in words:
        if cur and len(cur) + 1 + len(w) > width:
            lines.append(cur)
            cur = w
        else:
            cur = f"{cur} {w}" if cur else w
    if cur:
        lines.append(cur)
    return lines


def chevron(x, y, direction):
    """Arrow head at (x, y). direction: 'left' (pointing left) or 'down'."""
    if direction == "left":
        return f"{x+9},{y-9} {x},{y} {x+9},{y+9}"
    return f"{x-9},{y-9} {x},{y} {x+9},{y-9}"


def render(d, clip=True):
    body_color = COLORS["cream"] if d.get("palette", "app") == "app" else COLORS["green"]

    def color_of(name):
        return body_color if name in (None, "body") else COLORS[name]

    grid, emph, anchors = [], [], {}
    cur, y = 0, GY
    for idx, f in enumerate(d["fields"]):
        if "skip" in f:
            if cur != 0:
                # the ellipsis fills the rest of the current row
                x, w = GX + cur * BYTE_W, (4 - cur) * BYTE_W
                grid.append(f'<rect x="{x}" y="{y}" width="{w}" height="{ROW_H}" fill="{color_of(f.get("color"))}"/>')
                grid.append(f'<line x1="{x}" y1="{y}" x2="{x}" y2="{y+ROW_H}" stroke="{STROKE}" stroke-width="1" stroke-dasharray="4 4"/>')
                size = min(14, (w - 10) / (0.56 * len(f["skip"])))
                if size < 9.5:
                    size = 9.5
                grid.append(text(x + w / 2, y + 35, f["skip"], round(size, 1), 500, opacity=0.7, anchor="middle"))
                anchors[idx] = (x, y, w, ROW_H)
                cur, y = 0, y + ROW_H
                continue
            grid.append(f'<rect x="{GX}" y="{y}" width="{GRID_W}" height="{SKIP_H}" fill="{color_of(f.get("color"))}"/>')
            grid.append(f'<line x1="{GX}" y1="{y}" x2="{GX+GRID_W}" y2="{y}" stroke="{STROKE}" stroke-width="1" stroke-dasharray="4 4"/>')
            size = max(9.5, min(14, (GRID_W - 16) / (0.56 * len(f["skip"]))))
            grid.append(text(GX + GRID_W / 2, y + 25, f["skip"], round(size, 1), 500, opacity=0.7, anchor="middle"))
            anchors[idx] = (GX, y, GRID_W, SKIP_H)
            y += SKIP_H
            continue
        hx = f["hex"].replace(" ", "")
        remaining = [hx[i:i + 2].upper() for i in range(0, len(hx), 2)]
        color = color_of(f.get("color"))
        first = True
        while remaining:
            k = min(len(remaining), 4 - cur)
            part, remaining = remaining[:k], remaining[k:]
            x, w = GX + cur * BYTE_W, k * BYTE_W
            grid.append(f'<rect x="{x}" y="{y}" width="{w}" height="{ROW_H}" fill="{color}" stroke="{STROKE}" stroke-width="1.5"/>')
            for j in range(1, k):
                grid.append(f'<line x1="{x + j*BYTE_W}" y1="{y+26}" x2="{x + j*BYTE_W}" y2="{y+ROW_H}" stroke="{STROKE}" stroke-width="1"/>')
            label = None
            if first:
                label = f["label"]
            elif cur == 0 and k == 4:
                label = f.get("cont", f"{f['label']}, continued")
            if label:
                # shrink the label to its part, drop it when it cannot fit
                size = min(13.5, (w - 10) / (0.56 * len(label)))
                if size >= 9.5:
                    grid.append(text(x + w / 2, y + 19, label, round(size, 1), 500, opacity=0.62, anchor="middle"))
            for j, b in enumerate(part):
                grid.append(text(x + j * BYTE_W + BYTE_W / 2, y + 49, b, 20, 500, anchor="middle"))
            if first:
                anchors[idx] = (x, y, w, ROW_H)
                if f.get("emph"):
                    emph.append(f'<rect x="{x}" y="{y}" width="{w}" height="{ROW_H}" rx="5" fill="none" stroke="#1E1E1E" stroke-width="3.5"/>')
            first = False
            cur = (cur + k) % 4
            if cur == 0:
                y += ROW_H
    if cur != 0:
        y += ROW_H
    grid_h = y - GY
    bottom = y

    extra = []
    if d.get("payload"):
        py = bottom + 18
        extra.append(f'<rect x="{GX}" y="{py}" width="{GRID_W}" height="48" rx="10" fill="none" stroke="{COLORS["payload"]}" stroke-width="2.5" stroke-dasharray="7 6"/>')
        extra.append(text(GX + GRID_W / 2, py + 30, d["payload"], 14, 500, opacity=0.7, anchor="middle"))
        anchors["payload"] = (GX, py, GRID_W, 48)
        bottom = py + 48

    card_svg, arrows = [], []
    card = d.get("card")
    if card:
        cw = card.get("width", 250)
        cx = CARD_X
        fields = card["fields"]
        ch = 64 + len(fields) * 60
        cy0 = card.get("y", 48)
        card_svg.append(f'<rect x="{cx}" y="{cy0}" width="{cw}" height="{ch}" rx="10" fill="#1E1E1E"/>')
        card_svg.append(text(cx + cw / 2, cy0 + 39, card["title"], 20, 600, fill="#FFFFFF", anchor="middle"))
        corridor = 0
        for i, cf in enumerate(fields):
            fy = cy0 + 64 + i * 60
            card_svg.append(f'<rect x="{cx+4}" y="{fy}" width="{cw-8}" height="56" rx="6" fill="{color_of(cf.get("color"))}"/>')
            card_svg.append(text(cx + cw / 2, fy + 25, cf["name"], 16, 600, anchor="middle"))
            card_svg.append(text(cx + cw / 2, fy + 46, cf["value"], 14, 400, opacity=0.8, anchor="middle"))
            tgt = cf.get("arrow")
            if tgt is None or tgt not in anchors:
                continue
            ax, ay, aw, ah = anchors[tgt]
            col = ARROWS[cf.get("arrow_color", "orange")]
            sx, sy = cx - 12, fy + 28
            ty = ay + ah / 2
            if ay <= GY + 1 and sy < GY - 24 and ax + aw < GX + GRID_W - 1:
                # top row, card field above the grid: drop onto the field's top edge
                tx, tyt = ax + aw / 2, ay - 8
                path = f"M {sx} {sy} L {tx+11} {sy} Q {tx} {sy} {tx} {sy+11} L {tx} {tyt}"
                head = chevron(tx, tyt, "down")
            elif abs(ty - sy) < 6 and ax + aw >= GX + GRID_W - 1:
                tx = ax + aw + 10
                path = f"M {sx} {sy} L {tx} {sy}"
                head = chevron(tx, sy, "left")
            else:
                mx = GX + GRID_W + 44 + 18 * corridor
                corridor += 1
                tx = ax + aw + 10
                down = ty > sy
                path = (f"M {sx} {sy} L {mx+14} {sy} Q {mx} {sy} {mx} {sy + (14 if down else -14)} "
                        f"L {mx} {ty + (-14 if down else 14)} Q {mx} {ty} {mx-14} {ty} L {tx} {ty}")
                head = chevron(tx, ty, "left")
            arrows.append(f'<path d="{path}" fill="none" stroke="{col}" stroke-width="3.5" stroke-linecap="round" stroke-linejoin="round"/>')
            arrows.append(f'<polyline points="{head}" fill="none" stroke="{col}" stroke-width="3.5" stroke-linecap="round" stroke-linejoin="round"/>')
        bottom = max(bottom, cy0 + ch)

    height = int(bottom + 34)
    out = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 900 {height}" width="900" height="{height}" role="img" aria-labelledby="t d">',
           f'<title id="t">{esc(d["title"])}</title>',
           f'<desc id="d">{esc(d["desc"])}</desc>',
           f'<rect x="12" y="12" width="876" height="{height-24}" rx="18" fill="#FFEAD6" stroke="#FF9E42" stroke-width="2.5"/>',
           text(GX, 84, d["title"], 22 if len(d["title"]) <= 44 else 18, 600)]
    assert len(d["title"]) <= 54, f"title too long for the card: {d['title']!r}"
    for i, line in enumerate(wrap(d["subtitle"], 68)):
        out.append(text(GX, 110 + i * 20, line, 14, 400, opacity=0.55))
    for i, note in enumerate(d.get("notes", [])):
        out.append(text(GX, 160 + i * 20, note, 13.5, 400, opacity=0.75))
    if clip:
        out.append(f'<clipPath id="g"><rect x="{GX}" y="{GY}" width="{GRID_W}" height="{grid_h}" rx="12"/></clipPath>')
        out.append('<g clip-path="url(#g)">')
    else:
        out.append('<g>')
    out.extend(grid)
    out.append('</g>')
    out.append(f'<rect x="{GX}" y="{GY}" width="{GRID_W}" height="{grid_h}" rx="12" fill="none" stroke="#1E1E1E" stroke-width="3.5"/>')
    out.extend(emph)
    out.extend(extra)
    out.extend(card_svg)
    out.extend(arrows)
    out.append('</svg>')
    return "\n".join(out) + "\n"


def build(specs, root, preview_dir=None):
    """Write every spec under <root>/src/<out>; optionally a clip-free copy
    for preview rasterizers that ignore clipPath."""
    import pathlib
    written = []
    for d in specs:
        p = pathlib.Path(root, "src", d["out"])
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(render(d), encoding="utf-8")
        written.append(p)
        if preview_dir:
            q = pathlib.Path(preview_dir, p.name)
            q.parent.mkdir(parents=True, exist_ok=True)
            q.write_text(render(d, clip=False), encoding="utf-8")
    return written
