#!/usr/bin/env python3
"""Regenerate the "bytes -> struct" diagrams of the book from their specs.

Usage, from the repository root:

    python3 tools/diagrams/build.py            # writes every SVG under src/images/
    python3 tools/diagrams/build.py --check    # fails if a committed SVG differs

Each spec (tools/diagrams/specs_*.py) names its real frame of the crate's
corpus (`pcaps_exemple/`), lists the bytes field by field with their colour
and label, and describes the struct card and its arrows. The renderer is
tools/diagrams/wire_svg.py; nothing here reads the captures, the bytes are
copied from the crate's unit-test fixtures and from tshark.
"""

import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import specs_app  # noqa: E402
import specs_link  # noqa: E402
import specs_net  # noqa: E402
import wire_svg  # noqa: E402

ROOT = HERE.parent.parent
SPECS = specs_link.ALL + specs_net.ALL + specs_app.ALL


def main() -> int:
    check = "--check" in sys.argv[1:]
    stale = []
    for spec in SPECS:
        path = ROOT / "src" / spec["out"]
        rendered = wire_svg.render(spec)
        if check:
            if not path.is_file() or path.read_text(encoding="utf-8") != rendered:
                stale.append(path.relative_to(ROOT))
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(rendered, encoding="utf-8")
        print(f"wrote {path.relative_to(ROOT)}")
    if check:
        for path in stale:
            print(f"stale or missing: {path}", file=sys.stderr)
        print(f"{len(SPECS) - len(stale)}/{len(SPECS)} diagrams up to date")
        return 1 if stale else 0
    print(f"{len(SPECS)} diagrams written")
    return 0


if __name__ == "__main__":
    sys.exit(main())
