#!/usr/bin/env python3
"""Static checks on the book sources, to run before `mdbook build`.

`mdbook build` silently creates any chapter that SUMMARY.md references
but that does not exist, and never checks a local link. This script fails
on:

- a chapter referenced by SUMMARY.md that does not exist under src/;
- a chapter under src/ that SUMMARY.md does not reference (drafts);
- a Markdown or HTML link/image whose local target does not exist;
- a `{{#include path[:anchor]}}` whose file (or anchor) does not exist;
- an anchor link (`chapter.md#heading`) whose heading does not exist.

It reads the sources only and never writes anything.

Usage: tools/check_book.py [book_root]   (default: the repository root)
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

SUMMARY_LINK = re.compile(r"\[[^\]]*\]\(([^)]+)\)")
MD_LINK = re.compile(r"!?\[[^\]]*\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")
HTML_SRC = re.compile(r"""(?:src|href)=["']([^"']+)["']""")
INCLUDE = re.compile(r"\{\{#include\s+([^}\s]+)\s*\}\}")
HEADING = re.compile(r"^#{1,6}\s+(.+?)\s*$", re.MULTILINE)
FENCE = re.compile(r"^```.*?^```", re.MULTILINE | re.DOTALL)
EXTERNAL = ("http://", "https://", "mailto:")


def heading_id(text: str) -> str:
    """mdBook's slug: lowercase, punctuation removed, spaces become dashes."""
    text = re.sub(r"[`*_]", "", text)
    text = re.sub(r"[^\w\s-]", "", text.lower())
    return re.sub(r"\s+", "-", text.strip())


def strip_fences(text: str) -> str:
    return FENCE.sub("", text)


def check(root: Path) -> list[str]:
    src = root / "src"
    errors: list[str] = []

    summary = (src / "SUMMARY.md").read_text(encoding="utf-8")
    referenced = {Path(link) for link in SUMMARY_LINK.findall(summary)}
    for chapter in sorted(referenced):
        if not (src / chapter).is_file():
            errors.append(f"SUMMARY.md: chapter {chapter} does not exist")

    on_disk = {p.relative_to(src) for p in src.rglob("*.md")} - {Path("SUMMARY.md")}
    for orphan in sorted(on_disk - referenced):
        errors.append(f"{orphan}: not referenced by SUMMARY.md (draft?)")

    headings: dict[Path, set[str]] = {}
    for chapter in sorted(referenced & on_disk):
        text = strip_fences((src / chapter).read_text(encoding="utf-8"))
        headings[chapter] = {heading_id(h) for h in HEADING.findall(text)}

    for chapter in sorted(referenced & on_disk):
        path = src / chapter
        raw = path.read_text(encoding="utf-8")
        text = strip_fences(raw)

        for target in MD_LINK.findall(text) + HTML_SRC.findall(text):
            if target.startswith(EXTERNAL):
                continue
            file_part, _, anchor = target.partition("#")
            resolved = chapter if not file_part else (chapter.parent / file_part)
            if not (src / resolved).exists():
                errors.append(f"{chapter}: broken local link {target}")
                continue
            if anchor and resolved.suffix == ".md":
                known = headings.get(resolved)
                if known is not None and anchor not in known:
                    errors.append(f"{chapter}: anchor #{anchor} not found in {resolved}")

        for include in INCLUDE.findall(raw):
            file_part, _, anchor = include.partition(":")
            target = (path.parent / file_part).resolve()
            if not target.is_file():
                errors.append(f"{chapter}: include {file_part} does not exist")
                continue
            if anchor and not re.search(rf"ANCHOR:\s*{re.escape(anchor)}\b", target.read_text(encoding="utf-8")):
                errors.append(f"{chapter}: anchor {anchor} not found in {file_part}")

    return errors


def main() -> int:
    root = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parent.parent
    errors = check(root)
    for error in errors:
        print(f"error: {error}", file=sys.stderr)
    if errors:
        print(f"{len(errors)} problem(s) found", file=sys.stderr)
        return 1
    print("book sources OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
