"""Minimal PDF 1.4 writer using only standard fonts.

No images, no Unicode fonts, no third-party libraries. Non-Latin characters
become '?'. This is a lab report, not a print-shop layout engine.
"""

from __future__ import annotations

from collections.abc import Sequence

PAGE_WIDTH = 612  # US Letter points
PAGE_HEIGHT = 792
MARGIN = 50
BODY_SIZE = 8
TITLE_SIZE = 16
META_SIZE = 10
ROW_GAP = 11
META_GAP = 13
WRAP_META = 90
WRAP_ROW = 98


def pdf_safe(text: str) -> str:
    """Map text to Latin-1 for Helvetica/Courier; other characters become '?'."""
    cleaned = "".join(
        char if 32 <= ord(char) < 127 or 160 <= ord(char) <= 255 else "?"
        for char in text
    )
    return cleaned.encode("latin-1", "replace").decode("latin-1")


def wrap_text(text: str, width: int) -> list[str]:
    """Wrap a line on spaces when possible; hard-split overlong tokens."""
    cleaned = pdf_safe(text).replace("\t", " ")
    if not cleaned:
        return [""]
    chunks: list[str] = []
    remaining = cleaned
    while remaining:
        if len(remaining) <= width:
            chunks.append(remaining)
            break
        split_at = remaining.rfind(" ", 0, width + 1)
        if split_at < 1:
            split_at = width
            chunks.append(remaining[:split_at])
            remaining = remaining[split_at:]
        else:
            chunks.append(remaining[:split_at])
            remaining = remaining[split_at + 1 :]
    return chunks or [""]


def build_pdf(
    title: str,
    *,
    meta: Sequence[str] = (),
    rows: Sequence[str] = (),
    note: str = "",
) -> bytes:
    """Build a multi-page PDF with a title, meta lines, then monospaced rows."""
    entries: list[tuple[str, int, str]] = []
    entries.append(("F2", TITLE_SIZE, pdf_safe(title)[:WRAP_META]))
    if note:
        for piece in wrap_text(note, WRAP_META):
            entries.append(("F3", META_SIZE, piece))
    for line in meta:
        for piece in wrap_text(line, WRAP_META):
            entries.append(("F3", META_SIZE, piece))
    if rows:
        entries.append(("F3", META_SIZE, ""))
    for line in rows:
        for piece in wrap_text(line, WRAP_ROW):
            entries.append(("F1", BODY_SIZE, piece))
    pages = _paginate(title, entries)
    return _assemble(pages)


def _paginate(
    title: str,
    entries: Sequence[tuple[str, int, str]],
) -> list[list[tuple[str, int, str]]]:
    y_top = PAGE_HEIGHT - MARGIN - TITLE_SIZE
    y_min = MARGIN + 28
    pages: list[list[tuple[str, int, str]]] = []
    current: list[tuple[str, int, str]] = []
    y = y_top
    for font, size, text in entries:
        gap = ROW_GAP if font == "F1" else META_GAP
        if size >= TITLE_SIZE:
            gap = TITLE_SIZE + 6
        if current and y - gap < y_min:
            pages.append(current)
            current = [("F2", TITLE_SIZE, pdf_safe(title)[:WRAP_META] + " (cont.)")]
            y = y_top - (TITLE_SIZE + 6)
        current.append((font, size, text))
        y -= gap
    if current:
        pages.append(current)
    return pages or [[("F2", TITLE_SIZE, pdf_safe(title)[:WRAP_META])]]


def _escape(text: str) -> str:
    return (
        pdf_safe(text)
        .replace("\\", "\\\\")
        .replace("(", "\\(")
        .replace(")", "\\)")
    )


def _gap_for(font: str, size: int) -> int:
    if size >= TITLE_SIZE:
        return TITLE_SIZE + 6
    if font == "F1":
        return ROW_GAP
    return META_GAP


def _page_stream(
    rows: Sequence[tuple[str, int, str]],
    page_no: int,
    page_count: int,
) -> bytes:
    y_start = PAGE_HEIGHT - MARGIN - TITLE_SIZE
    chunks = ["BT"]
    last_font = ""
    last_size = 0
    for index, (font, size, text) in enumerate(rows):
        if index == 0:
            chunks.append(f"/{font} {size} Tf")
            chunks.append(f"{MARGIN} {y_start} Td")
        else:
            prev = rows[index - 1]
            gap = _gap_for(prev[0], prev[1])
            if font != last_font or size != last_size:
                chunks.append(f"/{font} {size} Tf")
            chunks.append(f"0 -{gap} Td")
        chunks.append(f"({_escape(text)}) Tj")
        last_font, last_size = font, size
    chunks.append("ET")
    footer = (
        f"BT\n/F3 8 Tf\n{MARGIN} {MARGIN - 4} Td\n"
        f"(Page {page_no} / {page_count}) Tj\nET\n"
    )
    return ("\n".join(chunks) + "\n" + footer).encode("latin-1")


def _assemble(pages: list[list[tuple[str, int, str]]]) -> bytes:
    page_count = len(pages)
    streams = [
        _page_stream(rows, index, page_count)
        for index, rows in enumerate(pages, start=1)
    ]

    objects: list[bytes] = []

    def add(payload: bytes) -> int:
        objects.append(payload)
        return len(objects)

    font1 = add(b"<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>")
    font2 = add(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>")
    font3 = add(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
    content_ids = [
        add(b"<< /Length %d >>\nstream\n" % len(stream) + stream + b"\nendstream")
        for stream in streams
    ]
    resources = (
        b"<< /Font << /F1 %d 0 R /F2 %d 0 R /F3 %d 0 R >> >>"
        % (font1, font2, font3)
    )
    page_ids = [
        add(
            b"<< /Type /Page /Parent PLACE_PAGES 0 R "
            b"/MediaBox [0 0 %d %d] /Contents %d 0 R /Resources %s >>"
            % (PAGE_WIDTH, PAGE_HEIGHT, content_id, resources)
        )
        for content_id in content_ids
    ]
    kids = b"[" + b" ".join(b"%d 0 R" % pid for pid in page_ids) + b"]"
    pages_id = add(b"<< /Type /Pages /Kids %s /Count %d >>" % (kids, page_count))
    catalog_id = add(b"<< /Type /Catalog /Pages %d 0 R >>" % pages_id)
    marker = str(pages_id).encode("ascii")
    for pid in page_ids:
        objects[pid - 1] = objects[pid - 1].replace(b"PLACE_PAGES", marker)

    header = b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n"
    parts = [header]
    offsets = [0]
    position = len(header)
    for index, payload in enumerate(objects, start=1):
        offsets.append(position)
        block = b"%d 0 obj\n" % index + payload + b"\nendobj\n"
        parts.append(block)
        position += len(block)
    xref = [b"xref\n0 %d\n" % (len(objects) + 1), b"0000000000 65535 f \n"]
    for offset in offsets[1:]:
        xref.append(b"%010d 00000 n \n" % offset)
    trailer = (
        b"trailer\n<< /Size %d /Root %d 0 R >>\nstartxref\n%d\n%%%%EOF\n"
        % (len(objects) + 1, catalog_id, position)
    )
    return b"".join(parts) + b"".join(xref) + trailer
