"""Read and edit supported PDF text-showing operands without rewriting other content."""

from __future__ import annotations

import contextlib
import math
import re
from dataclasses import dataclass

import pymupdf as fitz

_WHITE = b"\x00\x09\x0a\x0c\x0d\x20"
_DELIMITERS = _WHITE + b"()<>[]{}/%"
_NUMBER = re.compile(rb"[+-]?(?:\d+(?:\.\d*)?|\.\d+)\Z")
_ASCII_LETTERS = set(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")
_HEX_PAIR = re.compile(rb"<([0-9A-Fa-f]{2})>\s*<([0-9A-Fa-f]{4,})>")
_HEX_RANGE = re.compile(
    rb"<([0-9A-Fa-f]{2})>\s*<([0-9A-Fa-f]{2})>\s*<([0-9A-Fa-f]{4})>"
)


class UnsupportedText(ValueError):
    """The page uses PDF syntax or text state outside this method's scope."""


@dataclass(frozen=True)
class Token:
    kind: str
    value: bytes | float | None
    start: int
    end: int


def _literal(data: bytes, start: int) -> tuple[bytes, int]:
    out = bytearray()
    level = 1
    i = start + 1
    escapes = {ord("n"): 10, ord("r"): 13, ord("t"): 9,
               ord("b"): 8, ord("f"): 12}
    while i < len(data):
        ch = data[i]
        i += 1
        if ch == 92:  # Backslash.
            if i >= len(data):
                raise UnsupportedText("unfinished PDF string escape")
            ch = data[i]
            i += 1
            if ch in escapes:
                out.append(escapes[ch])
            elif ch in b"01234567":
                digits = bytes([ch])
                for _ in range(2):
                    if i < len(data) and data[i] in b"01234567":
                        digits += bytes([data[i]])
                        i += 1
                value = int(digits, 8)
                if value > 255:
                    raise UnsupportedText("invalid PDF octal escape")
                out.append(value)
            elif ch == 13:
                if i < len(data) and data[i] == 10:
                    i += 1
            elif ch != 10:
                out.append(ch)
        elif ch == 40:
            level += 1
            out.append(ch)
        elif ch == 41:
            level -= 1
            if level == 0:
                return bytes(out), i
            out.append(ch)
        else:
            out.append(ch)
    raise UnsupportedText("unterminated PDF string")


def tokenize(data: bytes) -> list[Token]:
    """Tokenize enough PDF syntax to locate intact Tj/TJ operands.

    Inline images are deliberately unsupported because their data is not lexically a
    sequence of PDF tokens.
    """
    tokens: list[Token] = []
    i = 0
    while i < len(data):
        if data[i] in _WHITE:
            i += 1
            continue
        if data[i] == 37:
            while i < len(data) and data[i] not in b"\r\n":
                i += 1
            continue
        start = i
        ch = data[i]
        if ch == 40:
            value, i = _literal(data, i)
            tokens.append(Token("string", value, start, i))
            continue
        if ch == 60 and data[i:i + 2] != b"<<":
            i = data.find(b">", i + 1)
            if i < 0:
                raise UnsupportedText("unterminated PDF hex string")
            raw = bytes(c for c in data[start + 1:i] if c not in _WHITE)
            if len(raw) % 2:
                raw += b"0"
            try:
                value = bytes.fromhex(raw.decode("ascii"))
            except (ValueError, UnicodeDecodeError) as exc:
                raise UnsupportedText("invalid PDF hex string") from exc
            i += 1
            tokens.append(Token("string", value, start, i))
            continue
        if data[i:i + 2] in (b"<<", b">>"):
            i += 2
            tokens.append(Token("symbol", data[start:i], start, i))
            continue
        if ch in b"[]{}>":
            i += 1
            tokens.append(Token("symbol", data[start:i], start, i))
            continue
        if ch == 47:
            i += 1
            while i < len(data) and data[i] not in _DELIMITERS:
                i += 1
            tokens.append(Token("name", data[start + 1:i], start, i))
            continue
        while i < len(data) and data[i] not in _DELIMITERS:
            i += 1
        if i == start:
            raise UnsupportedText("invalid PDF content token")
        raw = data[start:i]
        if raw == b"BI":
            raise UnsupportedText("inline images are unsupported")
        if _NUMBER.fullmatch(raw):
            value = float(raw)
            if not math.isfinite(value):
                raise UnsupportedText("non-finite PDF number")
            tokens.append(Token("number", value, start, i))
        else:
            tokens.append(Token("word", raw, start, i))
    return tokens


def _unicode_map(doc: fitz.Document, font_xref: int) -> dict[int, str] | None:
    kind, value = doc.xref_get_key(font_xref, "ToUnicode")
    if kind != "xref":
        return None
    try:
        cmap = doc.xref_stream(int(value.split()[0]))
    except (ValueError, RuntimeError):
        return {}
    mapping: dict[int, str] = {}
    mode = None
    for line in cmap.splitlines():
        line = line.strip()
        if line.endswith(b"beginbfchar"):
            mode = "char"
        elif line.endswith(b"beginbfrange"):
            mode = "range"
        elif line in (b"endbfchar", b"endbfrange"):
            mode = None
        elif mode == "char":
            match = _HEX_PAIR.fullmatch(line)
            if match:
                code = int(match[1], 16)
                try:
                    mapping[code] = bytes.fromhex(match[2].decode()).decode("utf-16-be")
                except (ValueError, UnicodeError):
                    continue
        elif mode == "range":
            match = _HEX_RANGE.fullmatch(line)
            if match:
                first, last, base = (int(part, 16) for part in match.groups())
                if last - first <= 255:
                    for code in range(first, last + 1):
                        with contextlib.suppress(ValueError):
                            mapping[code] = chr(base + code - first)
    return mapping


def _letter_codes(doc: fitz.Document, page: fitz.Page,
                  tolerant: bool = False) -> dict[bytes, set[int]]:
    result: dict[bytes, set[int]] = {}
    for xref, _ext, font_type, _base, resource, encoding, _referencer in page.get_fonts(full=True):
        if font_type not in ("Type1", "TrueType"):
            continue
        mapping = _unicode_map(doc, xref)
        if mapping is None:
            # Tolerant: a Type1 font without /Encoding uses its built-in one, Latin letters for
            # text fonts (the extracted-text check guards it).
            if encoding not in ("WinAnsiEncoding", "StandardEncoding") and not (
                    tolerant and font_type == "Type1" and not encoding):
                continue
            good = set(_ASCII_LETTERS)
        else:
            good = {code for code, char in mapping.items()
                    if code in _ASCII_LETTERS and char == chr(code)}
        if good:
            result[resource.encode("ascii")] = good
    return result


def _num(tokens: list[Token], index: int) -> float | None:
    if index < 0 or tokens[index].kind != "number":
        return None
    return float(tokens[index].value)


def _show_data(tokens: list[Token], op_index: int,
               array_open: dict[int, int]) -> tuple[int, bytes, list[float], float, float] | None:
    op = tokens[op_index].value
    if op == b"Tj":
        if op_index == 0 or tokens[op_index - 1].kind != "string":
            return None
        chars = bytes(tokens[op_index - 1].value)
        return tokens[op_index - 1].start, chars, [0.0] * max(0, len(chars) - 1), 0.0, 0.0
    if op != b"TJ" or op_index == 0 or tokens[op_index - 1].value != b"]":
        return None
    close = op_index - 1
    opening = array_open.get(close)
    if opening is None:
        return None
    chars = bytearray()
    gaps: list[float] = []
    pending = 0.0
    prefix = 0.0
    for token in tokens[opening + 1:close]:
        if token.kind == "number":
            pending += float(token.value)
        elif token.kind == "string":
            for ch in bytes(token.value):
                if chars:
                    gaps.append(pending)
                else:
                    prefix = pending
                chars.append(ch)
                pending = 0.0
        else:
            return None
    return tokens[opening].start, bytes(chars), gaps, prefix, pending


@dataclass
class TextRun:
    page: int
    stream: int
    xref: int
    ordinal: int
    start: int
    end: int
    font_size: float
    chars: bytes
    gaps: list[float]  # PDF TJ numbers, zero at implicit within-string gaps.
    prefix: float
    suffix: float
    letters: set[int]


@dataclass(frozen=True)
class Carrier:
    run: TextRun
    middle: int

    @property
    def identity(self) -> bytes:
        return (self.run.page.to_bytes(4, "big")
                + self.run.ordinal.to_bytes(4, "big")
                + self.middle.to_bytes(4, "big"))


def _scaling_cm(tokens: list[Token], i: int) -> bool:
    return i < 6 or any(_num(tokens, i - 6 + j) is None or
                        abs(float(tokens[i - 6 + j].value) - expected) > 1e-6
                        for j, expected in enumerate((1, 0, 0, 1)))


def _page_transformed(doc: fitz.Document, page: fitz.Page) -> bool:
    """Detect unsupported transformations that affect text placement.

    Ignore transformations inside balanced q/Q groups without text, including image
    overlays. Preserve the result when page streams are merged.
    """
    groups: list[list[bool]] = []  # [has text, has scaling cm] per open q.
    for xref in page.get_contents():
        tokens = tokenize(doc.xref_stream(xref))
        for i, token in enumerate(tokens):
            word = token.value if token.kind == "word" else None
            if word == b"q":
                groups.append([False, False])
            elif word == b"Q" and groups:
                has_text, scaled = groups.pop()
                if has_text and scaled:
                    return True
            elif word == b"BT":
                for group in groups:
                    group[0] = True
            elif word == b"cm" and _scaling_cm(tokens, i):
                if not groups:
                    return True
                groups[-1][1] = True
    return any(has_text and scaled for has_text, scaled in groups)


def _axis_scale(tokens: list[Token], i: int) -> float | None:
    """Return positive horizontal scaling for an axis-aligned matrix, or None."""
    values = [_num(tokens, i - 6 + j) for j in range(4)] if i >= 6 else [None]
    if any(v is None for v in values):
        return None
    a, b, c, d = values
    if abs(b) > 1e-9 or abs(c) > 1e-9 or a <= 0 or d <= 0:
        return None
    return a


def collect_runs(doc: fitz.Document, tolerant: bool = False, *, legacy_horizontal_scale: bool = False) -> list[TextRun]:
    """Collect text runs that satisfy strict or tolerant carrier policies.

    Strict mode accepts simple text. Tolerant mode also accepts positive axis-aligned text
    and page scaling, extra text state, and built-in font encodings, skipping unsupported
    pages. Both modes use the same TJ gaps for carrier bits.
    """
    # Legacy geometry is reserved for authenticated reads of pre-fix copies.
    runs: list[TextRun] = []
    seen_xrefs: set[int] = set()
    # Carriers are numbered by text page, not by page: dropping or adding a page without
    # carriers (a cover, a blank page) keeps every identity.
    page_no = 0
    for page in doc:
        if page.rotation:
            continue
        found = len(runs)
        try:
            page_runs = _page_runs(doc, page, page_no, seen_xrefs, tolerant, legacy_horizontal_scale)
        except UnsupportedText:
            if not tolerant:
                raise
            continue
        runs.extend(page_runs)
        if len(runs) > found:
            page_no += 1
    return runs


def _page_runs(doc: fitz.Document, page: fitz.Page, page_no: int,
               seen_xrefs: set[int], tolerant: bool, legacy_horizontal_scale: bool = False) -> list[TextRun]:
    runs: list[TextRun] = []
    seen_here: set[int] = set()
    fonts = _letter_codes(doc, page, tolerant)
    ordinal = 0
    # Tolerant mode follows the scale of axis-aligned cm instead.
    transformed = False if tolerant else _page_transformed(doc, page)
    # Font state survives BT/ET and stream boundaries; only Q restores the saved state.
    font_name: bytes | None = None
    font_size = 0.0
    # Horizontal scale of the text matrix and of the CTM (tolerant mode only).
    text_scale = 1.0
    ctm_scale: float | None = 1.0  # None: rotated or skewed.
    horizontal_scale: float | None = 1.0
    fonts_saved: list[tuple[bytes | None, float, float | None, float | None]] = []
    for stream_no, xref in enumerate(page.get_contents()):
        # A resave with garbage collection merges identical streams (e.g. the q/Q wrappers of
        # overlays). A shared stream still counts towards the ordinals, but only its first
        # occurrence yields carriers.
        shared = xref in seen_xrefs or xref in seen_here
        seen_here.add(xref)
        data = doc.xref_stream(xref)
        tokens = tokenize(data)
        array_stack: list[int] = []
        array_open: dict[int, int] = {}
        for i, token in enumerate(tokens):
            if token.value == b"[" and token.kind == "symbol":
                array_stack.append(i)
            elif token.value == b"]" and token.kind == "symbol":
                if not array_stack:
                    raise UnsupportedText("unbalanced PDF array")
                array_open[i] = array_stack.pop()
        if array_stack:
            raise UnsupportedText("unbalanced PDF array")

        inside = False
        simple_state = True
        for i, token in enumerate(tokens):
            word = token.value if token.kind == "word" else None
            if word == b"q":
                fonts_saved.append((font_name, font_size, ctm_scale, horizontal_scale))
            elif word == b"Q" and fonts_saved:
                font_name, font_size, ctm_scale, horizontal_scale = fonts_saved.pop()
            elif word == b"cm" and tolerant:
                scale = _axis_scale(tokens, i)
                ctm_scale = None if scale is None or ctm_scale is None else ctm_scale * scale
            elif word == b"BT":
                inside = True
                simple_state = not transformed
                text_scale = 1.0
            elif word == b"ET":
                inside = False
            elif word == b"Tf" and i >= 2:
                if tokens[i - 2].kind == "name" and _num(tokens, i - 1) is not None:
                    font_name = bytes(tokens[i - 2].value)
                    font_size = float(tokens[i - 1].value)
                else:
                    font_name = None
            elif word in (b"Tc", b"Tw", b"Ts", b"Tr") and inside:
                if _num(tokens, i - 1) is None or (
                        abs(float(tokens[i - 1].value)) > 1e-9 and not tolerant):
                    simple_state = False
            elif word == b"Tz":
                value = _num(tokens, i - 1)
                horizontal_scale = value / 100 if value is not None and value > 0 else None
            elif word == b"Tm" and inside:
                scale = _axis_scale(tokens, i) if tolerant else None
                if scale is not None:
                    text_scale = scale
                elif _scaling_cm(tokens, i):
                    simple_state = False
            elif word in (b"Tj", b"TJ", b"'", b'"'):
                if inside:
                    ordinal += 1
                scale = 1.0 if legacy_horizontal_scale else horizontal_scale
                size = font_size * text_scale * (ctm_scale or 0.0) * (scale or 0.0)
                if not tolerant and (scale is None or abs(scale - 1) > 1e-11):
                    continue
                if not inside or not simple_state or font_name not in fonts or not 8 <= size <= 30:
                    continue
                show = _show_data(tokens, i, array_open)
                if show is None:
                    continue
                start, chars, gaps, prefix, suffix = show
                if len(chars) >= 3 and not shared:
                    runs.append(TextRun(page_no, stream_no, xref, ordinal,
                                        start, token.end, size, chars,
                                        gaps, prefix, suffix, fonts[font_name]))
    seen_xrefs |= seen_here
    return runs


def carriers(runs: list[TextRun]) -> list[Carrier]:
    result: list[Carrier] = []
    for run in runs:
        i = 0
        while i + 2 < len(run.chars):
            if all(code in run.letters for code in run.chars[i:i + 3]):
                result.append(Carrier(run, i + 1))
                i += 2  # No gap belongs to two carriers.
            else:
                i += 1
    return result


def serialize_run(run: TextRun) -> bytes:
    """Serialize one modified show operation, leaving other page bytes alone."""
    items: list[bytes] = []
    if abs(run.prefix) > 1e-9:
        items.append(_format_number(run.prefix))
    chunk = bytearray()
    for index, code in enumerate(run.chars):
        chunk.append(code)
        if index < len(run.gaps) and abs(run.gaps[index]) > 1e-9:
            items.append(b"<" + chunk.hex().encode("ascii") + b">")
            items.append(_format_number(run.gaps[index]))
            chunk.clear()
    if chunk:
        items.append(b"<" + chunk.hex().encode("ascii") + b">")
    if abs(run.suffix) > 1e-9:
        items.append(_format_number(run.suffix))
    return b"[" + b" ".join(items) + b"] TJ"


def _format_number(value: float) -> bytes:
    return (f"{value:.6f}".rstrip("0").rstrip(".") or "0").encode("ascii")


def replace_runs(doc: fitz.Document, modified: list[TextRun]) -> None:
    by_xref: dict[int, list[TextRun]] = {}
    for run in modified:
        by_xref.setdefault(run.xref, []).append(run)
    for xref, edits in by_xref.items():
        content = doc.xref_stream(xref)
        for run in sorted(edits, key=lambda item: item.start, reverse=True):
            content = content[:run.start] + serialize_run(run) + content[run.end:]
        doc.update_stream(xref, content)
