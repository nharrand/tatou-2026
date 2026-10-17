"""PDF tokenization, font eligibility, text geometry and surgical stream edits."""

from __future__ import annotations

from itertools import pairwise

import pymupdf as fitz
import pytest

from watermarking_methods.khaled import pdf_text as parser
from watermarking_methods.khaled.pdf_text import TextRun, Token, _literal, carriers, tokenize


def test_literal_returns_content_and_next_position():
    assert _literal(b"(abc)", 0) == (b"abc", 5)


@pytest.mark.parametrize(("data", "expected"), [
    pytest.param(b"  ", [], id="whitespace"),
    pytest.param(b" <41><42>", [Token("string", b"A", 1, 5), Token("string", b"B", 5, 9)], id="hex-strings"),
    pytest.param(b" []", [Token("symbol", b"[", 1, 2), Token("symbol", b"]", 2, 3)], id="delimiters"),
    pytest.param(b"/AA /B", [Token("name", b"AA", 0, 3), Token("name", b"B", 4, 6)], id="names"),
    pytest.param(b" ab", [Token("word", b"ab", 1, 3)], id="words"),
])
def test_tokenize_preserves_values_and_offsets(data, expected):
    assert tokenize(data) == expected


@pytest.mark.parametrize(("chars", "expected"), [
    pytest.param(b"ABCDE", [1, 3], id="non-overlapping-gaps"),
    pytest.param(b"1234", [], id="no-letter-carriers"),
    pytest.param(b"1ABCDE", [2, 4], id="offset-letters"),
    pytest.param(b"ABC1DE", [1], id="broken-final-triple"),
    pytest.param(b"ABCD1EFG", [1, 6], id="separated-letter-runs"),
])
def test_carriers_select_non_overlapping_letter_gaps(chars, expected):
    run = TextRun(
        page=0, stream=0, xref=1, ordinal=0, start=0, end=len(chars),
        font_size=10.0, chars=chars, gaps=[0.0] * (len(chars) - 1),
        prefix=0.0, suffix=0.0, letters=set(b"ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
    )

    selected = carriers([run])

    assert [item.middle for item in selected] == expected
    assert all(item.run is run for item in selected)


def _document(content):
    document = fitz.open()
    page = document.new_page(width=600, height=800)
    page.insert_text((50, 50), "ABCDE", fontsize=10)
    resource = page.get_fonts()[0][4].encode()
    document.update_stream(page.get_contents()[0], content.replace(b"/F1", b"/" + resource))
    return document


def _set_cmap(document, content):
    xref = document.get_new_xref()
    document.update_object(xref, "<<>>")
    document.update_stream(xref, content)
    document.xref_set_key(document[0].get_fonts()[0][0], "ToUnicode", f"{xref} 0 R")


@pytest.mark.parametrize("payload,expected", [
    (rb"(a\nb\rc\td\be\f)", b"a\nb\rc\td\be\f"),
    (rb"(a\(b\)c\\)", b"a(b)c\\"),
    (b"(a(b)c)", b"a(b)c"),
    (rb"(\377)", b"\xff"),
    (rb"(\X)", b"X"),
    (rb"(\1X)", b"\x01X"),
    (rb"(\101\7\12\1234)", b"A\x07\nS4"),
    (b"(a\\\r\nb\\\rc\\\nd)", b"abcd"),
])
def test_literal_decodes_pdf_escapes(payload, expected):
    value, end = parser._literal(payload + b" Tj", 0)
    assert value == expected
    assert end == len(payload)


@pytest.mark.parametrize("payload", [b"(unfinished", b"(escape\\", b"(\\1", b"(a\\\r", rb"(\400)", rb"(\777)"])
def test_literal_rejects_incomplete_or_invalid_input(payload):
    with pytest.raises(parser.UnsupportedText):
        parser._literal(payload, 0)


@pytest.mark.parametrize("data,expected", [
    (b"%aXtail\rY", [("word", b"Y")]),
    (b"/ []", [("name", b""), ("symbol", b"["), ("symbol", b"]")]),
    (b"XX (abc) <>", [("word", b"XX"), ("string", b"abc"), ("string", b"")]),
    (b"%comment\r\n<4 1 4> Tj", [("string", b"A@"), ("word", b"Tj")]),
    (b"<< /A [1 -2.5 +.25] >>", [("symbol", b"<<"), ("name", b"A"), ("symbol", b"["),
                                    ("number", 1.0), ("number", -2.5), ("number", .25),
                                    ("symbol", b"]"), ("symbol", b">>")]),
    (b"0\x00\t1\f2\r3\n4", [("number", float(i)) for i in range(5)]),
])
def test_token_values_and_byte_intervals(data, expected):
    tokens = parser.tokenize(data)
    assert [(token.kind, token.value) for token in tokens] == expected
    assert all(0 <= token.start < token.end <= len(data) for token in tokens)
    assert all(a.end <= b.start for a, b in pairwise(tokens))


@pytest.mark.parametrize("data", [b"<41", b"<ZZ>", b")", b"BI", b"9" * 400])
def test_tokenizer_rejects_unsupported_syntax(data):
    with pytest.raises(parser.UnsupportedText):
        parser.tokenize(data)


@pytest.mark.parametrize("cmap,expected", [
    (b"2 beginbfchar\n<41> <0041>\n<42> <0042>\nendbfchar", {65: "A", 66: "B"}),
    (b"1 beginbfrange\n<41> <43> <0041>\nendbfrange", {65: "A", 66: "B", 67: "C"}),
    (b"1 beginbfchar\n<41> <0042>\nendbfchar", {65: "B"}),
    (b"1 beginbfchar\n<4A> <004A>\nendbfchar", {74: "J"}),
    (b"1 beginbfrange\n<4a> <4c> <004a>\nendbfrange", {74: "J", 75: "K", 76: "L"}),
])
def test_unicode_mapping_uses_explicit_font_values(cmap, expected):
    with _document(b"BT /F1 10 Tf (ABCDE) Tj ET") as document:
        _set_cmap(document, cmap)
        assert parser._unicode_map(document, document[0].get_fonts()[0][0]) == expected
        runs = parser.collect_runs(document)
        eligible = {code for code, char in expected.items()
                    if code in b"ABCDEFGHIJKLMNOPQRSTUVWXYZ" and char == chr(code)}
        assert (runs[0].letters if runs else set()) == eligible


@pytest.mark.parametrize("target", [b"00041", b"D800", b"004100"])
def test_malformed_cmap_does_not_hide_other_fonts(target):
    with _document(b"BT /F1 10 Tf (ABCDE) Tj ET") as document:
        _set_cmap(document, b"1 beginbfchar\n<41> <" + target + b">\nendbfchar")
        good = document.new_page()
        for row in range(42):
            good.insert_text((40, 40 + row * 17), "Simple selectable letters remain usable on another page",
                             fontsize=10, fontname="tiro")
        for tolerant in (False, True):
            runs = parser.collect_runs(document, tolerant)
            assert len(parser.carriers(runs)) >= 640
            assert all(run.xref in good.get_contents() for run in runs)


@pytest.mark.parametrize("percent", [80, 100, 200, 300, 301, 79, 0, -100])
@pytest.mark.parametrize("tolerant", [False, True])
def test_horizontal_scale_inherits_between_text_objects(percent, tolerant):
    content = f"BT /F1 10 Tf {percent} Tz ET BT 50 50 Td (ABCDE) Tj ET".encode()
    with _document(content) as document:
        runs = parser.collect_runs(document, tolerant)
        expected = 8 <= percent / 10 <= 30 and (tolerant or percent == 100)
        assert bool(runs) is expected
        if expected:
            assert runs[0].font_size == pytest.approx(percent / 10)


def _origins(page):
    return [char["origin"] for block in page.get_text("rawdict")["blocks"] if "lines" in block
            for line in block["lines"] for span in line["spans"] for char in span["chars"]]


@pytest.mark.parametrize("percent", [80, 100, 200])
def test_horizontal_scaling_preserves_real_glyph_displacement(percent):
    with _document(f"BT /F1 10 Tf {percent} Tz 50 50 Td (ABCDE) Tj ET".encode()) as document:
        runs = parser.collect_runs(document, True)
        before = _origins(document[0])
        run = runs[0]
        adjustment = .08 * 1000 / run.font_size
        run.gaps[0] -= adjustment
        run.gaps[1] += adjustment
        parser.replace_runs(document, [run])
        after = _origins(document[0])
        assert after[1][0] - before[1][0] == pytest.approx(.08, abs=1e-4)
        assert after[1][1] == before[1][1]
        for index in (0, 2, 3, 4):
            assert after[index] == pytest.approx(before[index], abs=1e-4)


def test_horizontal_scale_restores_at_graphics_state_boundary():
    content = b"BT /F1 10 Tf ET q BT 200 Tz 50 100 Td (ABCDE) Tj ET Q BT 50 50 Td (ABCDE) Tj ET"
    with _document(content) as document:
        assert [r.font_size for r in parser.collect_runs(document, True)] == [20, 10]
        assert len(parser.collect_runs(document, False)) == 1


@pytest.mark.parametrize("content,chars,gaps,prefix,suffix", [
    (b"(ABCDE) Tj", b"ABCDE", [0, 0, 0, 0], 0, 0),
    (b"() Tj", b"", [], 0, 0),
    (b"(A) Tj", b"A", [], 0, 0),
    (b"[(AB) (CDE)] TJ", b"ABCDE", [0, 0, 0, 0], 0, 0),
    (b"[12 (AB) 3 -5 (CDE) 9] TJ", b"ABCDE", [0, -2, 0, 0], 12, 9),
])
def test_show_operands_preserve_gap_components(content, chars, gaps, prefix, suffix):
    tokens = parser.tokenize(content)
    opens = {i: 0 for i, token in enumerate(tokens) if token.value == b"]"}
    result = parser._show_data(tokens, len(tokens) - 1, opens)
    assert result is not None
    assert result[1:] == (chars, gaps, prefix, suffix)


@pytest.mark.parametrize("prefix,suffix,gaps", [
    (12, -9, [0, -23, .25, 4]), (.25, -.5, [0, 0, 0, 0]), (0, 0, [0, 0, 0, 0]),
])
def test_serialization_preserves_numeric_values(prefix, suffix, gaps):
    run = TextRun(0, 0, 1, 1, 0, 0, 10, b"ABCDE", list(gaps), prefix, suffix, set(b"ABCDE"))
    tokens = parser.tokenize(parser.serialize_run(run))
    close = len(tokens) - 2
    assert parser._show_data(tokens, len(tokens) - 1, {close: 0})[1:] == (b"ABCDE", gaps, prefix, suffix)


def test_replacement_keeps_unrelated_bytes_and_handles_multiple_edits():
    data = b"q 1 0 0 rg Q\nBT /F1 10 Tf 50 50 Td [(ABC) -10 (DE)] TJ (FGHIJ) Tj ET\n%tail"
    with _document(data) as document:
        page = document[0]
        original = document.xref_stream(page.get_contents()[0])
        runs = parser.collect_runs(document)
        assert len(runs) == 2
        expected_parts = [original[:runs[0].start], original[runs[0].end:runs[1].start], original[runs[1].end:]]
        for run in runs:
            run.gaps[0] += .25
        parser.replace_runs(document, runs)
        rewritten = document.xref_stream(page.get_contents()[0])
        assert rewritten == (expected_parts[0] + parser.serialize_run(runs[0]) + expected_parts[1]
                             + parser.serialize_run(runs[1]) + expected_parts[2])
        reread = parser.collect_runs(document)
        assert [(r.chars, r.gaps) for r in reread] == [(r.chars, r.gaps) for r in runs]


@pytest.mark.parametrize("content,expected", [
    (b"BT /F1 10 Tf (ABCDE) Tj ET", True),
    (b"1 0 0 1 0 0 cm BT /F1 10 Tf (ABCDE) Tj ET", True),
    (b"BT /F1 10 Tf (cm) Tj (ABCDE) Tj ET", True),
    (b"q 2 0 0 2 0 0 cm 0 0 m 10 10 l S Q BT /F1 10 Tf (ABCDE) Tj ET", True),
    (b"q 2 0 0 2 0 0 cm BT /F1 10 Tf (ABCDE) Tj ET Q", False),
    (b"BT /F1 7.9 Tf (ABCDE) Tj ET", False),
    (b"BT /F1 30 Tf (ABCDE) Tj ET", True),
    (b"BT /F1 30.1 Tf (ABCDE) Tj ET", False),
])
def test_strict_carrier_state_eligibility(content, expected):
    with _document(content) as document:
        assert bool(parser.carriers(parser.collect_runs(document))) is expected


def test_carrier_identity_ignores_empty_cover_and_duplicate_streams():
    with _document(b"BT /F1 10 Tf 50 50 Td (ABCDEFGHI) Tj ET") as document:
        original = parser.carriers(parser.collect_runs(document))
        ids = [c.identity for c in original]
        xref = document[0].get_contents()[0]
        document.xref_set_key(document[0].xref, "Contents", f"[{xref} 0 R {xref} 0 R]")
        assert [c.identity for c in parser.carriers(parser.collect_runs(document))] == ids
        document.new_page(pno=0)
        assert [c.identity for c in parser.carriers(parser.collect_runs(document))] == ids


@pytest.mark.parametrize("ending,noise", [
    (b"endbfchar", b"<42> <0042>"),
    (b"endbfrange", b"<44> <45> <0044>"),
])
def test_cmap_ignores_mapping_shaped_data_outside_blocks(ending, noise):
    start = b"1 beginbfchar\n<41> <0041>\n" if ending == b"endbfchar" else b"1 beginbfrange\n<41> <41> <0041>\n"
    with _document(b"BT /F1 10 Tf (ABCDE) Tj ET") as document:
        _set_cmap(document, start + ending + b"\n" + noise)
        assert parser._unicode_map(document, document[0].get_fonts()[0][0]) == {65: "A"}


@pytest.mark.parametrize("subtype", ["Type1", "TrueType", "Type0"])
@pytest.mark.parametrize("encoding", ["WinAnsiEncoding", "StandardEncoding", "null"])
@pytest.mark.parametrize("tolerant", [False, True])
def test_font_metadata_eligibility(subtype, encoding, tolerant):
    with _document(b"BT /F1 10 Tf (ABCDE) Tj ET") as document:
        xref = document[0].get_fonts()[0][0]
        document.xref_set_key(xref, "Subtype", "/" + subtype)
        document.xref_set_key(xref, "Encoding", "null" if encoding == "null" else "/" + encoding)
        eligible = parser._letter_codes(document, document[0], tolerant)
        expected = subtype in ("Type1", "TrueType") and (
            encoding != "null" or (tolerant and subtype == "Type1")
        )
        assert bool(eligible) is expected


@pytest.mark.parametrize("state,strict,tolerant", [
    (b"0 Tc 0 Tw 0 Ts 0 Tr 100 Tz", True, True),
    (b"1 Tc", False, True), (b"1 Tw", False, True),
    (b"1 Ts", False, True), (b"1 Tr", False, True),
    (b"150 Tz", False, True), (b"0 Tz", False, False),
    (b"1 0 0 1 40 40 Tm", True, True),
    (b"2 0 0 2 40 40 Tm", False, True),
    (b"1 .1 0 1 40 40 Tm", False, False),
    (b"0 0 0 1 40 40 Tm", False, False),
    (b"bad 0 0 1 40 40 Tm", False, False),
])
def test_text_operator_state_eligibility(state, strict, tolerant):
    with _document(b"BT /F1 10 Tf " + state + b" (ABCDE) Tj ET") as document:
        assert bool(parser.carriers(parser.collect_runs(document, False))) is strict
        assert bool(parser.carriers(parser.collect_runs(document, True))) is tolerant


@pytest.mark.parametrize("matrices,effective", [
    (b"2 0 0 3 0 0 cm", 20),
    (b"2 0 0 2 0 0 cm .5 0 0 .5 0 0 cm", 10),
    (b"1 .1 0 1 0 0 cm", None),
    (b"-1 0 0 1 0 0 cm", None),
])
@pytest.mark.parametrize("wrapped", [False, True])
def test_page_axis_scale_composes_without_accepting_skew(matrices, effective, wrapped):
    content = matrices + b" BT /F1 10 Tf (ABCDE) Tj ET"
    with _document(b"q " + content + b" Q" if wrapped else content) as document:
        assert not parser.collect_runs(document, False)
        runs = parser.collect_runs(document, True)
        assert ([run.font_size for run in runs] if runs else []) == ([] if effective is None else [effective])


@pytest.mark.parametrize("data", [b"1 Tj", b"TJ", b"[(ABCDE)] '", b"[1] noop"])
def test_unsupported_show_operands_are_not_reinterpreted(data):
    tokens = parser.tokenize(data)
    close = {i: 0 for i, token in enumerate(tokens) if token.value == b"]"}
    assert parser._show_data(tokens, len(tokens) - 1, close) is None


@pytest.mark.parametrize("data", [b"BT /F1 10 Tf [(ABCDE) Tj ET", b"BT /F1 10 Tf ] TJ ET"])
def test_unbalanced_arrays_are_rejected_or_skipped_by_policy(data):
    with _document(data) as document:
        with pytest.raises(parser.UnsupportedText):
            parser.collect_runs(document, False)
        assert not parser.collect_runs(document, True)


@pytest.mark.parametrize("unsupported", ["rotation", "inline-image"])
@pytest.mark.parametrize("tolerant", [False, True])
def test_unsupported_first_page_keeps_later_carriers(unsupported, tolerant):
    with _document(b"BT /F1 10 Tf 50 50 Td (ABCDE) Tj ET") as document:
        if unsupported == "rotation":
            document[0].set_rotation(90)
        else:
            document.update_stream(document[0].get_contents()[0], b"BI /W 1 /H 1 ID x EI")
        page = document.new_page()
        page.insert_text((50, 50), "ABCDEFGHI", fontsize=10)
        if unsupported == "inline-image" and not tolerant:
            with pytest.raises(parser.UnsupportedText):
                parser.collect_runs(document, tolerant)
            return
        runs = parser.collect_runs(document, tolerant)
        assert len(parser.carriers(runs)) == 4
        assert all(run.xref in page.get_contents() for run in runs)


def test_carrier_page_identity_counts_only_usable_pages():
    with _document(b"BT /F1 10 Tf 50 50 Td (ABCDE) Tj ET") as document:
        for _ in range(2):
            page = document.new_page()
            page.insert_text((50, 50), "ABCDE", fontsize=10)
        selected = parser.carriers(parser.collect_runs(document))
        assert [int.from_bytes(c.identity[:4], "big") for c in selected] == [0, 0, 1, 1, 2, 2]
        identities = [c.identity for c in selected]
        document.new_page(pno=1)
        assert [c.identity for c in parser.carriers(parser.collect_runs(document))] == identities


@pytest.mark.parametrize("content,expected", [
    (b"BT /F1 10 Tf (ABC) Tj ET", [b"ABC"]),
    (b"/F1 10 Tf BT (ABCDE) Tj ET", [b"ABCDE"]),
    (b"BT /F1 10 Tf (ABCDE) Tj ET (FGHIJ) Tj", [b"ABCDE"]),
    (b"BT /F1 10 Tf (ABCDE) Tj ET BT /F1 1 Tf (x) Tj ET BT /F1 10 Tf (FGHIJ) Tj ET",
     [b"ABCDE", b"FGHIJ"]),
    (b"BT /F1 10 Tf (ABCDE) ' (FGHIJ) Tj ET", [b"FGHIJ"]),
    (b'BT /F1 10 Tf 0 0 (ABCDE) " (FGHIJ) Tj ET', [b"FGHIJ"]),
])
def test_run_selection_respects_text_object_boundaries(content, expected):
    with _document(content) as document:
        assert [run.chars for run in parser.collect_runs(document)] == expected


@pytest.mark.parametrize("matrix", [
    b"1 .01 0 1 0 0", b"1 0 .01 1 0 0", b"-1 0 0 1 0 0", b"1 0 0 -1 0 0", b"1 0 0 0 0 0",
])
def test_tolerant_geometry_rejects_skew_and_reflections(matrix):
    with _document(b"q " + matrix + b" cm BT /F1 10 Tf (ABCDE) Tj ET Q") as document:
        assert not parser.collect_runs(document, True)


def test_shared_stream_is_not_reused_after_an_independent_page():
    with _document(b"BT /F1 10 Tf (ABCDE) Tj ET") as document:
        shared = document[0].get_contents()[0]
        page = document.new_page()
        page.insert_text((50, 50), "FGHIJ", fontsize=10)
        page = document.new_page()
        page.insert_text((50, 50), "ABCDE", fontsize=10)
        document.xref_set_key(page.xref, "Contents", f"{shared} 0 R")
        assert [r.chars for r in parser.collect_runs(document)] == [b"ABCDE", b"FGHIJ"]


@pytest.mark.parametrize("first_font", ["unsupported-subtype", "unsupported-encoding"])
def test_unusable_font_keeps_later_font_eligible(first_font):
    with _document(b"BT /F1 10 Tf (ABCDE) Tj ET") as document:
        first = document[0].get_fonts()[0][0]
        if first_font == "unsupported-subtype":
            document.xref_set_key(first, "Subtype", "/Type0")
        else:
            document.xref_set_key(first, "Encoding", "/UnsupportedEncoding")
        document[0].insert_text((50, 100), "FGHIJ", fontname="tiro", fontsize=10)
        assert [run.chars for run in parser.collect_runs(document)] == [b"FGHIJ"]


def test_unsupported_quotes_still_count_in_carrier_identity():
    with _document(b'BT /F1 10 Tf (ABCDE) \' 0 0 (FGHIJ) " (KLMNO) Tj ET') as document:
        items = parser.carriers(parser.collect_runs(document))
        assert len(items) == 2
        assert all(int.from_bytes(item.identity[4:8], "big") == 3 for item in items)


def test_string_operands_are_not_interpreted_as_text_operators():
    with _document(b"BT /F1 10 Tf (ET) Tj (ABCDE) Tj ET") as document:
        assert [run.chars for run in parser.collect_runs(document)] == [b"ABCDE"]


@pytest.mark.parametrize("first", [0, 65])
def test_single_byte_cmap_full_range_preserves_ascii_letters(first):
    with _document(b"BT /F1 10 Tf (ABCDE) Tj ET") as document:
        cmap = f"1 beginbfrange\n<{first:02X}> <FF> <{first:04X}>\nendbfrange".encode()
        _set_cmap(document, cmap)
        assert len(parser.carriers(parser.collect_runs(document))) == 2


def test_tolerant_font_policy_is_forwarded_to_the_parser():
    with _document(b"BT /F1 10 Tf (ABCDE) Tj ET") as document:
        document.xref_set_key(document[0].get_fonts()[0][0], "Encoding", "null")
        assert not parser.collect_runs(document)
        assert len(parser.carriers(parser.collect_runs(document, True))) == 2


def test_marked_content_dictionary_keeps_text_eligible():
    with _document(b"/Span << /MCID 0 >> BDC BT /F1 10 Tf (ABCDE) Tj ET EMC") as document:
        assert len(parser.carriers(parser.collect_runs(document))) == 2


@pytest.mark.parametrize("target", [b"00041", b"D800", b"004100"])
def test_malformed_cmap_entry_preserves_independent_valid_entries(target):
    with _document(b"BT /F1 10 Tf (AAAAA) Tj ET") as document:
        _set_cmap(document, b"2 beginbfchar\n<41> <0041>\n<42> <" + target + b">\nendbfchar")
        assert parser._unicode_map(document, document[0].get_fonts()[0][0]) == {65: "A"}
        assert len(parser.carriers(parser.collect_runs(document))) == 2
