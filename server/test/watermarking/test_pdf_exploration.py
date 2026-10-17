"""PDF exploration contracts, independent from watermark method registration."""

import hashlib
import json
import sys
from types import SimpleNamespace

import pymupdf as fitz
import pytest

import watermarking_utils as utils


def _digest(data):
    return hashlib.sha1(data, usedforsecurity=False).hexdigest()


@pytest.fixture
def native_pdf():
    with fitz.open() as doc:
        first = doc.new_page(width=300, height=400)
        first.insert_text((40, 50), "First page")
        second = doc.new_page(width=500, height=700)
        second.insert_text((40, 50), "Second page")
        typed = doc.get_new_xref()
        doc.update_object(typed, "<< /Type /Example /Value 7 >>")
        plain = doc.get_new_xref()
        doc.update_object(plain, "<< /Value 9 >>")
        data = doc.tobytes()
        pages = [doc.page_xref(i) for i in range(2)]
        streams = {xref for page in doc for xref in page.get_contents()}
        hashes = {xref: _digest(doc.xref_object(xref).encode("utf-8"))
                  for xref in range(1, doc.xref_length())}
        return SimpleNamespace(data=data, pages=pages, streams=streams, hashes=hashes,
                               typed=typed, plain=plain, catalog=doc.pdf_catalog())


def test_native_exploration_describes_document_and_pages(native_pdf):
    tree = utils.explore_pdf(native_pdf.data)
    assert tree["id"] == f"pdf:{_digest(native_pdf.data)}"
    assert tree["type"] == "Document"
    assert tree["size"] == len(native_pdf.data)
    pages = [node for node in tree["children"] if node["type"] == "Page" and "index" in node]
    assert pages == [
        {"id": "page:0000", "type": "Page", "index": 0, "bbox": [0, 0, 300, 400]},
        {"id": "page:0001", "type": "Page", "index": 1, "bbox": [0, 0, 500, 700]},
    ]
    assert tree == utils.explore_pdf(native_pdf.data)
    assert json.loads(json.dumps(tree)) == tree


def test_native_exploration_inventories_xref_objects(native_pdf):
    tree = utils.explore_pdf(native_pdf.data)
    objects = [node for node in tree["children"] if "xref" in node]
    assert [node["xref"] for node in objects] == list(native_pdf.hashes)
    for node in objects:
        xref = node["xref"]
        assert node["id"] == f"obj:{xref:06d}"
        assert node["is_stream"] is (xref in native_pdf.streams)
        assert node["content_sha1"] == native_pdf.hashes[xref]
    by_xref = {node["xref"]: node for node in objects}
    assert by_xref[native_pdf.catalog]["type"] == "Catalog"
    assert all(by_xref[xref]["type"] == "Page" for xref in native_pdf.pages)
    assert by_xref[native_pdf.typed]["type"] == "Example"
    assert by_xref[native_pdf.plain]["type"] == "Object"


@pytest.mark.parametrize("error", [RuntimeError, ValueError, AttributeError])
def test_unreadable_xref_has_no_invented_content(native_pdf, monkeypatch, error):
    opened = []

    class Document:
        def __init__(self):
            self.doc = fitz.open(stream=native_pdf.data, filetype="pdf")
            opened.append(self.doc)

        def __getattr__(self, name):
            return getattr(self.doc, name)

        def xref_object(self, xref, **kwargs):
            if xref == native_pdf.typed:
                raise error("private-object-canary")
            return self.doc.xref_object(xref, **kwargs)

    monkeypatch.setitem(sys.modules, "fitz", SimpleNamespace(open=lambda **_kwargs: Document()))
    try:
        tree = utils.explore_pdf(native_pdf.data)
        by_xref = {node["xref"]: node for node in tree["children"] if "xref" in node}
        assert by_xref[native_pdf.typed]["content_sha1"] is None
        assert by_xref[native_pdf.typed]["type"] == "Object"
        assert by_xref[native_pdf.plain]["content_sha1"] == native_pdf.hashes[native_pdf.plain]
    finally:
        for doc in opened:
            if not doc.is_closed:
                doc.close()


def _named_objects(names):
    with fitz.open() as doc:
        doc.new_page()
        xrefs = []
        for name in names:
            xref = doc.get_new_xref()
            doc.update_object(xref, f"<< /Type /Example /Name /{name} >>")
            xrefs.append(xref)
        return doc.tobytes(), xrefs


@pytest.mark.parametrize("name", [r"\u6F22", r"\U0001F600", r"\uD800", r"\uDC00"])
def test_unicode_pdf_names_keep_native_exploration(name):
    data, xrefs = _named_objects([name])
    tree = utils.explore_pdf(data)
    objects = {node["xref"]: node for node in tree["children"] if "xref" in node}
    assert objects[xrefs[0]]["type"] == "Example"
    assert objects[xrefs[0]]["content_sha1"] is not None


@pytest.mark.parametrize("names", [(r"\u6F22", r"\u5B57"), (r"\uD800", r"\uDC00")])
def test_distinct_unicode_pdf_names_have_distinct_fingerprints(names):
    data, xrefs = _named_objects(names)
    tree = utils.explore_pdf(data)
    objects = {node["xref"]: node for node in tree["children"] if "xref" in node}
    hashes = [objects[xref]["content_sha1"] for xref in xrefs]
    assert None not in hashes
    assert len(set(hashes)) == len(names)


@pytest.mark.parametrize("error", [ImportError, RuntimeError, ValueError, AttributeError])
@pytest.mark.parametrize("unterminated", [False, True])
def test_regex_fallback_preserves_objects_and_page_references(monkeypatch, caplog, error, unterminated):
    bodies = [b" << /Type /Page >> ", b" << /Value 7 >> ", b" << /Type /Page >> "]
    headers = [(5, 2), (9, 3), (17, 7)]
    data = b"%PDF-1.4\n" + b"".join(
        f"{obj} {generation} obj".encode() + body + b"endobj\n"
        for (obj, generation), body in zip(headers, bodies, strict=True)
    )
    if unterminated:
        data += b"23 4 obj << /Type /Font >>"
    calls = []

    def unavailable(**kwargs):
        calls.append(kwargs.get("stream"))
        raise error("private-fallback-canary")

    monkeypatch.setitem(sys.modules, "fitz", SimpleNamespace(open=unavailable))
    tree = utils.explore_pdf(data)
    assert calls == [data]
    assert tree["id"] == f"pdf:{_digest(data)}"
    assert tree["type"] == "Document"
    assert tree["size"] == len(data)
    objects = [
        {"id": f"obj:{obj:06d}:{generation:05d}", "type": kind,
         "object": obj, "generation": generation, "content_sha1": _digest(body)}
        for (obj, generation), body, kind in zip(headers, bodies, ["Page", "Object", "Page"], strict=True)
    ]
    if unterminated:
        objects.append({"id": "obj:000023:00004", "type": "Object", "object": 23,
                        "generation": 4, "content_sha1": _digest(b"")})
    assert tree["children"] == [
        {"id": "page:0000", "type": "Page", "xref_hint": "obj:000005:00002"},
        {"id": "page:0001", "type": "Page", "xref_hint": "obj:000017:00007"},
        *objects,
    ]
    assert "private-fallback-canary" not in caplog.text
    assert json.loads(json.dumps(tree)) == tree
