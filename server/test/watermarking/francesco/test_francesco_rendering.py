"""Visual rendering and layout tests for QR and visible-label layers."""

from __future__ import annotations

import io

import pymupdf as fitz
import pytest
from PIL import Image

from watermarking_methods.francesco import rendering

KEY = "0123456789abcdef" * 4


def test_qr_png_bytes_are_opaque():
    payload = "v1.testpayload"
    png_bytes = rendering.build_opaque_qr_bytes(payload, target_pixel_size=240)
    assert isinstance(png_bytes, bytes)
    assert png_bytes.startswith(b"\x89PNG")
    with Image.open(io.BytesIO(png_bytes)) as png:
        assert png.getchannel("A").getextrema() == (255, 255)


def test_random_qr_avoids_content_and_stays_on_the_border():
    text_box = (100.0, 300.0, 450.0, 350.0)
    placed_boxes = [text_box]
    first = rendering.random_qr_rect(595.0, 842.0, placed_boxes, b"seed-qr-test", min_gap=15.0)
    placed_boxes.append(first)
    second = rendering.random_qr_rect(595.0, 842.0, placed_boxes, b"other-seed", min_gap=15.0)

    edge_inset = max(4.0, min(595.0, 842.0) * 0.012)
    qr_side = min(595.0, 842.0) * rendering.DEFAULT_QR_FRACTION
    for x0, y0, x1, y1 in (first, second):
        assert abs((x1 - x0) - qr_side) < 0.01
        assert (
            x0 <= edge_inset + 0.01
            or y0 <= edge_inset + 0.01
            or x1 >= 595.0 - edge_inset - 0.01
            or y1 >= 842.0 - edge_inset - 0.01
        )
    assert not rendering.boxes_overlap(first, text_box, min_gap=15.0)
    assert not rendering.boxes_overlap(second, text_box, min_gap=15.0)
    assert not rendering.boxes_overlap(first, second, min_gap=15.0)


def test_qr_refuses_to_cover_content_when_no_border_space_exists():
    with pytest.raises(ValueError, match="No text-free border position"):
        rendering.random_qr_rect(595.0, 842.0, [(0.0, 0.0, 595.0, 842.0)], b"blocked-page")


def test_corner_qr_is_flush_to_a_corner():
    x0, y0, x1, y1 = rendering.corner_qr_rect(595.0, 842.0, b"seed")
    side = 595.0 * rendering.DEFAULT_QR_FRACTION
    assert x0 in (0.0, 595.0 - side) and y0 in (0.0, 842.0 - side)
    assert (x1 - x0, y1 - y0) == (side, side)


@pytest.mark.parametrize("label", [
    "Group_05:da0bb583c432fbfd078959ecc9b62902",
    "Group_13 - " + "a" * 180,
    "Group_" + "x" * 54 + " - " + "a" * 180,
])
def test_visible_labels_fit_without_overlapping(pdf_bytes, label):
    with fitz.open(stream=pdf_bytes, filetype="pdf") as doc:
        page = doc[0]
        qr_box = rendering.random_qr_rect(page.rect.width, page.rect.height, [], b"seed-qr-test")
        placed_boxes = [qr_box]

        existing_xrefs = {image[0] for image in page.get_images(full=True)}

        # Place visible labels everywhere else, including across page content.
        text_boxes = rendering.stamp_random_native_visible_text(
            page=page,
            label=label,
            placed_boxes=placed_boxes,
            seed_material=b"seed-text-test",
        )
        assert 1 <= len(text_boxes) <= rendering.DEFAULT_VISIBLE_TEXT_COUNT
        assert len(placed_boxes) == len(text_boxes) + 1
        for text_box in text_boxes:
            assert not rendering.boxes_overlap(text_box, qr_box, min_gap=8.0)
            assert 0 <= text_box[0] < text_box[2] <= page.rect.width
            assert 0 <= text_box[1] < text_box[3] <= page.rect.height
        for index, text_box in enumerate(text_boxes):
            for other_box in text_boxes[index + 1:]:
                assert not rendering.boxes_overlap(text_box, other_box, min_gap=8.0)

        physical_boxes = [
            tuple(rect) for xref in {image[0] for image in page.get_images(full=True)} - existing_xrefs
            for rect in page.get_image_rects(xref)
        ]
        assert len(physical_boxes) == len(text_boxes)
        for box in physical_boxes:
            assert 0 <= box[0] < box[2] <= page.rect.width
            assert 0 <= box[1] < box[3] <= page.rect.height
            assert not rendering.boxes_overlap(box, qr_box, min_gap=0)
        for index, box in enumerate(physical_boxes):
            for other in physical_boxes[index + 1:]:
                assert not rendering.boxes_overlap(box, other, min_gap=0)


@pytest.mark.parametrize("width,height,protected", [(595, 842, True), (120, 120, False)])
def test_visible_labels_refuse_when_no_layout_fits(width, height, protected):
    with fitz.open() as document:
        page = document.new_page(width=width, height=height)
        with pytest.raises(ValueError):
            rendering.stamp_random_native_visible_text(
                page, "Group 13 - " + "a" * 180, [tuple(page.rect)] if protected else [],
            )
        assert not page.get_images()


@pytest.mark.parametrize("secret", ["x", "copy-identifier", "x" * 64])
def test_qr_image_is_readable(secret):
    import zxingcpp

    from watermarking_methods.francesco import crypto

    payload = crypto.encrypt_qr_payload(secret, KEY, salt=(55).to_bytes(16, "big"))
    with Image.open(io.BytesIO(rendering.build_opaque_qr_bytes(payload))) as image:
        assert image.getchannel("A").getextrema() == (255, 255)
        assert {barcode.text for barcode in zxingcpp.read_barcodes(image)} == {payload}


@pytest.mark.parametrize("other", [(12, 0, 22, 10), (-12, 0, -2, 10), (0, 12, 10, 22), (0, -12, 10, -2)])
def test_collision_gap_in_all_directions(other):
    import numpy as np

    box = (0, 0, 10, 10)
    for gap, expected in [(1, False), (2, False), (3, True)]:
        assert rendering.boxes_overlap(box, other, gap) is expected
        assert rendering._overlaps(np.array([box]), [other], gap).tolist() == [[expected]]


def test_content_boxes_include_clipped_vector_and_text():
    with fitz.open() as document:
        page = document.new_page(width=300, height=300)
        page.insert_text((100, 100), "synthetic text")
        page.draw_rect(fitz.Rect(-10, 150, 60, 200), color=(0, 0, 0))
        page.draw_line((20, 250), (100, 250))
        boxes = [fitz.Rect(box) for box in rendering.collect_page_content_boxes(page)]
        assert all(page.rect.contains(box) and not box.is_empty for box in boxes)
        assert all(not box.contains(fitz.Point(290, 290)) for box in boxes)
        assert all(not box.contains(fitz.Point(50, 250)) for box in boxes)
        assert any(box.contains(fitz.Rect(0, 150, 60, 200)) for box in boxes)
        assert any(box.contains(page.search_for("synthetic text")[0]) for box in boxes)


def test_border_qr_stays_inside_page():
    for number in range(1000):
        rect = fitz.Rect(rendering.random_qr_rect(300, 450, [], str(number).encode()))
        assert fitz.Rect(0, 0, 300, 450).contains(rect)


def test_collision_matrix_handles_no_exclusions():
    import numpy as np

    candidates = np.array([(0, 0, 10, 10), (20, 20, 30, 30)])
    collisions = rendering._overlaps(candidates, [], 2)
    assert collisions.shape == (2, 0)
    assert (~collisions.any(axis=1)).tolist() == [True, True]


@pytest.mark.parametrize("width,height", [(120, 120), (200, 200), (200, 450), (450, 200), (300, 300)])
@pytest.mark.parametrize("label", ["Group 13 - " + "a" * 79, "Group 13 - " + "a" * 180])
def test_constrained_layout_preserves_physical_exclusions(width, height, label):
    with fitz.open() as document:
        page = document.new_page(width=width, height=height)
        protected = (width * .45, 0, width * .55, height * .6)
        exclusions = [protected]
        try:
            boxes = rendering.stamp_random_native_visible_text(page, label, exclusions, seed_material=b"small-page")
        except ValueError:
            assert (width, height, len(label) - len("Group 13 - ")) in {
                (120, 120, 79), (120, 120, 180), (200, 200, 79), (200, 200, 180), (450, 200, 180),
            }
            assert not page.get_images()
            return
        assert 1 <= len(boxes) <= rendering.DEFAULT_VISIBLE_TEXT_COUNT
        physical = [fitz.Rect(info["bbox"]) for info in page.get_image_info()]
        assert len(physical) == len(boxes)
        for rect in physical:
            assert page.rect.contains(rect)
            assert not rect.intersects(fitz.Rect(protected))
        for index, rect in enumerate(physical):
            assert all(not rect.intersects(other) for other in physical[index + 1:])


@pytest.mark.parametrize("label", ["Group A - " + "B" * 40 + " - " + "a" * 180, "Group 13 - " + "a" * 79])
@pytest.mark.parametrize("width,height", [(300, 600), (800, 180)])
def test_long_recipient_fits_a_narrow_page(label, width, height):
    for number in range(20):
        with fitz.open() as document:
            page = document.new_page(width=width, height=height)
            boxes = rendering.stamp_random_native_visible_text(
                page, label, [], count=1, seed_material=str(number).encode(),
            )
            assert len(boxes) == 1
            assert all(page.rect.contains(fitz.Rect(image["bbox"])) for image in page.get_image_info())


def test_visible_label_is_drawn_over_page_images():
    buffer = io.BytesIO()
    Image.new("RGB", (300, 400), "white").save(buffer, format="PNG")
    with fitz.open() as document:
        page = document.new_page(width=300, height=400)
        page.insert_image(page.rect, stream=buffer.getvalue())
        rendering.stamp_random_native_visible_text(
            page, "Group 13 - " + "a" * 79, [], count=1, seed_material=b"paint-order",
        )
        pixmap = page.get_pixmap(dpi=72, alpha=False)
        image = Image.frombytes("RGB", (pixmap.width, pixmap.height), pixmap.samples)
        assert any(low < 255 for low, _high in image.getextrema())


def test_physical_labels_respect_surrounding_exclusions():
    label = "Group 13 - " + "a" * 79
    with fitz.open() as document:
        page = document.new_page(width=300, height=600)
        rendering.stamp_random_native_visible_text(page, label, [], count=1)
        physical = fitz.Rect(page.get_image_info()[0]["bbox"])
    hole = fitz.Rect(40, 200, 40 + physical.width + 60, 200 + physical.height + 60)
    protected = [(0, 0, hole.x0, 600), (hole.x1, 0, 300, 600),
                 (0, 0, 300, hole.y0), (0, hole.y1, 300, 600)]
    for number in range(20):
        with fitz.open() as document:
            page = document.new_page(width=300, height=600)
            try:
                rendering.stamp_random_native_visible_text(
                    page, label, list(protected), count=1, min_gap=0,
                    seed_material=str(number).encode(),
                )
            except ValueError:
                assert not page.get_images()
                continue
            assert all(hole.contains(fitz.Rect(image["bbox"])) for image in page.get_image_info())
