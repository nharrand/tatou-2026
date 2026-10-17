"""Drawing of the watermark: the opaque QR code, its placement and the visible labels."""

from __future__ import annotations

import hashlib
import io
import math
import random
import textwrap
from functools import lru_cache
from typing import Final

import numpy as np
import pymupdf as fitz
import zxingcpp
from PIL import Image, ImageDraw, ImageFont

Box = tuple[float, float, float, float]

# ~10% of the shortest page dimension (about 2 cm on A4): at 6% a code has fewer than 2 pixels
# per module at the 300 DPI read resolution and did not decode reliably.
DEFAULT_QR_FRACTION: Final[float] = 0.10
DEFAULT_VISIBLE_TEXT_COUNT: Final[int] = 6
VISIBLE_TEXT_ALPHA: Final[int] = 110
VISIBLE_WRAPPED_TEXT_ALPHA: Final[int] = 180


def _rng(seed_material: bytes, label: bytes) -> random.Random:
    # Placement only, nothing secret depends on it: the same copy gets the same layout.
    seed = hashlib.sha256(seed_material + label).digest()[:8]
    return random.Random(int.from_bytes(seed, "big"))  # noqa: S311


def collect_page_content_boxes(page: fitz.Page, padding: float = 8.0) -> list[Box]:
    """Return padded boxes for existing text, images, and vector drawings."""
    bounds = page.rect
    boxes: list[Box] = []

    def add(rect_like) -> None:
        rect = fitz.Rect(rect_like) & bounds
        if rect.is_empty or rect.is_infinite:
            return
        boxes.append((
            max(bounds.x0, rect.x0 - padding),
            max(bounds.y0, rect.y0 - padding),
            min(bounds.x1, rect.x1 + padding),
            min(bounds.y1, rect.y1 + padding),
        ))

    for block in page.get_text("blocks"):
        add(block[:4])
    for image in page.get_images(full=True):
        for rect in page.get_image_rects(image[0]):
            add(rect)
    for drawing in page.get_drawings():
        add(drawing["rect"])

    return boxes


def boxes_overlap(box1: Box, box2: Box, min_gap: float) -> bool:
    """Return True if two (x0, y0, x1, y1) boxes overlap or are closer than min_gap."""
    x0_1, y0_1, x1_1, y1_1 = box1
    x0_2, y0_2, x1_2, y1_2 = box2
    return not (
        x1_1 + min_gap <= x0_2
        or x1_2 + min_gap <= x0_1
        or y1_1 + min_gap <= y0_2
        or y1_2 + min_gap <= y0_1
    )


def _overlaps(cands: np.ndarray, boxes, min_gap: float) -> np.ndarray:
    """Return an overlap matrix for candidate rows and exclusion-box columns."""
    if not len(boxes):
        return np.zeros((len(cands), 0), dtype=bool)
    other = np.asarray(boxes, dtype=float)
    return ~((cands[:, None, 2] + min_gap <= other[None, :, 0])
             | (other[None, :, 2] + min_gap <= cands[:, None, 0])
             | (cands[:, None, 3] + min_gap <= other[None, :, 1])
             | (other[None, :, 3] + min_gap <= cands[:, None, 1]))


def build_opaque_qr_bytes(payload: str, target_pixel_size: int = 240) -> bytes:
    """Generate an opaque QR code (maximum scanner contrast) as PNG bytes."""
    barcode = zxingcpp.create_barcode(payload, zxingcpp.BarcodeFormat.QRCode, ec_level="H")
    # Integer pixels per module: resizing to an arbitrary size makes modules uneven, and about
    # half of the codes then failed to decode at 300 DPI.
    modules = barcode.to_image(scale=1).shape[0]
    raw_img = barcode.to_image(scale=max(1, target_pixel_size // modules))
    qr_mask = Image.fromarray(raw_img).convert("L")

    dark_layer = Image.new("RGBA", qr_mask.size, (15, 25, 35, 255))
    light_layer = Image.new("RGBA", qr_mask.size, (255, 255, 255, 255))
    qr_layer = Image.composite(light_layer, dark_layer, qr_mask)

    border = max(6, target_pixel_size // 16)
    total_side = target_pixel_size + 2 * border
    backed = Image.new("RGBA", (total_side, total_side), (255, 255, 255, 255))
    backed.paste(qr_layer, (border, border), qr_layer)

    buffer = io.BytesIO()
    backed.save(buffer, format="PNG")
    return buffer.getvalue()


def random_qr_rect(
    page_width: float,
    page_height: float,
    placed_boxes: list[Box],
    seed_material: bytes,
    min_gap: float = 8.0,
    qr_fraction: float = DEFAULT_QR_FRACTION,
) -> Box:
    """Choose a border rectangle that avoids existing content and placed boxes.

    Raise an error when no free border position fits.
    """
    rng = _rng(seed_material, b"/qr")
    qr_side = min(page_width, page_height) * qr_fraction
    edge_inset = max(4.0, min(page_width, page_height) * 0.012)
    if page_width < qr_side + 2 * edge_inset or page_height < qr_side + 2 * edge_inset:
        raise ValueError("Page is too small for a border QR code")

    for _attempt in range(500):
        edge = rng.randrange(4)
        if edge == 0:  # Top.
            x0, y0 = rng.uniform(edge_inset, page_width - qr_side - edge_inset), edge_inset
        elif edge == 1:  # Bottom.
            x0 = rng.uniform(edge_inset, page_width - qr_side - edge_inset)
            y0 = page_height - qr_side - edge_inset
        elif edge == 2:  # Left.
            x0, y0 = edge_inset, rng.uniform(edge_inset, page_height - qr_side - edge_inset)
        else:  # Right.
            x0 = page_width - qr_side - edge_inset
            y0 = rng.uniform(edge_inset, page_height - qr_side - edge_inset)
        candidate = (x0, y0, x0 + qr_side, y0 + qr_side)
        if not any(boxes_overlap(candidate, box, min_gap) for box in placed_boxes):
            return candidate

    raise ValueError("No text-free border position available for QR code")


def corner_qr_rect(
    page_width: float,
    page_height: float,
    seed_material: bytes,
    qr_fraction: float = DEFAULT_QR_FRACTION,
) -> Box:
    """Choose a random corner rectangle, allowing overlap with page content."""
    if page_width <= 0 or page_height <= 0 or not 0 < qr_fraction <= 0.5:
        raise ValueError("Invalid page dimensions or QR placement parameters")
    side = min(page_width, page_height) * qr_fraction
    x = _rng(seed_material, b"/qr-edge").choice((0.0, page_width - side))
    y = _rng(seed_material, b"/qr-edge-y").choice((0.0, page_height - side))
    return (x, y, x + side, y + side)


def load_font(size: int) -> ImageFont.FreeTypeFont | ImageFont.ImageFont:
    """Load a monospaced font or fall back to PIL's default."""
    try:
        return ImageFont.truetype("DejaVuSansMono.ttf", size)
    except OSError:
        return ImageFont.load_default(size=size)


@lru_cache(maxsize=32)  # Same label on every page: render it once.
def _label_png(
    label: str, fontsize: float, rotate: int, alpha: int = VISIBLE_TEXT_ALPHA,
) -> tuple[bytes, float, float]:
    """Return a rotated transparent label PNG and its dimensions in points."""
    scale = 6  # Render at 6x the point size, so the label stays sharp when zoomed.
    font = load_font(max(1, round(fontsize * scale)))
    padding = max(4, round(fontsize * scale * 0.25))
    spacing = max(1, round(fontsize * scale * 0.25))
    measure = ImageDraw.Draw(Image.new("RGBA", (1, 1)))
    if "\n" in label:
        x0, y0, x1, y1 = measure.multiline_textbbox(
            (0, 0), label, font=font, spacing=spacing,
        )
    else:
        x0, y0, x1, y1 = measure.textbbox((0, 0), label, font=font)
    canvas = Image.new("RGBA", (x1 - x0 + 2 * padding, y1 - y0 + 2 * padding), (255, 255, 255, 0))
    draw = ImageDraw.Draw(canvas)
    if "\n" in label:
        draw.multiline_text(
            (padding - x0, padding - y0), label, font=font, spacing=spacing,
            fill=(38, 56, 76, alpha),
        )
    else:
        draw.text(
            (padding - x0, padding - y0), label, font=font, fill=(38, 56, 76, alpha),
        )
    rotated = canvas.rotate(rotate, expand=True, resample=Image.Resampling.BICUBIC)
    buffer = io.BytesIO()
    rotated.save(buffer, format="PNG")
    return buffer.getvalue(), rotated.width / scale, rotated.height / scale


def _wrap_visible_label(label: str, fontsize: float, max_width: float) -> str:
    """Keep the group heading and evenly sized ciphertext chunks on separate lines."""
    scale = 6
    font = load_font(max(1, round(fontsize * scale)))
    padding = max(4, round(fontsize * scale * 0.25))
    measure = ImageDraw.Draw(Image.new("RGBA", (1, 1)))
    character_width = measure.textlength("M", font=font)
    max_chars = math.floor((max_width * scale - 2 * padding) / character_width)
    if max_chars < 8:
        raise ValueError("Page is too narrow for a visible label")

    if " - " not in label:
        return "\n".join(textwrap.wrap(label, max_chars, break_long_words=True))

    group, payload = label.rsplit(" - ", maxsplit=1)
    heading = textwrap.wrap(f"{group} -", max_chars, break_long_words=True)
    chunk_count = max(1, math.ceil(len(payload) / max_chars))
    chunk_size = math.ceil(len(payload) / chunk_count)
    chunks = [payload[index:index + chunk_size] for index in range(0, len(payload), chunk_size)]
    return "\n".join([*heading, *chunks])


def stamp_random_native_visible_text(
    page: fitz.Page,
    label: str,
    placed_boxes: list[Box],
    count: int = DEFAULT_VISIBLE_TEXT_COUNT,
    fontsize: float = 8.0,
    rotate: int = 30,
    seed_material: bytes = b"",
    min_gap: float = 8.0,
) -> list[Box]:
    """Stamp transparent label images within page bounds and outside exclusion boxes.

    Labels may cross document content but cannot overlap each other. Wrap long encrypted
    payloads into readable horizontal lines.
    """
    width, height = page.rect.width, page.rect.height
    protected_boxes = tuple(placed_boxes)
    content_boxes = collect_page_content_boxes(page, padding=0)
    rng = _rng(seed_material, b"/text")

    margin_x = max(20.0, width * 0.05)
    margin_y = max(20.0, height * 0.05)
    usable_width = width - 2 * (margin_x + 10.0)
    usable_height = height - 2 * (margin_y + 10.0)
    if usable_width <= 0 or usable_height <= 0:
        raise ValueError("Page is too small for visible labels")

    label_png, span_x, span_y = _label_png(label, fontsize, rotate)
    wrapped = False
    if (
        span_x > usable_width
        or span_y > usable_height
        or count * (span_y + 20.0 + min_gap) > usable_height
    ):
        wrapped = True
        wrapped_label = _wrap_visible_label(label, fontsize, usable_width)
        label_png, span_x, span_y = _label_png(
            wrapped_label, fontsize, 0, alpha=VISIBLE_WRAPPED_TEXT_ALPHA,
        )
    if span_x > usable_width or span_y > usable_height:
        raise ValueError("Page has insufficient room for a visible label")

    max_x = width - span_x - margin_x
    max_y = height - span_y - margin_y

    chosen_boxes: list[Box] = []
    placed_in_whitespace = False
    for _ in range(count):
        best_box: Box | None = None
        best_score = (-float("inf"), -1.0)

        # 1000 random candidates, scored at once with numpy (same choice as a loop).
        points = np.array([(rng.uniform(margin_x, max_x), rng.uniform(margin_y, max_y))
                           for _attempt in range(1000)])
        cands = np.column_stack((points[:, 0] - 10.0, points[:, 1] - 10.0,
                                 points[:, 0] + span_x + 10.0, points[:, 1] + span_y + 10.0))
        valid = ~_overlaps(cands, (*protected_boxes, *chosen_boxes), min_gap).any(axis=1)
        if valid.any():
            # Prefer whitespace, then spread the labels that fit without colliding. On dense
            # pages, content remains a soft exclusion.
            hits = _overlaps(cands, content_boxes, 0).sum(axis=1)
            center_x, center_y = (cands[:, 0] + cands[:, 2]) / 2, (cands[:, 1] + cands[:, 3]) / 2
            if chosen_boxes:
                chosen = np.array(chosen_boxes)
                distance = ((center_x[:, None] - (chosen[:, 0] + chosen[:, 2]) / 2) ** 2
                            + (center_y[:, None] - (chosen[:, 1] + chosen[:, 3]) / 2) ** 2).min(axis=1)
            else:
                distance = np.zeros(len(cands))
            best_hits = hits[valid].min()
            best = valid & (hits == best_hits)
            index = int(np.flatnonzero(best & (distance == distance[best].max()))[0])
            best_box = tuple(float(v) for v in cands[index])
            best_score = (-int(best_hits), float(distance[index]))

        if best_box is None:
            if not chosen_boxes:
                raise ValueError("Page has insufficient room for visible labels")
            break
        if wrapped and best_score[0] < 0 and placed_in_whitespace:
            break

        placed_boxes.append(best_box)
        chosen_boxes.append(best_box)
        placed_in_whitespace |= best_score[0] == 0
        px, py = best_box[0] + 10.0, best_box[1] + 10.0
        page.insert_image(fitz.Rect(px, py, px + span_x, py + span_y), stream=label_png, overlay=True)

    return chosen_boxes
