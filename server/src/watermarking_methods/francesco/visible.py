"""OCR recovery for the AES-SIV-encrypted visible labels."""

from __future__ import annotations

import io
import itertools
import re
import shutil
import subprocess
from collections import Counter
from difflib import SequenceMatcher

import numpy as np
import pymupdf as fitz
from PIL import Image

from watermarking_method import InvalidKeyError, WatermarkingError

from . import crypto

_PAYLOAD_PATTERN = re.compile(r"[A-Za-z0-9]{44,200}", re.IGNORECASE)
_LABEL_PAYLOAD_PATTERN = re.compile(
    r"GROUP[\s_A-Za-z0-9]*\s*-\s*([A-Za-z0-9]{44,200})", re.IGNORECASE,
)
_GROUP_HEADER_PATTERN = re.compile(r"GROUP[\s_A-Za-z0-9]*\s*-\s*", re.IGNORECASE)
# AES-SIV tag, salt, one UTF-8 byte and Reed-Solomon parity, encoded as Base32.
_MIN_PAYLOAD_CHARS = ((16 + crypto.SALT_BYTES + 1 + crypto.VISIBLE_RS_PARITY_BYTES) * 8 + 4) // 5
_BASE32_ALPHABET = "abcdefghijklmnopqrstuvwxyz234567"
_OCR_WHITELIST = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"
_OCR_DIGIT_TRANSLATION = str.maketrans({"0": "o", "1": "l", "8": "b", "9": "g"})


def _ocr(image: Image.Image) -> str:
    executable = shutil.which("tesseract")
    if executable is None:
        raise WatermarkingError("Visible watermark OCR requires Tesseract")

    buffer = io.BytesIO()
    image.save(buffer, format="PNG")
    try:
        # Tesseract is resolved from PATH and receives fixed arguments and image bytes on stdin.
        completed = subprocess.run(  # noqa: S603
            [
                executable,
                "stdin",
                "stdout",
                "--psm",
                "6",
                "-l",
                "eng",
                "-c",
                f"tessedit_char_whitelist={_OCR_WHITELIST}",
            ],
            input=buffer.getvalue(),
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise WatermarkingError("Visible watermark OCR failed") from error
    if completed.returncode != 0:
        return ""
    return completed.stdout.decode("utf-8", "ignore")


def _candidate_payloads(text: str) -> list[str]:
    candidates: list[str] = []
    lines = text.splitlines()
    for line in lines:
        label_match = _LABEL_PAYLOAD_PATTERN.search(line)
        if label_match:
            candidates.append(label_match.group(1).translate(_OCR_DIGIT_TRANSLATION))
        else:
            candidates.extend(
                candidate.translate(_OCR_DIGIT_TRANSLATION)
                for candidate in _PAYLOAD_PATTERN.findall(line)
            )

    # A long visible label has a group heading followed by Base32 lines. Keep the lines in
    # order; Reed-Solomon and AES-SIV reject incorrect OCR joins.
    for index, line in enumerate(lines):
        header = re.search(r"\s-\s*$", line) or _GROUP_HEADER_PATTERN.search(line)
        if header is None:
            continue
        joined = ""
        for fragment_line in [line[header.end():], *lines[index + 1:index + 9]]:
            if _GROUP_HEADER_PATTERN.search(fragment_line):
                break
            fragment = "".join(fragment_line.split())
            if not re.fullmatch(r"[A-Za-z0-9]{8,120}", fragment):
                if joined:
                    break
                continue
            joined += fragment.translate(_OCR_DIGIT_TRANSLATION)
            if len(joined) > 200:
                break
            if len(joined) >= _MIN_PAYLOAD_CHARS - 1:
                candidates.append(joined)
    return candidates


def _consensus_candidates(candidates: list[str]) -> set[str]:
    """Combine repeated OCR reads and enumerate ties for AES authentication."""
    length_counts = Counter(len(candidate) for candidate in candidates if len(candidate) >= _MIN_PAYLOAD_CHARS)
    anchor_lengths = {
        length for length, count in length_counts.items() if count >= 2
    }
    consensuses: set[str] = set()
    for anchor in candidates:
        if len(anchor) not in anchor_lengths:
            continue
        votes = [Counter() for _char in anchor]
        for candidate in candidates:
            if abs(len(candidate) - len(anchor)) > 2:
                continue
            for tag, a_start, a_end, b_start, b_end in SequenceMatcher(
                None, anchor, candidate, autojunk=False,
            ).get_opcodes():
                if tag == "equal":
                    for offset in range(a_end - a_start):
                        votes[a_start + offset][candidate[b_start + offset]] += 1
                elif tag == "replace":
                    shared = min(a_end - a_start, b_end - b_start)
                    for offset in range(shared):
                        votes[a_start + offset][candidate[b_start + offset]] += 1
        choices = []
        for vote in votes:
            top_count = vote.most_common(1)[0][1]
            choices.append([char for char, count in vote.items() if count == top_count])
        for variant in itertools.islice(itertools.product(*choices), 128):
            consensuses.add("".join(variant))
    return consensuses


def _single_character_repairs(candidates: list[str]):
    """Yield payloads with one OCR insertion or deletion repaired."""
    for candidate, _count in Counter(c for c in candidates if _MIN_PAYLOAD_CHARS - 1 <= len(c) <= 200).most_common(3):
        for index in range(len(candidate) + 1):
            for char in _BASE32_ALPHABET:
                yield candidate[:index] + char + candidate[index:]
        for index in range(len(candidate)):
            yield candidate[:index] + candidate[index + 1:]


def _ocr_confusable_variants(candidates: list[str]) -> set[str]:
    variants: set[str] = set()
    for candidate in candidates:
        if len(candidate) < _MIN_PAYLOAD_CHARS:
            continue
        choices = []
        for char in candidate:
            choices.append((char, "l") if char == "I" else (char,))
        for variant in itertools.islice(itertools.product(*choices), 128):
            variants.add("".join(variant))
    return variants


def _authenticated_secrets(candidates: list[str], key: str) -> set[str]:
    found: set[str] = set()
    for candidate in candidates:
        try:
            found.add(crypto.decrypt_visible_payload(candidate, key))
        except InvalidKeyError:
            continue

    for candidate in _consensus_candidates(candidates):
        try:
            found.add(crypto.decrypt_visible_payload(candidate, key))
        except InvalidKeyError:
            continue

    for candidate in _ocr_confusable_variants(candidates):
        try:
            found.add(crypto.decrypt_visible_payload(candidate, key))
            if len(found) > 1:
                return found
        except InvalidKeyError:
            continue

    if not found:
        damaged = Counter(c for c in candidates if _MIN_PAYLOAD_CHARS - 1 <= len(c) <= 200)
        for candidate, _count in damaged.most_common(3):
            for repaired in _single_character_repairs([candidate]):
                try:
                    found.add(crypto.decrypt_visible_payload(repaired, key))
                    if len(found) > 1:
                        return found
                    break
                except InvalidKeyError:
                    continue
    return found


def _isolated_watermark_ink(image: Image.Image, min_blue_red: int) -> Image.Image:
    """Keep blue-gray label pixels while dropping ordinary grayscale page text."""
    pixels = np.asarray(image)
    blue_red = np.subtract(pixels[:, :, 2], pixels[:, :, 0], dtype=np.int16)
    green_red = np.subtract(pixels[:, :, 1], pixels[:, :, 0], dtype=np.int16)
    mask = (
        (blue_red >= min_blue_red)
        & (green_red >= min_blue_red // 2)
        & (pixels[:, :, 2] < 245)
    )
    return Image.fromarray(np.where(mask, 0, 255).astype(np.uint8))


def read_visible_secrets(document: fitz.Document, key: str) -> set[str]:
    """Rasterize every page and authenticate candidate encrypted labels."""
    executable = shutil.which("tesseract")
    if executable is None:
        raise WatermarkingError("Visible watermark OCR requires Tesseract")

    found: set[str] = set()
    for page in document:
        dpi = 300
        pixmap = page.get_pixmap(dpi=dpi, colorspace=fitz.csRGB, alpha=False)
        image = Image.frombytes("RGB", (pixmap.width, pixmap.height), pixmap.samples)
        scale = dpi / 72
        prepared_page = image.rotate(
            -30,
            expand=True,
            resample=Image.Resampling.BICUBIC,
            fillcolor="white",
        )
        text_parts = [_ocr(prepared_page), _ocr(image)]
        seen_boxes = set()
        for image_info in page.get_images(full=True):
            xref = image_info[0]
            for rect in page.get_image_rects(xref):
                if rect.width < rect.height * 1.3:
                    continue
                box = (
                    max(0, round(rect.x0 * scale) - 8),
                    max(0, round(rect.y0 * scale) - 8),
                    min(image.width, round(rect.x1 * scale) + 8),
                    min(image.height, round(rect.y1 * scale) + 8),
                )
                if box in seen_boxes:
                    continue
                seen_boxes.add(box)
                label_image = image.crop(box)
                if rect.width <= rect.height * 3:
                    label_image = label_image.rotate(
                        -30,
                        expand=True,
                        resample=Image.Resampling.BICUBIC,
                        fillcolor="white",
                    )
                text_parts.append(_ocr(label_image))

        text = "\n".join(text_parts)
        candidates = _candidate_payloads(text)
        page_found = _authenticated_secrets(candidates, key)

        if not page_found:
            for threshold in (5, 15):
                isolated = _isolated_watermark_ink(image, threshold)
                page_found.update(_authenticated_secrets(_candidate_payloads(_ocr(isolated)), key))
                if page_found:
                    break
        found.update(page_found)

    return found
