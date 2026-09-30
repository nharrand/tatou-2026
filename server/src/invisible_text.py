import base64
import re

import pymupdf

from watermarking_method import (
    WatermarkingMethod,
    SecretNotFoundError,
    load_pdf_bytes,
)


class InvisibleText(WatermarkingMethod):
    name = "invisible-text"

    @staticmethod
    def get_usage():
        return (
            "Invisible text on every page. "
            "Secret: 1–100 UTF-8 bytes. Key and position are ignored."
        )

    def is_watermark_applicable(self, pdf, position=None):
        data = load_pdf_bytes(pdf)

        with pymupdf.open(stream=data, filetype="pdf") as doc:
            return (
                not doc.needs_pass
                and doc.page_count > 0
                and all(
                    page.cropbox.width >= 100
                    and page.cropbox.height >= 40
                    for page in doc
                )
            )

    def add_watermark(self, pdf, secret, key, position=None):
        raw = secret.encode("utf-8")

        if not 1 <= len(raw) <= 100:
            raise ValueError("Secret must contain 1–100 UTF-8 bytes")

        data = load_pdf_bytes(pdf)

        if not self.is_watermark_applicable(data):
            raise ValueError("PDF is protected, empty or too small")

        encoded = base64.b64encode(raw).decode("ascii")
        marker = f"TATOU:{encoded}:END"

        with pymupdf.open(stream=data, filetype="pdf") as doc:
            for page in doc:
                page.insert_text(
                    (10, 20),
                    marker,
                    fontname="cour",
                    fontsize=1,
                    render_mode=3,  # Invisible text
                )

            return doc.tobytes(deflate=True, no_new_id=True)

    def read_secret(self, pdf, key):
        data = load_pdf_bytes(pdf)

        with pymupdf.open(stream=data, filetype="pdf") as doc:
            if doc.needs_pass:
                raise ValueError("Password-protected PDF is not supported")

            for page in doc:
                text = page.get_text()
                match = re.search(
                    r"TATOU:([A-Za-z0-9+/=]+):END",
                    text,
                )

                if match:
                    return base64.b64decode(
                        match.group(1), validate=True
                    ).decode("utf-8")

        raise SecretNotFoundError("No invisible watermark found")