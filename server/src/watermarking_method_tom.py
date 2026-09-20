# Individual watermarking method for Tom Ellström Johansson

# Steps that I would like to implement in this method
# From research I have understood that a good watermarking method should include certain properties
# Hosny et al. 2024 (10.1016/j.cosrev.2024.100662) and Warhera et al. 2021 (https://arxiv.org/pdf/2207.06909)
    # 1. Imperceptibility: It should not visibly alter the document's appearance

    # 2. Safety and precaution: Making sure that there are some safety implementations
    # we do not want to execute unneccassary code if it is not needed

    # 3. Capacity: The amount of information embedded in a watermarked image also known as data payload

# These references are more structured for images/audio/video, but I still believe they provide good reasonings as to why I am using them for this watermarking method

# Improvements i would like to have implemented further on
    # Robustness: It should be able to clear PDF handling: opening/resaving in a viewer, printing into a pdf, edits
    # Secure: More security. This is probably the biggest problem and for forgeability: Cao et al. 2026 (https://arxiv.org/pdf/2510.02384)

# Base is taken from add_after_eof.py
from __future__ import annotations
from typing import Final

import fitz # PyMuPDF

from watermarking_method import(
    InvalidKeyError,
    SecretNotFoundError,
    WatermarkingError,
    WatermarkingMethod,

# adding in PdfSource and load_pdf_bytes in order to check the size of the pdf
    PdfSource,
    load_pdf_bytes,
)

class AuthorFieldVM(WatermarkingMethod):
    # Unique name, the other codes uses this to refer to the method
    name: Final[str] = "tom-author-field"

    @staticmethod
    def get_usage() -> str:
        # Shown to the API users api/get-watermarking-method. This is done so they
        # know what his method does and that positions and key is not used yet
        return "This should store the secret directly in the PDFs author metadata field. Will add in position and key later."

    def is_watermark_applicable(self, pdf: PdfSource, position: str | None = None) -> bool:
        # It first checks if it can even run on the file. This is called before add_watermark
        # It is for safety reasons
        try:
            data = load_pdf_bytes(pdf)                      # Normalizes input to raw byes
            doc = fitz.open(stream=data, filetype="pdf")    # Try to parse it with PyMuPDF
            doc.close()                                     # Dont need to have it open so closes it
            return True

        except Exception:
            return False

    def add_watermark(self, pdf: PdfSource, secret: str, key: str, position: str | None = None) -> bytes:
        # This is for capacity and imperceptibility are addressed
        data = load_pdf_bytes(pdf)
        if not secret:
            raise ValueError("Secret must be a non-empty string")

        doc = fitz.open(stream=data, filetype="pdf")
        try:
            meta = doc.metadata or {}
            # This is also for capacrity. The author field is just a string with no hard lenght limit
            # This should in theoiry give me some payload capacity, fille name, and ID 
            # string. This has not been tested for a maximum capacity yet
            # small robustness bit: backup copy in case author gets cleared
            meta["author"] = secret
            meta["subject"] = secret  

            # This is for imperceptability
            # the set_metadata only touches the PDFs information dictionary, not the whole page content.
            # This means nothing visible changes when the document is opened and read.
            # I guess this is visible for a normal reading of the document but not to someone who opens the properties, so that
            # would need to be enhanced aswell
            doc.set_metadata(meta)
            out = doc.tobytes()
        finally:
            doc.close()
        return out

    def read_secret(self, pdf: PdfSource, key: str) -> str:
        # this will reverse the add_watermark: open the file and pull the string back out of author filed
        # the key is accepted but it is not used.
        data = load_pdf_bytes(pdf)
        doc = fitz.open(stream=data, filetype="pdf")
        try:
            meta = doc.metadata or {}
            author = meta.get("author") or meta.get("subject") or ""
        finally:
            doc.close()

        if not author:
            raise SecretNotFoundError("No secret found in Author field")

        return author

# Will need to write a test file for this before implementing it into the project

__all__ = ["AuthorFieldWM"]