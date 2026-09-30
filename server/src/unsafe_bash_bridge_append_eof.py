"""unsafe_bash_bridge_append_eof.py

Toy watermarking method that appends an authenticated payload *after* the
PDF's final EOF marker but by calling a bash command. Technically you could bridge
any watermarking implementation this way. Don't, unless you know how to sanitize user inputs.

"""
from __future__ import annotations
from pathlib import Path
from typing import Final
import subprocess

from watermarking_method import (
    InvalidKeyError,
    SecretNotFoundError,
    WatermarkingError,
    WatermarkingMethod,
    load_pdf_bytes,
)


class UnsafeBashBridgeAppendEOF(WatermarkingMethod):
    """Toy method that appends a watermark record after the PDF EOF.

    """

    name: Final[str] = "bash-bridge-eof"

    # ---------------------
    # Public API overrides
    # ---------------------
    
    @staticmethod
    def get_usage() -> str:
        return "Toy method that appends a watermark record after the PDF EOF. Position and key are ignored."

    def add_watermark(self, pdf: str | Path, secret: str, key: str, position: str | None = None) -> bytes:
            pdf_path = Path(pdf)
            
           
            with pdf_path.open("rb") as f:
                pdf_bytes = f.read()
                
        
            watermarked_bytes = pdf_bytes + secret.encode('utf-8')
            
            return watermarked_bytes
        
    def is_watermark_applicable(
        self,
        pdf: PdfSource,
        position: str | None = None,
    ) -> bool:
        return True
    

    def read_secret(self, pdf, key: str) -> str:
            pdf_path = Path(pdf)
            
           
            with pdf_path.open("rb") as f:
                pdf_bytes = f.read()
                
          
            parts = pdf_bytes.split(b"%%EOF")
            
            if len(parts) > 1:
             
                secret_bytes = parts[-1]
               
                return secret_bytes.decode('utf-8', errors='ignore').strip()
                
            return ""



__all__ = ["UnsafeBashBridgeAppendEOF"]

