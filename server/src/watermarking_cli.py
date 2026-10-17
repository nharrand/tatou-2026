"""Embed, verify, and inspect PDF watermarks from the command line.

Exit codes: 0 for success, 2 for invalid input, 3 for missing secrets, 4 for invalid
keys, and 5 for other watermarking errors. Extraction verifies authentication without
printing the recovered secret.
"""
from __future__ import annotations

import argparse
import getpass
import json
import sys
from collections.abc import Iterable

from watermarking_method import InvalidKeyError, SecretNotFoundError, WatermarkingError
from watermarking_utils import (
    METHODS,
    apply_watermark,
    explore_pdf,
    is_watermarking_applicable,
    read_watermark,
)

__version__ = "0.1.0"


class SafeArgumentParser(argparse.ArgumentParser):
    """Reject invalid arguments without echoing their values."""

    def error(self, message: str) -> None:
        del message
        self.print_usage(sys.stderr)
        self.exit(2, f"{self.prog}: error: invalid arguments\n")


def _read_text_from_file(path: str) -> str:
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def _read_text_from_stdin() -> str:
    data = sys.stdin.read()
    if not data:
        raise ValueError("No data received on stdin")
    return data


def _resolve_secret(args: argparse.Namespace) -> str:
    if args.secret is not None:
        return args.secret
    if args.secret_file is not None:
        return _read_text_from_file(args.secret_file)
    if args.secret_stdin:
        return _read_text_from_stdin()

    return getpass.getpass("Secret: ")


def _resolve_key(args: argparse.Namespace) -> str:
    if args.key is not None:
        return args.key
    if args.key_file is not None:
        return _read_text_from_file(args.key_file).strip("\n\r")
    if args.key_stdin:
        return _read_text_from_stdin().strip("\n\r")
    if args.key_prompt:
        return getpass.getpass("Key: ")

    return getpass.getpass("Key: ")


def cmd_methods(_args: argparse.Namespace) -> int:
    for name in sorted(METHODS):
        print(name)
    return 0


def cmd_explore(args: argparse.Namespace) -> int:
    tree = explore_pdf(args.input)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(tree, fh, indent=2, ensure_ascii=False)
    else:
        json.dump(tree, sys.stdout, indent=2, ensure_ascii=False)
        print()
    return 0


def cmd_embed(args: argparse.Namespace) -> int:
    key = _resolve_key(args)
    secret = _resolve_secret(args)
    if not is_watermarking_applicable(method=args.method,pdf=args.input, position=args.position):
        print("watermarking failed", file=sys.stderr)
        return 5

    pdf_bytes = apply_watermark(
        method=args.method,
        pdf=args.input,
        secret=secret,
        key=key,
        position=args.position
    )
    with open(args.output, "wb") as fh:
        fh.write(pdf_bytes)
    print(f"Wrote watermarked PDF -> {args.output}")
    return 0


def cmd_extract(args: argparse.Namespace) -> int:
    key = _resolve_key(args)
    read_watermark(method=args.method, pdf=args.input, key=key)
    print("Watermark verified")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = SafeArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        required=True,
        help="Watermarking method name (see: pdfwm methods)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    p_extract = sub.add_parser(
        "extract",
        help="Verify a watermark without revealing its secret",
    )
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        required=True,
        help="Watermarking method name (see: pdfwm methods)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.set_defaults(func=cmd_extract)

    return p


def main(argv: Iterable[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)

    try:
        return int(args.func(args))
    except (OSError, ValueError, KeyError, EOFError):
        print("invalid input", file=sys.stderr)
        return 2
    except SecretNotFoundError:
        print("secret not found", file=sys.stderr)
        return 3
    except InvalidKeyError:
        print("invalid key", file=sys.stderr)
        return 4
    except WatermarkingError:
        print("watermarking failed", file=sys.stderr)
        return 5
    except Exception:  # CLI boundary must not emit tracebacks.
        print("watermarking failed", file=sys.stderr)
        return 5

if __name__ == "__main__":
    raise SystemExit(main())
