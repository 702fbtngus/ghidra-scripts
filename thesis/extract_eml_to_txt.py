#!/usr/bin/env python3
"""Extract subject and body text from .eml files."""

from __future__ import annotations

import argparse
import re
from email import policy
from email.header import decode_header, make_header
from email.parser import BytesParser
from html import unescape
from html.parser import HTMLParser
from pathlib import Path


class HtmlToText(HTMLParser):
    BLOCK_TAGS = {
        "address",
        "article",
        "aside",
        "blockquote",
        "br",
        "div",
        "footer",
        "h1",
        "h2",
        "h3",
        "h4",
        "h5",
        "h6",
        "header",
        "hr",
        "li",
        "main",
        "p",
        "pre",
        "section",
        "table",
        "tbody",
        "td",
        "tfoot",
        "th",
        "thead",
        "tr",
        "ul",
        "ol",
    }
    SKIP_TAGS = {"script", "style", "head", "title", "meta"}

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._chunks: list[str] = []
        self._skip_depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag = tag.lower()
        if tag in self.SKIP_TAGS:
            self._skip_depth += 1
            return
        if tag == "li":
            self._append_newline()
            self._chunks.append("- ")
        elif tag in self.BLOCK_TAGS:
            self._append_newline()

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag in self.SKIP_TAGS and self._skip_depth:
            self._skip_depth -= 1
            return
        if tag in self.BLOCK_TAGS:
            self._append_newline()

    def handle_data(self, data: str) -> None:
        if self._skip_depth:
            return
        self._chunks.append(data)

    def _append_newline(self) -> None:
        if self._chunks and not self._chunks[-1].endswith("\n"):
            self._chunks.append("\n")

    def get_text(self) -> str:
        return normalize_text("".join(self._chunks))


def decode_mime_header(value: str | None) -> str:
    if not value:
        return ""
    try:
        return str(make_header(decode_header(value)))
    except Exception:
        chunks: list[str] = []
        for chunk, charset in decode_header(value):
            if isinstance(chunk, bytes):
                for encoding in (charset, "utf-8", "cp949", "euc-kr", "latin-1"):
                    if not encoding:
                        continue
                    try:
                        chunks.append(chunk.decode(encoding))
                        break
                    except (LookupError, UnicodeDecodeError):
                        continue
                else:
                    chunks.append(chunk.decode("utf-8", errors="replace"))
            else:
                chunks.append(chunk)
        return "".join(chunks)


def part_to_text(part) -> str:
    try:
        content = part.get_content()
        if isinstance(content, str):
            return content
    except Exception:
        pass

    payload = part.get_payload(decode=True)
    if payload is None:
        raw_payload = part.get_payload()
        return raw_payload if isinstance(raw_payload, str) else ""

    encodings = [part.get_content_charset(), "utf-8", "cp949", "euc-kr", "latin-1"]
    for encoding in encodings:
        if not encoding:
            continue
        try:
            return payload.decode(encoding)
        except (LookupError, UnicodeDecodeError):
            continue
    return payload.decode("utf-8", errors="replace")


def html_to_text(html: str) -> str:
    parser = HtmlToText()
    parser.feed(html)
    parser.close()
    return parser.get_text()


def normalize_text(text: str) -> str:
    text = unescape(text)
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = text.replace("\xa0", " ")
    text = re.sub(r"[ \t]+\n", "\n", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def extract_body(message) -> str:
    plain_parts: list[str] = []
    html_parts: list[str] = []

    for part in message.walk():
        if part.is_multipart():
            continue
        if part.get_content_disposition() == "attachment" or part.get_filename():
            continue

        content_type = part.get_content_type().lower()
        if content_type == "text/plain":
            text = normalize_text(part_to_text(part))
            if text:
                plain_parts.append(text)
        elif content_type == "text/html":
            text = html_to_text(part_to_text(part))
            if text:
                html_parts.append(text)

    if plain_parts:
        return normalize_text("\n\n".join(plain_parts))
    if html_parts:
        return normalize_text("\n\n".join(html_parts))
    return ""


def convert_file(eml_path: Path, output_dir: Path) -> Path:
    with eml_path.open("rb") as fp:
        message = BytesParser(policy=policy.default).parse(fp)

    subject = decode_mime_header(message.get("Subject"))
    body = extract_body(message)
    output_text = f"제목: {subject}\n\n본문:\n{body}\n"

    output_path = output_dir / f"{eml_path.stem}.txt"
    output_path.write_text(output_text, encoding="utf-8")
    return output_path


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Extract only subject and body from .eml files into .txt files."
    )
    parser.add_argument(
        "input_dir",
        nargs="?",
        default="thesis/Sent_702fbtngus",
        help="Directory containing .eml files.",
    )
    parser.add_argument(
        "-o",
        "--output-dir",
        default=None,
        help="Directory where .txt files will be written.",
    )
    args = parser.parse_args()

    input_dir = Path(args.input_dir)
    output_dir = Path(args.output_dir) if args.output_dir else input_dir.with_name(f"{input_dir.name}_txt")
    output_dir.mkdir(parents=True, exist_ok=True)

    eml_files = sorted(input_dir.glob("*.eml"))
    converted = 0
    errors: list[tuple[Path, Exception]] = []

    for eml_path in eml_files:
        try:
            convert_file(eml_path, output_dir)
            converted += 1
        except Exception as exc:
            errors.append((eml_path, exc))

    print(f"Converted {converted} of {len(eml_files)} .eml files to {output_dir}")
    if errors:
        print("Errors:")
        for path, exc in errors:
            print(f"- {path}: {exc}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
