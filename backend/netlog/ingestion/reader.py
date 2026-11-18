"""Reads a log file one line at a time, whatever its size or encoding."""

from __future__ import annotations

import codecs
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

DEFAULT_MAX_LINE_LENGTH = 8192
_UTF8_BOM = codecs.BOM_UTF8
_UTF16_BOMS = (codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)


class BinaryFileError(ValueError):
    """The file is not text (an image, an archive, a database file and so on)."""


@dataclass(frozen=True)
class RawLine:
    line_no: int
    text: str
    truncated: bool = False


def read_lines(
    path: str | Path, max_line_length: int = DEFAULT_MAX_LINE_LENGTH
) -> Iterator[RawLine]:
    """Yield every line of a log file, numbered from 1, without loading the file into memory.

    Handles UTF-8 (with or without a byte-order mark), UTF-16 (what Windows PowerShell
    writes when output is redirected to a file), and stray non-UTF-8 bytes. Windows and
    Unix line endings are both stripped. Blank lines are yielded with empty text so that
    line numbers always match the file. A line longer than `max_line_length` is cut at
    that length and marked as truncated.
    """
    with open(path, "rb") as handle:
        head = handle.read(4096)
        if head.startswith(_UTF16_BOMS):
            yield from _read_utf16(path, max_line_length)
            return
        if b"\x00" in head:
            raise BinaryFileError(f"{Path(path).name} is not a text file")
        handle.seek(0)

        line_no = 0
        while chunk := handle.readline(max_line_length + 1):
            line_no += 1
            if line_no == 1 and chunk.startswith(_UTF8_BOM):
                chunk = chunk[len(_UTF8_BOM) :]

            truncated = len(chunk) > max_line_length and not chunk.endswith(b"\n")
            if truncated:
                chunk = chunk[:max_line_length]
                # Skip the rest of the oversized line in bounded pieces.
                while (rest := handle.readline(65536)) and not rest.endswith(b"\n"):
                    pass

            yield RawLine(line_no, _decode(chunk, lenient=truncated), truncated)


def _decode(chunk: bytes, *, lenient: bool) -> str:
    try:
        text = chunk.decode("utf-8")
    except UnicodeDecodeError:
        # A cut line may end mid-character; otherwise assume a legacy one-byte encoding.
        text = chunk.decode("utf-8", "replace") if lenient else chunk.decode("latin-1")
    return text.rstrip("\r\n")


def _read_utf16(path: str | Path, max_line_length: int) -> Iterator[RawLine]:
    with open(path, encoding="utf-16", errors="replace", newline=None) as handle:
        for line_no, line in enumerate(handle, 1):
            text = line.rstrip("\r\n")
            truncated = len(text) > max_line_length
            yield RawLine(line_no, text[:max_line_length], truncated)
