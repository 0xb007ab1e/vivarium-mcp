"""Pure parser for the U-Boot legacy uImage header (ADR-070 container follow-up).

A uImage wraps a payload (kernel/firmware) behind a fixed **64-byte** big-endian header
(``image_header_t``). This module parses ONLY that header — it never reads the payload, never
allocates by an untrusted length, and never touches the JVM or the filesystem — so it is a pure,
hermetically fuzzable boundary (``@rules/topic-architecture-patterns`` functional core). The worker
(``_decompress_container``) calls :func:`parse_uimage_header`, then slices + streams the payload
under the SAME zip-bomb caps as the plain ``gzip``/``xz``/``lzma`` containers.

Every byte here is HOSTILE input (a firmware image of unknown origin, ADR-005): the parser is
total on the header window — it either returns a validated :class:`UImageHeader` or raises
:class:`ValueError`; it must never crash, hang, or over-read on arbitrary bytes (verified by the
property/fuzz tests).
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Final

#: The legacy uImage magic (``IH_MAGIC``), big-endian at offset 0.
UIMAGE_MAGIC: Final = 0x27051956

#: The fixed legacy header size in bytes; the payload begins immediately after it.
UIMAGE_HEADER_SIZE: Final = 64

#: Compression codes (``ih_comp``) this project can unwrap. bzip2/lzo/lz4 (2/4/5) are intentionally
#: NOT accepted — they map to no stdlib streaming decompressor here and are rejected as unsupported.
_COMP_NONE: Final = 0
_COMP_GZIP: Final = 1
_COMP_LZMA: Final = 3
#: Public name for each supported code — the value the worker switches the decompressor on.
COMP_NAMES: Final = {_COMP_NONE: "none", _COMP_GZIP: "gzip", _COMP_LZMA: "lzma"}


@dataclass(frozen=True)
class UImageHeader:
    """A validated uImage legacy header (the fields the unwrap path needs).

    Attributes:
        payload_size: ``ih_size`` — the payload byte count that follows the 64-byte header (already
            range-checked to be positive and within the sanity ceiling; the worker still bounds the
            actual slice against the real file size + the zip-bomb caps).
        comp: The payload compression as a name — ``"none"`` / ``"gzip"`` / ``"lzma"``.
    """

    payload_size: int
    comp: str


def parse_uimage_header(data: bytes, *, max_payload_size: int) -> UImageHeader:
    """Parse + validate a uImage legacy header from the leading bytes of a firmware image.

    Args:
        data: The image bytes; only the first :data:`UIMAGE_HEADER_SIZE` are read.
        max_payload_size: The absolute ceiling the declared ``ih_size`` must not exceed — a hostile
            header claiming a huge payload is rejected here, before any slice/allocation (CWE-400 /
            CWE-190). The caller passes the operator's decompressed-output cap.

    Returns:
        The validated :class:`UImageHeader`.

    Raises:
        ValueError: If the header is short, the magic is wrong, the declared size is
            non-positive or over ``max_payload_size``, or the compression code is unsupported.
    """
    if len(data) < UIMAGE_HEADER_SIZE:
        raise ValueError("not a uImage: shorter than the 64-byte header")
    magic = struct.unpack_from(">I", data, 0)[0]
    if magic != UIMAGE_MAGIC:
        raise ValueError("not a uImage: bad magic")
    payload_size = struct.unpack_from(">I", data, 12)[0]
    comp_code = data[31]
    if payload_size <= 0:
        raise ValueError("uImage declares a non-positive payload size")
    if payload_size > max_payload_size:
        raise ValueError("uImage declares a payload larger than the allowed cap")
    comp = COMP_NAMES.get(comp_code)
    if comp is None:
        raise ValueError(f"uImage compression code {comp_code} is unsupported")
    return UImageHeader(payload_size=payload_size, comp=comp)
