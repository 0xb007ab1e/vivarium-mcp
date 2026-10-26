"""Unit tests for ADR-078 (C) allow-list projection (``vivarium.report.projection``).

These cover the keystone control: no binary-derived byte survives projection as active markup in any
consumer. The paired TB10 abuse-case suite (``tests/security/test_abuse_cases.py``) exercises the
same payloads end-to-end through the tool; these are the focused unit guarantees.
"""

from __future__ import annotations

import pytest

from vivarium.core.validation import _WRITE_NAME_REST
from vivarium.report.projection import (
    PROJECTION_NAME_CHARSET,
    PROJECTION_PREVIEW_SAFE,
    project_address,
    project_identifier,
    project_string,
)

# Bytes that must NEVER appear literally in a projected rendering — each is active in at least one
# uncontrolled consumer (HTML, Markdown/GFM, or an LLM instruction context).
_MARKUP_ACTIVE = set("<>&\"'[]():!*_~|\\`#{}")


class TestProjectIdentifier:
    def test_safe_charset_passes_literally(self) -> None:
        name = "FUN_00401000$ns.method_v2"
        assert project_identifier(name) == name

    def test_html_injection_fully_escaped(self) -> None:
        out = project_identifier("<img src=x onerror=alert(1)>")
        assert "<" not in out and ">" not in out
        assert "\\x3c" in out  # '<'
        assert "\\x3e" in out  # '>'

    def test_space_and_path_and_control_escaped(self) -> None:
        out = project_identifier("a b/c\x00\n")
        assert out == "a\\x20b\\x2fc\\x00\\x0a"

    def test_bidi_and_zero_width_escaped(self) -> None:
        out = project_identifier("ab‮cd​")
        assert "‮" not in out and "​" not in out
        assert "\\u202e" in out and "\\u200b" in out

    def test_non_bmp_escaped(self) -> None:
        out = project_identifier("x\U0001f4a9")
        assert out == "x\\U0001f4a9"

    def test_truncation_marker(self) -> None:
        out = project_identifier("a" * 10, max_chars=4)
        assert out == "aaaa\\u2026"

    def test_empty(self) -> None:
        assert project_identifier("") == ""

    def test_no_markup_byte_survives_any_payload(self) -> None:
        # Identifiers retain the C-identifier charset (``_ $ .``) by design; backslash appears only
        # as an escape prefix. Every OTHER markup-active byte must be escaped.
        disallowed = _MARKUP_ACTIVE - PROJECTION_NAME_CHARSET - {"\\"}
        for payload in (
            "<script>alert(1)</script>",
            "](javascript:evil)",
            "![](http://x/beacon.png)",
            "`cmd`$(id)",
            "a|b~c*d_e#f{g}",
        ):
            out = project_identifier(payload)
            leaked = set(out) & disallowed
            assert not leaked, f"markup leaked for {payload!r}: {out!r}"


class TestProjectAddress:
    def test_canonical_hex(self) -> None:
        assert project_address(0x401000) == "0x401000"
        assert project_address(0) == "0x0"

    def test_negative(self) -> None:
        assert project_address(-16) == "-0x10"


class TestProjectString:
    def test_markdown_link_injection_neutralized_in_preview(self) -> None:
        proj = project_string("](javascript:evil)")
        assert "](" not in proj.preview
        for ch in "]():":
            assert ch not in proj.preview
        # the bytes are still recoverable, inertly, in the hex dump
        assert "5d" in proj.hex  # ']'

    def test_html_and_svg_neutralized(self) -> None:
        proj = project_string("<svg onload=alert(1)>")
        assert "<" not in proj.preview and ">" not in proj.preview

    def test_markdown_emphasis_and_table_and_code_escaped(self) -> None:
        proj = project_string("a*b_c~d|e`f\\g")
        for ch in "*_~|`":  # original markup bytes gone (``\`` excluded — it is the escape prefix)
            assert ch not in proj.preview
        assert "\\x5c" in proj.preview  # the input backslash itself is escaped

    def test_safe_chars_pass(self) -> None:
        proj = project_string("hello world, v1.2-3=4+5@host")
        assert proj.preview == "hello world, v1.2-3=4+5@host"

    def test_hex_dump_shape_and_byte_len(self) -> None:
        proj = project_string("AB")
        assert proj.byte_len == 2
        assert proj.hex.startswith("00000000: 41 42")
        assert proj.hex.rstrip().endswith("|AB|")

    def test_control_bytes_dot_masked_in_gutter(self) -> None:
        proj = project_string(b"\x00\x01A")
        assert proj.hex.rstrip().endswith("|..A|")

    def test_truncation_flagged(self) -> None:
        proj = project_string("a" * 1000, max_preview=10, max_hex_bytes=10)
        assert proj.truncated is True
        assert proj.byte_len == 1000

    def test_no_markup_byte_survives_preview_for_any_payload(self) -> None:
        for payload in (
            "<img src=x onerror=alert(1)>",
            "](javascript:evil)",
            "![beacon](http://evil/x.png)",
            "`$(reboot)`",
            "# heading\n> quote",
            "{{7*7}}",
        ):
            proj = project_string(payload)
            leaked = set(proj.preview) & (_MARKUP_ACTIVE - {"\\"})
            assert not leaked, f"markup leaked in preview for {payload!r}: {proj.preview!r}"


def test_name_charset_matches_write_name_charset_anti_drift() -> None:
    """Projection's identifier charset must stay identical to the write-name allow-list."""
    assert PROJECTION_NAME_CHARSET == _WRITE_NAME_REST


def test_preview_safe_set_excludes_every_markup_active_byte() -> None:
    """The positive allow-list must contain no byte active in an uncontrolled consumer."""
    assert not (PROJECTION_PREVIEW_SAFE & _MARKUP_ACTIVE)


# Backslash is excluded everywhere below: the escape sequences begin with it, so a literal backslash
# in the OUTPUT is the inert escape prefix, not surviving input (its own escaping is covered by
# test_input_backslash_is_escaped_not_passed_through).
@pytest.mark.parametrize("ch", sorted(_MARKUP_ACTIVE - PROJECTION_NAME_CHARSET - {"\\"}))
def test_markup_byte_escaped_in_identifier(ch: str) -> None:
    # Identifiers retain the C-identifier charset (``_ $ .``); every other markup byte is escaped.
    assert ch not in project_identifier(f"x{ch}y")


@pytest.mark.parametrize("ch", sorted(_MARKUP_ACTIVE - {"\\"}))
def test_markup_byte_escaped_in_string_preview(ch: str) -> None:
    assert ch not in project_string(f"x{ch}y").preview


def test_input_backslash_is_escaped_not_passed_through() -> None:
    # A backslash in the INPUT must become ``\x5c`` (so it can't start a spurious escape); the only
    # backslashes in the output are the escape prefixes this projector itself emits.
    assert project_identifier("a\\b") == "a\\x5cb"
    assert "\\x5c" in project_string("a\\b").preview
