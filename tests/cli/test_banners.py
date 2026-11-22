import io
import sys
from unittest import mock

import pytest

from wapitiCore.main import banners


def make_output(encoding: str) -> io.TextIOWrapper:
    return io.TextIOWrapper(io.BytesIO(), encoding=encoding, newline="\n")


def printed_text(output: io.TextIOWrapper) -> str:
    output.flush()
    return output.buffer.getvalue().decode(output.encoding)


@pytest.mark.parametrize("banner_index", [0, 1, 2])
def test_print_banner_on_cp1252_output(banner_index, monkeypatch):
    """Any banner picked at random must not crash on an output that cannot encode box-drawing characters (#836)"""
    output = make_output("cp1252")
    monkeypatch.setattr(sys, "stdout", output)

    with mock.patch.object(banners, "choice", side_effect=lambda items: items[banner_index]):
        banners.print_banner()

    text = printed_text(output)
    assert text.strip()
    assert text.isascii()


def test_print_banner_keeps_unicode_banner_on_utf8_output(monkeypatch):
    output = make_output("utf-8")
    monkeypatch.setattr(sys, "stdout", output)

    with mock.patch.object(banners, "choice", side_effect=lambda items: items[-1]):
        banners.print_banner()

    assert "██╗" in printed_text(output)
