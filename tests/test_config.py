"""Tests for tshark/capinfos path resolution, including the bundled
``vendor/wireshark/`` fallback that lets the project run without a system
Wireshark install.

The bundled tree only ships with the source checkout (editable install), so
these tests skip cleanly when it is absent (e.g. a wheel install or CI without
the vendor tree).
"""

from __future__ import annotations

import os

import pytest

from tshark_mcp import config


def test_find_bundled_dir_locates_vendor_tree():
    """The bundled vendor/wireshark/ tree is found relative to the package."""
    bundled = config._find_bundled_dir()
    if bundled is None:
        pytest.skip("no bundled vendor/wireshark/ in this install")
    assert bundled.is_dir()
    assert bundled.name == "wireshark"
    assert bundled.parent.name == "vendor"
    assert (bundled / "tshark.exe").is_file()


@pytest.mark.integration
def test_resolve_prefers_bundled_when_no_env(monkeypatch):
    """With TSHARK_PATH unset and the vendor tree present, bundled wins.

    Marked integration because resolve_tshark_paths() probes the bundled
    tshark with `tshark --version` (a real, fast subprocess).
    """
    if config._find_bundled_dir() is None:
        pytest.skip("no bundled vendor/wireshark/ in this install")
    monkeypatch.delenv("TSHARK_PATH", raising=False)

    tshark, capinfos = config.resolve_tshark_paths()

    norm_t = os.path.normcase(tshark)
    assert os.sep + "vendor" + os.sep + "wireshark" in norm_t, tshark
    assert norm_t.endswith(os.sep + "tshark.exe")
    assert capinfos is not None
    assert os.path.normcase(capinfos).endswith(os.sep + "capinfos.exe")
