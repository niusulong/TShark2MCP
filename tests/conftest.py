"""Shared pytest fixtures.

pcap files live in the repository root (two levels above ``tests/``), not in
``TShark2MCP/``, so tests reference them via :data:`REPO_ROOT`.
"""

from __future__ import annotations

from pathlib import Path

import pytest

# tests/ -> TShark2MCP/ -> repository root (where the .pcap files live)
REPO_ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="session")
def repo_root() -> Path:
    return REPO_ROOT


@pytest.fixture(scope="session")
def pcap_paths() -> dict[str, Path]:
    return {
        "fail_123": REPO_ROOT / "123下载失败.pcap",
        "fail_1234": REPO_ROOT / "1234下载失败.pcap",
        "success": REPO_ROOT / "下载成功.pcap",
        "ftpsfota": REPO_ROOT / "ftpsfota.pcapng",
    }


@pytest.fixture(scope="session")
def small_pcap(pcap_paths) -> Path:
    """The 50-packet FTP/TLS capture used by most tests."""
    p = pcap_paths["fail_123"]
    if not p.exists():
        pytest.skip(f"small pcap missing: {p}")
    return p
