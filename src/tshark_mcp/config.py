"""Runtime configuration: tshark / capinfos executable discovery.

Resolution priority:
  1. ``TSHARK_PATH`` env var (executable file *or* Wireshark install directory)
  2. **Bundled** portable Wireshark shipped under ``vendor/wireshark/`` next to
     the package — the self-contained default for clone-and-run deployments
     (works for editable / source-tree installs where ``vendor/`` is present)
  3. Common Windows Wireshark install directories
  4. System ``PATH`` (bare ``tshark`` / ``capinfos``)

capinfos is discovered alongside tshark (same directory) when possible.

Note: the bundled ``vendor/wireshark/`` is resolved *relative to this module*.
It is therefore only found when running from the source tree or an editable
install (``pip install -e .``). A non-editable wheel install does not ship the
~155 MB of binaries and will transparently fall back to a system Wireshark.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
from pathlib import Path

logger = logging.getLogger(__name__)

# Common Wireshark install locations on Windows
_WINDOWS_CANDIDATES = [
    r"C:\Program Files\Wireshark",
    r"C:\Program Files (x86)\Wireshark",
]

#: Default subprocess timeout (seconds) for a single tshark invocation.
DEFAULT_TIMEOUT_SECONDS = 60.0


def _looks_executable(path: str) -> bool:
    """Return True if ``path --version`` exits cleanly."""
    try:
        result = subprocess.run(
            [path, "--version"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        return result.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def _find_in_dir(directory: str, name: str) -> str | None:
    """Find ``name`` (with optional ``.exe``) inside ``directory``."""
    for candidate in (Path(directory) / name, Path(directory) / f"{name}.exe"):
        if candidate.is_file():
            return str(candidate)
    return None


def _find_bundled_dir() -> Path | None:
    """Locate the bundled ``vendor/wireshark/`` directory relative to this file.

    Walks a bounded set of ancestors of this module so the lookup tolerates
    different source layouts (src-layout editable install → repo root is
    ``parents[2]``). Returns ``None`` when no bundled tree is present (e.g. a
    wheel install), so callers can fall back to a system Wireshark.
    """
    here = Path(__file__).resolve()
    for parent in list(here.parents)[:4]:
        candidate = parent / "vendor" / "wireshark"
        if (candidate / "tshark.exe").is_file():
            return candidate
    return None


def _resolve_bundled() -> tuple[str, str | None] | None:
    """Return ``(tshark, capinfos)`` from the bundled ``vendor/wireshark/``.

    Returns ``None`` when no usable bundled tree exists.
    """
    bundled_dir = _find_bundled_dir()
    if bundled_dir is None:
        return None
    tshark = _find_in_dir(str(bundled_dir), "tshark")
    if tshark and _looks_executable(tshark):
        logger.info("tshark via bundled vendor/wireshark: %s", tshark)
        return tshark, _find_in_dir(str(bundled_dir), "capinfos")
    return None


def resolve_tshark_paths() -> tuple[str, str | None]:
    """Resolve ``(tshark_path, capinfos_path)``.

    capinfos_path may be ``None`` when only tshark is available (overview then
    falls back to tshark-only statistics). Raises ``RuntimeError`` if tshark
    cannot be located or executed.
    """
    env_path = os.environ.get("TSHARK_PATH")

    # 1. TSHARK_PATH override (directory or executable)
    if env_path:
        env_p = Path(env_path)
        if env_p.is_dir():
            tshark = _find_in_dir(env_path, "tshark")
            if tshark and _looks_executable(tshark):
                logger.info("tshark via TSHARK_PATH dir: %s", tshark)
                return tshark, _find_in_dir(env_path, "capinfos")
        elif env_p.is_file() or _looks_executable(env_path):
            logger.info("tshark via TSHARK_PATH: %s", env_path)
            return env_path, _find_in_dir(str(env_p.parent), "capinfos")

    # 2. Bundled portable Wireshark (vendor/wireshark/) — self-contained default
    bundled = _resolve_bundled()
    if bundled:
        return bundled

    # 3. Common Windows install dirs
    for directory in _WINDOWS_CANDIDATES:
        tshark = _find_in_dir(directory, "tshark")
        if tshark and _looks_executable(tshark):
            logger.info("tshark via install dir: %s", tshark)
            return tshark, _find_in_dir(directory, "capinfos")

    # 4. System PATH
    if shutil.which("tshark"):
        logger.info("tshark via PATH")
        return "tshark", (shutil.which("capinfos") or None)

    raise RuntimeError(
        "tshark not found. Options: (a) keep the bundled vendor/wireshark/ in "
        "the source tree, (b) set TSHARK_PATH, (c) install Wireshark, or "
        "(d) add tshark to PATH."
    )
