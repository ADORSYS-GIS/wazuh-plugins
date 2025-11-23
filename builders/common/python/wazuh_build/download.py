"""
Common download operations for Wazuh builders.
"""

import shutil
import tarfile
import urllib.request
from pathlib import Path

from . import utils


def strip_components(tf: tarfile.TarFile, n: int = 1):
    for member in tf.getmembers():
        parts = member.name.split("/", n)
        member.name = parts[-1] if len(parts) == n + 1 else "/".join(parts[n:])
        yield member


def has_magic_header() -> bool:
    candidates = [
        Path("/usr/include/magic.h"),
        Path("/usr/local/include/magic.h"),
    ]
    candidates.extend(Path("/usr/include").glob("*/magic.h"))
    candidates.extend(Path("/usr/local/include").glob("*/magic.h"))
    return any(p.exists() for p in candidates)


def download_file(url: str, dest: Path) -> None:
    """
    Download a file from a URL to a destination path.
    """
    dest.parent.mkdir(parents=True, exist_ok=True)
    with urllib.request.urlopen(url) as resp, dest.open("wb") as fh:
        shutil.copyfileobj(resp, fh)


def ensure_archive(
    asset_url: str, sha256: str, archive_path: Path, force: bool = False
) -> Path:
    """
    Ensure an archive exists at the specified path and matches the SHA256 checksum.
    If not, download it.
    """
    if archive_path.exists() and not force:
        if utils.sha256_file(archive_path) != sha256:
            raise SystemExit(f"Cached archive checksum mismatch: {archive_path}")
        return archive_path
    download_file(asset_url, archive_path)
    actual = utils.sha256_file(archive_path)
    if actual != sha256:
        archive_path.unlink(missing_ok=True)
        raise SystemExit(
            f"Downloaded archive checksum mismatch (expected {sha256}, got {actual})"
        )
    return archive_path
