"""
Common download operations for Wazuh builders.
"""

import hashlib
import re
import shutil
import tarfile
import urllib.request
from pathlib import Path
from typing import Optional

from . import utils

_SIDECAR_DIGEST = re.compile(r"\b[0-9a-fA-F]{32}\b")


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


def fetch_sidecar_digest(url: str) -> str:
    """
    Read a published checksum sidecar (for example ``rules.tar.gz.md5``) and
    return the digest it contains.
    """
    with urllib.request.urlopen(url, timeout=60) as resp:
        text = resp.read().decode("utf-8", "replace")
    match = _SIDECAR_DIGEST.search(text)
    if not match:
        raise SystemExit(f"Unable to parse checksum sidecar: {url}")
    return match.group(0).lower()


def md5_file(path: Path) -> str:
    """
    Return the MD5 digest of a file.

    Several upstream feeds publish only an MD5 sidecar next to a file that they
    regenerate continuously. It is used to detect truncated or corrupted
    downloads; transport security still comes from TLS. Bandit reports
    ``hashlib.md5`` at HIGH severity, hence the explicit, justified suppression.
    """
    # MD5 is the only digest the publisher maintains for this rolling feed. It
    # is a download-corruption check, not a security control: TLS is the
    # transport boundary, and the immutable YARA assets are pinned with
    # SHA-256. Both analysers are told so explicitly, since neither can know
    # that the weak algorithm is dictated by the upstream feed.
    digest = hashlib.md5()  # nosec B324  # NOSONAR
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _verify_archive(
    archive_path: Path,
    sha256: Optional[str],
    md5: Optional[str],
    cached: bool,
) -> None:
    if md5:
        actual_md5 = md5_file(archive_path)
        if actual_md5 != md5:
            if not cached:
                archive_path.unlink(missing_ok=True)
            prefix = "Cached" if cached else "Downloaded"
            raise SystemExit(
                f"{prefix} archive md5 mismatch (expected {md5}, got {actual_md5})"
            )
    if sha256 and utils.sha256_file(archive_path) != sha256:
        if not cached:
            archive_path.unlink(missing_ok=True)
        prefix = "Cached" if cached else "Downloaded"
        raise SystemExit(f"{prefix} archive checksum mismatch: {archive_path}")


def ensure_archive(
    asset_url: str,
    sha256: Optional[str],
    archive_path: Path,
    force: bool = False,
    md5_url: Optional[str] = None,
) -> Path:
    """
    Ensure an archive exists at the specified path and matches the published
    checksum. If not, download it.

    ``sha256`` may be ``None`` for rolling upstream feeds that publish no stable
    digest; callers should only do this for sources that cannot be pinned. Such
    a feed can still be verified with ``md5_url``, a sidecar maintained by the
    publisher (see ``builders/suricata/rules/source.json``).
    """
    md5 = fetch_sidecar_digest(md5_url) if md5_url else None

    if archive_path.exists() and not force:
        if md5 and md5_file(archive_path) != md5:
            # The publisher replaced the artifact since we cached it. That is
            # expected for rolling feeds, so refetch rather than fail.
            print(
                f"[download] cached {archive_path.name} no longer matches the "
                "upstream digest; refetching"
            )
        else:
            _verify_archive(archive_path, sha256, md5, cached=True)
            return archive_path

    download_file(asset_url, archive_path)
    if sha256 or md5:
        _verify_archive(archive_path, sha256, md5, cached=False)
        return archive_path

    actual = utils.sha256_file(archive_path)
    print(
        f"[download] no published checksum for {archive_path.name}; "
        f"skipping verification (sha256 {actual})"
    )
    return archive_path
