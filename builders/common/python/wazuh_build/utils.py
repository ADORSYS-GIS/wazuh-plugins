import hashlib
import os
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator


DEFAULT_CACHE_DIR = Path(os.environ.get("WAZUH_BUILD_CACHE", Path.home() / ".cache" / "wazuh-build")).resolve()


def ensure_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path


@contextmanager
def tempdir(prefix: str = "wazuh-build-") -> Iterator[Path]:
    root = Path(tempfile.mkdtemp(prefix=prefix))
    try:
        yield root
    finally:
        if root.exists():
            import shutil

            shutil.rmtree(root, ignore_errors=True)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(8192), b""):
            digest.update(chunk)
    return digest.hexdigest()
