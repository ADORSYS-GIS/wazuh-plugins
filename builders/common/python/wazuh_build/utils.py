import hashlib
import os
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from . import platform as wb_platform


DEFAULT_CACHE_DIR = Path(
    os.environ.get("WAZUH_BUILD_CACHE", Path.home() / ".cache" / "wazuh-build")
).resolve()


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


def prepend_path_if_missing(path_str: str) -> None:
    current = os.environ.get("PATH", "")
    parts = current.split(":") if current else []
    if path_str and path_str not in parts:
        parts.insert(0, path_str)
        os.environ["PATH"] = ":".join(parts)


def detect_jobs() -> str:
    if "MAKE_JOBS" in os.environ and os.environ["MAKE_JOBS"]:
        return os.environ["MAKE_JOBS"]
    return str(wb_platform.cpu_count())


def _should_be_executable(path: Path) -> bool:
    return (
        path.parent.name == "bin"
        or path.suffix in {".sh", ".py"}
        or os.access(path, os.X_OK)
    )


def fix_permissions(component_root: Path) -> None:
    for path in component_root.rglob("*"):
        try:
            if path.is_dir():
                path.chmod(0o770)
            else:
                path.chmod(0o775 if _should_be_executable(path) else 0o770)
        except Exception:
            continue
