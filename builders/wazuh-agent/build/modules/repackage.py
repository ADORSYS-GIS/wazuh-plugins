#!/usr/bin/env python3
from __future__ import annotations

import os
import shutil
import tempfile
from pathlib import Path
from typing import List, Tuple

from builders.common.python.wazuh_build import packaging, platform as wb_platform, shell


def stream_from_version(version: str) -> str:
    parts = version.split(".")
    if parts and parts[0].isdigit():
        return f"{parts[0]}.x"
    return "4.x"


def require_tools(tool_names: List[str]) -> None:
    missing = [tool for tool in tool_names if not shell.command_exists(tool)]
    if missing:
        raise SystemExit(f"Missing required tools: {', '.join(missing)}")


def download_linux_deb(
    version: str, revision: str, arch: str, target: Path
) -> Tuple[Path, str]:
    stream = stream_from_version(version)
    filename = f"wazuh-agent_{version}-{revision}_{arch}.deb"
    url = f"https://packages.wazuh.com/{stream}/apt/pool/main/w/wazuh-agent/{filename}"
    dest = target / filename
    shell.run(["curl", "-fsSL", url, "-o", str(dest)])
    return dest, url


def download_macos_pkg(
    version: str, revision: str, arch: str, target: Path
) -> Tuple[Path, str]:
    stream = stream_from_version(version)
    filename = f"wazuh-agent-{version}-{revision}.{arch}.pkg"
    url = f"https://packages.wazuh.com/{stream}/macos/{filename}"
    dest = target / filename
    shell.run(["curl", "-fsSL", url, "-o", str(dest)])
    return dest, url


def extract_linux_package(deb_path: Path, release_root: Path) -> None:
    shell.run(["dpkg-deb", "-x", str(deb_path), str(release_root)])


def extract_macos_package(pkg_path: Path, release_root: Path) -> None:
    with tempfile.TemporaryDirectory(prefix="wazuh-agent-pkg-") as tmpdir:
        expanded = Path(tmpdir) / "expanded"
        shell.run(["pkgutil", "--expand-full", str(pkg_path), str(expanded)])
        payload_dirs = sorted(expanded.glob("**/Payload"))
        if not payload_dirs:
            raise SystemExit("No Payload directory found in macOS pkg.")
        payload_dir = payload_dirs[0]
        shutil.copytree(payload_dir, release_root, dirs_exist_ok=True, symlinks=True)


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