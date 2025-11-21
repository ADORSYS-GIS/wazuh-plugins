import os
import shlex
import shutil
import subprocess
from pathlib import Path
from typing import Iterable, List, Optional

from . import shell, utils


def install_apt(packages: Iterable[str]) -> None:
    pkgs = [p for p in packages if p]
    if not pkgs:
        return
    shell.run("apt-get update -qq")
    shell.run(["apt-get", "install", "-y", "--no-install-recommends", *pkgs])


def install_brew(packages: Iterable[str]) -> None:
    pkgs = [p for p in packages if p]
    if not pkgs:
        return
    shell.run(["brew", "update"])
    shell.run(["brew", "install", *pkgs])


def run_bash_commands(commands: Iterable[str]) -> None:
    for cmd in commands:
        cmd = cmd.strip()
        if not cmd:
            continue
        shell.run(cmd)


def ensure_syft(version: str, tools_dir: Path) -> Path:
    utils.ensure_dir(tools_dir)
    cache_dir = utils.DEFAULT_CACHE_DIR / "syft"
    utils.ensure_dir(cache_dir)
    syft_target = cache_dir / f"syft-{version}"
    if syft_target.exists():
        return syft_target
    install_script = "https://raw.githubusercontent.com/anchore/syft/main/install.sh"
    shell.run(f"curl -sSfL {install_script} | sh -s -- -b {shlex.quote(str(cache_dir))} {version}")
    final = cache_dir / "syft"
    if not final.exists():
        raise RuntimeError("syft installation failed")
    final.rename(syft_target)
    return syft_target


def _version_at_least(version: str, required: str) -> bool:
    def normalize(v: str) -> List[int]:
        return [int(x) for x in v.split(".") if x.isdigit()]

    return normalize(version) >= normalize(required)
