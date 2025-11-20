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


def ensure_cbindgen(required: str, minimum: str = "0.20.0") -> None:
    def current_version() -> Optional[str]:
        if not shell.command_exists("cbindgen"):
            return None
        try:
            result = subprocess.check_output(["cbindgen", "--version"], text=True).strip()
            return result.split()[-1]
        except Exception:
            return None

    cur = current_version()
    if cur and _version_at_least(cur, minimum):
        return
    if not shell.command_exists("cargo"):
        raise RuntimeError("cargo not available to install cbindgen")
    cache_dir = utils.DEFAULT_CACHE_DIR / "cargo-bin"
    env = os.environ.copy()
    env["CARGO_INSTALL_ROOT"] = str(cache_dir)
    shell.run(["cargo", "install", "--locked", "--force", "cbindgen", "--version", required], env=env)
    # Add to PATH
    os.environ["PATH"] = f"{cache_dir}/bin:{os.environ.get('PATH','')}"


def _version_at_least(version: str, required: str) -> bool:
    def normalize(v: str) -> List[int]:
        return [int(x) for x in v.split(".") if x.isdigit()]

    return normalize(version) >= normalize(required)
