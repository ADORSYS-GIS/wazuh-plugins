import os
import shlex
import subprocess
from pathlib import Path
from typing import Iterable, List, Optional

from . import shell, utils, download


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

    def is_installed(pkg: str) -> bool:
        result = shell.run(
            ["brew", "list", "--versions", pkg], check=False, capture=True
        )
        return result.returncode == 0 and bool((result.stdout or "").strip())

    missing = [pkg for pkg in pkgs if not is_installed(pkg)]
    if not missing:
        print("[brew] all requested packages are already installed; skipping.")
        return

    _update_brew()
    _install_missing_packages(missing, is_installed)


def _update_brew() -> None:
    """Attempt to update brew, but continue on failure."""
    try:
        shell.run(["brew", "update"])
    except Exception as exc:
        print(f"[brew] update failed ({exc}); continuing with installs.")


def _install_missing_packages(missing: List[str], is_installed) -> None:
    """Install missing packages with retry logic."""
    failures = []
    for pkg in missing:
        try:
            shell.run(["brew", "install", pkg])
        except Exception:
            # If the install failed but the package ended up present, continue.
            if is_installed(pkg):
                continue
            # One retry via reinstall to recover from partial/dirty installs.
            retry = shell.run(["brew", "reinstall", pkg], check=False)
            if retry.returncode != 0 and not is_installed(pkg):
                failures.append(pkg)
    if failures:
        raise SystemExit(f"Failed to install Homebrew packages: {', '.join(failures)}")


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
    shell.run(
        f"curl -sSfL {install_script} | sh -s -- -b {shlex.quote(str(cache_dir))} {version}"
    )
    final = cache_dir / "syft"
    if not final.exists():
        raise RuntimeError("syft installation failed")
    final.rename(syft_target)
    return syft_target


def ensure_cbindgen() -> None:
    def current_version() -> Optional[str]:
        if not shell.command_exists("cbindgen"):
            return None
        try:
            result = subprocess.check_output(
                ["cbindgen", "--version"], text=True
            ).strip()
            return result.split()[-1]
        except Exception:
            return None

    cur = current_version()
    if cur and _version_at_least(cur, "0.20.0"):
        return
    
    _install_cbindgen()


def _install_cbindgen() -> None:
    """Install cbindgen via cargo."""
    if not shell.command_exists("cargo"):
        raise RuntimeError("cargo not available to install cbindgen")

    cache_dir = utils.DEFAULT_CACHE_DIR / "cargo-bin"
    env = os.environ.copy()
    env["CARGO_INSTALL_ROOT"] = str(cache_dir)
    shell.run(["cargo", "install", "--locked", "--force", "cbindgen"], env=env)
    # Add to PATH
    os.environ["PATH"] = f"{cache_dir}/bin:{os.environ.get('PATH', '')}"


def _version_at_least(version: str, required: str) -> bool:
    def normalize(v: str) -> List[int]:
        return [int(x) for x in v.split(".") if x.isdigit()]

    return normalize(version) >= normalize(required)


def ensure_pkg_config_path() -> None:
    """Populate PKG_CONFIG_PATH with common locations (including multiarch) if missing."""
    if "PKG_CONFIG_PATH" in os.environ and os.environ["PKG_CONFIG_PATH"]:
        return
    
    candidates = _get_pkg_config_candidates()
    if candidates:
        os.environ["PKG_CONFIG_PATH"] = ":".join(candidates)


def _get_pkg_config_candidates() -> List[str]:
    """Get list of pkg-config paths to use."""
    candidates = []
    
    # Try to get multiarch path
    multiarch = _get_multiarch()
    if multiarch:
        candidates.append(f"/usr/lib/{multiarch}/pkgconfig")
    
    # Add standard paths
    candidates.extend(["/usr/lib/pkgconfig", "/usr/share/pkgconfig"])
    
    # Filter to only existing paths
    existing = [c for c in candidates if Path(c).exists()]
    
    # Add any existing PKG_CONFIG_PATH
    if os.environ.get("PKG_CONFIG_PATH"):
        existing.append(os.environ["PKG_CONFIG_PATH"])
    
    return existing


def _get_multiarch() -> str:
    """Get the multiarch string from dpkg-architecture."""
    try:
        result = shell.run(
            ["dpkg-architecture", "-qDEB_HOST_MULTIARCH"], capture=True, check=False
        )
        return (result.stdout or "").strip()
    except Exception:
        return ""


def require_tools(tool_names: List[str]) -> None:
    missing = [tool for tool in tool_names if not shell.command_exists(tool)]
    if missing:
        raise SystemExit(f"Missing required tools: {', '.join(missing)}")


def require_libraries(lib_names: List[str]) -> None:
    missing: List[str] = []
    for lib in lib_names:
        if not _check_library_available(lib):
            missing.append(lib)
    if missing:
        raise SystemExit(f"Missing required libraries: {', '.join(missing)}")


def _check_library_available(lib: str) -> bool:
    """Check if a library is available via pkg-config."""
    try:
        shell.run(["pkg-config", "--exists", lib], check=True, capture=True)
        return True
    except Exception:
        if lib == "libmagic":
            # libmagic pkg-config metadata is flaky; never fail the build on
            # it. Fall back to the header check purely for logging purposes.
            if download.has_magic_header():
                print(
                    "Warning: libmagic pkg-config check failed; proceeding because header check passed."
                )
            else:
                print(
                    "Warning: libmagic pkg-config check failed; proceeding anyway."
                )
            return True
        return False
