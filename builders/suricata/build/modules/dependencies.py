#!/usr/bin/env python3
from __future__ import annotations

import os
from pathlib import Path

from builders.common.python.wazuh_build import config as wb_config
from builders.common.python.wazuh_build import deps, platform as wb_platform, shell, utils


def ensure_dependencies(cfg: wb_config.BuilderConfig) -> None:
    if wb_platform.os_id() == "linux" and shell.command_exists("apt-get"):
        deps.install_apt(cfg.dependency_section("apt"))
        deps.run_bash_commands(cfg.dependency_section("bash"))
    if wb_platform.os_id() == "macos" and shell.command_exists("brew"):
        deps.install_brew(cfg.dependency_section("brew"))
        configure_macos_env()

    deps.ensure_pkg_config_path()
    deps.ensure_cbindgen()


def configure_macos_env() -> None:
    if wb_platform.os_id() != "macos" or not shell.command_exists("brew"):
        return
    pkgconfig_paths = []
    for pkg in ["pcre", "pcre2", "libyaml", "jansson", "libmagic", "libpcap", "libnet", "lz4", "zlib"]:
        try:
            result = shell.run(["brew", "--prefix", pkg], capture=True, check=False)
            prefix = (result.stdout or "").strip()
        except Exception:
            prefix = ""
        if prefix:
            pc = Path(prefix) / "lib" / "pkgconfig"
            if pc.exists():
                pkgconfig_paths.append(str(pc))
            include_dir = Path(prefix) / "include"
            lib_dir = Path(prefix) / "lib"
            if include_dir.exists():
                os.environ["CPPFLAGS"] = (
                    f"-I{include_dir} {os.environ.get('CPPFLAGS', '')}"
                )
            if lib_dir.exists():
                os.environ["LDFLAGS"] = f"-L{lib_dir} {os.environ.get('LDFLAGS', '')}"
            
            bin_dir = Path(prefix) / "bin"
            if bin_dir.exists():
                utils.prepend_path_if_missing(str(bin_dir))

    if pkgconfig_paths:
        existing = os.environ.get("PKG_CONFIG_PATH", "")
        os.environ["PKG_CONFIG_PATH"] = ":".join(
            pkgconfig_paths + ([existing] if existing else [])
        )


def setup_environment() -> None:
    # Ensure common tool locations are on PATH (cargo everywhere, Homebrew on macOS).
    utils.prepend_path_if_missing(str(Path.home() / ".cargo" / "bin"))
    if wb_platform.os_id() == "macos":
        hb = Path("/opt/homebrew/bin")
        if hb.exists():
            utils.prepend_path_if_missing(str(hb))