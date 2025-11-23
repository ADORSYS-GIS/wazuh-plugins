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


def configure_macos_env() -> None:
    if wb_platform.os_id() != "macos" or not shell.command_exists("brew"):
        return
    openssl_prefix = _brew_prefix("openssl@3")
    libmagic_prefix = _brew_prefix("libmagic")
    pcre2_prefix = _brew_prefix("pcre2")

    pkgconfig_parts = []
    for prefix in [openssl_prefix, libmagic_prefix, pcre2_prefix]:
        if prefix:
            pc = Path(prefix) / "lib" / "pkgconfig"
            if pc.exists():
                pkgconfig_parts.append(str(pc))
    if pkgconfig_parts:
        existing = os.environ.get("PKG_CONFIG_PATH", "")
        os.environ["PKG_CONFIG_PATH"] = ":".join(
            pkgconfig_parts + ([existing] if existing else [])
        )

    def add_flag(env_key: str, flag: str) -> None:
        os.environ[env_key] = f"{flag} {os.environ.get(env_key, '')}".strip()

    for prefix in [openssl_prefix, libmagic_prefix, pcre2_prefix]:
        if prefix:
            include_dir = Path(prefix) / "include"
            lib_dir = Path(prefix) / "lib"
            if include_dir.exists():
                add_flag("CPPFLAGS", f"-I{include_dir}")
            if lib_dir.exists():
                add_flag("LDFLAGS", f"-L{lib_dir}")


def _brew_prefix(pkg: str) -> str:
    try:
        result = shell.run(["brew", "--prefix", pkg], capture=True, check=False)
        return (result.stdout or "").strip()
    except Exception:
        return ""


def setup_environment() -> None:
    # Ensure cargo-installed tools are discoverable (and Homebrew on macOS).
    utils.prepend_path_if_missing(str(Path.home() / ".cargo" / "bin"))
    if wb_platform.os_id() == "macos":
        hb = Path("/opt/homebrew/bin")
        if hb.exists():
            utils.prepend_path_if_missing(str(hb))