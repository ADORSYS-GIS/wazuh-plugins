#!/usr/bin/env python3
from __future__ import annotations

import os
import shutil
import tempfile
from pathlib import Path

from builders.common.python.wazuh_build import config as wb_config, packaging, platform as wb_platform, shell, utils
from builders.yara.build.modules.download import download_and_unpack, write_revision_header, _feature_enabled
from builders.yara.build.modules.packaging import (
    bundle_runtime_libs,
    install_rules_and_scripts,
    wrap_linux_binaries,
    write_metadata,
)


def prepare_dest(release_root: Path, component_root: Path, dest: Path) -> None:
    if release_root.exists():
        shutil.rmtree(release_root)
    component_root.mkdir(parents=True, exist_ok=True)
    (dest / "artifacts").mkdir(parents=True, exist_ok=True)


def build_yara(
    cfg: wb_config.BuilderConfig,
    dest: Path,
    triplet: str,
    version: str,
    rule_bundle: Path,
    rules_info: dict,
) -> None:
    platform_os = wb_platform.os_id()
    platform_arch = wb_platform.arch_id()
    release_name = f"yara-{version}-{platform_os}-{platform_arch}"
    release_root = dest / "release" / release_name
    component_prefix = "/opt/wazuh/yara"
    component_root = release_root / component_prefix.lstrip("/")
    prepare_dest(release_root, component_root, dest)

    yara_version = os.environ.get("PIPELINE_VERSION", "").strip()
    if not yara_version:
        raise SystemExit("PIPELINE_VERSION not provided")

    jobs = utils.detect_jobs()
    with tempfile.TemporaryDirectory(prefix="yara-build-") as build_dir_raw:
        build_dir = Path(build_dir_raw)
        src_dir = download_and_unpack(yara_version, build_dir)
        revision_header = write_revision_header(build_dir)
        env = os.environ.copy()
        env["CPPFLAGS"] = f'{env.get("CPPFLAGS", "")} -include {revision_header}'
        rpath_flag = (
            "-Wl,-rpath,@loader_path/../lib -Wl,-install_name,@rpath/libyara.dylib"
            if wb_platform.os_id() == "macos"
            else "-Wl,-rpath,$ORIGIN/../lib"
        )
        env["LDFLAGS"] = f'{env.get("LDFLAGS", "")} {rpath_flag}'

        default_enable = wb_platform.os_id() == "linux"
        enable_cuckoo = _feature_enabled("ENABLE_YARA_CUCKOO", default_enable)
        enable_dotnet = _feature_enabled("ENABLE_YARA_DOTNET", default_enable)
        configure_args = [
            "--prefix",
            component_prefix,
            "--with-crypto",
            "--enable-magic",
        ]
        if enable_cuckoo:
            configure_args.append("--enable-cuckoo")
        if enable_dotnet:
            configure_args.append("--enable-dotnet")
        shell.run(["./bootstrap.sh"], cwd=src_dir, env=env)
        shell.run(["./configure", *configure_args], cwd=src_dir, env=env)
        shell.run(["make", "-j", jobs], cwd=src_dir, env=env)
        shell.run(["make", f"DESTDIR={release_root}", "install"], cwd=src_dir, env=env)

    packaging.prune_payload_directory(component_root)
    bundle_runtime_libs(component_root)
    wrap_linux_binaries(component_root)
    install_rules_and_scripts(
        release_root, rule_bundle, component_root, Path(__file__).parent.parent.parent / "system"
    )
    write_metadata(
        component_root, triplet, release_name, version, yara_version, rules_info
    )
    utils.fix_permissions(component_root)