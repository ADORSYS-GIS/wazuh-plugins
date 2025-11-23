#!/usr/bin/env python3
from __future__ import annotations

import os
import shutil
import tempfile
from pathlib import Path

from builders.common.python.wazuh_build import config as wb_config, packaging, platform as wb_platform, shell, utils
from builders.suricata.build.modules.download import download_and_unpack, write_revision_header
from builders.suricata.build.modules.packaging import (
    bundle_runtime_libs,
    install_rules_and_scripts,
    wrap_linux_binaries,
    write_metadata,
    write_systemd_unit,
)


def prepare_dest(release_root: Path, component_root: Path, dest: Path) -> None:
    if release_root.exists():
        shutil.rmtree(release_root)
    (component_root).mkdir(parents=True, exist_ok=True)
    (dest / "artifacts").mkdir(parents=True, exist_ok=True)
    (component_root / "var" / "log" / "suricata").mkdir(parents=True, exist_ok=True)
    (component_root / "var" / "run").mkdir(parents=True, exist_ok=True)
    (component_root / "var" / "lib" / "suricata").mkdir(parents=True, exist_ok=True)


def build_suricata(
    cfg: wb_config.BuilderConfig,
    dest: Path,
    triplet: str,
    version: str,
    rule_bundle: Path,
    rules_info: dict,
) -> None:
    platform_os = wb_platform.os_id()
    platform_arch = wb_platform.arch_id()
    release_name = f"suricata-{version}-{platform_os}-{platform_arch}"
    release_root = dest / "release" / release_name
    component_prefix = "/opt/wazuh/suricata"
    component_root = release_root / component_prefix.lstrip("/")
    prepare_dest(release_root, component_root, dest)
    write_systemd_unit(release_root, component_prefix)

    suricata_version = os.environ.get("PIPELINE_VERSION", "").strip()
    if not suricata_version:
        raise SystemExit("PIPELINE_VERSION not provided")
    suricata_tag = (
        suricata_version
        if suricata_version.startswith("suricata-")
        else f"suricata-{suricata_version}"
    )

    jobs = utils.detect_jobs()
    with tempfile.TemporaryDirectory(prefix="suricata-build-") as build_dir_raw:
        build_dir = Path(build_dir_raw)
        src_dir = download_and_unpack(suricata_tag, build_dir)
        revision_header = write_revision_header(build_dir)

        env = os.environ.copy()
        env["CPPFLAGS"] = f'{env.get("CPPFLAGS", "")} -include {revision_header}'

        configure_args = [
            "--prefix",
            component_prefix,
            "--sysconfdir",
            f"{component_prefix}/etc",
            "--localstatedir",
            f"{component_prefix}/var",
            "--disable-gccmarch-native",
        ]

        if wb_platform.os_id() == "linux":
            configure_args.append("--enable-geoip")
            # configure_args.append("--enable-dpdk")

        if (src_dir / "autogen.sh").exists():
            # Suricata tarballs from GitHub do not include libhtp, which is a submodule.
            # We need to fetch it manually if it's missing.
            libhtp_dir = src_dir / "libhtp"
            if not (libhtp_dir / "Makefile.am").exists():
                print("Fetching libhtp...", flush=True)
                shell.run(["git", "clone", "https://github.com/OISF/libhtp", str(libhtp_dir)], env=env)

            shell.run(["./autogen.sh"], cwd=src_dir, env=env)
        shell.run(["./configure", *configure_args], cwd=src_dir, env=env)
        shell.run(["make", "-j", jobs], cwd=src_dir, env=env)
        shell.run(
            ["make", f"DESTDIR={release_root}", "install"], cwd=src_dir, env=env
        )
        shell.run(
            ["make", f"DESTDIR={release_root}", "install-conf"], cwd=src_dir, env=env
        )

    packaging.prune_payload_directory(component_root)
    bundle_runtime_libs(component_root)
    wrap_linux_binaries(component_root)
    install_rules_and_scripts(rule_bundle, component_root, Path(__file__).parent.parent.parent / "system")
    write_metadata(
        component_root,
        triplet,
        release_name,
        version,
        suricata_tag,
        suricata_version,
        rules_info,
    )
    utils.fix_permissions(component_root)