#!/usr/bin/env python3
from __future__ import annotations

import shutil
from pathlib import Path
from typing import Optional

from builders.common.python.wazuh_build import packaging, platform as wb_platform, sbom, shell


def bundle_runtime_libs(component_root: Path) -> None:
    if wb_platform.os_id() != "linux":
        return
    multiarch = ""
    try:
        result = shell.run(["dpkg-architecture", "-qDEB_HOST_MULTIARCH"], capture=True)
        multiarch = (result.stdout or "").strip()
    except Exception:
        pass
    search_paths = []
    if multiarch:
        search_paths.append(Path("/usr/lib") / multiarch)
    search_paths.extend([Path("/usr/lib"), Path("/usr/lib64")])
    libs = [
        "libnet.so.1",
        "libjansson.so.4",
        "libpcap.so.1",
        "libpcap.so.0.8",
        "libmaxminddb.so.0",
    ]
    copied = False
    for lib in libs:
        for base in search_paths:
            candidate = base / lib
            if candidate.exists():
                dest = component_root / "lib"
                dest.mkdir(parents=True, exist_ok=True)
                shutil.copy2(candidate, dest / candidate.name)
                copied = True
                break
    if not copied:
        print(
            "Warning: Unable to bundle runtime libraries; Suricata may require system libs.",
            flush=True,
        )


def wrap_linux_binaries(component_root: Path) -> None:
    if wb_platform.os_id() != "linux":
        return
    bin_dir = component_root / "bin"
    for name in ["suricata", "suricatactl", "suricatasc"]:
        target = bin_dir / name
        if target.exists() and not target.is_symlink():
            real = target.with_suffix(".real")
            target.rename(real)
            wrapper = f"""#!/usr/bin/env bash
set -euo pipefail
script_dir="$(cd "$(dirname "${{BASH_SOURCE[0]}}")" && pwd)"
export LD_LIBRARY_PATH="${{script_dir}}/../lib:${{LD_LIBRARY_PATH:-}}"
exec "${{script_dir}}/{real.name}" "$@"
"""
            target.write_text(wrapper)
            target.chmod(0o770)


def write_systemd_unit(release_root: Path, component_prefix: str) -> None:
    if wb_platform.os_id() != "linux":
        return
    unit_dir = release_root / "lib" / "systemd" / "system"
    unit_dir.mkdir(parents=True, exist_ok=True)
    unit_path = unit_dir / "suricata-wazuh.service"
    unit_path.write_text(
        f"""[Unit]
Description=Wazuh Suricata IDS
After=network.target

[Service]
Type=simple
User=wazuh
Group=wazuh
WorkingDirectory={component_prefix}
PermissionsStartOnly=true
ExecStart={component_prefix}/scripts/start-on-service.sh --pidfile {component_prefix}/var/run/suricata.pid
PIDFile={component_prefix}/var/run/suricata.pid
Restart=on-failure
RestartSec=5
LimitNOFILE=409600
LimitNPROC=409600
ExecReload=/bin/kill -USR2 $MAINPID

AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_IPC_LOCK CAP_SYS_NICE
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_IPC_LOCK CAP_SYS_NICE
NoNewPrivileges=no

### Security Settings ###
MemoryDenyWriteExecute=true
LockPersonality=true
ProtectControlGroups=true
ProtectKernelModules=true
ProtectHome=true
ProtectSystem=full
PrivateTmp=true

[Install]
WantedBy=multi-user.target
"""
    )


def install_rules_and_scripts(
    rule_bundle: Path, component_root: Path, script_dir: Path
) -> None:
    if rule_bundle.exists():
        shutil.copytree(
            rule_bundle,
            component_root / "var" / "lib" / "suricata" / "rules",
            dirs_exist_ok=True,
        )

    scripts_dest = component_root / "scripts"
    scripts_dest.mkdir(parents=True, exist_ok=True)

    scripts_to_copy = {
        "postinstall.sh": "postinstall.sh",
        "services/linux.sh": "start-on-service.sh",
        "services/macos.sh": "macos-start-on-service.sh",
    }
    for src, dest_name in scripts_to_copy.items():
        shutil.copy2(script_dir / src, scripts_dest / dest_name)

    for script in scripts_dest.rglob("*.py"):
        script.chmod(0o770)


def write_metadata(
    component_root: Path,
    triplet: str,
    release_name: str,
    version: str,
    suricata_tag: str,
    suricata_version: str,
    rules_info: dict | None = None,
) -> None:
    rules_info = rules_info or {}
    (component_root / "BUILDINFO.txt").write_text(
        "\n".join(
            [
                "# Suricata native build",
                f"PIPELINE_VERSION={version}",
                f"TRIPLET={triplet}",
                f"SURICATA_TAG={suricata_tag}",
                f"SURICATA_VERSION={suricata_version}",
                f"RELEASE_NAME={release_name}",
                f"RULES_SOURCE={rules_info.get('source', '')}",
                f"RULES_TAG={rules_info.get('tag', '')}",
                f"RULES_FLAVOR={rules_info.get('flavor', '')}",
                "",
            ]
        )
    )
    (component_root / "README.txt").write_text(
        f"Wazuh Suricata package {version}\n"
        f"Contains Suricata upstream release {suricata_version} ({suricata_tag}) for {wb_platform.os_id()}/{wb_platform.arch_id()}.\n"
    )


def package_release(
    cfg: wb_config.BuilderConfig,
    dest: Path,
    component_root: Path,
    release_root: Path,
    release_name: str,
    triplet: str,
    builder_version: str,
    suricata_tag: str,
    suricata_version: str,
) -> None:
    outbase = release_name
    dist_dir = dest / "artifacts"
    artifact_root = dist_dir / outbase
    sbom_dir = artifact_root / "SBOM"
    tarball = dist_dir / f"{outbase}.tar.gz"
    checksum_file_path = dist_dir / f"{outbase}.sha256.txt"
    pom_file = artifact_root / f"{outbase}.pom.json"

    shutil.rmtree(artifact_root, ignore_errors=True)
    artifact_root.mkdir(parents=True, exist_ok=True)
    sbom_dir.mkdir(parents=True, exist_ok=True)

    shutil.copytree(release_root, artifact_root, dirs_exist_ok=True)
    packaging.prune_payload_directory(
        artifact_root / component_root.relative_to(release_root)
    )

    syft_version = cfg.build_setting("syft_version") or "v1.5.0"
    sbom.generate_sboms(
        dest,
        artifact_root,
        sbom_dir / f"{outbase}.sbom.spdx.json",
        sbom_dir / f"{outbase}.sbom.cdx.json",
        syft_version,
    )
    packaging.write_pom(
        pom_file,
        outbase,
        builder_version,
        wb_platform.os_id(),
        wb_platform.arch_id(),
        builder="suricata-native",
        triplet=triplet,
        upstream={"suricata_tag": suricata_tag, "suricata": suricata_version},
    )

    packaging.make_tarball(artifact_root, tarball)

    deb_pkg = packaging.package_deb(
        outbase,
        release_root,
        "/opt/wazuh/suricata",
        builder_version,
        dist_dir,
    )
    rpm_pkg = packaging.package_rpm(
        outbase,
        release_root,
        "/opt/wazuh/suricata",
        builder_version,
        dist_dir,
        requires="glibc, libpcap, pcre2, libyaml, file-libs, lz4-libs, libcap-ng",
        extra_files=["/lib/systemd/system/suricata-wazuh.service"],
    )
    dmg_pkg = packaging.package_dmg(outbase, release_root, dist_dir)

    with checksum_file_path.open("w", encoding="utf-8") as fh:
        for file in [
            tarball,
            sbom_dir / f"{outbase}.sbom.spdx.json",
            sbom_dir / f"{outbase}.sbom.cdx.json",
            pom_file,
        ]:
            fh.write(f"{packaging.checksum_file(file)}  {file.name}\n")
        for file in [deb_pkg, rpm_pkg, dmg_pkg]:
            if file:
                fh.write(f"{packaging.checksum_file(file)}  {file.name}\n")