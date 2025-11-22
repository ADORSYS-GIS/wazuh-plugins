#!/usr/bin/env python3
from __future__ import annotations

import os
import shutil
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from builders.common.python.wazuh_build import config as wb_config
from builders.common.python.wazuh_build import deps, packaging, platform as wb_platform, sbom, shell


def ensure_dependencies(cfg: wb_config.BuilderConfig) -> None:
    if wb_platform.os_id() == "linux" and shell.command_exists("apt-get"):
        deps.install_apt(cfg.dependency_section("apt"))
        deps.run_bash_commands(cfg.dependency_section("bash"))
    if wb_platform.os_id() == "macos" and shell.command_exists("brew"):
        deps.install_brew(cfg.dependency_section("brew"))


def require_tools(tool_names: list[str]) -> None:
    missing = [tool for tool in tool_names if not shell.command_exists(tool)]
    if missing:
        raise SystemExit(f"Missing required tools: {', '.join(missing)}")


def stream_from_version(version: str) -> str:
    parts = version.split(".")
    if parts and parts[0].isdigit():
        return f"{parts[0]}.x"
    return "4.x"


def prepare_dest(release_root: Path, dest: Path) -> None:
    if release_root.exists():
        shutil.rmtree(release_root)
    release_root.mkdir(parents=True, exist_ok=True)
    (dest / "artifacts").mkdir(parents=True, exist_ok=True)


def download_linux_deb(version: str, revision: str, arch: str, target: Path) -> tuple[Path, str]:
    stream = stream_from_version(version)
    filename = f"wazuh-agent_{version}-{revision}_{arch}.deb"
    url = f"https://packages.wazuh.com/{stream}/apt/pool/main/w/wazuh-agent/{filename}"
    dest = target / filename
    shell.run(["curl", "-fsSL", url, "-o", str(dest)])
    return dest, url


def download_macos_pkg(version: str, revision: str, arch: str, target: Path) -> tuple[Path, str]:
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


def write_metadata(
    component_root: Path,
    triplet: str,
    release_name: str,
    artifact_version: str,
    agent_version: str,
    package_revision: str,
    package_source: str,
    component_prefix: str,
) -> None:
    (component_root / "BUILDINFO.txt").write_text(
        "\n".join(
            [
                "# Wazuh agent native build (repackaged)",
                f"PIPELINE_VERSION={artifact_version}",
                f"TRIPLET={triplet}",
                f"RELEASE_NAME={release_name}",
                f"UPSTREAM_AGENT={agent_version}-{package_revision}",
                f"PACKAGE_SOURCE={package_source}",
                "",
            ]
        )
    )
    (component_root / "README.txt").write_text(
        f"Wazuh agent bundle {artifact_version}\n"
        f"Upstream agent version {agent_version}-{package_revision} staged under {component_prefix}.\n"
        "Post-install tasks such as enrollment, user creation, and service enablement remain operator controlled.\n"
    )


def _should_be_executable(path: Path) -> bool:
    return path.parent.name == "bin" or path.suffix in {".sh", ".py"} or os.access(path, os.X_OK)


def fix_permissions(component_root: Path) -> None:
    for path in component_root.rglob("*"):
        try:
            if path.is_dir():
                path.chmod(0o770)
            else:
                path.chmod(0o775 if _should_be_executable(path) else 0o770)
        except Exception:
            continue


def package_release(
    cfg: wb_config.BuilderConfig,
    dest: Path,
    release_root: Path,
    component_root: Path,
    component_prefix: str,
    release_name: str,
    triplet: str,
    builder_version: str,
    agent_version: str,
    package_revision: str,
    package_source: str,
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
    packaging.prune_payload_directory(artifact_root / component_root.relative_to(release_root))

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
        builder="wazuh-agent-native",
        triplet=triplet,
        upstream={
            "wazuh-agent": agent_version,
            "package_revision": package_revision,
            "package_source": package_source,
        },
    )

    packaging.make_tarball(artifact_root, tarball)
    deb_pkg = packaging.package_deb(
        outbase,
        release_root,
        component_prefix,
        builder_version,
        dist_dir,
        package_name="wazuh-agent",
    )
    rpm_pkg = packaging.package_rpm(
        outbase,
        release_root,
        component_prefix,
        builder_version,
        dist_dir,
        requires="glibc",
        package_name="wazuh-agent",
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


def build_wazuh_agent(
    cfg: wb_config.BuilderConfig,
    dest: Path,
    triplet: str,
    agent_version: str,
    package_revision: str,
) -> None:
    platform_os = wb_platform.os_id()
    platform_arch = wb_platform.arch_id()
    release_name = f"wazuh-agent-{agent_version}-r{package_revision}-{platform_os}-{platform_arch}"
    release_root = dest / "release" / release_name
    component_prefix = "/var/ossec" if platform_os == "linux" else "/Library/Ossec"
    component_root = release_root / component_prefix.lstrip("/")

    prepare_dest(release_root, dest)

    package_source = ""
    with tempfile.TemporaryDirectory(prefix="wazuh-agent-build-") as build_dir:
        build_root = Path(build_dir)
        if platform_os == "linux":
            deb_arch = {"amd64": "amd64", "arm64": "arm64"}.get(platform_arch)
            if not deb_arch:
                raise SystemExit(f"Unsupported linux architecture: {platform_arch}")
            deb_path, package_source = download_linux_deb(agent_version, package_revision, deb_arch, build_root)
            extract_linux_package(deb_path, release_root)
        elif platform_os == "macos":
            pkg_arch = {"amd64": "intel64", "arm64": "arm64"}.get(platform_arch)
            if not pkg_arch:
                raise SystemExit(f"Unsupported macOS architecture: {platform_arch}")
            pkg_path, package_source = download_macos_pkg(agent_version, package_revision, pkg_arch, build_root)
            extract_macos_package(pkg_path, release_root)
        else:
            raise SystemExit(f"Unsupported platform: {platform_os}/{platform_arch}")

    if not component_root.exists():
        raise SystemExit(f"Component root not found after extraction: {component_root}")

    packaging.prune_payload_directory(component_root)
    write_metadata(
        component_root,
        triplet,
        release_name,
        agent_version,
        agent_version,
        package_revision,
        package_source,
        component_prefix,
    )
    fix_permissions(component_root)
    package_release(
        cfg,
        dest,
        release_root,
        component_root,
        component_prefix,
        release_name,
        triplet,
        agent_version,
        agent_version,
        package_revision,
        package_source,
    )


def main() -> None:
    triplet = os.environ.get("ARTIFACT_TRIPLET", "native")
    script_dir = Path(__file__).parent
    builder_root = script_dir.parent
    config_path = builder_root / "config.yaml"
    cfg = wb_config.BuilderConfig(config_path)
    dest = Path(os.environ.get("ARTIFACT_DEST", builder_root / "dist" / triplet)).resolve()
    agent_version = os.environ.get("PIPELINE_VERSION", "").strip()
    package_revision = os.environ.get("PACKAGE_REVISION", "1").strip() or "1"

    if not agent_version:
        raise SystemExit("PIPELINE_VERSION not provided")

    ensure_dependencies(cfg)
    if wb_platform.os_id() == "linux":
        require_tools(["curl", "dpkg-deb", "tar"])
    elif wb_platform.os_id() == "macos":
        require_tools(["curl", "pkgutil", "tar"])

    build_wazuh_agent(cfg, dest, triplet, agent_version, package_revision)


if __name__ == "__main__":
    main()
