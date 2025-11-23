#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import shutil
import sys
import tarfile
import tempfile
from pathlib import Path
from typing import Tuple

REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from builders.common.python.wazuh_build import config as wb_config
from builders.common.python.wazuh_build import (
    deps,
    packaging,
    platform as wb_platform,
    sbom,
    shell,
    utils,
    download,
    rules,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


# Ensure cargo-installed tools are discoverable (and Homebrew on macOS).
utils.prepend_path_if_missing(str(Path.home() / ".cargo" / "bin"))
if wb_platform.os_id() == "macos":
    hb = Path("/opt/homebrew/bin")
    if hb.exists():
        utils.prepend_path_if_missing(str(hb))


def ensure_dependencies(cfg: wb_config.BuilderConfig) -> None:
    if wb_platform.os_id() == "linux" and shell.command_exists("apt-get"):
        deps.install_apt(cfg.dependency_section("apt"))
        deps.run_bash_commands(cfg.dependency_section("bash"))
    if wb_platform.os_id() == "macos" and shell.command_exists("brew"):
        deps.install_brew(cfg.dependency_section("brew"))
        configure_macos_env()
    deps.ensure_pkg_config_path()


def _bool_env(name: str) -> bool:
    val = os.environ.get(name, "")
    return val.lower() in {"1", "true", "yes", "y"}


def _feature_enabled(env_name: str, default: bool) -> bool:
    val = os.environ.get(env_name)
    if val is None or val == "":
        return default
    return _bool_env(env_name)


def resolve_rule_bundle(builder_root: Path) -> Tuple[Path, dict]:
    return rules.resolve_rule_bundle(
        builder_root,
        default_flavor="full",
        fetcher_script_name="fetch_yara_rules.py",
        source_name="yara-forge",
    )


def prepare_dest(release_root: Path, component_root: Path, dest: Path) -> None:
    if release_root.exists():
        shutil.rmtree(release_root)
    component_root.mkdir(parents=True, exist_ok=True)
    (dest / "artifacts").mkdir(parents=True, exist_ok=True)


def download_and_unpack(version: str, target: Path) -> Path:
    url = f"https://github.com/VirusTotal/yara/archive/refs/tags/{version}.tar.gz"
    tarball = target / "yara.tar.gz"
    shell.run(["curl", "-fsSL", url, "-o", str(tarball)])
    src_dir = target / "src"
    src_dir.mkdir(parents=True, exist_ok=True)
    with tarfile.open(tarball, "r:gz") as tf:
        tf.extractall(path=src_dir, members=download.strip_components(tf))
    return src_dir


def write_revision_header(build_dir: Path) -> Path:
    revision_label = (
        f"Wazuh Plugin Build {os.environ.get('PIPELINE_COMMIT', 'unknown')}"
    )
    revision_header = build_dir / "revision.h"
    escaped = revision_label.replace('"', r"\"")
    revision_header.write_text(f'#define REVISION "{escaped}"\n')
    return revision_header


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
    libs = ["libcrypto.so.1.1", "libssl.so.1.1", "libjansson.so.4"]
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
            "Warning: Unable to bundle OpenSSL runtime libraries; YARA may expect system libs.",
            flush=True,
        )


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


def wrap_linux_binaries(component_root: Path) -> None:
    if wb_platform.os_id() != "linux":
        return
    bin_dir = component_root / "bin"
    for name in ["yara", "yarac"]:
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


def install_rules_and_scripts(
    release_root: Path, rule_bundle: Path, component_root: Path, script_dir: Path
) -> None:
    rules_dest = component_root / "rules"
    rules_dest.mkdir(parents=True, exist_ok=True)
    if not rule_bundle.exists():
        raise SystemExit(f"Rule bundle path does not exist: {rule_bundle}")
    if rule_bundle.is_file():
        shutil.copy2(rule_bundle, rules_dest / rule_bundle.name)
    elif rule_bundle.is_dir():
        yar_files = list(rule_bundle.rglob("*.yar"))
        if yar_files:
            for file in yar_files:
                shutil.copy2(file, rules_dest / file.name)
        else:
            shutil.copytree(rule_bundle, rules_dest, dirs_exist_ok=True)
    else:
        raise SystemExit(f"Unsupported rule bundle type: {rule_bundle}")

    local_rules = release_root / "rules"
    yar_files = list(local_rules.rglob("*.yar"))
    if yar_files:
        for file in yar_files:
            shutil.copy2(file, rules_dest / file.name)

    scripts_dest = component_root / "scripts"
    scripts_dest.mkdir(parents=True, exist_ok=True)
    for script_name in ["postinstall.sh"]:  # TODO @sse
        shutil.copy2(script_dir / script_name, scripts_dest / script_name)
    for script in scripts_dest.rglob("*.py"):
        script.chmod(0o770)


def write_metadata(
    component_root: Path,
    triplet: str,
    release_name: str,
    version: str,
    yara_version: str,
    rules_info: dict | None = None,
) -> None:
    rules_info = rules_info or {}
    (component_root / "BUILDINFO.txt").write_text(
        "\n".join(
            [
                "# YARA native build",
                f"PIPELINE_VERSION={version}",
                f"TRIPLET={triplet}",
                f"YARA_VERSION={yara_version}",
                f"RELEASE_NAME={release_name}",
                f"RULES_SOURCE={rules_info.get('source', '')}",
                f"RULES_TAG={rules_info.get('tag', '')}",
                f"RULES_FLAVOR={rules_info.get('flavor', '')}",
                "",
            ]
        )
    )
    (component_root / "README.txt").write_text(
        f"adorsys Wazuh YARA package {version}\n"
        f"Contains YARA upstream release {yara_version} for {wb_platform.os_id()}/{wb_platform.arch_id()}.\n"
    )


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
        release_root, rule_bundle, component_root, Path(__file__).parent
    )
    write_metadata(
        component_root, triplet, release_name, version, yara_version, rules_info
    )
    utils.fix_permissions(component_root)
    package_release(
        cfg,
        dest,
        component_root,
        release_root,
        release_name,
        triplet,
        version,
        yara_version,
    )


def package_release(
    cfg: wb_config.BuilderConfig,
    dest: Path,
    component_root: Path,
    release_root: Path,
    release_name: str,
    triplet: str,
    builder_version: str,
    yara_version: str,
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
        builder="yara-native",
        triplet=triplet,
        upstream={"yara": yara_version},
    )

    packaging.make_tarball(artifact_root, tarball)
    deb_pkg = packaging.package_deb(
        outbase,
        release_root,
        "/opt/wazuh/yara",
        f"{yara_version}+{builder_version}",
        dist_dir,
    )
    rpm_pkg = packaging.package_rpm(
        outbase,
        release_root,
        "/opt/wazuh/yara",
        f"{yara_version}+{builder_version}",
        dist_dir,
        requires="glibc, file-libs, jansson",
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


def main() -> None:
    triplet = os.environ.get("ARTIFACT_TRIPLET", "native")
    script_dir = Path(__file__).parent
    builder_root = script_dir.parent
    config_path = builder_root / "config.yaml"
    cfg = wb_config.BuilderConfig(config_path)
    dest = Path(
        os.environ.get("ARTIFACT_DEST", builder_root / "dist" / triplet)
    ).resolve()
    version = os.environ.get("PIPELINE_VERSION", "dev")
    rule_bundle, rules_info = resolve_rule_bundle(builder_root)

    ensure_dependencies(cfg)
    deps.require_tools(
        [
            "curl",
            "tar",
            "make",
            "gcc",
            "autoconf",
            "automake",
            "pkg-config",
            "python3",
            "flex",
            "bison",
        ]
    )
    deps.require_libraries(
        ["openssl", "libpcre2-8", "libmagic", "jansson", "libprotobuf-c"]
    )

    build_yara(cfg, dest, triplet, version, rule_bundle, rules_info)


if __name__ == "__main__":
    main()
