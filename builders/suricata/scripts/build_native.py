#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import shutil
import sys
import tarfile
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from builders.common.python.wazuh_build import config as wb_config
from builders.common.python.wazuh_build import deps, packaging, platform as wb_platform, sbom, shell


# Ensure common tool locations are on PATH (cargo everywhere, Homebrew on macOS).
def _prepend_path_if_missing(path_str: str) -> None:
    current = os.environ.get("PATH", "")
    parts = current.split(":") if current else []
    if path_str and path_str not in parts:
        parts.insert(0, path_str)
        os.environ["PATH"] = ":".join(parts)


_prepend_path_if_missing(str(Path.home() / ".cargo" / "bin"))
if wb_platform.os_id() == "macos":
    hb = Path("/opt/homebrew/bin")
    if hb.exists():
        _prepend_path_if_missing(str(hb))


def detect_jobs() -> str:
    if "MAKE_JOBS" in os.environ and os.environ["MAKE_JOBS"]:
        return os.environ["MAKE_JOBS"]
    return str(wb_platform.cpu_count())


def ensure_dependencies(cfg: wb_config.BuilderConfig) -> None:
    if wb_platform.os_id() == "linux" and shell.command_exists("apt-get"):
        deps.install_apt(cfg.dependency_section("apt"))
        deps.run_bash_commands(cfg.dependency_section("bash"))
    if wb_platform.os_id() == "macos" and shell.command_exists("brew"):
        deps.install_brew(cfg.dependency_section("brew"))
        configure_macos_env()

    deps.ensure_pkg_config_path()
    deps.ensure_cbindgen()


def require_tools(tool_names: list[str]) -> None:
    missing = [tool for tool in tool_names if not shell.command_exists(tool)]
    if missing:
        raise SystemExit(f"Missing required tools: {', '.join(missing)}")


def _has_magic_header() -> bool:
    candidates = [
        Path("/usr/include/magic.h"),
        Path("/usr/local/include/magic.h"),
    ]
    candidates.extend(Path("/usr/include").glob("*/magic.h"))
    candidates.extend(Path("/usr/local/include").glob("*/magic.h"))
    return any(p.exists() for p in candidates)


def require_libraries(lib_names: list[str]) -> None:
    missing: list[str] = []
    for lib in lib_names:
        try:
            shell.run(["pkg-config", "--exists", lib], check=True, capture=True)
        except Exception:
            if lib == "libmagic":
                # libmagic pkg-config metadata is flaky; if headers exist, continue without failing.
                if _has_magic_header():
                    continue
                print("Warning: libmagic pkg-config check failed; proceeding because header is absent check only.")
                continue
            missing.append(lib)
    if missing:
        raise SystemExit(f"Missing required libraries: {', '.join(missing)}")


def _bool_env(name: str) -> bool:
    val = os.environ.get(name, "")
    return val.lower() in {"1", "true", "yes", "y"}


def load_rules_metadata(builder_root: Path) -> dict:
    metadata_path = builder_root / "rules" / "source.json"
    if not metadata_path.exists():
        raise SystemExit(f"Rule metadata not found: {metadata_path}")
    try:
        return json.loads(metadata_path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise SystemExit(f"Unable to parse rule metadata {metadata_path}: {exc}") from exc


def resolve_rule_bundle(builder_root: Path) -> tuple[Path, dict]:
    if os.environ.get("RULE_BUNDLE"):
        bundle = Path(os.environ["RULE_BUNDLE"]).expanduser().resolve()
        if not bundle.exists():
            raise SystemExit(f"RULE_BUNDLE path does not exist: {bundle}")
        return bundle, {"source": "custom", "tag": "manual", "flavor": "custom"}

    metadata = load_rules_metadata(builder_root)
    flavor = os.environ.get("RULES_FLAVOR", "open")
    cache_root = Path(os.environ.get("RULES_CACHE", builder_root / "rules-cache")).resolve()
    expected = cache_root / metadata.get("tag", "unknown") / flavor

    if expected.exists():
        return expected, {"source": metadata.get("source"), "tag": metadata.get("tag"), "flavor": flavor}

    local_rules = builder_root / "rules"
    if local_rules.exists() and list(local_rules.glob("*.rules")):
        return local_rules, {"source": "local", "tag": "local", "flavor": "local"}

    fetcher = builder_root / "scripts" / "fetch_suricata_rules.py"
    if not fetcher.exists():
        raise SystemExit(f"Fetcher script not found: {fetcher}")

    shell.run(["python3", str(fetcher), "--dest", str(cache_root), "--flavor", flavor])
    if expected.exists():
        return expected, {"source": metadata.get("source"), "tag": metadata.get("tag"), "flavor": flavor}

    raise SystemExit(
        "Rule bundle not found. Run "
        f"'python builders/suricata/scripts/fetch_suricata_rules.py --flavor {flavor}' "
        f"or set RULE_BUNDLE to an existing path."
    )


def prepare_dest(release_root: Path, component_root: Path, dest: Path) -> None:
    if release_root.exists():
        shutil.rmtree(release_root)
    (component_root).mkdir(parents=True, exist_ok=True)
    (dest / "artifacts").mkdir(parents=True, exist_ok=True)
    (component_root / "var" / "log" / "suricata").mkdir(parents=True, exist_ok=True)
    (component_root / "var" / "run").mkdir(parents=True, exist_ok=True)
    (component_root / "var" / "lib" / "suricata").mkdir(parents=True, exist_ok=True)


def download_and_unpack(tag: str, target: Path) -> Path:
    url = f"https://github.com/OISF/suricata/archive/refs/tags/{tag}.tar.gz"
    tarball = target / "suricata.tar.gz"
    shell.run(["curl", "-fsSL", url, "-o", str(tarball)])
    src_dir = target / "src"
    src_dir.mkdir(parents=True, exist_ok=True)
    with tarfile.open(tarball, "r:gz") as tf:
        tf.extractall(path=src_dir, members=_strip_components(tf))
    return src_dir


def _strip_components(tf: tarfile.TarFile, n: int = 1):
    for member in tf.getmembers():
        parts = member.name.split("/", n)
        member.name = parts[-1] if len(parts) == n + 1 else "/".join(parts[n:])
        yield member


def write_revision_header(build_dir: Path) -> Path:
    revision_label = f"Wazuh Plugin Build {os.environ.get('PIPELINE_COMMIT', 'unknown')}"
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
    libs = ["libnet.so.1", "libjansson.so.4", "libpcap.so.1", "libpcap.so.0.8"]
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
        print("Warning: Unable to bundle runtime libraries; Suricata may require system libs.", flush=True)


def configure_macos_env() -> None:
    if wb_platform.os_id() != "macos" or not shell.command_exists("brew"):
        return
    pkgconfig_paths = []
    for pkg in ["pcre2", "libyaml", "jansson", "libmagic", "libpcap", "libnet", "lz4"]:
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
                os.environ["CPPFLAGS"] = f"-I{include_dir} {os.environ.get('CPPFLAGS', '')}"
            if lib_dir.exists():
                os.environ["LDFLAGS"] = f"-L{lib_dir} {os.environ.get('LDFLAGS', '')}"
    if pkgconfig_paths:
        existing = os.environ.get("PKG_CONFIG_PATH", "")
        os.environ["PKG_CONFIG_PATH"] = ":".join(pkgconfig_paths + ([existing] if existing else []))


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
LimitNOFILE=409600
LimitNPROC=409600
ExecReload=/bin/kill -USR2 $MAINPID

### Security Settings ###
MemoryDenyWriteExecute=true
LockPersonality=true
ProtectControlGroups=true
ProtectKernelModules=true

[Install]
WantedBy=multi-user.target
"""
    )


def install_rules_and_scripts(rule_bundle: Path, component_root: Path, script_dir: Path) -> None:
    if rule_bundle.exists():
        shutil.copytree(rule_bundle, component_root / "var" / "lib" / "suricata" / "rules", dirs_exist_ok=True)

    scripts_dest = component_root / "scripts"
    scripts_dest.mkdir(parents=True, exist_ok=True)

    for script_name in ["macos-start-on-service.sh", "start-on-service.sh"]:
        shutil.copy2(script_dir / script_name, scripts_dest / script_name)

    for script in scripts_dest.rglob("*.py"):
        script.chmod(0o770)


def write_metadata(component_root: Path, triplet: str, release_name: str, version: str, suricata_tag: str,
                   suricata_version: str, rules_info: dict | None = None) -> None:
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


def build_suricata(cfg: wb_config.BuilderConfig, dest: Path, triplet: str, version: str, rule_bundle: Path,
                   rules_info: dict) -> None:
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
    suricata_tag = suricata_version if suricata_version.startswith("suricata-") else f"suricata-{suricata_version}"

    jobs = detect_jobs()
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
            # "--enable-geoip",
            # "--enable-dpdk",
        ]
        if (src_dir / "autogen.sh").exists():
            shell.run(["./autogen.sh"], cwd=src_dir, env=env)
        shell.run(["./configure", *configure_args], cwd=src_dir, env=env)
        shell.run(["make", "-j", jobs], cwd=src_dir, env=env)
        shell.run(["make", f"DESTDIR={release_root}", "install"], cwd=src_dir, env=env)
        shell.run(["make", f"DESTDIR={release_root}", "install-conf"], cwd=src_dir, env=env, check=False)
        shell.run(["make", f"DESTDIR={release_root}", "install-rules"], cwd=src_dir, env=env, check=False)

    packaging.prune_payload_directory(component_root)
    bundle_runtime_libs(component_root)
    wrap_linux_binaries(component_root)
    install_rules_and_scripts(rule_bundle, component_root, Path(__file__).parent)
    write_metadata(component_root, triplet, release_name, version, suricata_tag, suricata_version, rules_info)
    fix_permissions(component_root)
    package_release(cfg, dest, component_root, release_root, release_name, triplet, version, suricata_tag,
                    suricata_version)


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


def package_release(cfg: wb_config.BuilderConfig, dest: Path, component_root: Path, release_root: Path,
                    release_name: str, triplet: str, builder_version: str, suricata_tag: str,
                    suricata_version: str) -> None:
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
    sbom.generate_sboms(dest, artifact_root, sbom_dir / f"{outbase}.sbom.spdx.json",
                        sbom_dir / f"{outbase}.sbom.cdx.json", syft_version)
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

    deb_pkg = packaging.package_deb(outbase, release_root, "/opt/wazuh/suricata", builder_version, dist_dir,
                                    systemd_unit="suricata-wazuh.service")
    rpm_pkg = packaging.package_rpm(outbase, release_root, "/opt/wazuh/suricata", builder_version, dist_dir,
                                    requires="glibc, libpcap, pcre2, libyaml, file-libs, lz4-libs, libcap-ng",
                                    systemd_unit="suricata-wazuh.service")
    dmg_pkg = packaging.package_dmg(outbase, release_root, dist_dir)

    with checksum_file_path.open("w", encoding="utf-8") as fh:
        for file in [tarball, sbom_dir / f"{outbase}.sbom.spdx.json", sbom_dir / f"{outbase}.sbom.cdx.json", pom_file]:
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
    dest = Path(os.environ.get("ARTIFACT_DEST", builder_root / "dist" / triplet)).resolve()
    version = os.environ.get("PIPELINE_VERSION", "dev")
    rule_bundle, rules_info = resolve_rule_bundle(builder_root)

    ensure_dependencies(cfg)
    require_tools(["curl", "tar", "make", "gcc", "autoconf", "automake", "pkg-config", "python3"])
    libs = ["libpcap", "libpcre2-8", "yaml-0.1", "jansson", "libmagic", "liblz4", "zlib"]
    if wb_platform.os_id() == "linux":
        libs.append("libcap-ng")
    require_libraries(libs)

    build_suricata(cfg, dest, triplet, version, rule_bundle, rules_info)


if __name__ == "__main__":
    main()
