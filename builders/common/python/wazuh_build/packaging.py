import json
import os
import shlex
import subprocess
import tarfile
import tempfile
from pathlib import Path
from typing import List, Optional

from . import platform as wb_platform
from . import shell, utils


def write_pom(
    output: Path,
    component: str,
    component_version: str,
    platform_os: str,
    platform_arch: str,
    builder: str,
    triplet: str,
    upstream: Optional[dict] = None,
) -> None:
    payload = {
        "artifact": component,
        "version": component_version,
        "os": platform_os,
        "arch": platform_arch,
        "build": {
            "timestamp": os.popen("date -u +%FT%TZ").read().strip(),
            "builder": builder,
            "triplet": triplet,
            "user": os.environ.get("USER", "unknown"),
        },
        "source": {
            "repository": os.environ.get("PIPELINE_REPO", ""),
            "commit": os.environ.get("PIPELINE_COMMIT", ""),
            "ref": os.environ.get("PIPELINE_REF", ""),
        },
    }
    if upstream:
        payload["upstream"] = upstream
    output.write_text(json.dumps(payload, indent=2))


def checksum_file(path: Path) -> str:
    digest = utils.sha256_file(path)
    print(f"{digest}  {path.name}")
    return digest


def _stringify_command(command: shell.Command) -> str:
    if isinstance(command, str):
        return command
    return " ".join(shlex.quote(str(part)) for part in command)


def _log_subprocess_failure(name: str, exc: subprocess.CalledProcessError) -> None:
    command = _stringify_command(exc.cmd)
    print(f"[error] {name} failed (exit {exc.returncode}): {command}")
    if exc.stdout:
        print(f"[{name}] stdout:")
        print(exc.stdout)
    if exc.stderr:
        print(f"[{name}] stderr:")
        print(exc.stderr)


def prune_payload_directory(target_dir: Path) -> None:
    if not target_dir.exists():
        return
    for path in [
        target_dir / "include",
        target_dir / "share" / "doc",
        target_dir / "share" / "man",
        target_dir / "share" / "info",
        target_dir / "lib" / "pkgconfig",
        target_dir / "var" / "lib",
    ]:
        if path.is_dir():
            import shutil

            shutil.rmtree(path, ignore_errors=True)
    lib_dir = target_dir / "lib"
    if lib_dir.exists():
        for file in lib_dir.rglob("*"):
            if file.suffix in {".a", ".la"}:
                file.unlink(missing_ok=True)


def make_tarball(src_dir: Path, tarball: Path) -> None:
    tarball.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(tarball, "w:gz") as tf:
        tf.add(src_dir, arcname=src_dir.name)


def package_deb(
    outbase: str,
    release_dir: Path,
    component_prefix: str,
    component_version: str,
    dest: Path,
    package_name: Optional[str] = None,
) -> Optional[Path]:
    if wb_platform.os_id() != "linux":
        return None
    if not shell.command_exists("dpkg-deb"):
        return None
    import tempfile

    release_version = os.environ.get("RELEASE_VERSION", "").strip()
    if release_version != "":
        component_version = f"{component_version}+{release_version}"

    staging = Path(tempfile.mkdtemp(prefix="deb-staging-"))
    try:
        (staging / "DEBIAN").mkdir(parents=True, exist_ok=True)
        shell.run(["cp", "-R", f"{release_dir}/.", str(staging)])

        deb_arch = {"amd64": "amd64", "arm64": "arm64"}.get(
            wb_platform.arch_id(), "all"
        )
        component_path = staging / component_prefix.lstrip("/")
        installed_size = int(os.popen(f"du -ks {component_path}").read().split()[0])
        deb_version = (
            component_version[1:]
            if component_version.startswith("v")
            else component_version
        )
        pkg_name = package_name or Path(component_prefix).name
        control_content = f"""Package: {pkg_name}
Maintainer: Wazuh Plugins <info@adorsys.com>
Section: utils
Priority: optional
Description: {pkg_name} packaged for Wazuh deployments
Version: {deb_version}
Architecture: {deb_arch}
Installed-Size: {installed_size}
"""
        (staging / "DEBIAN" / "control").write_text(control_content)
        postinst = staging / "DEBIAN" / "postinst"
        postinst.write_text(
            f"""#!/bin/sh
set -e

case "$1" in
  configure|reconfigure)
    /bin/sh {component_prefix}/scripts/postinstall.sh {component_prefix} || true
  ;;
esac

exit 0
"""
        )
        postinst.chmod(0o775)
        deb_out = dest / f"{outbase}.deb"
        try:
            shell.run(["dpkg-deb", "--build", str(staging), str(deb_out)], capture=True)
        except subprocess.CalledProcessError as exc:
            _log_subprocess_failure("dpkg-deb", exc)
            raise
        return deb_out
    finally:
        import shutil

        shutil.rmtree(staging, ignore_errors=True)


def package_rpm(
    outbase: str,
    release_dir: Path,
    component_prefix: str,
    rpm_version: str,
    dest: Path,
    requires: Optional[str] = None,
    package_name: Optional[str] = None,
    extra_files: Optional[List[str]] = None,
) -> Optional[Path]:
    if wb_platform.os_id() != "linux":
        return None

    if not shell.command_exists("rpmbuild"):
        return None

    rpm_arch = {"amd64": "x86_64", "arm64": "aarch64"}.get(
        wb_platform.arch_id(), "noarch"
    )
    import tempfile

    release_version = os.environ.get("RELEASE_VERSION", "").strip()
    if release_version != "":
        rpm_version = f"{rpm_version}+{release_version}"

    staging = Path(tempfile.mkdtemp(prefix="rpm-staging-"))
    rpmroot = staging / "rpmbuild"

    for sub in ["BUILD", "RPMS", "SOURCES", "SPECS", "SRPMS"]:
        (rpmroot / sub).mkdir(parents=True, exist_ok=True)

    spec = rpmroot / "SPECS" / "package.spec"
    req_line = f"Requires: {requires}\n" if requires else ""
    pkg_name = package_name or Path(component_prefix).name
    extra_files_lines = ""
    if extra_files:
        extra_files_lines = "".join(f"{path}\n" for path in extra_files)
    spec.write_text(
        f"""Name: {pkg_name}
Version: {rpm_version}
Release: 1
Summary: {pkg_name} packaged for Wazuh deployments
License: GPLv2
BuildArch: {rpm_arch}
{req_line}AutoReqProv: no
AutoReq: no
AutoProv: no
%global _use_internal_dependency_generator 0
%global __provides_exclude_from ^{component_prefix}/lib/.*$

%description
Packaged component for Wazuh deployments.

%post
/bin/sh {component_prefix}/scripts/postinstall.sh {component_prefix} || true

%install
mkdir -p %{{buildroot}}
cp -a {release_dir}/. %{{buildroot}}

%files
{component_prefix}
{extra_files_lines}
"""
    )

    def cleanup_staging() -> None:
        import shutil

        shutil.rmtree(staging, ignore_errors=True)

    try:
        shell.run(
            [
                "rpmbuild",
                "-bb",
                str(spec),
                "--define",
                f"_topdir {rpmroot}",
                "--define",
                "_use_internal_dependency_generator 0",
                "--define",
                "autoreqprov 0",
                "--buildroot",
                f"{rpmroot}/BUILDROOT",
            ],
            capture=True,
        )
    except subprocess.CalledProcessError as exc:
        _log_subprocess_failure("rpmbuild", exc)
        cleanup_staging()
        return None
    except Exception as exc:
        print(f"[error] rpmbuild invocation failed: {exc}")
        cleanup_staging()
        return None

    rpm_path = next(rpmroot.rglob("*.rpm"), None)
    if not rpm_path:
        print("[error] rpmbuild finished without producing an RPM artifact")
        cleanup_staging()
        return None

    dest_path = dest / f"{outbase}.rpm"
    dest_path.parent.mkdir(parents=True, exist_ok=True)
    shell.run(["cp", str(rpm_path), str(dest_path)])
    cleanup_staging()
    return dest_path


def package_dmg(outbase: str, release_dir: Path, dest: Path) -> Optional[Path]:
    if wb_platform.os_id() != "macos":
        return None
    if not shell.command_exists("hdiutil"):
        return None
    staging = Path(tempfile.mkdtemp(prefix="dmg-staging-"))
    try:
        (staging / outbase).mkdir(parents=True, exist_ok=True)
        shell.run(["cp", "-R", f"{release_dir}/.", str(staging / outbase)])
        dmg_out = dest / f"{outbase}.dmg"
        shell.run(
            [
                "hdiutil",
                "create",
                "-volname",
                outbase,
                "-srcfolder",
                str(staging),
                "-format",
                "UDZO",
                "-ov",
                str(dmg_out),
            ],
            check=True,
        )
        return dmg_out
    finally:
        import shutil

        shutil.rmtree(staging, ignore_errors=True)
