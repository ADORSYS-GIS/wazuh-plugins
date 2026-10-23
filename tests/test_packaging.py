import json
import os
import subprocess
import tarfile
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest

from wazuh_build import packaging


def test_write_pom(tmp_path: Path):
    pom_file = tmp_path / "pom.json"
    packaging.write_pom(
        pom_file,
        component="wazuh-plugin-yara",
        component_version="4.3.2",
        platform_os="linux",
        platform_arch="amd64",
        builder="yara",
        triplet="linux-amd64",
        upstream={"version": "4.3.2"},
    )
    assert pom_file.exists()
    data = json.loads(pom_file.read_text())
    assert data["artifact"] == "wazuh-plugin-yara"
    assert data["version"] == "4.3.2"
    assert data["build"]["builder"] == "yara"
    assert data["upstream"]["version"] == "4.3.2"


def test_checksum_file(tmp_path: Path):
    data_file = tmp_path / "artifact.tar.gz"
    data_file.write_bytes(b"artifact contents\n")
    digest = packaging.checksum_file(data_file)
    assert isinstance(digest, str)
    assert len(digest) == 64


def test_stringify_command():
    assert packaging._stringify_command("sh test.sh") == "sh test.sh"
    assert packaging._stringify_command(["sh", "test.sh", "arg 1"]) == "sh test.sh 'arg 1'"


def test_log_subprocess_failure():
    exc = subprocess.CalledProcessError(1, ["test_cmd"], output="some stdout", stderr="some stderr")
    packaging._log_subprocess_failure("test_proc", exc)


def test_prune_payload_directory(tmp_path: Path):
    target = tmp_path / "payload"
    target.mkdir()
    (target / "include").mkdir()
    (target / "include" / "header.h").write_text("h")
    (target / "share" / "man").mkdir(parents=True)
    (target / "share" / "man" / "man.1").write_text("man")
    lib = target / "lib"
    lib.mkdir()
    (lib / "libstatic.a").write_text("a")
    (lib / "libshared.so").write_text("so")

    packaging.prune_payload_directory(target)
    assert not (target / "include").exists()
    assert not (target / "share" / "man").exists()
    assert not (lib / "libstatic.a").exists()
    assert (lib / "libshared.so").exists()


def test_make_tarball(tmp_path: Path):
    src = tmp_path / "src_dir"
    src.mkdir()
    (src / "test.txt").write_text("hello")
    tarball = tmp_path / "out" / "archive.tar.gz"

    packaging.make_tarball(src, tarball)
    assert tarball.exists()

    with tarfile.open(tarball, "r:gz") as tf:
        names = tf.getnames()
        assert "src_dir/test.txt" in names


def test_package_deb_non_linux(tmp_path: Path):
    with patch("wazuh_build.platform.os_id", return_value="macos"):
        res = packaging.package_deb("out", tmp_path, "/opt/wazuh", "1.0", tmp_path)
        assert res is None


def test_package_deb_no_dpkg(tmp_path: Path):
    with patch("wazuh_build.platform.os_id", return_value="linux"), patch(
        "wazuh_build.shell.command_exists", return_value=False
    ):
        res = packaging.package_deb("out", tmp_path, "/opt/wazuh", "1.0", tmp_path)
        assert res is None


def test_package_deb_success(tmp_path: Path):
    rel_dir = tmp_path / "release"
    rel_dir.mkdir()
    dest = tmp_path / "dist"
    dest.mkdir()

    def fake_deb_run(cmd, *args, **kwargs):
        if cmd[0] == "cp":
            staging_target = Path(cmd[-1])
            (staging_target / "opt" / "component").mkdir(parents=True, exist_ok=True)
            (staging_target / "opt" / "component" / "file.txt").write_text("data")
        return MagicMock(returncode=0)

    with patch("wazuh_build.platform.os_id", return_value="linux"), patch(
        "wazuh_build.platform.arch_id", return_value="amd64"
    ), patch("wazuh_build.shell.command_exists", return_value=True), patch(
        "wazuh_build.shell.run", side_effect=fake_deb_run
    ) as mock_run:
        res = packaging.package_deb("component-1.0", rel_dir, "/opt/component", "v1.0.0", dest)
        assert res == dest / "component-1.0.deb"
        assert any("dpkg-deb" in str(call_arg) for call_arg in mock_run.call_args_list)


def test_package_rpm_non_linux(tmp_path: Path):
    with patch("wazuh_build.platform.os_id", return_value="macos"):
        res = packaging.package_rpm("out", tmp_path, "/opt/wazuh", "1.0", tmp_path)
        assert res is None


def test_package_rpm_no_rpmbuild(tmp_path: Path):
    with patch("wazuh_build.platform.os_id", return_value="linux"), patch(
        "wazuh_build.shell.command_exists", return_value=False
    ):
        res = packaging.package_rpm("out", tmp_path, "/opt/wazuh", "1.0", tmp_path)
        assert res is None


def test_package_rpm_success(tmp_path: Path):
    rel_dir = tmp_path / "release"
    rel_dir.mkdir()
    dest = tmp_path / "dist"
    dest.mkdir()

    def fake_rpm_run(cmd, capture=False):
        if "rpmbuild" in cmd:
            # Create a mock rpm file inside rpmroot
            spec_path = Path(cmd[2])
            rpmroot = spec_path.parent.parent
            rpm_file = rpmroot / "RPMS" / "x86_64" / "pkg.rpm"
            rpm_file.parent.mkdir(parents=True, exist_ok=True)
            rpm_file.write_bytes(b"fake rpm")
        return MagicMock(returncode=0)

    with patch("wazuh_build.platform.os_id", return_value="linux"), patch(
        "wazuh_build.platform.arch_id", return_value="amd64"
    ), patch("wazuh_build.shell.command_exists", return_value=True), patch(
        "wazuh_build.shell.run", side_effect=fake_rpm_run
    ):
        res = packaging.package_rpm(
            "component-1.0", rel_dir, "/opt/component", "1.0.0", dest, requires="bash"
        )
        assert res == dest / "component-1.0.rpm"


def test_package_dmg_non_macos(tmp_path: Path):
    with patch("wazuh_build.platform.os_id", return_value="linux"):
        res = packaging.package_dmg("out", tmp_path, tmp_path)
        assert res is None


def test_package_dmg_no_hdiutil(tmp_path: Path):
    with patch("wazuh_build.platform.os_id", return_value="macos"), patch(
        "wazuh_build.shell.command_exists", return_value=False
    ):
        res = packaging.package_dmg("out", tmp_path, tmp_path)
        assert res is None


def test_package_dmg_success(tmp_path: Path):
    rel_dir = tmp_path / "release"
    rel_dir.mkdir()
    dest = tmp_path / "dist"
    dest.mkdir()

    with patch("wazuh_build.platform.os_id", return_value="macos"), patch(
        "wazuh_build.shell.command_exists", return_value=True
    ), patch("wazuh_build.shell.run") as mock_run:
        res = packaging.package_dmg("pkg-macos", rel_dir, dest)
        assert res == dest / "pkg-macos.dmg"
        assert any("hdiutil" in str(call_arg) for call_arg in mock_run.call_args_list)
