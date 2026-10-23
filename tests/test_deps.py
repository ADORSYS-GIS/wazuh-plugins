import os
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, call, patch
import pytest

from wazuh_build import deps


def test_install_apt_empty():
    with patch("wazuh_build.shell.run") as mock_run:
        deps.install_apt([])
        deps.install_apt(["", None])
        mock_run.assert_not_called()


def test_install_apt_packages():
    with patch("wazuh_build.shell.run") as mock_run:
        deps.install_apt(["curl", "git"])
        assert mock_run.call_count == 2
        mock_run.assert_has_calls(
            [
                call("apt-get update -qq"),
                call(["apt-get", "install", "-y", "--no-install-recommends", "curl", "git"]),
            ]
        )


def test_install_brew_empty():
    with patch("wazuh_build.shell.run") as mock_run:
        deps.install_brew([])
        mock_run.assert_not_called()


def test_install_brew_all_installed():
    with patch("wazuh_build.shell.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="1.0.0\n")
        deps.install_brew(["git", "curl"])
        # Should only call brew list --versions, no brew install
        for c in mock_run.call_args_list:
            assert c[0][0][1] == "list"


def test_install_brew_missing_and_success():
    call_log = []

    def fake_run(cmd, check=True, capture=False):
        call_log.append(cmd)
        if cmd[:2] == ["brew", "list"]:
            return MagicMock(returncode=1, stdout="")
        return MagicMock(returncode=0, stdout="")

    with patch("wazuh_build.shell.run", side_effect=fake_run):
        deps.install_brew(["custom-pkg"])
        assert ["brew", "update"] in call_log
        assert ["brew", "install", "custom-pkg"] in call_log


def test_install_brew_failure():
    def fake_run(cmd, check=True, capture=False):
        if cmd[:2] == ["brew", "list"]:
            return MagicMock(returncode=1, stdout="")
        if cmd[:2] == ["brew", "update"]:
            return MagicMock(returncode=0)
        if cmd[:2] == ["brew", "install"]:
            raise subprocess.CalledProcessError(1, cmd)
        if cmd[:2] == ["brew", "reinstall"]:
            return MagicMock(returncode=1)
        return MagicMock(returncode=0)

    with patch("wazuh_build.shell.run", side_effect=fake_run):
        with pytest.raises(SystemExit, match="Failed to install Homebrew packages: fail-pkg"):
            deps.install_brew(["fail-pkg"])


def test_run_bash_commands():
    with patch("wazuh_build.shell.run") as mock_run:
        deps.run_bash_commands(["echo 1", "", "  ", "echo 2"])
        assert mock_run.call_count == 2
        mock_run.assert_has_calls([call("echo 1"), call("echo 2")])


def test_ensure_syft_cached(tmp_path: Path):
    with patch("wazuh_build.utils.DEFAULT_CACHE_DIR", tmp_path):
        syft_target = tmp_path / "syft" / "syft-v1.0"
        syft_target.parent.mkdir(parents=True)
        syft_target.write_text("fake binary")

        res = deps.ensure_syft("v1.0", tmp_path / "tools")
        assert res == syft_target


def test_ensure_syft_download(tmp_path: Path):
    with patch("wazuh_build.utils.DEFAULT_CACHE_DIR", tmp_path):
        syft_cache = tmp_path / "syft"

        def fake_curl_run(cmd):
            syft_cache.mkdir(parents=True, exist_ok=True)
            (syft_cache / "syft").write_text("binary")

        with patch("wazuh_build.shell.run", side_effect=fake_curl_run):
            res = deps.ensure_syft("v1.5", tmp_path / "tools")
            assert res == syft_cache / "syft-v1.5"
            assert res.exists()


def test_ensure_syft_download_fails(tmp_path: Path):
    with patch("wazuh_build.utils.DEFAULT_CACHE_DIR", tmp_path):
        with patch("wazuh_build.shell.run"):
            with pytest.raises(RuntimeError, match="syft installation failed"):
                deps.ensure_syft("v1.5", tmp_path / "tools")


def test_version_at_least():
    assert deps._version_at_least("0.20.0", "0.20.0") is True
    assert deps._version_at_least("0.21.0", "0.20.0") is True
    assert deps._version_at_least("0.19.0", "0.20.0") is False
    assert deps._version_at_least("1.0.0", "0.20.0") is True


def test_ensure_cbindgen_already_satisfied():
    with patch("wazuh_build.shell.command_exists", return_value=True), patch(
        "subprocess.check_output", return_value="cbindgen 0.24.3\n"
    ), patch("wazuh_build.shell.run") as mock_run:
        deps.ensure_cbindgen()
        mock_run.assert_not_called()


def test_ensure_cbindgen_needs_install():
    with patch("wazuh_build.shell.command_exists", side_effect=lambda c: c == "cargo"), patch(
        "subprocess.check_output", side_effect=Exception
    ), patch("wazuh_build.shell.run") as mock_run:
        deps.ensure_cbindgen()
        mock_run.assert_called_once()
        assert "cbindgen" in mock_run.call_args[0][0]


def test_ensure_cbindgen_no_cargo():
    with patch("wazuh_build.shell.command_exists", return_value=False):
        with pytest.raises(RuntimeError, match="cargo not available to install cbindgen"):
            deps.ensure_cbindgen()


def test_ensure_pkg_config_path(tmp_path: Path):
    with patch.dict(os.environ, {"PKG_CONFIG_PATH": ""}, clear=False):
        fake_dpkg = MagicMock(stdout="x86_64-linux-gnu\n")
        with patch("wazuh_build.shell.run", return_value=fake_dpkg):
            deps.ensure_pkg_config_path()
            # PKG_CONFIG_PATH should be set if candidates exist or empty if none
            assert "PKG_CONFIG_PATH" in os.environ


def test_require_tools():
    with patch("wazuh_build.shell.command_exists", side_effect=lambda x: x == "make"):
        deps.require_tools(["make"])
        with pytest.raises(SystemExit, match="Missing required tools: cmake, gcc"):
            deps.require_tools(["make", "cmake", "gcc"])


def test_require_libraries_success():
    with patch("wazuh_build.shell.run", return_value=MagicMock(returncode=0)):
        deps.require_libraries(["openssl", "zlib"])


def test_require_libraries_missing():
    def fake_run(cmd, check=True, capture=True):
        if "badlib" in cmd:
            raise subprocess.CalledProcessError(1, cmd)
        return MagicMock(returncode=0)

    with patch("wazuh_build.shell.run", side_effect=fake_run):
        with pytest.raises(SystemExit, match="Missing required libraries: badlib"):
            deps.require_libraries(["goodlib", "badlib"])


def test_require_libraries_libmagic_fallback():
    def fake_run(cmd, check=True, capture=True):
        if "libmagic" in cmd:
            raise subprocess.CalledProcessError(1, cmd)
        return MagicMock(returncode=0)

    with patch("wazuh_build.shell.run", side_effect=fake_run), patch(
        "wazuh_build.download.has_magic_header", return_value=True
    ):
        deps.require_libraries(["libmagic"])
