from unittest.mock import patch
from wazuh_build import platform


def test_os_id_linux():
    with patch("platform.system", return_value="Linux"):
        assert platform.os_id() == "linux"


def test_os_id_macos():
    with patch("platform.system", return_value="Darwin"):
        assert platform.os_id() == "macos"


def test_os_id_unknown():
    with patch("platform.system", return_value="Windows"):
        assert platform.os_id() == "unknown"


def test_arch_id_amd64():
    with patch("platform.machine", return_value="x86_64"):
        assert platform.arch_id() == "amd64"
    with patch("platform.machine", return_value="amd64"):
        assert platform.arch_id() == "amd64"


def test_arch_id_arm64():
    with patch("platform.machine", return_value="aarch64"):
        assert platform.arch_id() == "arm64"
    with patch("platform.machine", return_value="arm64"):
        assert platform.arch_id() == "arm64"


def test_arch_id_unknown():
    with patch("platform.machine", return_value="mips64"):
        assert platform.arch_id() == "unknown"


def test_cpu_count_success():
    with patch("multiprocessing.cpu_count", return_value=8):
        assert platform.cpu_count() == 8


def test_cpu_count_not_implemented():
    with patch("multiprocessing.cpu_count", side_effect=NotImplementedError):
        assert platform.cpu_count() == 1
