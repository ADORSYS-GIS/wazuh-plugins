import subprocess
from pathlib import Path
from unittest.mock import patch
import pytest

from wazuh_build import shell


def test_stringify_str():
    assert shell._stringify("echo 'hello world'") == "echo 'hello world'"


def test_stringify_list():
    assert shell._stringify(["echo", "hello world"]) == "echo 'hello world'"


def test_run_command_list(tmp_path: Path):
    res = shell.run(["echo", "testing 123"], capture=True)
    assert res.returncode == 0
    assert "testing 123" in res.stdout


def test_run_command_str():
    res = shell.run("echo string_command", capture=True)
    assert res.returncode == 0
    assert "string_command" in res.stdout


def test_run_command_env():
    res = shell.run("echo $CUSTOM_VAR", env={"CUSTOM_VAR": "secret_val"}, capture=True)
    assert "secret_val" in res.stdout


def test_run_command_fail():
    with pytest.raises(subprocess.CalledProcessError):
        shell.run(["false"], check=True)


def test_command_exists():
    assert shell.command_exists("sh") is True
    assert shell.command_exists("definitely_nonexistent_binary_xyz_123") is False
