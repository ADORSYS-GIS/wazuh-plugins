import os
import stat
from pathlib import Path
from unittest.mock import patch

from wazuh_build import utils


def test_ensure_dir(tmp_path: Path):
    target = tmp_path / "sub" / "dir"
    res = utils.ensure_dir(target)
    assert res == target
    assert target.is_dir()


def test_tempdir():
    created_path = None
    with utils.tempdir(prefix="test-wb-") as tmp:
        created_path = tmp
        assert tmp.exists()
        assert "test-wb-" in tmp.name
        (tmp / "sample.txt").write_text("hello")
    assert not created_path.exists()


def test_sha256_file(tmp_path: Path):
    file_path = tmp_path / "data.bin"
    file_path.write_bytes(b"hello wazuh plugins\n")
    digest = utils.sha256_file(file_path)
    assert isinstance(digest, str)
    assert len(digest) == 64
    import hashlib

    expected = hashlib.sha256(b"hello wazuh plugins\n").hexdigest()
    assert digest == expected


def test_prepend_path_if_missing():
    with patch.dict(os.environ, {"PATH": "/usr/bin:/bin"}):
        utils.prepend_path_if_missing("/custom/bin")
        assert os.environ["PATH"] == "/custom/bin:/usr/bin:/bin"
        # Calling again should not duplicate
        utils.prepend_path_if_missing("/custom/bin")
        assert os.environ["PATH"] == "/custom/bin:/usr/bin:/bin"


def test_prepend_path_if_missing_empty():
    with patch.dict(os.environ, {"PATH": ""}):
        utils.prepend_path_if_missing("/custom/bin")
        assert os.environ["PATH"] == "/custom/bin"


def test_detect_jobs_env_var():
    with patch.dict(os.environ, {"MAKE_JOBS": "4"}):
        assert utils.detect_jobs() == "4"


def test_detect_jobs_fallback():
    with patch.dict(os.environ, {}, clear=True):
        with patch("wazuh_build.platform.cpu_count", return_value=6):
            assert utils.detect_jobs() == "6"


def test_should_be_executable(tmp_path: Path):
    bin_file = tmp_path / "bin" / "tool"
    bin_file.parent.mkdir()
    bin_file.write_text("binary")
    assert utils._should_be_executable(bin_file)

    sh_file = tmp_path / "script.sh"
    sh_file.write_text("#!/bin/sh")
    assert utils._should_be_executable(sh_file)

    py_file = tmp_path / "script.py"
    py_file.write_text("#!/usr/bin/env python3")
    assert utils._should_be_executable(py_file)

    regular_file = tmp_path / "config.txt"
    regular_file.write_text("text")
    assert not utils._should_be_executable(regular_file)


def test_fix_permissions(tmp_path: Path):
    root = tmp_path / "component"
    root.mkdir()
    sub_dir = root / "bin"
    sub_dir.mkdir()
    sh_file = sub_dir / "run.sh"
    sh_file.write_text("#!/bin/sh")
    txt_file = root / "readme.txt"
    txt_file.write_text("readme")

    utils.fix_permissions(root)

    # Check dir mode
    dir_stat = sub_dir.stat().st_mode & 0o777
    assert dir_stat == 0o770

    # Executable file
    sh_stat = sh_file.stat().st_mode & 0o777
    assert sh_stat == 0o775

    # Regular file
    txt_stat = txt_file.stat().st_mode & 0o770
    assert txt_stat == 0o770
