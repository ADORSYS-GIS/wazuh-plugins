import io
import tarfile
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest

from wazuh_build import download, utils


def test_strip_components():
    tf = MagicMock()
    m1 = tarfile.TarInfo(name="stripme/dir/file.txt")
    m2 = tarfile.TarInfo(name="stripme/top.txt")
    tf.getmembers.return_value = [m1, m2]

    results = list(download.strip_components(tf, n=1))
    assert results[0].name == "dir/file.txt"
    assert results[1].name == "top.txt"


def test_has_magic_header(tmp_path: Path):
    with patch("wazuh_build.download.Path.exists", return_value=True):
        assert download.has_magic_header() is True

    with patch("wazuh_build.download.Path.exists", return_value=False):
        assert download.has_magic_header() is False


def test_download_file(tmp_path: Path):
    dest = tmp_path / "out" / "file.txt"
    fake_data = b"content from url"
    mock_resp = io.BytesIO(fake_data)

    with patch("urllib.request.urlopen", return_value=mock_resp):
        download.download_file("http://example.com/file.txt", dest)

    assert dest.exists()
    assert dest.read_bytes() == fake_data


def test_ensure_archive_cached_valid(tmp_path: Path):
    archive = tmp_path / "archive.tar.gz"
    archive.write_bytes(b"cached content")
    expected_sha = utils.sha256_file(archive)

    result = download.ensure_archive("http://example.com/a.tar.gz", expected_sha, archive)
    assert result == archive


def test_ensure_archive_cached_mismatch(tmp_path: Path):
    archive = tmp_path / "archive.tar.gz"
    archive.write_bytes(b"cached content")

    with pytest.raises(SystemExit, match="Cached archive checksum mismatch"):
        download.ensure_archive("http://example.com/a.tar.gz", "wrong_sha", archive)


def test_ensure_archive_download_valid(tmp_path: Path):
    archive = tmp_path / "archive.tar.gz"
    fake_data = b"new downloaded archive"
    mock_resp = io.BytesIO(fake_data)
    import hashlib

    expected_sha = hashlib.sha256(fake_data).hexdigest()

    with patch("urllib.request.urlopen", return_value=mock_resp):
        result = download.ensure_archive("http://example.com/a.tar.gz", expected_sha, archive)
        assert result == archive
        assert archive.read_bytes() == fake_data


def test_ensure_archive_download_mismatch(tmp_path: Path):
    archive = tmp_path / "archive.tar.gz"
    fake_data = b"new downloaded archive"
    mock_resp = io.BytesIO(fake_data)

    with patch("urllib.request.urlopen", return_value=mock_resp):
        with pytest.raises(SystemExit, match="Downloaded archive checksum mismatch"):
            download.ensure_archive("http://example.com/a.tar.gz", "bad_sha", archive)
    assert not archive.exists()
