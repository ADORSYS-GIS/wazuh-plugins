from __future__ import annotations

import io
import json
import tarfile
import zipfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

import builders.suricata.utils.fetch_rules as suricata_fetch
import builders.yara.utils.fetch_rules as yara_fetch


class TestYaraFetchRules:
    def test_extract_bundle_directory(self, tmp_path: Path):
        archive_path = tmp_path / "test.zip"
        with zipfile.ZipFile(archive_path, "w") as zf:
            zf.writestr("rules/sample.yar", "rule test { condition: true }")

        out_dir = tmp_path / "out"
        out_dir.mkdir()
        (out_dir / "old.txt").write_text("old")

        res = yara_fetch.extract_bundle(archive_path, "rules", out_dir)
        assert res == out_dir
        assert not (out_dir / "old.txt").exists()
        assert (out_dir / "sample.yar").exists()

    def test_extract_bundle_file(self, tmp_path: Path):
        archive_path = tmp_path / "test.zip"
        with zipfile.ZipFile(archive_path, "w") as zf:
            zf.writestr("single.yar", "rule single { condition: true }")

        out_dir = tmp_path / "out_file"
        res = yara_fetch.extract_bundle(archive_path, "single.yar", out_dir)
        assert res == out_dir
        assert (out_dir / "single.yar").exists()

    def test_extract_bundle_missing_bundle_path(self, tmp_path: Path):
        archive_path = tmp_path / "empty.zip"
        with zipfile.ZipFile(archive_path, "w") as zf:
            zf.writestr("other.yar", "rule other {}")

        out_dir = tmp_path / "out"
        with pytest.raises(SystemExit, match="Bundle path missing not found"):
            yara_fetch.extract_bundle(archive_path, "missing", out_dir)

    def test_parse_args(self):
        meta = {"assets": {"full": {}, "core": {}}}
        with patch("sys.argv", ["fetch_rules.py", "--flavor", "core", "--force"]):
            args = yara_fetch.parse_args(meta)
            assert args.flavor == "core"
            assert args.force is True
            assert args.metadata is None
            assert args.dest is None

    def test_main_default(self, monkeypatch):
        mock_load = MagicMock(return_value={"assets": {"full": {}}})
        mock_fetch = MagicMock()
        monkeypatch.setattr(yara_fetch.rules, "load_rules_metadata", mock_load)
        monkeypatch.setattr(yara_fetch.rules, "fetch_rules", mock_fetch)

        with patch("sys.argv", ["fetch_rules.py"]):
            yara_fetch.main()
            assert mock_fetch.called
            _, kwargs = mock_fetch.call_args
            assert "url_template" in kwargs

    def test_main_custom_metadata(self, tmp_path: Path, monkeypatch):
        meta_file = tmp_path / "source.json"
        meta_file.write_text(json.dumps({"assets": {"full": {}}}))
        dest_dir = tmp_path / "dest"

        mock_load = MagicMock(return_value={"assets": {"full": {}}})
        mock_fetch = MagicMock()
        monkeypatch.setattr(yara_fetch.rules, "load_rules_metadata", mock_load)
        monkeypatch.setattr(yara_fetch.rules, "fetch_rules", mock_fetch)

        with patch("sys.argv", ["fetch_rules.py", "--metadata", str(meta_file), "--dest", str(dest_dir)]):
            yara_fetch.main()
            assert mock_fetch.called

    def test_main_invalid_metadata(self, tmp_path: Path, monkeypatch):
        bad_meta = tmp_path / "bad.json"
        bad_meta.write_text("invalid json")

        mock_load = MagicMock(return_value={"assets": {"full": {}}})
        monkeypatch.setattr(yara_fetch.rules, "load_rules_metadata", mock_load)

        with patch("sys.argv", ["fetch_rules.py", "--metadata", str(bad_meta)]):
            with pytest.raises(SystemExit, match="Unable to parse metadata"):
                yara_fetch.main()


class TestSuricataFetchRules:
    def test_extract_bundle_tar_gz(self, tmp_path: Path):
        archive_path = tmp_path / "rules.tar.gz"
        with tarfile.open(archive_path, "w:gz") as tf:
            tar_data = b"# rule content\n"
            ti = tarfile.TarInfo(name="rules/test.rules")
            ti.size = len(tar_data)
            tf.addfile(ti, io.BytesIO(tar_data))

        out_dir = tmp_path / "suricata_out"
        out_dir.mkdir()
        (out_dir / "old.txt").write_text("old")

        res = suricata_fetch.extract_bundle(archive_path, "rules", out_dir)
        assert res == out_dir
        assert not (out_dir / "old.txt").exists()
        assert (out_dir / "test.rules").exists()

    def test_extract_bundle_non_tar(self, tmp_path: Path):
        file_path = tmp_path / "rules.txt"
        file_path.write_text("plain rule")

        out_dir = tmp_path / "suricata_plain"
        res = suricata_fetch.extract_bundle(file_path, "bundle.txt", out_dir)
        assert res == out_dir
        assert (out_dir / "bundle.txt").exists()

    def test_parse_args(self):
        meta = {"assets": {"open": {}, "pro": {}}}
        with patch("sys.argv", ["fetch_rules.py", "--flavor", "pro", "--force"]):
            args = suricata_fetch.parse_args(meta)
            assert args.flavor == "pro"
            assert args.force is True
            assert args.metadata is None
            assert args.dest is None

    def test_main_default(self, monkeypatch):
        mock_load = MagicMock(return_value={"assets": {"open": {}}})
        mock_fetch = MagicMock()
        monkeypatch.setattr(suricata_fetch.rules, "load_rules_metadata", mock_load)
        monkeypatch.setattr(suricata_fetch.rules, "fetch_rules", mock_fetch)

        with patch("sys.argv", ["fetch_rules.py"]):
            suricata_fetch.main()
            assert mock_fetch.called

    def test_main_custom_metadata(self, tmp_path: Path, monkeypatch):
        meta_file = tmp_path / "source.json"
        meta_file.write_text(json.dumps({"assets": {"open": {}}}))
        dest_dir = tmp_path / "dest"

        mock_load = MagicMock(return_value={"assets": {"open": {}}})
        mock_fetch = MagicMock()
        monkeypatch.setattr(suricata_fetch.rules, "load_rules_metadata", mock_load)
        monkeypatch.setattr(suricata_fetch.rules, "fetch_rules", mock_fetch)

        with patch("sys.argv", ["fetch_rules.py", "--metadata", str(meta_file), "--dest", str(dest_dir)]):
            suricata_fetch.main()
            assert mock_fetch.called

    def test_main_invalid_metadata(self, tmp_path: Path, monkeypatch):
        bad_meta = tmp_path / "bad.json"
        bad_meta.write_text("not json")

        mock_load = MagicMock(return_value={"assets": {"open": {}}})
        monkeypatch.setattr(suricata_fetch.rules, "load_rules_metadata", mock_load)

        with patch("sys.argv", ["fetch_rules.py", "--metadata", str(bad_meta)]):
            with pytest.raises(SystemExit, match="Unable to parse metadata"):
                suricata_fetch.main()
