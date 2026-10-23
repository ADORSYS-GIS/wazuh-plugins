import json
import os
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest

from wazuh_build import rules


def test_load_rules_metadata_success(tmp_path: Path):
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    meta_file = rules_dir / "source.json"
    meta_file.write_text(json.dumps({"source": "upstream", "tag": "v1.0"}))

    res = rules.load_rules_metadata(tmp_path)
    assert res["source"] == "upstream"
    assert res["tag"] == "v1.0"


def test_load_rules_metadata_missing(tmp_path: Path):
    with pytest.raises(SystemExit, match="Rule metadata not found"):
        rules.load_rules_metadata(tmp_path)


def test_load_rules_metadata_invalid_json(tmp_path: Path):
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    meta_file = rules_dir / "source.json"
    meta_file.write_text("{bad json")

    with pytest.raises(SystemExit, match="Unable to parse rule metadata"):
        rules.load_rules_metadata(tmp_path)


def test_resolve_rule_bundle_env_set(tmp_path: Path):
    bundle_path = tmp_path / "custom_bundle"
    bundle_path.mkdir()

    with patch.dict(os.environ, {"RULE_BUNDLE": str(bundle_path)}):
        path, info = rules.resolve_rule_bundle(tmp_path, "default", "fetch.py")
        assert path == bundle_path.resolve()
        assert info["source"] == "custom"


def test_resolve_rule_bundle_env_missing_path(tmp_path: Path):
    with patch.dict(os.environ, {"RULE_BUNDLE": "/nonexistent/path"}):
        with pytest.raises(SystemExit, match="RULE_BUNDLE path does not exist"):
            rules.resolve_rule_bundle(tmp_path, "default", "fetch.py")


def test_resolve_rule_bundle_cached_expected(tmp_path: Path):
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "source.json").write_text(json.dumps({"source": "rules-src", "tag": "v2.0"}))

    cache_expected = tmp_path / "rules-cache" / "v2.0" / "full"
    cache_expected.mkdir(parents=True)

    with patch.dict(os.environ, {"RULES_FLAVOR": "full"}, clear=False):
        path, info = rules.resolve_rule_bundle(tmp_path, "full", "fetch.py")
        assert path == cache_expected
        assert info["tag"] == "v2.0"
        assert info["flavor"] == "full"


def test_resolve_rule_bundle_local_rules(tmp_path: Path):
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "source.json").write_text(json.dumps({"source": "rules-src", "tag": "v2.0"}))
    (rules_dir / "sample.rules").write_text("alert tcp any any -> any any")

    path, info = rules.resolve_rule_bundle(tmp_path, "default", "fetch.py")
    assert path == rules_dir
    assert info["source"] == "local"


def test_resolve_rule_bundle_fetcher(tmp_path: Path):
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "source.json").write_text(json.dumps({"source": "rules-src", "tag": "v2.0"}))
    fetcher = tmp_path / "fetch.py"
    fetcher.write_text("#!/usr/bin/env python3")

    expected_path = tmp_path / "rules-cache" / "v2.0" / "core"

    def fake_run(cmd):
        expected_path.mkdir(parents=True, exist_ok=True)

    with patch("wazuh_build.shell.run", side_effect=fake_run):
        path, info = rules.resolve_rule_bundle(tmp_path, "core", "fetch.py")
        assert path == expected_path


def test_fetch_rules_invalid_flavor(tmp_path: Path):
    meta = {"assets": {"full": {"name": "full.tar.gz"}}}
    with pytest.raises(SystemExit, match="Flavor 'missing' not defined"):
        rules.fetch_rules(meta, "missing", tmp_path, lambda a, b, c: c)


def test_fetch_rules_success(tmp_path: Path):
    meta = {
        "source": "https://example.com/rules",
        "tag": "v1.2.3",
        "assets": {
            "core": {
                "name": "core.tar.gz",
                "sha256": "abcdef123456",
                "bundle_path": "rules/core",
            }
        },
    }

    archive_fake = tmp_path / "core.tar.gz"
    archive_fake.write_bytes(b"content")

    callback = MagicMock(side_effect=lambda a, b, c: c)

    with patch("wazuh_build.download.ensure_archive", return_value=archive_fake):
        out = rules.fetch_rules(meta, "core", tmp_path, callback)
        assert out == tmp_path / "v1.2.3" / "core"
        callback.assert_called_once()
