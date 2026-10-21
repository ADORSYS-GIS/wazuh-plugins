import json
from pathlib import Path
from unittest.mock import patch
import pytest

from builders.common import dependencies


def test_fallback_dependencies():
    yaml_text = """
some_other_key: val
dependencies:
  apt:
    - curl
    - git
  brew:
    - openssl
not_in_deps:
  key: val
"""
    parsed = dependencies._fallback_dependencies(yaml_text)
    assert "dependencies" in parsed
    deps = parsed["dependencies"]
    assert deps["apt"] == ["curl", "git"]
    assert deps["brew"] == ["openssl"]


def test_load_config_with_yaml(tmp_path: Path):
    cfg_file = tmp_path / "config.yaml"
    cfg_file.write_text("pipeline:\n  name: mypipe\n")
    data = dependencies._load_config(cfg_file)
    assert data["pipeline"]["name"] == "mypipe"


def test_load_config_fallback(tmp_path: Path):
    cfg_file = tmp_path / "config.yaml"
    cfg_file.write_text("dependencies:\n  apt:\n    - wget\n")
    with patch.dict("sys.modules", {"yaml": None}):
        data = dependencies._load_config(cfg_file)
        assert data["dependencies"]["apt"] == ["wget"]


def test_collect_dependencies(tmp_path: Path):
    f1 = tmp_path / "c1.yaml"
    f1.write_text("dependencies:\n  apt:\n    - pkg1\n    - pkg2\n")
    f2 = tmp_path / "c2.yaml"
    f2.write_text("dependencies:\n  apt:\n    - pkg2\n    - pkg3\n")

    res = dependencies.collect_dependencies([f1, f2], "apt")
    assert res == ["pkg1", "pkg2", "pkg3"]


def test_collect_dependencies_dict_mapping(tmp_path: Path):
    f1 = tmp_path / "c1.yaml"
    f1.write_text("dependencies:\n  apt:\n    key1: pkgA\n    key2: [pkgB, pkgC]\n")

    res = dependencies.collect_dependencies([f1], "apt")
    assert "pkgA" in res
    assert "pkgB" in res
    assert "pkgC" in res


def test_read_value(tmp_path: Path):
    f1 = tmp_path / "c1.yaml"
    f1.write_text("pipeline:\n  meta:\n    version: 3.2.1\n")

    assert dependencies.read_value(f1, "pipeline.meta.version") == "3.2.1"
    assert dependencies.read_value(f1, "pipeline.meta.none") is None
    assert dependencies.read_value(f1, "unknown.key") is None


def test_main_cli_section_lines(tmp_path: Path, capsys):
    f1 = tmp_path / "c1.yaml"
    f1.write_text("dependencies:\n  apt:\n    - curl\n")

    with patch("sys.argv", ["dependencies.py", "--section", "apt", str(f1)]):
        dependencies.main()
    captured = capsys.readouterr()
    assert captured.out.strip() == "curl"


def test_main_cli_section_json(tmp_path: Path, capsys):
    f1 = tmp_path / "c1.yaml"
    f1.write_text("dependencies:\n  apt:\n    - curl\n")

    with patch("sys.argv", ["dependencies.py", "--section", "apt", "--format", "json", str(f1)]):
        dependencies.main()
    captured = capsys.readouterr()
    assert json.loads(captured.out.strip()) == ["curl"]


def test_main_cli_value(tmp_path: Path, capsys):
    f1 = tmp_path / "c1.yaml"
    f1.write_text("pipeline:\n  version: 2.5.0\n")

    with patch("sys.argv", ["dependencies.py", "--value", "pipeline.version", str(f1)]):
        dependencies.main()
    captured = capsys.readouterr()
    assert captured.out.strip() == "2.5.0"
