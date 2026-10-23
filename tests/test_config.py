from pathlib import Path
from wazuh_build import config


def test_builder_config(tmp_path: Path):
    cfg_file = tmp_path / "config.yaml"
    cfg_file.write_text(
        """
pipeline:
  name: test-component
  version: 1.0.0
dependencies:
  apt:
    - curl
    - git
  bash:
    - echo hello
build:
  target: release
  jobs: 4
"""
    )
    cfg = config.BuilderConfig(cfg_file)
    assert cfg.pipeline["name"] == "test-component"
    assert cfg.dependencies["apt"] == ["curl", "git"]
    assert cfg.dependency_section("apt") == ["curl", "git"]
    assert cfg.dependency_section("nonexistent") == []
    assert cfg.build_setting("target") == "release"
    assert cfg.build_setting("jobs") == "4"
    assert cfg.build_setting("missing", default="def") == "def"


def test_builder_config_empty(tmp_path: Path):
    cfg_file = tmp_path / "empty.yaml"
    cfg_file.write_text("{}")
    cfg = config.BuilderConfig(cfg_file)
    assert cfg.pipeline == {}
    assert cfg.dependencies == {}
    assert cfg.dependency_section("apt") == []
    assert cfg.build_setting("opt", default="none") == "none"


def test_resolve_artifact_dest(tmp_path: Path):
    config_dir = tmp_path / "builder"
    config_dir.mkdir()

    # Case 1: artifact_triplet supplied
    dest = config.resolve_artifact_dest(config_dir, {}, "linux-amd64")
    assert dest == (config_dir / "dist" / "linux-amd64").resolve()

    # Case 2: relative dest in cfg
    dest = config.resolve_artifact_dest(config_dir, {"dest": "output/build"}, None)
    assert dest == (config_dir / "output/build").resolve()

    # Case 3: absolute dest in cfg
    abs_dest = tmp_path / "custom_abs"
    dest = config.resolve_artifact_dest(config_dir, {"dest": str(abs_dest)}, None)
    assert dest == abs_dest.resolve()

    # Case 4: default dest
    dest = config.resolve_artifact_dest(config_dir, {}, None)
    assert dest == (config_dir / "dist").resolve()


def test_ensure_artifact_dest(tmp_path: Path):
    dest = tmp_path / "dist"
    dest.mkdir()
    (dest / "old_file.txt").write_text("old")

    config.ensure_artifact_dest(dest)
    assert dest.exists()
    assert not (dest / "old_file.txt").exists()
