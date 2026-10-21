import json
import os
import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest

import generate_install_wrappers
import package_artifacts
import run_builder


def test_generate_install_wrappers_update_pinned():
    t1 = 'PINNED_VERSION="${PINNED_VERSION:-1.0.0}"\necho test'
    r1 = generate_install_wrappers.update_pinned(t1, "2.0.0")
    assert 'PINNED_VERSION="${PINNED_VERSION:-2.0.0}"' in r1

    t2 = 'PINNED_VERSION="1.0.0"\necho test'
    r2 = generate_install_wrappers.update_pinned(t2, "2.0.0")
    assert 'PINNED_VERSION="2.0.0"' in r2

    with pytest.raises(SystemExit, match="Unable to locate PINNED_VERSION"):
        generate_install_wrappers.update_pinned("echo nothing", "2.0.0")


def test_generate_install_wrappers_render(tmp_path: Path):
    scripts_dir = tmp_path / "scripts"
    scripts_dir.mkdir()
    (scripts_dir / "install.sh").write_text('PINNED_VERSION="${PINNED_VERSION:-0.1}"\n')
    (scripts_dir / "uninstall.sh").write_text('PINNED_VERSION="0.1"\n')

    out_dir = tmp_path / "rendered"
    generate_install_wrappers.render(tmp_path, out_dir, "4.2.0")

    assert (out_dir / "install.sh").exists()
    assert 'PINNED_VERSION="${PINNED_VERSION:-4.2.0}"' in (out_dir / "install.sh").read_text()
    assert (out_dir / "uninstall.sh").exists()
    assert 'PINNED_VERSION="4.2.0"' in (out_dir / "uninstall.sh").read_text()


def test_package_artifacts_success(tmp_path: Path):
    repo_root = tmp_path
    builder_dir = repo_root / "builders" / "yara"
    dist_artifacts = builder_dir / "dist" / "linux-amd64" / "artifacts"
    dist_artifacts.mkdir(parents=True)
    (builder_dir / "release.txt").write_text("1")
    (builder_dir / "version.txt").write_text("4.3.2")
    (dist_artifacts / "yara.tar.gz").write_bytes(b"tarball")
    (dist_artifacts / "yara.sha256.txt").write_text("hash  yara.tar.gz")

    gh_out = tmp_path / "github_output"

    real_resolve = Path.resolve
    def fake_resolve(self):
        if str(self).endswith("package_artifacts.py"):
            return repo_root / ".github" / "scripts" / "package_artifacts.py"
        return real_resolve(self)

    with patch.dict(os.environ, {"GITHUB_OUTPUT": str(gh_out)}), patch.object(
        Path, "resolve", fake_resolve
    ):
        package_artifacts.package_artifacts("yara", "linux-amd64")

    stage_dir = repo_root / "artifacts" / "yara-1-linux-amd64"
    assert stage_dir.exists()
    assert (stage_dir / "yara.tar.gz").exists()
    assert gh_out.exists()
    assert "version=1" in gh_out.read_text()


def test_package_artifacts_no_dir(tmp_path: Path):
    repo_root = tmp_path
    builder_dir = repo_root / "builders" / "yara"
    builder_dir.mkdir(parents=True)
    (builder_dir / "release.txt").write_text("1")

    real_resolve = Path.resolve
    def fake_resolve(self):
        if str(self).endswith("package_artifacts.py"):
            return repo_root / ".github" / "scripts" / "package_artifacts.py"
        return real_resolve(self)

    with patch.object(Path, "resolve", fake_resolve):
        with pytest.raises(SystemExit, match="Package artifacts directory not found"):
            package_artifacts.package_artifacts("yara", "linux-amd64")


def test_package_artifacts_no_artifacts(tmp_path: Path):
    repo_root = tmp_path
    builder_dir = repo_root / "builders" / "yara"
    dist_artifacts = builder_dir / "dist" / "linux-amd64" / "artifacts"
    dist_artifacts.mkdir(parents=True)
    (builder_dir / "release.txt").write_text("1")

    real_resolve = Path.resolve
    def fake_resolve(self):
        if str(self).endswith("package_artifacts.py"):
            return repo_root / ".github" / "scripts" / "package_artifacts.py"
        return real_resolve(self)

    with patch.object(Path, "resolve", fake_resolve):
        with pytest.raises(SystemExit, match="No packaged artifacts found"):
            package_artifacts.package_artifacts("yara", "linux-amd64")


def test_run_builder_helpers(tmp_path: Path):
    run_builder.log("test message")

    with patch("subprocess.run") as mock_sub:
        run_builder.run_command("echo hello", tmp_path)
        mock_sub.assert_called_once()

    dest = run_builder.resolve_artifact_dest(tmp_path, {}, "linux-amd64")
    assert dest == (tmp_path / "dist" / "linux-amd64").resolve()

    dest_dir = tmp_path / "clean_me"
    dest_dir.mkdir()
    (dest_dir / "old.txt").write_text("old")
    run_builder.clean_artifact_dest(dest_dir)
    assert dest_dir.exists()
    assert not (dest_dir / "old.txt").exists()


def test_run_builder_build_native(tmp_path: Path):
    config_dir = tmp_path / "builders" / "mybuilder"
    config_dir.mkdir(parents=True)
    script_path = config_dir / "build" / "main.py"
    script_path.parent.mkdir()
    script_path.write_text("print('build')")

    pipeline = {"name": "mybuilder", "native_build_script": "build/main.py"}
    artifact_dest = config_dir / "dist"

    with patch("subprocess.run") as mock_sub:
        run_builder.build_native(
            config_dir,
            pipeline,
            artifact_dest,
            "1.0.0",
            "1",
            "linux-amd64",
        )
        mock_sub.assert_called_once()
        assert mock_sub.call_args[0][0] == ["python3", str(script_path.resolve())]


def test_discover_matrix_script(tmp_path: Path):
    gh_out = tmp_path / "gh_output.txt"
    repo_root = Path(__file__).resolve().parent.parent
    env = {
        "GITHUB_REPOSITORY": "ADORSYS-GIS/wazuh-plugins",
        "GITHUB_OUTPUT": str(gh_out),
        "PYTHONPATH": f"{repo_root}:{os.environ.get('PYTHONPATH', '')}",
    }
    script = repo_root / ".github" / "scripts" / "discover_matrix.py"
    res = subprocess.run([sys.executable, str(script)], cwd=repo_root, env=env, capture_output=True, text=True)
    assert res.returncode == 0
    assert gh_out.exists()
    content = gh_out.read_text()
    assert "has_builders=true" in content
    assert "repo_lc=adorsys-gis/wazuh-plugins" in content


def test_discover_matrix_inprocess(tmp_path: Path):
    import runpy
    gh_out = tmp_path / "gh_output.txt"
    repo_root = Path(__file__).resolve().parent.parent
    script = repo_root / ".github" / "scripts" / "discover_matrix.py"
    with patch.dict(os.environ, {"GITHUB_REPOSITORY": "ADORSYS-GIS/wazuh-plugins", "GITHUB_OUTPUT": str(gh_out)}):
        runpy.run_path(str(script))
    assert gh_out.exists()


def test_generate_install_wrappers_main_cli(tmp_path: Path):
    with patch("sys.argv", ["generate_install_wrappers.py", "--version", "1.0", "--output-dir", str(tmp_path)]), patch(
        "generate_install_wrappers.render"
    ) as mock_render:
        generate_install_wrappers.main()
        mock_render.assert_called_once()


def test_package_artifacts_main_cli():
    with patch("sys.argv", ["package_artifacts.py", "yara", "linux-amd64"]), patch(
        "package_artifacts.package_artifacts"
    ) as mock_pkg:
        package_artifacts.main()
        mock_pkg.assert_called_once_with("yara", "linux-amd64")


def test_run_builder_main(tmp_path: Path):
    builder_dir = tmp_path / "builders" / "testb"
    builder_dir.mkdir(parents=True)
    cfg_file = builder_dir / "config.yaml"
    cfg_file.write_text(
        """
ci:
  lint:
    - echo linting
  tests:
    - command: echo testing
pipeline:
  name: testb
  builder: native
  version_file: version.txt
  release_file: release.txt
"""
    )
    (builder_dir / "version.txt").write_text("1.0.0")
    (builder_dir / "release.txt").write_text("1")

    with patch("sys.argv", ["run_builder.py", str(cfg_file), "--artifact-triplet", "linux-amd64"]), patch(
        "run_builder.run_command"
    ) as mock_cmd, patch("run_builder.build_native") as mock_build:
        run_builder.main()
        assert mock_cmd.call_count == 2
        mock_build.assert_called_once()
