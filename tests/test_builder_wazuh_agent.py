import importlib.util
import os
import shutil
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest

from modules import repackage

# Dynamically import builders/wazuh-agent/build/main.py
repo_root = Path(__file__).resolve().parent.parent
agent_main_path = repo_root / "builders" / "wazuh-agent" / "build" / "main.py"
spec = importlib.util.spec_from_file_location("wazuh_agent_main", agent_main_path)
agent_main = importlib.util.module_from_spec(spec)
spec.loader.exec_module(agent_main)


# ---- repackage.py tests ----

def test_stream_from_version():
    assert repackage.stream_from_version("4.8.0") == "4.x"
    assert repackage.stream_from_version("5.0.1") == "5.x"
    assert repackage.stream_from_version("invalid") == "4.x"


def test_require_tools():
    with patch("builders.common.python.wazuh_build.shell.command_exists", return_value=True):
        repackage.require_tools(["curl", "tar"])

    with patch("builders.common.python.wazuh_build.shell.command_exists", return_value=False):
        with pytest.raises(SystemExit, match="Missing required tools: nonexistent_tool"):
            repackage.require_tools(["nonexistent_tool"])


def test_download_linux_deb(tmp_path: Path):
    with patch("builders.common.python.wazuh_build.shell.run"):
        dest, url = repackage.download_linux_deb("4.8.0", "1", "amd64", tmp_path)
        assert dest == tmp_path / "wazuh-agent_4.8.0-1_amd64.deb"
        assert "packages.wazuh.com/4.x/apt/pool/main" in url


def test_download_macos_pkg(tmp_path: Path):
    with patch("builders.common.python.wazuh_build.shell.run"):
        dest, url = repackage.download_macos_pkg("4.8.0", "1", "intel", tmp_path)
        assert dest == tmp_path / "wazuh-agent-4.8.0-1.intel.pkg"
        assert "packages.wazuh.com/4.x/macos" in url


def test_extract_linux_package(tmp_path: Path):
    with patch("builders.common.python.wazuh_build.shell.run") as mock_run:
        deb = tmp_path / "agent.deb"
        deb.write_text("deb")
        repackage.extract_linux_package(deb, tmp_path / "release")
        mock_run.assert_called_once()


def test_extract_macos_package(tmp_path: Path):
    def fake_run(cmd):
        # Fake pkgutil expanding Payload
        expanded = Path(cmd[3])
        payload = expanded / "component" / "Payload"
        payload.mkdir(parents=True)
        (payload / "sample.txt").write_text("agent content")

    with patch("builders.common.python.wazuh_build.shell.run", side_effect=fake_run):
        pkg = tmp_path / "agent.pkg"
        pkg.write_text("pkg")
        release_root = tmp_path / "release"
        release_root.mkdir()
        repackage.extract_macos_package(pkg, release_root)
        assert (release_root / "sample.txt").exists()


def test_fix_permissions(tmp_path: Path):
    comp_root = tmp_path / "comp"
    comp_root.mkdir()
    bin_dir = comp_root / "bin"
    bin_dir.mkdir()
    (bin_dir / "tool").write_text("executable")
    (comp_root / "script.sh").write_text("#!/bin/sh")
    (comp_root / "readme.txt").write_text("text")

    repackage.fix_permissions(comp_root)


# ---- main.py tests ----

def test_wazuh_agent_prepare_dest(tmp_path: Path):
    rel = tmp_path / "rel"
    rel.mkdir()
    dest = tmp_path / "dest"
    agent_main.prepare_dest(rel, dest)
    assert rel.exists()
    assert (dest / "artifacts").exists()


def test_wazuh_agent_write_metadata(tmp_path: Path):
    comp_root = tmp_path / "comp"
    comp_root.mkdir()
    agent_main.write_metadata(
        comp_root, "x86_64-linux", "wazuh-agent-1.0", "1.0", "4.8.0", "1", "packages.wazuh.com", "/var/ossec"
    )
    assert (comp_root / "BUILDINFO.txt").exists()
    assert (comp_root / "README.txt").exists()
    assert "UPSTREAM_AGENT=4.8.0-1" in (comp_root / "BUILDINFO.txt").read_text()


def test_wazuh_agent_package_release(tmp_path: Path):
    cfg = MagicMock()
    cfg.build_setting.return_value = "v1.5.0"
    dest = tmp_path / "dest"
    dest.mkdir()
    release_root = tmp_path / "release"
    component_root = release_root / "var" / "ossec"
    component_root.mkdir(parents=True)

    with patch("builders.common.python.wazuh_build.sbom.generate_sboms"), \
         patch("builders.common.python.wazuh_build.packaging.write_pom"), \
         patch("builders.common.python.wazuh_build.packaging.make_tarball"), \
         patch("builders.common.python.wazuh_build.packaging.package_deb", return_value=tmp_path / "pkg.deb"), \
         patch("builders.common.python.wazuh_build.packaging.package_rpm", return_value=tmp_path / "pkg.rpm"), \
         patch("builders.common.python.wazuh_build.packaging.package_dmg", return_value=None), \
         patch("builders.common.python.wazuh_build.packaging.checksum_file", return_value="abcdef1234567890"):
        (tmp_path / "pkg.deb").write_text("deb")
        (tmp_path / "pkg.rpm").write_text("rpm")
        agent_main.package_release(
            cfg, dest, release_root, component_root, "/var/ossec", "wazuh-agent-test", "native", "1.0.0", "4.8.0", "1", "packages.wazuh.com"
        )
        assert (dest / "artifacts" / "wazuh-agent-test.sha256.txt").exists()


def test_wazuh_agent_main_execution(tmp_path: Path):
    def fake_extract(deb, rel_root):
        (rel_root / "var" / "ossec").mkdir(parents=True, exist_ok=True)

    with patch.dict(os.environ, {"PIPELINE_VERSION": "4.8.0", "ARTIFACT_DEST": str(tmp_path / "dist")}), \
         patch("builders.common.python.wazuh_build.config.BuilderConfig"), \
         patch("builders.common.python.wazuh_build.platform.os_id", return_value="linux"), \
         patch("builders.common.python.wazuh_build.platform.arch_id", return_value="amd64"), \
         patch.object(agent_main, "require_tools"), \
         patch.object(agent_main, "download_linux_deb", return_value=(tmp_path / "agent.deb", "http://pkg")), \
         patch.object(agent_main, "extract_linux_package", side_effect=fake_extract), \
         patch.object(agent_main, "write_metadata"), \
         patch.object(agent_main, "fix_permissions"), \
         patch.object(agent_main, "package_release"):
        (tmp_path / "agent.deb").write_text("deb")
        agent_main.main()
