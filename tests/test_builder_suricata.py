import os
import shutil
import tarfile
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest

from builders.suricata.build.modules import download, dependencies, build, packaging
import builders.suricata.build.main as suricata_main


# ---- download.py tests ----

def test_suricata_resolve_rule_bundle(tmp_path: Path):
    with patch("builders.common.python.wazuh_build.rules.resolve_rule_bundle", return_value=(tmp_path, {"tag": "v1"})):
        bundle_path, info = download.resolve_rule_bundle(tmp_path)
        assert bundle_path == tmp_path
        assert info["tag"] == "v1"


def test_suricata_write_revision_header(tmp_path: Path):
    with patch.dict(os.environ, {"PIPELINE_COMMIT": "deadbeef"}):
        header = download.write_revision_header(tmp_path)
        assert header.exists()
        assert "Wazuh Plugin Build deadbeef" in header.read_text()


def test_suricata_download_and_unpack(tmp_path: Path):
    archive_path = tmp_path / "suricata.tar.gz"
    sample_file = tmp_path / "sample.txt"
    sample_file.write_text("suricata source")
    with tarfile.open(archive_path, "w:gz") as tf:
        tf.add(sample_file, arcname="suricata-7.0.2/sample.txt")

    with patch("builders.common.python.wazuh_build.shell.run"):
        src_dir = download.download_and_unpack("suricata-7.0.2", tmp_path)
        assert src_dir.is_dir()
        assert (src_dir / "sample.txt").exists()


# ---- dependencies.py tests ----

def test_suricata_dependencies_ensure(tmp_path: Path):
    cfg = MagicMock()
    cfg.dependency_section.return_value = ["libfoo-dev"]

    with patch("builders.common.python.wazuh_build.platform.os_id", return_value="linux"), \
         patch("builders.common.python.wazuh_build.shell.command_exists", return_value=True), \
         patch("builders.common.python.wazuh_build.deps.install_apt") as mock_apt, \
         patch("builders.common.python.wazuh_build.deps.run_bash_commands"), \
         patch("builders.common.python.wazuh_build.deps.ensure_pkg_config_path"), \
         patch("builders.common.python.wazuh_build.deps.ensure_cbindgen"):
        dependencies.ensure_dependencies(cfg)
        mock_apt.assert_called_once_with(["libfoo-dev"])

    with patch("builders.common.python.wazuh_build.platform.os_id", return_value="macos"), \
         patch("builders.common.python.wazuh_build.shell.command_exists", return_value=True), \
         patch("builders.common.python.wazuh_build.deps.install_brew") as mock_brew, \
         patch("builders.suricata.build.modules.dependencies.configure_macos_env") as mock_mac_env, \
         patch("builders.common.python.wazuh_build.deps.ensure_pkg_config_path"), \
         patch("builders.common.python.wazuh_build.deps.ensure_cbindgen"):
        dependencies.ensure_dependencies(cfg)
        mock_brew.assert_called_once_with(["libfoo-dev"])
        mock_mac_env.assert_called_once()


def test_suricata_configure_macos_env(tmp_path: Path):
    with patch("builders.common.python.wazuh_build.platform.os_id", return_value="macos"), \
         patch("builders.common.python.wazuh_build.shell.command_exists", return_value=True), \
         patch("builders.common.python.wazuh_build.shell.run", return_value=MagicMock(stdout=str(tmp_path / "pkg"))), \
         patch.dict(os.environ, {"PKG_CONFIG_PATH": "", "CPPFLAGS": "", "LDFLAGS": ""}):
        (tmp_path / "pkg" / "lib" / "pkgconfig").mkdir(parents=True, exist_ok=True)
        (tmp_path / "pkg" / "include").mkdir(parents=True, exist_ok=True)
        (tmp_path / "pkg" / "bin").mkdir(parents=True, exist_ok=True)

        dependencies.configure_macos_env()
        assert "pkgconfig" in os.environ["PKG_CONFIG_PATH"]
        assert "-I" in os.environ["CPPFLAGS"]
        assert "-L" in os.environ["LDFLAGS"]


def test_suricata_setup_environment(tmp_path: Path):
    with patch("builders.common.python.wazuh_build.platform.os_id", return_value="macos"), \
         patch.object(Path, "exists", return_value=True), \
         patch("builders.common.python.wazuh_build.utils.prepend_path_if_missing") as mock_prepend:
        dependencies.setup_environment()
        assert mock_prepend.call_count >= 1


# ---- packaging.py tests ----

def test_suricata_bundle_runtime_libs(tmp_path: Path):
    comp_root = tmp_path / "suricata"
    comp_root.mkdir()
    # Non-linux returns immediately
    with patch("builders.common.python.wazuh_build.platform.os_id", return_value="darwin"):
        packaging.bundle_runtime_libs(comp_root)


def test_suricata_wrap_linux_binaries(tmp_path: Path):
    comp_root = tmp_path / "comp"
    bin_dir = comp_root / "bin"
    bin_dir.mkdir(parents=True)
    suricata_bin = bin_dir / "suricata"
    suricata_bin.write_text("binary content")

    with patch("builders.common.python.wazuh_build.platform.os_id", return_value="linux"):
        packaging.wrap_linux_binaries(comp_root)
        assert (bin_dir / "suricata.real").exists()
        wrapper_content = suricata_bin.read_text()
        assert "LD_LIBRARY_PATH" in wrapper_content


def test_suricata_install_rules_and_scripts(tmp_path: Path):
    component_root = tmp_path / "component"
    component_root.mkdir()
    script_dir = tmp_path / "scripts"
    script_dir.mkdir()
    (script_dir / "postinstall.sh").write_text("#!/bin/sh")
    (script_dir / "services").mkdir()
    (script_dir / "services" / "linux.sh").write_text("#!/bin/sh")
    (script_dir / "services" / "macos.sh").write_text("#!/bin/sh")

    rule_dir = tmp_path / "rules"
    rule_dir.mkdir()
    (rule_dir / "sample.rules").write_text("alert tcp any any -> any any (msg:\"test\";)")
    packaging.install_rules_and_scripts(rule_dir, component_root, script_dir)
    assert (component_root / "var" / "lib" / "suricata" / "rules" / "sample.rules").exists()


def test_suricata_write_systemd_unit(tmp_path: Path):
    rel_root = tmp_path / "rel"
    with patch("builders.common.python.wazuh_build.platform.os_id", return_value="linux"):
        packaging.write_systemd_unit(rel_root, "/opt/wazuh/suricata")
        unit = rel_root / "lib" / "systemd" / "system" / "suricata-wazuh.service"
        assert unit.exists()
        assert "/opt/wazuh/suricata/scripts/start-on-service.sh" in unit.read_text()


def test_suricata_write_metadata(tmp_path: Path):
    comp_root = tmp_path / "comp"
    comp_root.mkdir()
    packaging.write_metadata(
        comp_root, "x86_64-linux", "suricata-1.0", "1.0", "suricata-7.0.2", "7.0.2", {"source": "et-open", "tag": "v1", "flavor": "open"}
    )
    assert (comp_root / "BUILDINFO.txt").exists()
    assert (comp_root / "README.txt").exists()


def test_suricata_package_release(tmp_path: Path):
    cfg = MagicMock()
    cfg.build_setting.return_value = "v1.5.0"
    dest = tmp_path / "dest"
    dest.mkdir()
    component_root = tmp_path / "release" / "opt" / "wazuh" / "suricata"
    component_root.mkdir(parents=True)
    release_root = tmp_path / "release"

    with patch("builders.common.python.wazuh_build.sbom.generate_sboms"), \
         patch("builders.common.python.wazuh_build.packaging.write_pom"), \
         patch("builders.common.python.wazuh_build.packaging.make_tarball"), \
         patch("builders.common.python.wazuh_build.packaging.package_deb", return_value=tmp_path / "pkg.deb"), \
         patch("builders.common.python.wazuh_build.packaging.package_rpm", return_value=tmp_path / "pkg.rpm"), \
         patch("builders.common.python.wazuh_build.packaging.package_dmg", return_value=None), \
         patch("builders.common.python.wazuh_build.packaging.checksum_file", return_value="abcdef1234567890"):
        (tmp_path / "pkg.deb").write_text("deb")
        (tmp_path / "pkg.rpm").write_text("rpm")
        packaging.package_release(
            cfg, dest, component_root, release_root, "suricata-test", "native", "1.0.0", "suricata-7.0.2", "7.0.2"
        )
        assert (dest / "artifacts" / "suricata-test.sha256.txt").exists()


# ---- build.py & main.py tests ----

def test_suricata_prepare_dest(tmp_path: Path):
    rel = tmp_path / "rel"
    rel.mkdir()
    comp = rel / "comp"
    dest = tmp_path / "dest"
    build.prepare_dest(rel, comp, dest)
    assert comp.exists()
    assert (dest / "artifacts").exists()
    assert (comp / "var" / "log" / "suricata").exists()


def test_suricata_build_missing_version(tmp_path: Path):
    cfg = MagicMock()
    with patch.dict(os.environ, {}, clear=True):
        with pytest.raises(SystemExit, match="PIPELINE_VERSION not provided"):
            build.build_suricata(cfg, tmp_path, "native", "1.0", tmp_path, {})


def test_suricata_build_success(tmp_path: Path):
    cfg = MagicMock()
    rule_bundle = tmp_path / "rules"
    rule_bundle.mkdir()

    with patch.dict(os.environ, {"PIPELINE_VERSION": "7.0.2"}), \
         patch("builders.suricata.build.modules.build.download_and_unpack", return_value=tmp_path / "src"), \
         patch("builders.suricata.build.modules.build.write_revision_header", return_value=tmp_path / "rev.h"), \
         patch("builders.common.python.wazuh_build.shell.run"), \
         patch("builders.common.python.wazuh_build.packaging.prune_payload_directory"), \
         patch("builders.suricata.build.modules.build.bundle_runtime_libs"), \
         patch("builders.suricata.build.modules.build.wrap_linux_binaries"), \
         patch("builders.suricata.build.modules.build.install_rules_and_scripts"), \
         patch("builders.suricata.build.modules.build.write_metadata"), \
         patch("builders.common.python.wazuh_build.utils.fix_permissions"):
        (tmp_path / "src").mkdir()
        (tmp_path / "rev.h").write_text("#define REV 1")
        build.build_suricata(cfg, tmp_path, "native", "1.0", rule_bundle, {"tag": "v1"})


def test_suricata_main_execution(tmp_path: Path):
    with patch("builders.suricata.build.main.wb_config.BuilderConfig"), \
         patch("builders.suricata.build.main.resolve_rule_bundle", return_value=(tmp_path, {})), \
         patch("builders.suricata.build.main.setup_environment"), \
         patch("builders.suricata.build.main.ensure_dependencies"), \
         patch("builders.suricata.build.main.deps.require_tools"), \
         patch("builders.suricata.build.main.deps.require_libraries"), \
         patch("builders.suricata.build.main.build_suricata"), \
         patch("builders.suricata.build.main.package_release"):
        suricata_main.main()
