import os
import shutil
import tarfile
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest

from builders.yara.build.modules import download, dependencies, build, packaging
import builders.yara.build.main as yara_main


# ---- download.py tests ----

def test_yara_download_bool_env():
    with patch.dict(os.environ, {"TEST_BOOL": "true"}):
        assert download._bool_env("TEST_BOOL") is True
    with patch.dict(os.environ, {"TEST_BOOL": "0"}):
        assert download._bool_env("TEST_BOOL") is False
    with patch.dict(os.environ, {"TEST_BOOL": ""}):
        assert download._bool_env("TEST_BOOL") is False


def test_yara_download_feature_enabled():
    with patch.dict(os.environ, {"FEATURE_X": "1"}):
        assert download._feature_enabled("FEATURE_X", False) is True
    with patch.dict(os.environ, {}, clear=True):
        assert download._feature_enabled("FEATURE_X", True) is True


def test_yara_resolve_rule_bundle(tmp_path: Path):
    with patch("builders.common.python.wazuh_build.rules.resolve_rule_bundle", return_value=(tmp_path, {"tag": "v1"})):
        bundle_path, info = download.resolve_rule_bundle(tmp_path)
        assert bundle_path == tmp_path
        assert info["tag"] == "v1"


def test_yara_write_revision_header(tmp_path: Path):
    with patch.dict(os.environ, {"PIPELINE_COMMIT": "abc1234"}):
        header = download.write_revision_header(tmp_path)
        assert header.exists()
        content = header.read_text()
        assert "Wazuh Plugin Build abc1234" in content


def test_yara_download_and_unpack(tmp_path: Path):
    archive_path = tmp_path / "yara.tar.gz"
    # Create valid tar.gz archive with a sample file
    sample_file = tmp_path / "sample.txt"
    sample_file.write_text("yara source")
    with tarfile.open(archive_path, "w:gz") as tf:
        tf.add(sample_file, arcname="yara-v4.3.2/sample.txt")

    def fake_run(cmd):
        # Do not run curl; archive is already created
        pass

    with patch("builders.common.python.wazuh_build.shell.run", side_effect=fake_run):
        src_dir = download.download_and_unpack("4.3.2", tmp_path)
        assert src_dir.is_dir()
        assert (src_dir / "sample.txt").exists()


# ---- dependencies.py tests ----

def test_yara_dependencies_ensure(tmp_path: Path):
    cfg = MagicMock()
    cfg.dependency_section.return_value = ["libfoo-dev"]

    with patch("builders.common.python.wazuh_build.platform.os_id", return_value="linux"), \
         patch("builders.common.python.wazuh_build.shell.command_exists", return_value=True), \
         patch("builders.common.python.wazuh_build.deps.install_apt") as mock_apt, \
         patch("builders.common.python.wazuh_build.deps.run_bash_commands") as mock_bash, \
         patch("builders.common.python.wazuh_build.deps.ensure_pkg_config_path") as mock_pkg:
        dependencies.ensure_dependencies(cfg)
        mock_apt.assert_called_once_with(["libfoo-dev"])
        mock_bash.assert_called_once()
        mock_pkg.assert_called_once()

    with patch("builders.common.python.wazuh_build.platform.os_id", return_value="macos"), \
         patch("builders.common.python.wazuh_build.shell.command_exists", return_value=True), \
         patch("builders.common.python.wazuh_build.deps.install_brew") as mock_brew, \
         patch("builders.yara.build.modules.dependencies.configure_macos_env") as mock_mac_env, \
         patch("builders.common.python.wazuh_build.deps.ensure_pkg_config_path"):
        dependencies.ensure_dependencies(cfg)
        mock_brew.assert_called_once_with(["libfoo-dev"])
        mock_mac_env.assert_called_once()


def test_yara_configure_macos_env(tmp_path: Path):
    with patch("builders.common.python.wazuh_build.platform.os_id", return_value="macos"), \
         patch("builders.common.python.wazuh_build.shell.command_exists", return_value=True), \
         patch("builders.yara.build.modules.dependencies._brew_prefix", side_effect=lambda p: str(tmp_path / p)), \
         patch.dict(os.environ, {"PKG_CONFIG_PATH": "", "CPPFLAGS": "", "LDFLAGS": ""}):
        for p in ["openssl@3", "libmagic", "pcre2"]:
            (tmp_path / p / "lib" / "pkgconfig").mkdir(parents=True, exist_ok=True)
            (tmp_path / p / "include").mkdir(parents=True, exist_ok=True)

        dependencies.configure_macos_env()
        assert "pkgconfig" in os.environ["PKG_CONFIG_PATH"]
        assert "-I" in os.environ["CPPFLAGS"]
        assert "-L" in os.environ["LDFLAGS"]


def test_yara_setup_environment(tmp_path: Path):
    with patch("builders.common.python.wazuh_build.platform.os_id", return_value="macos"), \
         patch.object(Path, "exists", return_value=True), \
         patch("builders.common.python.wazuh_build.utils.prepend_path_if_missing") as mock_prepend:
        dependencies.setup_environment()
        assert mock_prepend.call_count >= 1


# ---- packaging.py tests ----

def test_yara_bundle_runtime_libs(tmp_path: Path):
    comp_root = tmp_path / "opt" / "wazuh" / "yara"
    comp_root.mkdir(parents=True)

    # Non-linux returns immediately
    with patch("builders.common.python.wazuh_build.platform.os_id", return_value="darwin"):
        packaging.bundle_runtime_libs(comp_root)
        assert not (comp_root / "lib").exists()

    # Linux copies candidate libraries if found
    fake_lib = tmp_path / "usr" / "lib"
    fake_lib.mkdir(parents=True)
    (fake_lib / "libcrypto.so.1.1").write_text("mock")

    with patch("builders.common.python.wazuh_build.platform.os_id", return_value="linux"), \
         patch("builders.common.python.wazuh_build.shell.run", side_effect=Exception("no dpkg")), \
         patch.object(packaging, "Path", side_effect=lambda *a: tmp_path / a[0].lstrip("/") if a and str(a[0]).startswith("/usr") else Path(*a)):
        packaging.bundle_runtime_libs(comp_root)


def test_yara_wrap_linux_binaries(tmp_path: Path):
    comp_root = tmp_path / "yara_comp"
    bin_dir = comp_root / "bin"
    bin_dir.mkdir(parents=True)
    yara_bin = bin_dir / "yara"
    yara_bin.write_text("binary content")

    with patch("builders.common.python.wazuh_build.platform.os_id", return_value="linux"):
        packaging.wrap_linux_binaries(comp_root)
        assert (bin_dir / "yara.real").exists()
        wrapper_content = yara_bin.read_text()
        assert "LD_LIBRARY_PATH" in wrapper_content


def test_yara_install_rules_and_scripts(tmp_path: Path):
    release_root = tmp_path / "release"
    release_root.mkdir()
    component_root = tmp_path / "component"
    component_root.mkdir()
    script_dir = tmp_path / "scripts"
    script_dir.mkdir()
    (script_dir / "postinstall.sh").write_text("#!/bin/sh")

    # File rule bundle
    rule_file = tmp_path / "sample.yar"
    rule_file.write_text("rule test { condition: true }")
    packaging.install_rules_and_scripts(release_root, rule_file, component_root, script_dir)
    assert (component_root / "rules" / "sample.yar").exists()

    # Dir rule bundle
    rule_dir = tmp_path / "rule_dir"
    rule_dir.mkdir()
    (rule_dir / "rule2.yar").write_text("rule test2 { condition: true }")
    packaging.install_rules_and_scripts(release_root, rule_dir, component_root, script_dir)
    assert (component_root / "rules" / "rule2.yar").exists()


def test_yara_write_metadata(tmp_path: Path):
    comp_root = tmp_path / "comp"
    comp_root.mkdir()
    packaging.write_metadata(
        comp_root, "x86_64-linux", "yara-1.0", "1.0", "4.5.0", {"source": "github", "tag": "v1", "flavor": "full"}
    )
    assert (comp_root / "BUILDINFO.txt").exists()
    assert (comp_root / "README.txt").exists()
    info = (comp_root / "BUILDINFO.txt").read_text()
    assert "YARA_VERSION=4.5.0" in info


def test_yara_package_release(tmp_path: Path):
    cfg = MagicMock()
    cfg.build_setting.return_value = "v1.5.0"
    dest = tmp_path / "dest"
    dest.mkdir()
    component_root = tmp_path / "release" / "opt" / "wazuh" / "yara"
    component_root.mkdir(parents=True)
    release_root = tmp_path / "release"

    with patch("builders.common.python.wazuh_build.sbom.generate_sboms"), \
         patch("builders.common.python.wazuh_build.packaging.write_pom"), \
         patch("builders.common.python.wazuh_build.packaging.make_tarball"), \
         patch("builders.common.python.wazuh_build.packaging.package_deb", return_value=tmp_path / "pkg.deb"), \
         patch("builders.common.python.wazuh_build.packaging.package_rpm", return_value=tmp_path / "pkg.rpm"), \
         patch("builders.common.python.wazuh_build.packaging.package_dmg", return_value=None), \
         patch("builders.common.python.wazuh_build.packaging.checksum_file", return_value="1234567890abcdef"):
        (tmp_path / "pkg.deb").write_text("deb")
        (tmp_path / "pkg.rpm").write_text("rpm")
        packaging.package_release(
            cfg, dest, component_root, release_root, "yara-test", "native", "1.0.0", "4.3.2"
        )
        assert (dest / "artifacts" / "yara-test.sha256.txt").exists()


# ---- build.py & main.py tests ----

def test_yara_prepare_dest(tmp_path: Path):
    rel = tmp_path / "rel"
    rel.mkdir()
    comp = rel / "comp"
    dest = tmp_path / "dest"
    build.prepare_dest(rel, comp, dest)
    assert comp.exists()
    assert (dest / "artifacts").exists()


def test_yara_build_missing_version(tmp_path: Path):
    cfg = MagicMock()
    with patch.dict(os.environ, {}, clear=True):
        with pytest.raises(SystemExit, match="PIPELINE_VERSION not provided"):
            build.build_yara(cfg, tmp_path, "native", "1.0", tmp_path, {})


def test_yara_build_success(tmp_path: Path):
    cfg = MagicMock()
    rule_bundle = tmp_path / "rules"
    rule_bundle.mkdir()

    with patch.dict(os.environ, {"PIPELINE_VERSION": "4.3.2"}), \
         patch("builders.yara.build.modules.build.download_and_unpack", return_value=tmp_path / "src"), \
         patch("builders.yara.build.modules.build.write_revision_header", return_value=tmp_path / "rev.h"), \
         patch("builders.common.python.wazuh_build.shell.run"), \
         patch("builders.common.python.wazuh_build.packaging.prune_payload_directory"), \
         patch("builders.yara.build.modules.build.bundle_runtime_libs"), \
         patch("builders.yara.build.modules.build.wrap_linux_binaries"), \
         patch("builders.yara.build.modules.build.install_rules_and_scripts"), \
         patch("builders.yara.build.modules.build.write_metadata"), \
         patch("builders.common.python.wazuh_build.utils.fix_permissions"):
        (tmp_path / "src").mkdir()
        (tmp_path / "rev.h").write_text("#define REV 1")
        build.build_yara(cfg, tmp_path, "native", "1.0", rule_bundle, {"tag": "v1"})


def test_yara_main_execution(tmp_path: Path):
    with patch("builders.yara.build.main.wb_config.BuilderConfig"), \
         patch("builders.yara.build.main.resolve_rule_bundle", return_value=(tmp_path, {})), \
         patch("builders.yara.build.main.setup_environment"), \
         patch("builders.yara.build.main.ensure_dependencies"), \
         patch("builders.yara.build.main.deps.require_tools"), \
         patch("builders.yara.build.main.deps.require_libraries"), \
         patch("builders.yara.build.main.build_yara"), \
         patch("builders.yara.build.main.package_release"):
        yara_main.main()
