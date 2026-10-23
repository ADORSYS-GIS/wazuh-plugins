from pathlib import Path
from unittest.mock import MagicMock, patch

from wazuh_build import sbom


def test_generate_sboms(tmp_path: Path):
    dest_root = tmp_path / "dest"
    dest_root.mkdir()
    scan_dir = tmp_path / "scan"
    scan_dir.mkdir()
    spdx_out = dest_root / "sbom.spdx.json"
    cdx_out = dest_root / "sbom.cdx.json"

    def fake_run(cmd, capture=False):
        if "spdx-json" in cmd:
            return MagicMock(stdout='{"spdx": "data"}')
        if "cyclonedx-json" in cmd:
            return MagicMock(stdout='{"cdx": "data"}')
        return MagicMock(stdout="")

    with patch("wazuh_build.deps.ensure_syft", return_value=tmp_path / "syft"), patch(
        "wazuh_build.shell.run", side_effect=fake_run
    ):
        sbom.generate_sboms(dest_root, scan_dir, spdx_out, cdx_out)

    assert spdx_out.exists()
    assert '{"spdx": "data"}' in spdx_out.read_text()
    assert cdx_out.exists()
    assert '{"cdx": "data"}' in cdx_out.read_text()
