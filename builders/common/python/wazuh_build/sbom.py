from pathlib import Path

from . import deps, shell, utils


def generate_sboms(
    dest_root: Path,
    scan_dir: Path,
    spdx_out: Path,
    cdx_out: Path,
    syft_version: str = "v1.5.0",
) -> None:
    tools_dir = dest_root / ".tools"
    syft_bin = deps.ensure_syft(syft_version, tools_dir)
    utils.ensure_dir(spdx_out.parent)
    utils.ensure_dir(cdx_out.parent)
    spdx_content = shell.run(
        [str(syft_bin), f"dir:{scan_dir}", "-o", "spdx-json"], capture=True
    ).stdout
    cdx_content = shell.run(
        [str(syft_bin), f"dir:{scan_dir}", "-o", "cyclonedx-json"], capture=True
    ).stdout
    spdx_out.write_text(spdx_content or "")
    cdx_out.write_text(cdx_content or "")
