#!/usr/bin/env python3
"""List staged artifact files and derive release-friendly asset names."""
from __future__ import annotations

import argparse
import os
from pathlib import Path


def build_manifest(
    stage_dir: Path,
    builder: str,
    version: str,
    triplet: str,
    workspace: Path | None = None,
) -> list[str]:
    stage_dir = stage_dir.resolve()
    workspace = workspace.resolve() if workspace else None
    entries: list[str] = []
    for path in sorted(stage_dir.rglob("*")):
        path = path.resolve()
        if not path.is_file():
            continue
        if path.name.endswith(".tar.gz"):
            continue
        rel = path.relative_to(stage_dir).as_posix()
        asset_name = f"{builder}-{version}-{triplet}-{rel.replace('/', '-')}"
        if workspace:
            rel_path = os.path.relpath(path, workspace)
            fs_path = Path(rel_path)
        else:
            fs_path = path
        entries.append(f"{fs_path.as_posix()}#{asset_name}")
    return entries


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("stage_dir", type=Path)
    parser.add_argument("builder")
    parser.add_argument("version")
    parser.add_argument("triplet")
    parser.add_argument(
        "--workspace",
        type=Path,
        default=Path.cwd(),
        help="Workspace root to which file paths should be relative.",
    )
    args = parser.parse_args()

    manifest = build_manifest(
        args.stage_dir,
        args.builder,
        args.version,
        args.triplet,
        args.workspace,
    )
    print("\n".join(manifest))


if __name__ == "__main__":
    main()
