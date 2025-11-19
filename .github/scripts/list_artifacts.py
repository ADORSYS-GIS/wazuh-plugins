#!/usr/bin/env python3
"""List staged artifact files and derive release-friendly asset names."""
from __future__ import annotations

import argparse
import os
import shutil
from pathlib import Path


def build_manifest(
    stage_dir: Path,
    builder: str,
    version: str,
    triplet: str,
    workspace: Path | None = None,
    flatten_dir: Path | None = None,
) -> list[str]:
    stage_dir = stage_dir.resolve()
    workspace = workspace.resolve() if workspace else None
    flatten_dir = flatten_dir.resolve() if flatten_dir else None

    if flatten_dir:
        if flatten_dir.exists():
            shutil.rmtree(flatten_dir)
        flatten_dir.mkdir(parents=True, exist_ok=True)

    entries: list[str] = []
    seen_names: set[str] = set()
    for path in sorted(stage_dir.rglob("*")):
        path = path.resolve()
        if flatten_dir and flatten_dir in path.parents:
            continue
        if not path.is_file():
            continue
        if path.name.endswith(".tar.gz"):
            continue
        rel = path.relative_to(stage_dir).as_posix()
        asset_name = f"{builder}-{version}-{triplet}-{rel.replace('/', '-')}"
        if asset_name in seen_names:
            continue
        seen_names.add(asset_name)
        output_path: Path
        if flatten_dir:
            dest = flatten_dir / asset_name
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, dest)
            output_path = dest
        else:
            output_path = path
        if workspace:
            rel_path = os.path.relpath(output_path, workspace)
            output_path = Path(rel_path)
        entries.append(output_path.as_posix())
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
    parser.add_argument(
        "--flatten-dir",
        type=Path,
        help="Optional directory to copy files into with flattened names.",
    )
    args = parser.parse_args()

    manifest = build_manifest(
        args.stage_dir,
        args.builder,
        args.version,
        args.triplet,
        args.workspace,
        args.flatten_dir,
    )
    print("\n".join(manifest))


if __name__ == "__main__":
    main()
