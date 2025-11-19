#!/usr/bin/env python3
"""List staged artifact files and derive release-friendly asset names."""
from __future__ import annotations

import argparse
from pathlib import Path


def build_manifest(stage_dir: Path, builder: str, version: str, triplet: str) -> list[str]:
    entries: list[str] = []
    for path in sorted(stage_dir.rglob("*")):
        if not path.is_file():
            continue
        if path.name.endswith(".tar.gz"):
            continue
        rel = path.relative_to(stage_dir).as_posix()
        asset_name = f"{builder}-{version}-{triplet}-{rel.replace('/', '-')}"
        entries.append(f"{path}#{asset_name}")
    return entries


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("stage_dir", type=Path)
    parser.add_argument("builder")
    parser.add_argument("version")
    parser.add_argument("triplet")
    args = parser.parse_args()

    manifest = build_manifest(args.stage_dir, args.builder, args.version, args.triplet)
    print("\n".join(manifest))


if __name__ == "__main__":
    main()
