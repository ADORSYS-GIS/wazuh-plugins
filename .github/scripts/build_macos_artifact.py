#!/usr/bin/env python3
"""Generate placeholder macOS artifacts for builder releases."""
from __future__ import annotations

import argparse
import shutil
from pathlib import Path

import yaml


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--triplet", required=True)
    parser.add_argument("--arch", required=True)
    args = parser.parse_args()

    config_path = args.config.resolve()
    config_dir = config_path.parent

    data = yaml.safe_load(config_path.read_text())
    pipeline = data.get("pipeline", {})

    builder_name = pipeline.get("name") or config_dir.name
    release_file = pipeline.get("release_file", "release.txt")
    release_path = (config_dir / release_file).resolve()
    release_version = release_path.read_text().strip()

    artifact_root = config_dir / "dist" / args.triplet
    if artifact_root.exists():
        shutil.rmtree(artifact_root)
    artifact_root.mkdir(parents=True, exist_ok=True)

    binary_path = artifact_root / f"{builder_name}-{args.triplet}"
    binary_path.write_text(
        (
            "This is a placeholder artifact for the {builder} macOS build.\n"
            "Triplet: {triplet}\n"
            "Architecture: {arch}\n"
            "Version: {version}\n"
        ).format(
            builder=builder_name,
            triplet=args.triplet,
            arch=args.arch,
            version=release_version,
        )
    )

    metadata_path = artifact_root / "BUILD_INFO.txt"
    metadata_path.write_text(
        (
            "builder={builder}\n"
            "triplet={triplet}\n"
            "architecture={arch}\n"
            "version={version}\n"
        ).format(
            builder=builder_name,
            triplet=args.triplet,
            arch=args.arch,
            version=release_version,
        )
    )

    print(
        f"Generated macOS placeholder artifacts for {builder_name} "
        f"({args.triplet}, {args.arch}) at {artifact_root}"
    )


if __name__ == "__main__":
    main()
