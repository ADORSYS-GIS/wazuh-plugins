#!/usr/bin/env python3
from __future__ import annotations

import argparse
import shutil
from pathlib import Path


def package_artifacts(builder: str, triplet: str) -> None:
    repo_root = Path(__file__).resolve().parents[2]
    release_file = repo_root / "builders" / builder / "release.txt"
    version = release_file.read_text().strip()
    artifact_dir = repo_root / "builders" / builder / "dist" / triplet / "artifacts"
    artifacts_root = repo_root / "artifacts"
    stage_name = f"{builder}-{version}-{triplet}"
    stage_dir = artifacts_root / stage_name

    if stage_dir.exists():
        shutil.rmtree(stage_dir)
    stage_dir.mkdir(parents=True, exist_ok=True)

    for meta_name in ("version.txt", "release.txt", "package_revision.txt"):
        meta_path = repo_root / "builders" / builder / meta_name
        if meta_path.exists():
            dest_name = f"{builder}-{version}-{triplet}-{meta_name}"
            shutil.copy2(meta_path, stage_dir / dest_name)

    if not artifact_dir.exists():
        raise SystemExit(f"Package artifacts directory not found: {artifact_dir}")

    patterns = ["*.tar.gz", "*.sha256.txt", "*.deb", "*.dmg", "*.rpm"]
    copied = 0
    for pattern in patterns:
        for file in artifact_dir.glob(pattern):
            shutil.copy2(file, stage_dir / file.name)
            copied += 1
    if copied == 0:
        raise SystemExit(f"No packaged artifacts found in {artifact_dir}")

    manifest = sorted(p for p in stage_dir.glob("*") if p.is_file())
    output = [
        f"version={version}",
        f"artifact_name={stage_name}",
        f"artifact_path={stage_dir}",
        "files<<EOF",
        *[str(p.relative_to(repo_root)) for p in manifest],
        "EOF",
    ]
    import os

    github_output = os.environ.get("GITHUB_OUTPUT")
    dest = Path(github_output) if github_output else None
    if dest:
        with dest.open("a", encoding="utf-8") as fh:
            fh.write("\n".join(output) + "\n")
    else:
        print("\n".join(output))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("builder")
    parser.add_argument("triplet")
    args = parser.parse_args()
    package_artifacts(args.builder, args.triplet)


if __name__ == "__main__":
    main()
