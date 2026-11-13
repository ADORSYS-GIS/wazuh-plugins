#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import shutil
import sys
import tarfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from builders.common.python.wazuh_build import rules


def extract_bundle(archive: Path, bundle_path: str, output_dir: Path) -> Path:
    if output_dir.exists():
        shutil.rmtree(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    suffix = archive.name.lower()
    if suffix.endswith((".tar.gz", ".tgz")):
        _extract_tar_bundle(archive, bundle_path, output_dir)
    else:
        _copy_bundle(archive, bundle_path, output_dir)
    
    return output_dir



def _extract_tar_bundle(archive: Path, bundle_path: str, output_dir: Path) -> None:
    """Extract tar.gz archive with optional bundle path filtering."""
    with tarfile.open(archive, "r:gz") as tf:
        members = _filter_tar_members(tf.getmembers(), bundle_path)
        tf.extractall(output_dir, members=members)



def _filter_tar_members(members: list, bundle_path: str) -> list:
    """Filter tar members to extract only those under bundle_path."""
    prefix = bundle_path.rstrip("/") + "/" if bundle_path else ""
    filtered = []
    for member in members:
        if not prefix or member.name.startswith(prefix):
            if prefix:
                member.name = member.name[len(prefix) :]  # strip leading path
            filtered.append(member)
    return filtered



def _copy_bundle(archive: Path, bundle_path: str, output_dir: Path) -> None:
    """Copy archive file to output directory."""
    dest = output_dir / (bundle_path or archive.name)
    shutil.copy2(archive, dest)



def parse_args(meta: dict) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Fetch and verify Suricata rule bundles."
    )
    parser.add_argument(
        "--metadata", type=Path, default=None, help="Path to source.json metadata."
    )
    parser.add_argument(
        "--dest", type=Path, default=None, help="Rules cache directory."
    )
    parser.add_argument(
        "--flavor",
        choices=sorted(meta.get("assets", {}).keys()),
        default="open",
        help="Rule flavor to fetch.",
    )
    parser.add_argument(
        "--force", action="store_true", help="Redownload even if cached."
    )
    return parser.parse_args()



def main() -> None:
    script_dir = Path(__file__).resolve().parent
    builder_root = script_dir.parent
    default_dest = builder_root / "rules-cache"

    prelim_meta = rules.load_rules_metadata(builder_root)
    args = parse_args(prelim_meta)

    meta = _load_metadata(args, builder_root)
    dest = (args.dest or default_dest).resolve()
    rules.fetch_rules(meta, args.flavor, dest, extract_bundle, args.force)



def _load_metadata(args, builder_root: Path) -> dict:
    """Load rules metadata from args or default location."""
    if args.metadata:
        try:
            return json.loads(args.metadata.read_text(encoding="utf-8"))
        except Exception as exc:
            raise SystemExit(f"Unable to parse metadata {args.metadata}: {exc}") from exc
    return rules.load_rules_metadata(builder_root)


if __name__ == "__main__":
    main()
