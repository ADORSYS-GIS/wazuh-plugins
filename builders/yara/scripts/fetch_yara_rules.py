#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
import tempfile
import zipfile
from pathlib import Path
from typing import Dict, Tuple


def load_metadata(path: Path) -> Dict:
    if not path.exists():
        raise SystemExit(f"Rule metadata file not found: {path}")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise SystemExit(f"Unable to parse metadata {path}: {exc}") from exc


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(8192), b""):
            digest.update(chunk)
    return digest.hexdigest()


def download(url: str, dest: Path) -> None:
    import urllib.request

    dest.parent.mkdir(parents=True, exist_ok=True)
    with urllib.request.urlopen(url) as resp, dest.open("wb") as fh:
        shutil.copyfileobj(resp, fh)


def ensure_archive(asset_url: str, sha256: str, archive_path: Path, force: bool) -> Path:
    if archive_path.exists() and not force:
        if sha256_file(archive_path) != sha256:
            raise SystemExit(f"Cached archive checksum mismatch: {archive_path}")
        return archive_path
    download(asset_url, archive_path)
    actual = sha256_file(archive_path)
    if actual != sha256:
        archive_path.unlink(missing_ok=True)
        raise SystemExit(f"Downloaded archive checksum mismatch (expected {sha256}, got {actual})")
    return archive_path


def extract_bundle(archive: Path, bundle_path: str, output_dir: Path) -> Path:
    target = output_dir
    if target.exists():
        shutil.rmtree(target)
    target.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="yara-forge-") as tmpdir:
        tmp_root = Path(tmpdir)
        with zipfile.ZipFile(archive) as zf:
            zf.extractall(tmp_root)
        bundle_root = tmp_root / bundle_path
        if not bundle_root.exists():
            raise SystemExit(f"Bundle path {bundle_path} not found inside archive {archive.name}")

        if bundle_root.is_file():
            shutil.copy2(bundle_root, target / bundle_root.name)
        else:
            shutil.copytree(bundle_root, target, dirs_exist_ok=True)

    return target


def fetch_rules(meta: Dict, flavor: str, dest: Path, force: bool = False) -> Path:
    assets = meta.get("assets", {})
    if flavor not in assets:
        raise SystemExit(f"Flavor '{flavor}' not defined in metadata. Available: {', '.join(sorted(assets))}")
    asset = assets[flavor]
    tag = meta.get("tag", "unknown")
    asset_name = asset["name"]
    sha256 = asset["sha256"]
    bundle_path = asset.get("bundle_path", "")

    cache_root = dest.resolve()
    archive_path = cache_root / asset_name
    asset_url = asset.get("url") or f"https://github.com/YARAHQ/yara-forge/releases/download/{tag}/{asset_name}"

    archive = ensure_archive(asset_url, sha256, archive_path, force)
    output_dir = cache_root / tag / flavor
    extracted = extract_bundle(archive, bundle_path, output_dir)
    print(f"Fetched rules flavor '{flavor}' from tag {tag} into: {extracted}")
    return extracted


def parse_args(meta: Dict) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Fetch and verify YARA Forge rule bundles.")
    parser.add_argument("--metadata", type=Path, default=None, help="Path to source.json metadata.")
    parser.add_argument("--dest", type=Path, default=None, help="Rules cache directory.")
    parser.add_argument("--flavor", choices=sorted(meta.get("assets", {}).keys()), default="full", help="Rule flavor to fetch.")
    parser.add_argument("--force", action="store_true", help="Redownload even if cached.")
    return parser.parse_args()


def main() -> None:
    script_dir = Path(__file__).resolve().parent
    builder_root = script_dir.parent
    default_metadata = builder_root / "rules" / "source.json"
    default_dest = builder_root / "rules-cache"

    prelim_meta = load_metadata(default_metadata)
    args = parse_args(prelim_meta)

    meta = load_metadata(args.metadata or default_metadata)
    dest = (args.dest or default_dest).resolve()
    fetch_rules(meta, args.flavor, dest, args.force)


if __name__ == "__main__":
    main()
