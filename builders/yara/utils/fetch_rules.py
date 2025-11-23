#!/usr/bin/env python3
from __future__ import annotations

import argparse
import shutil
import sys
import tempfile
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from builders.common.python.wazuh_build import rules


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
            raise SystemExit(
                f"Bundle path {bundle_path} not found inside archive {archive.name}"
            )

        if bundle_root.is_file():
            shutil.copy2(bundle_root, target / bundle_root.name)
        else:
            shutil.copytree(bundle_root, target, dirs_exist_ok=True)

    return target


def parse_args(meta: dict) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Fetch and verify YARA Forge rule bundles."
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
        default="full",
        help="Rule flavor to fetch.",
    )
    parser.add_argument(
        "--force", action="store_true", help="Redownload even if cached."
    )
    return parser.parse_args()


def main() -> None:
    script_dir = Path(__file__).resolve().parent
    builder_root = script_dir.parent
    default_metadata = builder_root / "rules" / "source.json"
    default_dest = builder_root / "rules-cache"

    prelim_meta = rules.load_rules_metadata(builder_root)
    args = parse_args(prelim_meta)

    meta = rules.load_rules_metadata(builder_root)
    if args.metadata:
        import json
        try:
            meta = json.loads(args.metadata.read_text(encoding="utf-8"))
        except Exception as exc:
             raise SystemExit(f"Unable to parse metadata {args.metadata}: {exc}") from exc

    dest = (args.dest or default_dest).resolve()
    
    # YARA uses a specific URL template if not provided in metadata
    url_template = "https://github.com/YARAHQ/yara-forge/releases/download/{tag}/{asset_name}"
    
    rules.fetch_rules(
        meta, 
        args.flavor, 
        dest, 
        extract_bundle, 
        args.force,
        url_template=url_template
    )


if __name__ == "__main__":
    main()
