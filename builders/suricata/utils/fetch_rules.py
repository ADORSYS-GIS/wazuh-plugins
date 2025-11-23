#!/usr/bin/env python3
from __future__ import annotations

import argparse
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
        with tarfile.open(archive, "r:gz") as tf:
            members = []
            prefix = bundle_path.rstrip("/") + "/" if bundle_path else ""
            for member in tf.getmembers():
                if not prefix or member.name.startswith(prefix):
                    if prefix:
                        member.name = member.name[len(prefix) :]  # strip leading path
                    members.append(member)
            tf.extractall(output_dir, members=members)
    else:
        dest = output_dir / (bundle_path or archive.name)
        shutil.copy2(archive, dest)
    return output_dir


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
    default_metadata = builder_root / "rules" / "source.json"
    default_dest = builder_root / "rules-cache"

    prelim_meta = rules.load_rules_metadata(builder_root)
    args = parse_args(prelim_meta)

    meta = rules.load_rules_metadata(builder_root)
    if args.metadata:
        # If metadata path is explicitly provided, load it (though we prefer builder_root based)
        # But since load_rules_metadata takes builder_root, we might need to adjust if we want to support arbitrary metadata paths
        # For now, let's stick to the pattern. If args.metadata is different, we might need to handle it.
        # However, the original script allowed --metadata.
        # Let's just use the one from args if provided, otherwise default.
        import json
        try:
            meta = json.loads(args.metadata.read_text(encoding="utf-8"))
        except Exception as exc:
             raise SystemExit(f"Unable to parse metadata {args.metadata}: {exc}") from exc

    dest = (args.dest or default_dest).resolve()
    rules.fetch_rules(meta, args.flavor, dest, extract_bundle, args.force)


if __name__ == "__main__":
    main()
