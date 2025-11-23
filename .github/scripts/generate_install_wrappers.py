#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
from pathlib import Path


def update_pinned(text: str, version: str) -> str:
    pattern = re.compile(r'PINNED_VERSION="\${PINNED_VERSION:-[^"}]*}"')
    if pattern.search(text):
        return pattern.sub(f'PINNED_VERSION="${{PINNED_VERSION:-{version}}}"', text)
    pattern = re.compile(r'PINNED_VERSION="[^"]*"')
    if pattern.search(text):
        return pattern.sub(f'PINNED_VERSION="{version}"', text)
    raise SystemExit("Unable to locate PINNED_VERSION placeholder")


def render(repo_root: Path, output_dir: Path, version: str) -> None:
    templates = ["install.sh", "uninstall.sh"]
    scripts_dir = repo_root / "scripts"
    output_dir.mkdir(parents=True, exist_ok=True)

    for name in templates:
        src = scripts_dir / name
        if not src.exists():
            raise SystemExit(f"Template not found: {src}")
        text = src.read_text()
        rendered = update_pinned(text, version)
        dest = output_dir / name
        dest.write_text(rendered)
        dest.chmod(0o755)
        print(f"Wrote {dest} with PINNED_VERSION={version}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate pinned top-level install/uninstall scripts.")
    parser.add_argument("--version", required=True, help="Release version to hardcode")
    parser.add_argument(
        "--output-dir",
        default="scripts",
        help="Destination directory for rendered scripts (default: scripts)",
    )
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parents[2]
    render(repo_root, Path(args.output_dir), args.version)


if __name__ == "__main__":
    main()
