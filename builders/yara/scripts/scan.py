#!/usr/bin/env python3
import argparse
import os
import shutil
import subprocess
from pathlib import Path


def resolve_rule(rules_root: Path, rule_input: str) -> Path:
    candidate = Path(rule_input)
    if candidate.is_file():
        return candidate
    bundled = rules_root / rule_input
    if bundled.is_file():
        return bundled
    raise SystemExit(f"Rule file '{rule_input}' was not found.")


def resolve_target(release_root: Path, target_input: str) -> Path:
    candidate = Path(target_input)
    if candidate.exists():
        return candidate
    relative = release_root / target_input
    if relative.exists():
        return relative
    raise SystemExit(f"Target '{target_input}' does not exist.")


def find_yara_binary(release_root: Path) -> Path:
    default = release_root / "bin" / "yara"
    if default.exists():
        return default
    yara_path = shutil.which("yara")
    if yara_path:
        return Path(yara_path)
    raise SystemExit("Unable to find a yara binary. Set YARA_BIN to override.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Run a YARA scan.")
    parser.add_argument("rule", help="Rule file path or rule name inside bundled rules.")
    parser.add_argument("target", help="File or directory to scan.")
    args = parser.parse_args()

    script_dir = Path(__file__).parent
    release_root = script_dir.parent
    rules_root = Path(os.environ.get("YARA_RULES_DIR", release_root / "rules"))
    yara_bin = Path(os.environ.get("YARA_BIN", release_root / "bin" / "yara"))
    if not yara_bin.exists():
        yara_bin = find_yara_binary(release_root)

    rule_path = resolve_rule(rules_root, args.rule)
    target_path = resolve_target(release_root, args.target)

    subprocess.run([str(yara_bin), str(rule_path), str(target_path)], check=True)


if __name__ == "__main__":
    main()
