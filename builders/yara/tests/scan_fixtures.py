#!/usr/bin/env python3
from pathlib import Path


def main() -> None:
    print("[yara] Running sample scan")
    rules_dir = Path(__file__).resolve().parent.parent / "rules"
    if not rules_dir.exists():
        print("No rules directory found.")
        return
    for rule in sorted(rules_dir.iterdir()):
        print(rule.name)


if __name__ == "__main__":
    main()
