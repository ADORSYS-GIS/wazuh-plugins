#!/usr/bin/env python3
from pathlib import Path


def main() -> None:
    print("[suricata] Running regression suite")
    rules_dir = Path(__file__).resolve().parent.parent / "rules"
    for rule in sorted(rules_dir.iterdir()) if rules_dir.exists() else []:
        print(rule.name)


if __name__ == "__main__":
    main()
