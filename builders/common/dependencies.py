#!/usr/bin/env python3
import argparse
import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Set


def _fallback_dependencies(text: str) -> Dict[str, List[str]]:
    """Minimal parser for the dependencies block without requiring PyYAML."""
    deps: Dict[str, List[str]] = {}
    current = None
    in_deps = False

    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        if not in_deps:
            if stripped == "dependencies:":
                in_deps = True
            continue

        indent = len(line) - len(line.lstrip(" "))
        if indent < 2:
            break

        if indent == 2 and stripped.endswith(":"):
            current = stripped[:-1]
            deps.setdefault(current, [])
            continue

        if indent >= 4 and stripped.startswith("- "):
            if current:
                deps.setdefault(current, []).append(stripped[2:].strip())

    return {"dependencies": deps}


def _load_config(path: Path) -> Dict:
    text = path.read_text(encoding="utf-8")

    try:
        import yaml  # type: ignore
    except Exception:
        yaml = None

    if yaml:
        try:
            loaded = yaml.safe_load(text)
            if isinstance(loaded, dict):
                return loaded
        except Exception:
            pass

    return _fallback_dependencies(text)


def collect_dependencies(files: Iterable[Path], section: str) -> List[str]:
    seen: Set[str] = set()
    items: List[str] = []

    for path in files:
        config = _load_config(path)
        deps = config.get("dependencies", {}) or {}
        section_items = deps.get(section, [])
        if isinstance(section_items, dict):
            # Allow a nested mapping but keep only string values
            flattened: List[str] = []
            for value in section_items.values():
                if isinstance(value, str):
                    flattened.append(value)
                elif isinstance(value, (list, tuple, set)):
                    flattened.extend(str(v) for v in value if isinstance(v, str))
            section_items = flattened

        for entry in section_items:
            if not isinstance(entry, str):
                continue
            name = entry.strip()
            if not name or name in seen:
                continue
            seen.add(name)
            items.append(name)

    return items


def read_value(path: Path, dotted: str) -> Any:
    config = _load_config(path)
    node: Any = config
    for part in dotted.split("."):
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Extract dependency lists or config values from builder config files."
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--section",
        choices=["apt", "bash", "brew"],
        help="Dependency section to extract.",
    )
    group.add_argument(
        "--value", help="Dotted config key to read (uses the first config only)."
    )
    parser.add_argument(
        "--format",
        choices=["lines", "json"],
        default="lines",
        help="Output format (for dependencies).",
    )
    parser.add_argument("configs", nargs="+", type=Path, help="Config files to read.")
    args = parser.parse_args()

    if args.value:
        target = read_value(args.configs[0], args.value)
        if target is None:
            return
        if isinstance(target, (dict, list)):
            print(json.dumps(target))
        else:
            print(target)
        return

    deps = collect_dependencies(args.configs, args.section or "")

    if args.format == "json":
        print(json.dumps(deps))
    else:
        for item in deps:
            print(item)


if __name__ == "__main__":
    main()
