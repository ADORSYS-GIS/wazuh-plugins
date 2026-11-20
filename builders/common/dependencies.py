#!/usr/bin/env python3
import argparse
import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Set


def _dependencies_block(text: str) -> List[str]:
    """Return the raw lines belonging to the top-level ``dependencies:`` block."""
    lines = text.splitlines()
    start = next(
        (index for index, line in enumerate(lines) if line.strip() == "dependencies:"),
        None,
    )
    if start is None:
        return []

    block: List[str] = []
    for line in lines[start + 1 :]:
        indent = len(line) - len(line.lstrip(" "))
        if line.strip() and indent < 2:
            break
        block.append(line)
    return block


def _fallback_dependencies(text: str) -> Dict[str, List[str]]:
    """Minimal parser for the dependencies block without requiring PyYAML."""
    deps: Dict[str, List[str]] = {}
    current = None

    for line in _dependencies_block(text):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        indent = len(line) - len(line.lstrip(" "))
        if indent == 2 and stripped.endswith(":"):
            current = stripped[:-1]
            deps.setdefault(current, [])
        elif indent >= 4 and stripped.startswith("- ") and current:
            deps[current].append(stripped[2:].strip())

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


def _flatten_section(section_items: Any) -> List[str]:
    """Normalise a dependency section to a flat list of strings."""
    if isinstance(section_items, dict):
        # Allow a nested mapping but keep only string values
        section_items = list(section_items.values())

    flattened: List[str] = []
    for item in section_items or []:
        if isinstance(item, str):
            flattened.append(item)
        elif isinstance(item, (list, tuple, set)):
            flattened.extend(value for value in item if isinstance(value, str))
    return flattened


def collect_dependencies(files: Iterable[Path], section: str) -> List[str]:
    seen: Set[str] = set()
    items: List[str] = []

    for path in files:
        config = _load_config(path)
        deps = config.get("dependencies", {}) or {}
        for entry in _flatten_section(deps.get(section, [])):
            name = entry.strip()
            if name and name not in seen:
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


def _resolve_config(config_path: Path, root: Path) -> Path:
    """Resolve a config path, rejecting anything outside ``root``.

    The paths come straight from the command line, so an arbitrary value could
    otherwise point at any file the process can read.
    """
    resolved = config_path.resolve()
    try:
        resolved.relative_to(root)
    except ValueError:
        raise ValueError(f"Config path escapes {root}: {config_path}") from None
    if not resolved.is_file():
        raise ValueError(f"Config file not found or is not a file: {config_path}")
    return resolved


def _parse_configs(parser: argparse.ArgumentParser, args: argparse.Namespace) -> List[Path]:
    root = args.root.resolve()
    resolved: List[Path] = []
    for config_path in args.configs:
        try:
            resolved.append(_resolve_config(config_path, root))
        except ValueError as exc:
            parser.error(str(exc))
    return resolved


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
    parser.add_argument(
        "--root",
        type=Path,
        default=Path.cwd(),
        help="Directory config files must live under (default: current directory).",
    )
    parser.add_argument("configs", nargs="+", type=Path, help="Config files to read.")
    args = parser.parse_args()

    configs = _parse_configs(parser, args)

    if args.value:
        target = read_value(configs[0], args.value)
        if target is None:
            return
        if isinstance(target, (dict, list)):
            print(json.dumps(target))
        else:
            print(target)
        return

    deps = collect_dependencies(configs, args.section or "")

    if args.format == "json":
        print(json.dumps(deps))
    else:
        for item in deps:
            print(item)


if __name__ == "__main__":
    main()
