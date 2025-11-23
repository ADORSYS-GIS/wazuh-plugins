"""
Common rules operations for Wazuh builders.
"""
import json
import os
from pathlib import Path
from typing import Tuple, Dict, Optional, Callable

from . import shell, download


def load_rules_metadata(builder_root: Path) -> dict:
    """
    Load rule metadata from source.json in the rules directory.
    """
    metadata_path = builder_root / "rules" / "source.json"
    if not metadata_path.exists():
        raise SystemExit(f"Rule metadata not found: {metadata_path}")
    try:
        return json.loads(metadata_path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise SystemExit(
            f"Unable to parse rule metadata {metadata_path}: {exc}"
        ) from exc


def resolve_rule_bundle(
    builder_root: Path,
    default_flavor: str,
    fetcher_script_name: str,
    source_name: Optional[str] = None
) -> Tuple[Path, Dict[str, str]]:
    """
    Resolve the path to the rule bundle, fetching it if necessary.

    Args:
        builder_root: The root directory of the builder.
        default_flavor: The default flavor to use if RULES_FLAVOR is not set.
        fetcher_script_name: The name of the fetcher script (e.g., "fetch_suricata_rules.py").
        source_name: Optional source name override (e.g., "yara-forge"). If None, uses metadata source.

    Returns:
        A tuple containing the path to the rule bundle and a dictionary of rule information.
    """
    if os.environ.get("RULE_BUNDLE"):
        bundle = Path(os.environ["RULE_BUNDLE"]).expanduser().resolve()
        if not bundle.exists():
            raise SystemExit(f"RULE_BUNDLE path does not exist: {bundle}")
        return bundle, {"source": "custom", "tag": "manual", "flavor": "custom"}

    metadata = load_rules_metadata(builder_root)
    flavor = os.environ.get("RULES_FLAVOR", default_flavor)

    cache_root = Path(
        os.environ.get("RULES_CACHE", builder_root / "rules-cache")
    ).resolve()

    expected = cache_root / metadata.get("tag", "unknown") / flavor

    rule_source = source_name if source_name else metadata.get("source")

    if expected.exists():
        return expected, {
            "source": rule_source,
            "tag": metadata.get("tag"),
            "flavor": flavor,
        }

    # Check for local rules if applicable (Suricata pattern)
    local_rules = builder_root / "rules"
    if local_rules.exists() and list(local_rules.glob("*.rules")):
        return local_rules, {"source": "local", "tag": "local", "flavor": "local"}

    fetcher = (builder_root / fetcher_script_name).resolve()
    if not fetcher.exists():
        raise SystemExit(f"Fetcher script not found: {fetcher}")

    shell.run(["python3", str(fetcher), "--dest", str(cache_root), "--flavor", flavor])
    if expected.exists():
        return expected, {
            "source": rule_source,
            "tag": metadata.get("tag"),
            "flavor": flavor,
        }

    raise SystemExit(
        "Rule bundle not found. Run "
        f"'python {fetcher} --flavor {flavor}' "
        f"or set RULE_BUNDLE to an existing path."
    )


def fetch_rules(
    meta: Dict,
    flavor: str,
    dest: Path,
    extract_callback: Callable[[Path, str, Path], Path],
    force: bool = False,
    url_template: Optional[str] = None,
) -> Path:
    """
    Fetch rules based on metadata and flavor.

    Args:
        meta: The rules metadata dictionary.
        flavor: The flavor of rules to fetch.
        dest: The destination directory for the cache.
        extract_callback: A function to extract the downloaded archive.
                          Signature: (archive_path, bundle_path, output_dir) -> extracted_path
        force: Whether to force redownload.
        url_template: Optional URL template for downloading. If None, uses metadata URL or constructs default.

    Returns:
        The path to the extracted rules.
    """
    assets = meta.get("assets", {})
    if flavor not in assets:
        raise SystemExit(
            f"Flavor '{flavor}' not defined in metadata. Available: {', '.join(sorted(assets))}"
        )
    asset = assets[flavor]
    tag = meta.get("tag", "unknown")
    asset_name = asset["name"]
    sha256 = asset["sha256"]
    bundle_path = asset.get("bundle_path", "")

    cache_root = dest.resolve()
    archive_path = cache_root / asset_name

    if url_template:
        asset_url = url_template.format(tag=tag, asset_name=asset_name)
    else:
        asset_url = asset.get("url") or f"{meta.get('source').rstrip('/')}/{asset_name}"

    archive = download.ensure_archive(asset_url, sha256, archive_path, force)
    output_dir = cache_root / tag / flavor
    extracted = extract_callback(archive, bundle_path, output_dir)
    print(f"Fetched rules flavor '{flavor}' (tag {tag}) into: {extracted}")
    return extracted
