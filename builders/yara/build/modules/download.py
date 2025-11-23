#!/usr/bin/env python3
from __future__ import annotations

import os
import tarfile
from pathlib import Path
from typing import Tuple

from builders.common.python.wazuh_build import download, rules, shell


def resolve_rule_bundle(builder_root: Path) -> Tuple[Path, dict]:
    return rules.resolve_rule_bundle(
        builder_root,
        default_flavor="full",
        fetcher_script_name="utils/fetch_rules.py",
        source_name="yara-forge",
    )


def download_and_unpack(version: str, target: Path) -> Path:
    # YARA uses version tags with 'v' prefix (e.g., v4.3.2)
    if not version.startswith('v'):
        version = f'v{version}'
        
    url = f"https://github.com/VirusTotal/yara/archive/refs/tags/{version}.tar.gz"
    tarball = target / "yara.tar.gz"
    shell.run(["curl", "-fsSL", url, "-o", str(tarball)])
    src_dir = target / "src"
    src_dir.mkdir(parents=True, exist_ok=True)
    with tarfile.open(tarball, "r:gz") as tf:
        tf.extractall(path=src_dir, members=download.strip_components(tf))
    return src_dir


def write_revision_header(build_dir: Path) -> Path:
    revision_label = (
        f"Wazuh Plugin Build {os.environ.get('PIPELINE_COMMIT', 'unknown')}"
    )
    revision_header = build_dir / "revision.h"
    escaped = revision_label.replace('"', r"\"")
    revision_header.write_text(f'#define REVISION "{escaped}"\n')
    return revision_header


def _bool_env(name: str) -> bool:
    val = os.environ.get(name, "")
    return val.lower() in {"1", "true", "yes", "y"}


def _feature_enabled(env_name: str, default: bool) -> bool:
    val = os.environ.get(env_name)
    if val is None or val == "":
        return default
    return _bool_env(env_name)