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
        default_flavor="open",
        fetcher_script_name="utils/fetch_rules.py",
    )


def download_and_unpack(tag: str, target: Path) -> Path:
    url = f"https://github.com/OISF/suricata/archive/refs/tags/{tag}.tar.gz"
    tarball = target / "suricata.tar.gz"
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