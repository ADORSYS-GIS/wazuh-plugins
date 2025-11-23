#!/usr/bin/env python3
from __future__ import annotations

import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from builders.common.python.wazuh_build import config as wb_config, deps, platform as wb_platform
from builders.yara.build.modules.dependencies import ensure_dependencies, setup_environment
from builders.yara.build.modules.download import resolve_rule_bundle
from builders.yara.build.modules.build import build_yara
from builders.yara.build.modules.packaging import package_release


def _bool_env(name: str) -> bool:
    val = os.environ.get(name, "")
    return val.lower() in {"1", "true", "yes", "y"}


def main() -> None:
    triplet = os.environ.get("ARTIFACT_TRIPLET", "native")
    script_dir = Path(__file__).parent
    builder_root = script_dir.parent
    config_path = builder_root / "config.yaml"
    cfg = wb_config.BuilderConfig(config_path)
    dest = Path(
        os.environ.get("ARTIFACT_DEST", builder_root / "dist" / triplet)
    ).resolve()
    version = os.environ.get("PIPELINE_VERSION", "dev")
    rule_bundle, rules_info = resolve_rule_bundle(builder_root)

    setup_environment()
    ensure_dependencies(cfg)
    deps.require_tools(
        [
            "curl",
            "tar",
            "make",
            "gcc",
            "autoconf",
            "automake",
            "pkg-config",
            "python3",
            "flex",
            "bison",
        ]
    )
    deps.require_libraries(
        ["openssl", "libpcre2-8", "libmagic", "jansson", "libprotobuf-c"]
    )

    build_yara(cfg, dest, triplet, version, rule_bundle, rules_info)
    
    # Package the release
    platform_os = wb_platform.os_id()
    platform_arch = wb_platform.arch_id()
    release_name = f"yara-{version}-{platform_os}-{platform_arch}"
    release_root = dest / "release" / release_name
    component_root = release_root / "opt" / "wazuh" / "yara"
    yara_version = os.environ.get("PIPELINE_VERSION", "").strip()
    
    package_release(
        cfg,
        dest,
        component_root,
        release_root,
        release_name,
        triplet,
        version,
        yara_version,
    )


if __name__ == "__main__":
    main()