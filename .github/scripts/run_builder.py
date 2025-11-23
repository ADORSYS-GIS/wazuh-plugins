#!/usr/bin/env python3
"""Execute a builder pipeline defined in builders/<name>/config.yaml."""
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
from pathlib import Path

import yaml


def log(message: str) -> None:
    print(f"::notice ::{message}")


def run_command(command: str, cwd: Path) -> None:
    log(f"Running '{command}' inside {cwd}")
    subprocess.run(command, shell=True, check=True, cwd=cwd)


def resolve_artifact_dest(
    config_dir: Path,
    artifacts_cfg: dict,
    artifact_triplet: str | None,
) -> Path:
    artifact_dest_cfg = artifacts_cfg.get("dest")
    if artifact_triplet:
        artifact_dest = (config_dir / "dist" / artifact_triplet).resolve()
    elif artifact_dest_cfg:
        artifact_dest = Path(artifact_dest_cfg)
        if not artifact_dest.is_absolute():
            artifact_dest = (config_dir / artifact_dest_cfg).resolve()
    else:
        artifact_dest = (config_dir / "dist").resolve()
    return artifact_dest


def clean_artifact_dest(artifact_dest: Path) -> None:
    if artifact_dest.exists():
        shutil.rmtree(artifact_dest)
    artifact_dest.mkdir(parents=True, exist_ok=True)


def build_native(
    config_dir: Path,
    pipeline: dict,
    artifact_dest: Path,
    version: str,
    artifact_triplet: str | None,
) -> None:
    clean_artifact_dest(artifact_dest)
    script = pipeline.get("native_build_script")
    if not script:
        script = "scripts/build_native.py"
    script_path = (config_dir / script).resolve()
    if not script_path.exists():
        raise FileNotFoundError(f"Native build script not found: {script_path}")

    repo_root = config_dir.parent.parent
    env = os.environ.copy()
    env.update(
        {
            "ARTIFACT_DEST": str(artifact_dest),
            "PIPELINE_VERSION": version,
            "PIPELINE_NAME": pipeline.get("name", config_dir.name),
            "PYTHONPATH": f"{repo_root}:{env.get('PYTHONPATH', '')}",
        }
    )
    if artifact_triplet:
        env["ARTIFACT_TRIPLET"] = artifact_triplet

    log(f"Executing native build script {script_path}")
    if script_path.suffix == ".py":
        subprocess.run(
            ["python3", str(script_path)], check=True, cwd=config_dir, env=env
        )
    else:
        subprocess.run([str(script_path)], check=True, cwd=config_dir, env=env)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("config", type=Path)
    parser.add_argument(
        "--artifact-triplet",
        help="Override the artifact output directory to dist/<triplet>.",
    )
    args = parser.parse_args()

    config_path = args.config.resolve()
    config_dir = config_path.parent
    data = yaml.safe_load(config_path.read_text())

    ci = data.get("ci", {})
    pipeline = data.get("pipeline", {})
    version_file = pipeline.get("version_file", "version.txt")
    version_path = (config_dir / version_file).resolve()
    version = version_path.read_text().strip()
    artifacts_cfg = pipeline.get("artifacts", {})
    artifact_dest = resolve_artifact_dest(
        config_dir, artifacts_cfg, args.artifact_triplet
    )
    builder_mode = pipeline.get("builder", "native")

    for command in ci.get("lint", []):
        run_command(command, config_dir)

    for test in ci.get("tests", []):
        if isinstance(test, dict):
            command = test.get("command")
        else:
            command = str(test)
        if not command:
            continue
        run_command(command, config_dir)

    if builder_mode != "native":
        raise ValueError(
            f"Unsupported builder mode '{builder_mode}'. Only native builds are supported."
        )

    build_native(
        config_dir,
        pipeline,
        artifact_dest,
        version,
        args.artifact_triplet,
    )


if __name__ == "__main__":
    main()
