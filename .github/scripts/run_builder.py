#!/usr/bin/env python3
"""Execute a builder pipeline defined in builders/<name>/config.yaml."""
from __future__ import annotations

import argparse
import shutil
import subprocess
from pathlib import Path

import yaml


def log(message: str) -> None:
    print(f"::notice ::{message}")


def run_command(command: str, cwd: Path) -> None:
    log(f"Running '{command}' inside {cwd}")
    subprocess.run(command, shell=True, check=True, cwd=cwd)


def build_image(
    config_dir: Path,
    pipeline: dict,
    publish: dict,
    cache_only: bool = False,
    artifact_triplet: str | None = None,
) -> None:
    context = Path(pipeline.get("context", config_dir)).resolve()
    dockerfile = pipeline.get("dockerfile", "Dockerfile")
    dockerfile_path = (config_dir / dockerfile).resolve()
    version_file = pipeline.get("version_file", "version.txt")
    version_path = (config_dir / version_file).resolve()
    version = version_path.read_text().strip()

    target = pipeline.get("target")

    artifacts_cfg = pipeline.get("artifacts", {})
    artifact_type = artifacts_cfg.get("type", "local")
    artifact_dest_cfg = artifacts_cfg.get("dest")
    if artifact_triplet:
        artifact_dest = (config_dir / "dist" / artifact_triplet).resolve()
    elif artifact_dest_cfg:
        artifact_dest = Path(artifact_dest_cfg)
        if not artifact_dest.is_absolute():
            artifact_dest = (config_dir / artifact_dest).resolve()
    else:
        artifact_dest = (config_dir / "dist").resolve()

    if not cache_only and artifact_type == "local":
        if artifact_dest.exists():
            shutil.rmtree(artifact_dest)
        artifact_dest.mkdir(parents=True, exist_ok=True)

    tags = [tag.replace("${VERSION}", version) for tag in pipeline.get("tags", [])]
    platforms = pipeline.get("platforms", ["linux/amd64"])
    build_args = pipeline.get("build_args", {})
    cache = pipeline.get("cache", {})

    cmd = [
        "docker",
        "buildx",
        "build",
        str(context),
        "--file",
        str(dockerfile_path),
        "--platform",
        ",".join(platforms),
    ]

    if target:
        cmd.extend(["--target", target])

    if not cache_only:
        for tag in tags:
            cmd.extend(["-t", tag])

    for key, value in build_args.items():
        cmd.extend(["--build-arg", f"{key}={value}"])

    cache_url = cache.get("url")
    cache_type = cache.get("type")
    if cache_url and cache_type == "registry":
        cache_ref = f"type=registry,ref={cache_url},mode=max"
        cmd.extend(["--cache-from", cache_ref, "--cache-to", cache_ref])

    if cache_only:
        cmd.extend(["--output", "type=cacheonly"])
    else:
        output_arg = artifacts_cfg.get("output")
        if output_arg:
            cmd.extend(["--output", output_arg])
        else:
            cmd.extend(["--output", f"type={artifact_type},dest={artifact_dest}"])

        push = bool(publish.get("push"))
        if push:
            cmd.append("--push")

    provenance = publish.get("provenance") or (
        isinstance(publish.get("attestations"), list)
        and "provenance" in publish["attestations"]
    )
    if provenance:
        cmd.extend(["--provenance", "true"])

    log("Executing docker buildx pipeline")
    subprocess.run(cmd, check=True)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("config", type=Path)
    parser.add_argument(
        "--cache-only",
        action="store_true",
        help="Skip tagging/pushing images and only refresh the remote Buildx cache.",
    )
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

    build_image(
        config_dir,
        pipeline,
        ci.get("publish", {}),
        cache_only=args.cache_only,
        artifact_triplet=args.artifact_triplet,
    )


if __name__ == "__main__":
    main()
