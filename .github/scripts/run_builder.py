#!/usr/bin/env python3
"""Execute a builder pipeline defined in builders/<name>/config.yaml."""
from __future__ import annotations

import argparse
import subprocess
from pathlib import Path

import yaml


def log(message: str) -> None:
    print(f"::notice ::{message}")


def run_command(command: str, cwd: Path) -> None:
    log(f"Running '{command}' inside {cwd}")
    subprocess.run(command, shell=True, check=True, cwd=cwd)


def build_image(config_dir: Path, pipeline: dict, publish: dict) -> None:
    context = Path(pipeline.get("context", config_dir)).resolve()
    dockerfile = pipeline.get("dockerfile", "Dockerfile")
    dockerfile_path = (config_dir / dockerfile).resolve()
    version_file = pipeline.get("version_file", "version.txt")
    version_path = (config_dir / version_file).resolve()
    version = version_path.read_text().strip()

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

    for tag in tags:
        cmd.extend(["-t", tag])

    for key, value in build_args.items():
        cmd.extend(["--build-arg", f"{key}={value}"])

    cache_url = cache.get("url")
    cache_type = cache.get("type")
    if cache_url and cache_type == "registry":
        cache_ref = f"type=registry,ref={cache_url}"
        cmd.extend(["--cache-from", cache_ref, "--cache-to", cache_ref])

    push = bool(publish.get("push"))
    if push:
        cmd.append("--push")
    else:
        cmd.append("--load")

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

    build_image(config_dir, pipeline, ci.get("publish", {}))


if __name__ == "__main__":
    main()
