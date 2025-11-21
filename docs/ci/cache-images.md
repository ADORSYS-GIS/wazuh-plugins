# CI Cache Images

A separate workflow (`.github/workflows/cache-builders.yaml`) builds and
pushes a multi-architecture cache image to GHCR on a weekly schedule. The image
is based on Ubuntu 18.04 and pre-installs the full toolchain required by the
native build scripts (autotools, cmake, ninja, rust, cargo, cbindgen, etc.).

## Workflow overview

* **build-cache-image job**: builds `.github/docker/cache.Dockerfile` once and
  pushes two tags to GHCR: `cache-builders:latest` and `cache-builders:<git sha>`.
* The workflow runs on a cron schedule (`0 3 * * 0`) and can also be
  triggered manually.

## Dockerfile highlights

`.github/docker/cache.Dockerfile` installs the same package set that the main
build workflow requires, and runs the bash/apt dependency sets declared in
`builders/*/config.yaml` so toolchains are pre-warmed (including cbindgen).
CI systems other than GitHub Actions (Jenkins, Tekton, GitLab) can pull
`ghcr.io/<org>/<repo>/cache-builders:latest` and run the standard Python
entrypoints (`run_builder.py`, `package_artifacts.py`) inside that container
for reproducible builds.
