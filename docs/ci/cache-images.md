# CI Cache Images

A separate workflow (`.github/workflows/cache-builders.yaml`) now builds and
pushes multi-architecture cache images to GHCR on a weekly schedule. Each image
is based on Ubuntu 18.04 and pre-installs the full toolchain required by the
native build scripts (autotools, cmake, ninja, rust, cargo, cbindgen, etc.).

## Workflow overview

* **discover job**: scans `builders/` for directories containing `config.yaml`
  and produces the builder matrix.
* **build-cache-images job**: for each builder, builds
  `.github/docker/cache.Dockerfile` and pushes two tags to GHCR:
  `cache-<builder>:latest` and `cache-<builder>:<git sha>`.
* The workflow runs on a cron schedule (`0 3 * * 0`) and can also be
  triggered manually.

## Dockerfile highlights

`.github/docker/cache.Dockerfile` installs the same package set that the main
build workflow requires, and runs `cargo install --locked cbindgen` so Rust
components can compile immediately. We can reference these GHCR images in the
future to avoid re-installing packages on each CI run.
