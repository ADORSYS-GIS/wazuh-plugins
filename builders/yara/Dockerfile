# syntax=docker/dockerfile:1.7
FROM alpine:3.19 AS builder

ARG YARA_VERSION=latest
ARG RULE_BUNDLE=./rules/
ARG MAKE_JOBS=
ARG GITHUB_TOKEN=
ARG SYFT_VERSION=v1.5.0

ENV YARA_VERSION=${YARA_VERSION}
ENV GITHUB_TOKEN=${GITHUB_TOKEN}

RUN apk add --no-cache \
        autoconf \
        automake \
        bash \
        bison \
        build-base \
        ca-certificates \
        coreutils \
        curl \
        file \
        file-dev \
        flex \
        jansson-dev \
        pcre2-dev \
        libtool \
        openssl-dev \
        protobuf-c-dev \
        pkgconfig \
        python3

WORKDIR /tmp/yara-src
COPY scripts/resolve_yara_version.py /tmp/resolve_yara_version.py
RUN set -euxo pipefail; \
    RESOLVED_VERSION="$(python3 /tmp/resolve_yara_version.py)"; \
    if [ -z "$RESOLVED_VERSION" ]; then \
        echo "Unable to resolve YARA version" >&2; \
        exit 1; \
    fi; \
    echo "$RESOLVED_VERSION" > /tmp/YARA_VERSION; \
    curl -fsSL "https://github.com/VirusTotal/yara/archive/refs/tags/${RESOLVED_VERSION}.tar.gz" -o /tmp/yara.tar.gz; \
    tar -xzf /tmp/yara.tar.gz --strip-components=1; \
    ./bootstrap.sh; \
    INSTALL_PREFIX=/workspace/yara; \
    CORES="$MAKE_JOBS"; \
    if [ -z "$CORES" ]; then \
        CORES=$(nproc 2>/dev/null || getconf _NPROCESSORS_ONLN 2>/dev/null || echo 1); \
    fi; \
    RPATH_FLAG="-Wl,-rpath,\\$ORIGIN/../lib"; \
    LDFLAGS="${LDFLAGS:-} ${RPATH_FLAG}" ./configure --prefix="${INSTALL_PREFIX}" --with-crypto --enable-magic; \
    make -j "${CORES}"; \
    make install

WORKDIR /workspace/yara
RUN set -eux; mkdir -p /workspace/yara/rules /workspace/yara/scripts
COPY ${RULE_BUNDLE} /workspace/yara/rules/
COPY scripts/ /workspace/yara/scripts/
RUN set -eux; \
    chmod +x /workspace/yara/scripts/*.sh; \
    RESOLVED_VERSION=$(cat /tmp/YARA_VERSION); \
    printf 'YARA_VERSION=%s\nRULE_BUNDLE=%s\n' "$RESOLVED_VERSION" "$RULE_BUNDLE" > /workspace/yara/BUILDINFO.txt; \
    printf "# Wazuh Plugins YARA bundle\nBuilt from %s\n" "$RESOLVED_VERSION" > /workspace/yara/README.txt

RUN <<'EOF'
set -euxo pipefail
RESOLVED_VERSION="$(cat /tmp/YARA_VERSION)"
apk add --no-cache --virtual .sbom-deps curl tar
OS_NAME="linux"
ARCH_NAME="$(uname -m)"
case "${ARCH_NAME}" in
    x86_64|amd64) ARCH_NAME="amd64" ;;
    aarch64|arm64) ARCH_NAME="arm64" ;;
esac
OUTBASE="yara-${RESOLVED_VERSION}-${OS_NAME}-${ARCH_NAME}"
DIST_DIR="/workspace/dist"
ARTIFACT_ROOT="${DIST_DIR}/${OUTBASE}"
SBOM_DIR="${ARTIFACT_ROOT}/SBOM"
mkdir -p "${SBOM_DIR}" "${DIST_DIR}"
cp -R /workspace/yara/. "${ARTIFACT_ROOT}/"
curl -sSfL "https://raw.githubusercontent.com/anchore/syft/main/install.sh" | sh -s -- -b /usr/local/bin "${SYFT_VERSION}"
syft "dir:${ARTIFACT_ROOT}" -o spdx-json > "${SBOM_DIR}/${OUTBASE}.sbom.spdx.json"
syft "dir:${ARTIFACT_ROOT}" -o cyclonedx-json > "${SBOM_DIR}/${OUTBASE}.sbom.cdx.json"
cat > "${ARTIFACT_ROOT}/${OUTBASE}.pom.json" <<JSON
{
  "artifact": "${OUTBASE}",
  "version": "${RESOLVED_VERSION}",
  "os": "${OS_NAME}",
  "arch": "${ARCH_NAME}",
  "build": {
    "builder": "yara-docker",
    "timestamp": "$(date -u +%FT%TZ)",
    "image": "alpine:3.19"
  }
}
JSON
tar -czf "${DIST_DIR}/${OUTBASE}.tar.gz" -C "${DIST_DIR}" "${OUTBASE}"
{
  sha256sum "${DIST_DIR}/${OUTBASE}.tar.gz"
  sha256sum "${SBOM_DIR}/${OUTBASE}.sbom.spdx.json"
  sha256sum "${SBOM_DIR}/${OUTBASE}.sbom.cdx.json"
  sha256sum "${ARTIFACT_ROOT}/${OUTBASE}.pom.json"
} > "${DIST_DIR}/${OUTBASE}.sha256.txt"
EOF

FROM scratch AS artifacts
COPY --from=builder /workspace/dist/ /release/
