# syntax=docker/dockerfile:1.7
FROM alpine:3.19 AS builder

ARG YARA_VERSION=latest
ARG RULE_BUNDLE=./rules/
ARG MAKE_JOBS=
ARG GITHUB_TOKEN=

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
        flex \
        jansson-dev \
        libtool \
        openssl-dev \
        pkgconfig \
        python3

WORKDIR /tmp/yara-src
RUN set -euxo pipefail; \
    RESOLVED_VERSION="$YARA_VERSION"; \
    if [ "$RESOLVED_VERSION" = "latest" ]; then \
        RESOLVED_VERSION=$(python3 - <<'PY'
import json
import os
import sys
import urllib.request

url = "https://api.github.com/repos/VirusTotal/yara/releases/latest"
headers = {
    "Accept": "application/vnd.github+json",
    "User-Agent": "wazuh-plugins-builder",
}
token = os.environ.get("GITHUB_TOKEN")
if token:
    headers["Authorization"] = f"Bearer {token}"
    headers["X-GitHub-Api-Version"] = "2022-11-28"
req = urllib.request.Request(url, headers=headers)
try:
    with urllib.request.urlopen(req, timeout=30) as resp:
        data = resp.read()
except Exception as exc:  # pragma: no cover - network failures
    print(f"Unable to query the YARA releases API: {exc}", file=sys.stderr)
    sys.exit(1)
print(json.loads(data)["tag_name"])
PY
        ); \
    fi; \
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
    ./configure --prefix="${INSTALL_PREFIX}"; \
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

FROM scratch AS artifacts
COPY --from=builder /workspace/yara/ /release/
