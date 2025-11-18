# syntax=docker/dockerfile:1.7
FROM alpine:3.19 AS builder

ARG YARA_VERSION=latest
ARG RULE_BUNDLE=./rules/
ARG MAKE_JOBS=
ARG GITHUB_TOKEN=

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
        flex \
        jansson-dev \
        libtool \
        openssl-dev \
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
    LDFLAGS="${LDFLAGS:-} ${RPATH_FLAG}" ./configure --prefix="${INSTALL_PREFIX}"; \
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
