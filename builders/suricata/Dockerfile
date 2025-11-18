# syntax=docker/dockerfile:1.7
FROM alpine:3.19 AS builder
ARG SURICATA_VERSION="6.0.10"
ARG RULESET_URL="https://example.com/rules.tar.gz"
ARG SYFT_VERSION=v1.5.0
RUN echo "Simulating Suricata build for version ${SURICATA_VERSION}" \
    && mkdir -p /workspace/suricata/bin \
    && mkdir -p /workspace/suricata/rules \
    && printf '#!/bin/sh\necho "Suricata ${SURICATA_VERSION} running"\n' > /workspace/suricata/bin/suricata \
    && chmod +x /workspace/suricata/bin/suricata \
    && printf "# Suricata build info\nVERSION=${SURICATA_VERSION}\nRULESET_URL=${RULESET_URL}\n" > /workspace/suricata/BUILDINFO.txt \
    && printf "alert http any any -> any any (msg:\"fake rule\"; sid:1; rev:1;)\n" > /workspace/suricata/rules/generated.rules
COPY rules/ /workspace/suricata/custom-rules/
COPY scripts/entrypoint.sh /workspace/suricata/entrypoint.sh
RUN chmod +x /workspace/suricata/entrypoint.sh

RUN set -euxo pipefail; \
    apk add --no-cache --virtual .sbom-deps curl tar; \
    OS_NAME="linux"; \
    ARCH_NAME="$(uname -m)"; \
    case "${ARCH_NAME}" in \
        x86_64|amd64) ARCH_NAME="amd64" ;; \
        aarch64|arm64) ARCH_NAME="arm64" ;; \
    esac; \
    OUTBASE="suricata-${SURICATA_VERSION}-${OS_NAME}-${ARCH_NAME}"; \
    DIST_DIR="/workspace/dist"; \
    ARTIFACT_ROOT="${DIST_DIR}/${OUTBASE}"; \
    SBOM_DIR="${ARTIFACT_ROOT}/SBOM"; \
    mkdir -p "${SBOM_DIR}" "${DIST_DIR}"; \
    cp -R /workspace/suricata/. "${ARTIFACT_ROOT}/"; \
    curl -sSfL "https://raw.githubusercontent.com/anchore/syft/main/install.sh" | sh -s -- -b /usr/local/bin "${SYFT_VERSION}"; \
    syft "dir:${ARTIFACT_ROOT}" -o spdx-json > "${SBOM_DIR}/${OUTBASE}.sbom.spdx.json"; \
    syft "dir:${ARTIFACT_ROOT}" -o cyclonedx-json > "${SBOM_DIR}/${OUTBASE}.sbom.cdx.json"; \
    cat > "${ARTIFACT_ROOT}/${OUTBASE}.pom.json" <<EOF
{
  "artifact": "${OUTBASE}",
  "version": "${SURICATA_VERSION}",
  "os": "${OS_NAME}",
  "arch": "${ARCH_NAME}",
  "build": {
    "builder": "suricata-docker",
    "timestamp": "$(date -u +%FT%TZ)",
    "image": "alpine:3.19"
  }
}
EOF
    tar -czf "${DIST_DIR}/${OUTBASE}.tar.gz" -C "${DIST_DIR}" "${OUTBASE}"; \
    {
      sha256sum "${DIST_DIR}/${OUTBASE}.tar.gz";
      sha256sum "${SBOM_DIR}/${OUTBASE}.sbom.spdx.json";
      sha256sum "${SBOM_DIR}/${OUTBASE}.sbom.cdx.json";
      sha256sum "${ARTIFACT_ROOT}/${OUTBASE}.pom.json";
    } > "${DIST_DIR}/${OUTBASE}.sha256.txt"

FROM scratch AS artifacts
COPY --from=builder /workspace/dist/ /release/
