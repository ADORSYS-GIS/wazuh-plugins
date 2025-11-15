# syntax=docker/dockerfile:1.7
FROM alpine:3.19 AS builder
ARG SURICATA_VERSION="6.0.10"
ARG RULESET_URL="https://example.com/rules.tar.gz"
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

FROM scratch AS artifacts
COPY --from=builder /workspace/suricata/ /release/
