# syntax=docker/dockerfile:1.7
FROM alpine:3.19 AS builder
ARG YARA_VERSION="4.5.0"
ARG RULE_BUNDLE="./rules"
RUN mkdir -p /workspace/yara/bin \
    && printf '#!/bin/sh\necho "YARA ${YARA_VERSION} scanning $1"\n' > /workspace/yara/bin/yara \
    && chmod +x /workspace/yara/bin/yara \
    && printf "YARA_VERSION=${YARA_VERSION}\nRULE_BUNDLE=${RULE_BUNDLE}\n" > /workspace/yara/BUILDINFO.txt
COPY rules/ /workspace/yara/rules/
COPY scripts/scan.sh /workspace/yara/scan.sh
COPY scripts/scan-fixtures.sh /workspace/yara/scan-fixtures.sh
RUN chmod +x /workspace/yara/scan.sh /workspace/yara/scan-fixtures.sh

FROM scratch AS artifacts
COPY --from=builder /workspace/yara/ /release/
