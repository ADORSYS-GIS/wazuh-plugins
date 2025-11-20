# syntax=docker/dockerfile:1.7
ARG BASE_IMAGE=ubuntu:18.04
FROM ${BASE_IMAGE}

ARG DEBIAN_FRONTEND=noninteractive
ENV TZ=Etc/UTC
ENV PATH="/root/.cargo/bin:${PATH}"

COPY builders/common/dependencies.py /tmp/dependencies.py
COPY builders/suricata/config.yaml /tmp/config-suricata.yaml
COPY builders/yara/config.yaml /tmp/config-yara.yaml

RUN apt-get update \
    && ln -fs /usr/share/zoneinfo/Etc/UTC /etc/localtime \
    && apt-get install -y --no-install-recommends python3 ca-certificates curl sudo git \
    && python3 /tmp/dependencies.py --section apt /tmp/config-suricata.yaml /tmp/config-yara.yaml >/tmp/apt.txt \
    && if [ -s /tmp/apt.txt ]; then \
           xargs -a /tmp/apt.txt -r apt-get install -y --no-install-recommends; \
       fi \
    && python3 /tmp/dependencies.py --section bash /tmp/config-suricata.yaml /tmp/config-yara.yaml >/tmp/bash.txt \
    && if [ -s /tmp/bash.txt ]; then \
           while read -r cmd; do \
               [ -z "$cmd" ] && continue; \
               bash -lc "$cmd"; \
           done < /tmp/bash.txt; \
       fi \
    && rm -rf /var/lib/apt/lists/* /tmp/apt.txt /tmp/bash.txt /tmp/config-*.yaml /tmp/dependencies.py

LABEL org.opencontainers.image.source="https://github.com/${GITHUB_REPOSITORY}" \
      org.opencontainers.image.description="Builder cache image"
