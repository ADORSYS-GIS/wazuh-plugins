# syntax=docker/dockerfile:1.7
ARG BASE_IMAGE=ubuntu:20.04
FROM ${BASE_IMAGE}

ARG DEBIAN_FRONTEND=noninteractive
ENV TZ=Etc/UTC
ENV PATH="/root/.cargo/bin:${PATH}"

COPY builders/common/dependencies.py /tmp/dependencies.py
COPY builders/suricata/config.yaml /tmp/config-suricata.yaml
COPY builders/yara/config.yaml /tmp/config-yara.yaml
COPY builders/wazuh-agent/config.yaml /tmp/config-wazuh-agent.yaml

RUN apt-get update \
    && ln -fs /usr/share/zoneinfo/Etc/UTC /etc/localtime \
    && apt-get install -y --no-install-recommends python3 ca-certificates curl sudo git \
    && python3 /tmp/dependencies.py --section apt /tmp/config-suricata.yaml /tmp/config-yara.yaml /tmp/config-wazuh-agent.yaml >/tmp/apt.txt \
    && if [ -s /tmp/apt.txt ]; then \
           xargs -a /tmp/apt.txt -r apt-get install -y --no-install-recommends; \
       fi \
    && python3 /tmp/dependencies.py --section bash /tmp/config-suricata.yaml /tmp/config-yara.yaml /tmp/config-wazuh-agent.yaml >/tmp/bash.txt \
    && if [ -s /tmp/bash.txt ]; then \
           while read -r cmd; do \
               [ -z "$cmd" ] && continue; \
               bash -lc "$cmd"; \
           done < /tmp/bash.txt; \
       fi \
    && curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg | dd of=/usr/share/keyrings/githubcli-archive-keyring.gpg \
    && chmod go+r /usr/share/keyrings/githubcli-archive-keyring.gpg \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" > /etc/apt/sources.list.d/github-cli.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends gh \
    && rm -rf /var/lib/apt/lists/* /tmp/apt.txt /tmp/bash.txt /tmp/config-*.yaml /tmp/dependencies.py

LABEL org.opencontainers.image.source="https://github.com/${GITHUB_REPOSITORY}" \
      org.opencontainers.image.description="Builder cache image"
