# syntax=docker/dockerfile:1.7
ARG BASE_IMAGE=ubuntu:20.04
FROM ${BASE_IMAGE}

ARG DEBIAN_FRONTEND=noninteractive
ENV TZ=Etc/UTC

RUN apt-get update \
    && ln -fs /usr/share/zoneinfo/Etc/UTC /etc/localtime \
    && apt-get install -y --no-install-recommends \
        sudo \
        git \
        python3 \
        python3-venv \
        python3-pip \
        ca-certificates \
        curl \
        build-essential \
        autoconf \
        automake \
        libtool \
        pkg-config \
        dpkg-dev \
        flex \
        bison \
        libssl-dev \
        libpcre2-dev \
        libmagic-dev \
        libjansson-dev \
        libprotobuf-c-dev \
        protobuf-c-compiler \
        cmake \
        ninja-build \
        rustc \
        cargo \
        libyaml-dev \
        libpcap-dev \
        libcap-ng-dev \
        libnss3-dev \
        libnspr4-dev \
        liblz4-dev \
        liblzma-dev \
        libnet1-dev \
        zlib1g-dev \
        libhtp-dev \
        gnupg2 \
    && rm -rf /var/lib/apt/lists/*

ENV PATH="/root/.cargo/bin:${PATH}"
RUN cargo install --locked --force cbindgen --version 0.26.0

LABEL org.opencontainers.image.source="https://github.com/${GITHUB_REPOSITORY}" \
      org.opencontainers.image.description="Builder cache image"
