# syntax=docker/dockerfile:1.7
FROM alpine:3.19 AS builder
ARG SURICATA_VERSION="6.0.10"
ARG RULESET_URL="https://example.com/rules.tar.gz"
RUN echo "Simulating Suricata build for version ${SURICATA_VERSION}" \
    && mkdir -p /tmp/suricata \
    && printf "rule fake_suricata_rule {\n  strings: $a = \"alert\"\n  condition: any of them\n}\n" > /tmp/suricata/rules.yar

FROM alpine:3.19
ARG SURICATA_VERSION="6.0.10"
COPY --from=builder /tmp/suricata/rules.yar /opt/suricata/rules/rules.yar
COPY rules/ /opt/suricata/custom-rules/
COPY scripts/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENV SURICATA_VERSION=${SURICATA_VERSION}
ENTRYPOINT ["/entrypoint.sh"]
CMD ["--help"]
