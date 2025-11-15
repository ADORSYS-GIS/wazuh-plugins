# syntax=docker/dockerfile:1.7
FROM alpine:3.19
ARG YARA_VERSION="4.5.0"
ARG RULE_BUNDLE="./rules"
RUN apk add --no-cache bash
COPY rules/ /opt/yara/rules/
COPY scripts/scan.sh /usr/local/bin/scan.sh
RUN chmod +x /usr/local/bin/scan.sh
ENV YARA_VERSION=${YARA_VERSION}
ENTRYPOINT ["/usr/local/bin/scan.sh"]
CMD ["/fixtures"]
