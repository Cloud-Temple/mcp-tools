# Image de sonde contrôlée (curl, ping, traceroute), sans SDK ni secret.
FROM alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b

LABEL org.opencontainers.image.title="mcp-cybersec-network"
LABEL org.opencontainers.image.version="0.7.0"

RUN apk add --no-cache curl iputils traceroute bind-tools openssl \
    && addgroup -S -g 10001 scanner \
    && adduser -S -D -H -u 10001 -G scanner scanner

USER scanner
WORKDIR /tmp
CMD ["/bin/sh"]
