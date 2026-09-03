# Templates officiels figés au commit v10.4.2, copiés au build uniquement.
FROM alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b AS templates

ARG NUCLEI_TEMPLATES_COMMIT=8de881615f58b3427f0424338779d28de68d2ee1
RUN apk add --no-cache git ca-certificates \
    && git clone https://github.com/projectdiscovery/nuclei-templates.git /src/templates \
    && git -C /src/templates checkout --detach "$NUCLEI_TEMPLATES_COMMIT" \
    && test "$(git -C /src/templates rev-parse HEAD)" = "$NUCLEI_TEMPLATES_COMMIT"

FROM projectdiscovery/nuclei:v3.7.1@sha256:fd5f31f093f3d373e578ee639fc16efa49ffebe8340b39635435ce2957924631

LABEL org.opencontainers.image.title="mcp-cybersec-nuclei"
LABEL org.opencontainers.image.version="0.7.0"
LABEL org.opencontainers.image.engine.version="3.7.1"
LABEL org.opencontainers.image.templates.revision="v10.4.2"
LABEL org.opencontainers.image.templates.commit="8de881615f58b3427f0424338779d28de68d2ee1"

COPY --from=templates /src/templates/http/technologies/tech-detect.yaml /templates/official/tech-detect.yaml
COPY --from=templates /src/templates/http/misconfiguration/http-missing-security-headers.yaml /templates/official/http-missing-security-headers.yaml
COPY cybersec/nuclei-templates/internal/ /templates/internal/

RUN chmod -R a=rX /templates
ENV HOME=/tmp
USER 10001
ENTRYPOINT ["nuclei"]
