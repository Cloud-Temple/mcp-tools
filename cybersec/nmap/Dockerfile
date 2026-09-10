# Nmap versionné ; l'image est exécutée avec --cap-drop=ALL et TCP connect scan.
FROM instrumentisto/nmap:7.98-r2@sha256:96f6ed194519b62421a1a1c57809e65a7f94d2aa1c8c25676f247e5e148c0827

LABEL org.opencontainers.image.title="mcp-cybersec-nmap"
LABEL org.opencontainers.image.version="0.7.0"
LABEL org.opencontainers.image.engine.version="7.98"

USER 10001
ENTRYPOINT ["nmap"]
