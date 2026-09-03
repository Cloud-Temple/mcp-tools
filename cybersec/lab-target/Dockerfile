# Cible explicitement locale de recette ; aucun port n'est publié sur l'hôte.
FROM nginx:1.27.5-alpine@sha256:65645c7bb6a0661892a8b03b89d0743208a18dd2f3f17a54ef4b76fb8e2f2a10

LABEL org.opencontainers.image.title="mcp-cybersec-lab-target"
LABEL org.opencontainers.image.version="0.7.0"

COPY cybersec/lab-target/index.html /usr/share/nginx/html/index.html
