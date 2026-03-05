# =============================================================================
# MCP Tools Service - Dockerfile
# =============================================================================
# Build   : docker build -t mcp-tools .
# Run     : docker run -p 8050:8050 --env-file .env mcp-tools
# =============================================================================

FROM python:3.11-slim

# Métadonnées
LABEL maintainer="Cloud Temple"
LABEL description="MCP Tools — Bibliothèque d'outils exécutables pour agents IA"
LABEL version="0.1.0"

# Variables d'environnement Python
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app

# Répertoire de travail
WORKDIR /app

# Dépendances système (outils réseau pour ping/dig/traceroute + curl pour healthcheck)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    iputils-ping \
    dnsutils \
    traceroute \
    git \
    && rm -rf /var/lib/apt/lists/*

# Docker CLI (binaire statique) — nécessaire pour lancer les sandbox éphémères
ARG DOCKER_VERSION=27.4.1
RUN ARCH=$(dpkg --print-architecture) && \
    if [ "$ARCH" = "arm64" ]; then ARCH="aarch64"; fi && \
    curl -fsSL "https://download.docker.com/linux/static/stable/${ARCH}/docker-${DOCKER_VERSION}.tgz" \
    | tar xz -C /tmp && mv /tmp/docker/docker /usr/local/bin/docker && rm -rf /tmp/docker

# Copie et installation des dépendances Python
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

# Créer un utilisateur non-root pour la sécurité
RUN groupadd -r mcp && useradd -r -g mcp -d /app -s /sbin/nologin mcp

# Copie de la version et du code source
COPY VERSION .
COPY src/ ./src/

# Donner les droits à l'utilisateur mcp
RUN chown -R mcp:mcp /app

# Port exposé
EXPOSE 8050

# Passer en utilisateur non-root
USER mcp

# Healthcheck via /health endpoint
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD curl -sf http://localhost:8050/health -o /dev/null 2>/dev/null

# Point d'entrée
ENTRYPOINT ["python", "-m", "src.mcp_tools.server"]
