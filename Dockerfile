# =============================================================================
# MCP Tools Service - Dockerfile
# =============================================================================
# Build   : docker build -t mcp-tools .
# Run     : docker run -p 8050:8050 --env-file .env mcp-tools
# =============================================================================

# Image de base épinglée par DIGEST, pas par tag.
# `python:3.11-slim` est un tag mouvant : reconstruire un tag applicatif publié
# ramènerait une base différente, ce qui annule la reproductibilité que cette
# version installe. Le digest la fige.
# Relever ce digest est une opération DÉLIBÉRÉE (correctifs OS) :
#     docker buildx imagetools inspect python:3.11-slim
#     puis rejouer ./scripts/lock_requirements.sh et le scan docker scout.
FROM python:3.11-slim@sha256:94c50be2dc994b873b55bc123e95e6dbade08095b3dfd790f51c34de3f08cbb7

# Métadonnées
LABEL maintainer="Cloud Temple"
LABEL description="MCP Tools — Bibliothèque d'outils exécutables pour agents IA"
LABEL version="0.5.0"

# Variables d'environnement Python
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app

# Répertoire de travail
WORKDIR /app

# Dépendances système (outils réseau pour ping/dig/traceroute + curl pour healthcheck)
#
# ⚠️ `git` a été RETIRÉ en v0.5.0. Il n'était appelé par aucun outil (l'outil
# `git` est en Phase 2, non implémenté), mais il tirait `perl`, porteur de
# 4 CVE dont 2 CRITIQUES (CVE-2026-13221, CVE-2026-12087) toutes marquées
# « not fixed » côté Debian : aucun `apt upgrade` ne les corrige. Embarquer un
# binaire inutilisé et non corrigeable est une surface d'attaque gratuite.
# → À réintroduire AVEC un contrôle `docker scout` quand l'outil `git` Phase 2
#   sera implémenté (voir DESIGN/mcp-tools/TOOLS_CATALOG.md).
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    iputils-ping \
    dnsutils \
    traceroute \
    && rm -rf /var/lib/apt/lists/*

# Docker CLI (binaire statique) — nécessaire pour lancer les sandbox éphémères
#
# ⚠️ Ce binaire Go embarque sa propre bibliothèque standard : c'est une surface
# d'attaque que `pip-audit` ne voit PAS (il n'audite que le Python). La 27.4.1
# était compilée avec Go 1.22.10, porteuse de 18 CVE dont 2 critiques
# (CVE-2025-68121, CVE-2025-22871). Vérifier à chaque montée :
#     docker scout cves --only-package stdlib <image>
ARG DOCKER_VERSION=29.7.2
RUN ARCH=$(dpkg --print-architecture) && \
    if [ "$ARCH" = "arm64" ]; then ARCH="aarch64"; \
    elif [ "$ARCH" = "amd64" ]; then ARCH="x86_64"; fi && \
    curl -fsSL "https://download.docker.com/linux/static/stable/${ARCH}/docker-${DOCKER_VERSION}.tgz" \
    | tar xz -C /tmp && mv /tmp/docker/docker /usr/local/bin/docker && rm -rf /tmp/docker

# Copie et installation des dépendances Python
#
# On installe requirements.lock (clôture transitive figée), PAS requirements.txt.
# Sans cela, un rebuild d'un tag déjà publié résout les dernières versions amont
# et peut devenir inexécutable : c'est ce qui est arrivé à la v0.4.1 quand
# mcp 2.0.0 est sorti (issue #2). requirements.txt reste embarqué pour tracer le
# contrat de compatibilité ayant servi à générer le lock.
# Le lock fige AUSSI pip/setuptools/wheel : un `--upgrade pip` non borné
# réintroduirait la dérive que cette version corrige, et c'est le setuptools
# ancien de l'image de base qui portait PYSEC-2026-3447.
COPY requirements.txt requirements.lock ./
RUN pip install --no-cache-dir -r requirements.lock \
    && pip check

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
