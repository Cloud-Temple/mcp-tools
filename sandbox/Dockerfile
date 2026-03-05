# =============================================================================
# Sandbox Container — MCP Tools
# =============================================================================
# Image Alpine pour exécuter des commandes de manière isolée.
# Lancée en éphémère (--rm) par le tool `shell` de MCP Tools.
#
# Langages : bash, sh, python3, node
# Outils   : coreutils, grep, sed, awk, jq, bc, curl, git, openssl, gnupg
#
# Sécurité (flags docker run) :
#   --network=none    → pas de réseau
#   --read-only       → filesystem immuable
#   --cap-drop=ALL    → zéro capabilities Linux
#   --memory=256m     → limite mémoire
#   --cpus=0.5        → limite CPU
#   --pids-limit=10   → anti fork-bomb
#   --user sandbox    → non-root
#   --no-new-privileges → pas d'escalade
# =============================================================================

FROM alpine:3.20

# Créer un utilisateur non-root
RUN addgroup -S sandbox && adduser -S sandbox -G sandbox

# Outils shell classiques
RUN apk add --no-cache \
    bash \
    coreutils \
    grep \
    sed \
    gawk \
    jq \
    bc \
    curl \
    wget \
    findutils \
    diffutils \
    file \
    tree \
    git \
    && rm -rf /var/cache/apk/*

# Crypto & sécurité (openssl, gpg — opérations locales sans réseau)
# sha256sum, md5sum, sha512sum sont dans coreutils (déjà installé)
RUN apk add --no-cache \
    openssl \
    gnupg \
    && rm -rf /var/cache/apk/*

# Python 3 (calculs, traitement de données, scripts)
RUN apk add --no-cache \
    python3 \
    py3-pip \
    && rm -rf /var/cache/apk/*

# Node.js (traitement JSON, scripts JS)
RUN apk add --no-cache \
    nodejs \
    && rm -rf /var/cache/apk/*

# Répertoire de travail
WORKDIR /tmp/workspace

# Utilisateur non-root par défaut
USER sandbox

# Pas d'ENTRYPOINT — c'est docker run qui fournit la commande
CMD ["/bin/sh"]
