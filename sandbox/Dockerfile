# =============================================================================
# Sandbox Container — MCP Tools
# =============================================================================
# Image Alpine pour exécuter des commandes de manière isolée.
# Lancée en éphémère (--rm) par le tool `shell` de MCP Tools.
#
# Langages : bash, sh, python3, node
# Outils   : coreutils, grep, sed, awk, jq, bc, curl, git, openssl, gnupg
#
# Python  : numpy, pandas, requests, beautifulsoup4, lxml, pyyaml, scipy,
#           matplotlib, pillow, boto3, tabulate, toml, chardet, dateutil
#
# Sécurité (flags docker run) :
#   --network=none    → pas de réseau (défaut shell/calc)
#   --network=bridge  → accès réseau (si network=true, ou tools http/ssh/files)
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

# Outils réseau (tool network : ping, traceroute, dig, nslookup)
RUN apk add --no-cache \
    iputils \
    bind-tools \
    traceroute \
    && rm -rf /var/cache/apk/*

# SSH client (tool ssh : exec, upload, download, status)
RUN apk add --no-cache \
    openssh-client \
    sshpass \
    && rm -rf /var/cache/apk/*

# Crypto & sécurité (openssl, gpg — opérations locales sans réseau)
# sha256sum, md5sum, sha512sum sont dans coreutils (déjà installé)
RUN apk add --no-cache \
    openssl \
    gnupg \
    && rm -rf /var/cache/apk/*

# Python 3 + packages courants (calculs, traitement de données, scripts)
# On utilise les py3-* Alpine (pré-compilés) quand disponibles pour limiter la taille
RUN apk add --no-cache \
    python3 \
    py3-pip \
    py3-numpy \
    py3-pandas \
    py3-requests \
    py3-yaml \
    py3-lxml \
    py3-chardet \
    py3-dateutil \
    py3-pillow \
    py3-scipy \
    py3-matplotlib \
    && pip3 install --no-cache-dir --break-system-packages \
        boto3 \
        beautifulsoup4 \
        tabulate \
        toml \
    && rm -rf /var/cache/apk/* /root/.cache

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
