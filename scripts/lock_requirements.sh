#!/usr/bin/env bash
# =============================================================================
# Régénère requirements.lock DANS l'image cible.
# =============================================================================
#
# Le lock DOIT être produit dans le même interpréteur et la même plateforme que
# l'image de production. Un `pip freeze` lancé sur un poste de développement
# (macOS, Python 3.13) résout des versions et des wheels différents de ceux de
# python:3.11-slim linux/amd64 : le lock serait faux et le build casserait.
#
# Usage :
#     ./scripts/lock_requirements.sh                 # linux/amd64 (défaut)
#     PLATFORM=linux/arm64 ./scripts/lock_requirements.sh
#
# =============================================================================
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PLATFORM="${PLATFORM:-linux/amd64}"
BASE_IMAGE="${BASE_IMAGE:-python:3.11-slim}"

echo "→ Génération du lock dans ${BASE_IMAGE} (${PLATFORM})"

docker run --rm \
    --platform "${PLATFORM}" \
    -v "${REPO_ROOT}:/work" \
    -w /work \
    "${BASE_IMAGE}" \
    bash -c '
        set -euo pipefail
        # L'\''outillage de build (pip/setuptools/wheel) entre AUSSI dans le lock.
        # python:3.11-slim embarque un setuptools ancien : il a porté
        # PYSEC-2026-3447 sans que l'\''audit du lock ne le voie, car `pip freeze`
        # exclut l'\''outillage par défaut. D'\''où `--all` plus bas.
        pip install --quiet --no-cache-dir --upgrade pip setuptools wheel
        pip install --quiet --no-cache-dir -r requirements.txt
        {
            echo "# ============================================================================="
            echo "# requirements.lock — GÉNÉRÉ, NE PAS ÉDITER À LA MAIN"
            echo "# ============================================================================="
            echo "#"
            echo "# Clôture transitive complète résolue depuis requirements.txt."
            echo "# C'"'"'est ce fichier qu'"'"'installe le Dockerfile : il rend un rebuild d'"'"'un tag"
            echo "# publié reproductible, y compris quand une majeure amont sort."
            echo "#"
            echo "# Régénérer :  ./scripts/lock_requirements.sh"
            echo "# Image       : '"${BASE_IMAGE}"'"
            echo "# Plateforme  : '"${PLATFORM}"'"
            echo "# Python      : $(python --version 2>&1)"
            echo "# ============================================================================="
            echo
            pip freeze --all --exclude-editable
        } > requirements.lock
    '

echo "→ requirements.lock régénéré :"
grep -c -v -E '^\s*(#|$)' "${REPO_ROOT}/requirements.lock" | xargs -I{} echo "  {} paquets figés"
