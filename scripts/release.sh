#!/usr/bin/env bash
# =============================================================================
# Publie une version : bump, contrôles, commit, tag, release — en un geste.
# =============================================================================
#
# Pourquoi ce script existe : le 2026-08-06, du travail a été fusionné sur
# `main` après la publication de v0.5.0 sans bump ni tag. `main` portait donc
# des changements sous un numéro déjà publié, la plateforme s'est vu annoncer
# une cible de déploiement qui a changé sous elle, et il a fallu corriger
# l'annonce. La cause n'était pas l'oubli d'une commande : c'était une suite
# d'étapes manuelles dont une pouvait sauter sans que rien ne le signale.
#
# Ce script rend la séquence atomique. Le garde CI
# (scripts/check_release_coherence.py) reste le filet si on le contourne.
#
# Usage :
#     ./scripts/release.sh 0.5.2
#     DRY_RUN=1 ./scripts/release.sh 0.5.2      # tout contrôler sans rien pousser
#
# =============================================================================
set -euo pipefail

VERSION_CIBLE="${1:-}"
DRY_RUN="${DRY_RUN:-0}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [[ -z "$VERSION_CIBLE" ]]; then
    echo "usage: $0 <X.Y.Z>   (ex: $0 0.5.2)" >&2
    exit 2
fi
if [[ ! "$VERSION_CIBLE" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "❌ « $VERSION_CIBLE » n'est pas un semver X.Y.Z" >&2
    exit 2
fi

etape() { printf "\n\033[1m→ %s\033[0m\n" "$1"; }
echec() { printf "\n❌ %s\n" "$1" >&2; exit 1; }

# --- Contrôles préalables : tout ce qui rend une release ambiguë -------------
etape "Contrôles préalables"

[[ "$(git rev-parse --abbrev-ref HEAD)" == "main" ]] \
    || echec "Il faut être sur main (branche courante : $(git rev-parse --abbrev-ref HEAD))."

[[ -z "$(git status --porcelain)" ]] \
    || echec "Arbre de travail sale. Committer ou remiser d'abord :
$(git status --short)"

git fetch --quiet --tags origin
[[ "$(git rev-parse HEAD)" == "$(git rev-parse origin/main)" ]] \
    || echec "main local ≠ origin/main. Faire git pull / git push d'abord."

git rev-parse "v${VERSION_CIBLE}" >/dev/null 2>&1 \
    && echec "Le tag v${VERSION_CIBLE} existe DÉJÀ. Un tag publié ne se déplace pas — choisir un autre numéro."

grep -q "^## \[${VERSION_CIBLE}\]" CHANGELOG.md \
    || echec "CHANGELOG.md ne porte pas d'entrée « ## [${VERSION_CIBLE}] ».
   Rédiger les notes de version AVANT de publier : une release sans notes est
   inexploitable pour qui déploie."

# Un secret indexé par erreur ne doit jamais atteindre un tag.
git ls-files | grep -E '^\.env($|~|\..*)' | grep -v '^\.env\.example$' \
    && echec "Un fichier .env est suivi par git. Le retirer avant toute publication."

echo "  ok  main propre, synchronisée, tag libre, CHANGELOG rédigé, aucun secret suivi"

# --- Bump --------------------------------------------------------------------
etape "Bump VERSION → ${VERSION_CIBLE}"
echo "${VERSION_CIBLE}" > VERSION
if grep -q '^LABEL version=' Dockerfile; then
    sed -i.bak "s/^LABEL version=.*/LABEL version=\"${VERSION_CIBLE}\"/" Dockerfile && rm -f Dockerfile.bak
fi
echo "  VERSION=$(cat VERSION) · $(grep '^LABEL version=' Dockerfile)"

# --- Gardes ------------------------------------------------------------------
etape "Gardes de cohérence et de reproductibilité"
python3 scripts/check_release_coherence.py --tag "v${VERSION_CIBLE}" \
    || echec "Garde de cohérence en échec."
python3 scripts/test_service.py --test reproducibility --no-docker \
    || echec "Gardes de reproductibilité en échec."

if [[ "$DRY_RUN" == "1" ]]; then
    etape "DRY_RUN — annulation du bump, rien n'est publié"
    git checkout -- VERSION Dockerfile
    echo "  ok  tous les contrôles passent ; relancer sans DRY_RUN pour publier"
    exit 0
fi

# --- Publication atomique ----------------------------------------------------
etape "Commit, tag et publication"
git add VERSION Dockerfile
git commit -m "v${VERSION_CIBLE}

$(sed -n "/^## \[${VERSION_CIBLE}\]/,/^## \[/p" CHANGELOG.md | sed '1d;$d' | head -40)

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
git push origin main

git tag -a "v${VERSION_CIBLE}" -m "v${VERSION_CIBLE}"
git push origin "v${VERSION_CIBLE}"

gh release create "v${VERSION_CIBLE}" \
    --title "v${VERSION_CIBLE}" \
    --latest \
    --notes "$(sed -n "/^## \[${VERSION_CIBLE}\]/,/^## \[/p" CHANGELOG.md | sed '1d;$d')"

etape "Contrôle final"
python3 scripts/check_release_coherence.py
printf "\n✅ v%s publiée — tag == origin/main == VERSION\n" "${VERSION_CIBLE}"
