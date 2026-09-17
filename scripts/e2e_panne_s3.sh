#!/usr/bin/env bash
# =============================================================================
# Recette manuelle : le magasin de tokens échoue-t-il vraiment en FERMÉ ?
# =============================================================================
#
# Les tests unitaires exercent un faux client S3. Ils prouvent que le code se
# comporte comme il est écrit. Ils ne prouvent pas que le SERVICE se comporte
# ainsi : le middleware, le routeur admin, la configuration lue depuis
# l'environnement et le vrai client boto3 n'y sont pas.
#
# Ce script joue le scénario complet contre un vrai S3 (minio) qu'on éteint :
#
#   A. S3 debout      token accepté (200), token inconnu refusé (401)
#   B. S3 éteint      le MÊME token reçoit 503, pas 401 et pas 200 ;
#                     la clé bootstrap et /health restent joignables ;
#                     une révocation est refusée au lieu d'être simulée
#   C. S3 revenu      le token repasse, SANS redémarrage du service
#   D. Révocation     succès, puis 401
#
# Il n'est PAS branché dans la CI : il tire une image externe (quay.io/minio)
# et construit l'image du service. Comme la recette complète de
# `scripts/test_service.py`, il relève de la qualification manuelle.
# Voir README §4.
#
# Usage :  ./scripts/e2e_panne_s3.sh [tag-image]
# Prérequis : docker. Aucune donnée n'est écrite hors des conteneurs.
# =============================================================================

set -euo pipefail

IMAGE="${1:-mcp-tools:e2e-panne}"
RESEAU=e2e-panne-net
MINIO=e2e-panne-minio
SVC=e2e-panne-svc
PORT=18099
CLE=cle_bootstrap_e2e_panne
RACINE="$(cd "$(dirname "$0")/.." && pwd)"

nettoyer() {
  docker rm -f "$SVC" "$MINIO" >/dev/null 2>&1 || true
  docker network rm "$RESEAU" >/dev/null 2>&1 || true
}
trap nettoyer EXIT
nettoyer

echec=0
attendu() { # attendu <libelle> <obtenu> <attendu>
  if [ "$2" = "$3" ]; then
    printf '  ok   %-46s %s\n' "$1" "$2"
  else
    printf '  KO   %-46s %s (attendu %s)\n' "$1" "$2" "$3"
    echec=1
  fi
}
statut() { curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $1" "http://localhost:$PORT$2"; }

echo "== Construction de l'image =="
docker build -q -t "$IMAGE" "$RACINE" >/dev/null

echo "== Démarrage de minio =="
docker network create "$RESEAU" >/dev/null
docker run -d --name "$MINIO" --network "$RESEAU" \
  -e MINIO_ROOT_USER=cletest -e MINIO_ROOT_PASSWORD=secrettest123 \
  quay.io/minio/minio server /data >/dev/null
sleep 6
docker run --rm --network "$RESEAU" --entrypoint sh quay.io/minio/mc -c \
  'mc alias set m http://'"$MINIO"':9000 cletest secrettest123 >/dev/null 2>&1; mc mb m/mcp-tools >/dev/null 2>&1; true'

echo "== Démarrage du service =="
# TTL et grâce à 1s : la fenêtre par défaut est de 600s, inutilisable ici.
# Seule la DURÉE change, jamais le comportement observé.
docker run -d --name "$SVC" --network "$RESEAU" -p "$PORT:8050" \
  -e ADMIN_BOOTSTRAP_KEY="$CLE" \
  -e S3_ENDPOINT_URL="http://$MINIO:9000" \
  -e S3_ACCESS_KEY_ID=cletest -e S3_SECRET_ACCESS_KEY=secrettest123 \
  -e S3_BUCKET_NAME=mcp-tools -e S3_REGION_NAME=us-east-1 \
  -e TOKEN_STORE_CACHE_TTL=1 -e TOKEN_STORE_STALE_GRACE=1 \
  "$IMAGE" >/dev/null
for _ in $(seq 1 20); do
  [ "$(docker inspect -f '{{.State.Health.Status}}' "$SVC" 2>/dev/null)" = "healthy" ] && break
  sleep 3
done
attendu "service en bonne santé" "$(docker inspect -f '{{.State.Health.Status}}' "$SVC")" healthy

echo "== Création d'un token =="
REPONSE="$(curl -s -X POST "http://localhost:$PORT/admin/api/tokens" \
  -H "Authorization: Bearer $CLE" -H 'Content-Type: application/json' \
  -d '{"client_name":"sonde-panne","permissions":["access"],"tool_ids":["calc"],"expires_days":1}')"
TOKEN="$(printf '%s' "$REPONSE" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("token",""))')"
if [ -z "$TOKEN" ]; then
  echo "  KO   création du token impossible : $REPONSE"
  exit 1
fi

echo "== A. S3 debout =="
attendu "token valide" "$(statut "$TOKEN" /admin/api/me)" 200
attendu "token inconnu" "$(statut jenexistepas /admin/api/me)" 401

echo "== B. S3 éteint =="
docker stop "$MINIO" >/dev/null
sleep 5
attendu "token valide, magasin injoignable" "$(statut "$TOKEN" /admin/api/me)" 503
attendu "clé bootstrap (diagnostic possible)" "$(statut "$CLE" /admin/api/me)" 200
attendu "/health" "$(curl -s -o /dev/null -w '%{http_code}' "http://localhost:$PORT/health")" 200
REV="$(curl -s -X DELETE -H "Authorization: Bearer $CLE" "http://localhost:$PORT/admin/api/tokens/sonde-panne")"
case "$REV" in
  *indisponible*) printf '  ok   %-46s refusée\n' "révocation pendant la panne" ;;
  *) printf '  KO   %-46s %s\n' "révocation pendant la panne" "$REV"; echec=1 ;;
esac

echo "== C. S3 revenu =="
docker start "$MINIO" >/dev/null
sleep 8
attendu "token valide, sans redémarrage du service" "$(statut "$TOKEN" /admin/api/me)" 200

echo "== D. Révocation réelle =="
REV="$(curl -s -X DELETE -H "Authorization: Bearer $CLE" "http://localhost:$PORT/admin/api/tokens/sonde-panne")"
case "$REV" in
  *success*) printf '  ok   %-46s succès\n' "révocation" ;;
  *) printf '  KO   %-46s %s\n' "révocation" "$REV"; echec=1 ;;
esac
sleep 3
attendu "token après révocation" "$(statut "$TOKEN" /admin/api/me)" 401

echo
if [ "$echec" -eq 0 ]; then
  echo "TOUT PASSE"
else
  echo "AU MOINS UN CONTRÔLE A ÉCHOUÉ"
fi
exit "$echec"
