# -*- coding: utf-8 -*-
"""
Token Store — Gestion des tokens MCP avec stockage S3 + cache mémoire.

Architecture :
  - Tokens stockés en S3 sous _tokens/{sha256_hash}.json
  - Cache in-memory avec TTL (5 min par défaut)
  - SHA-256 hash comme filename (token brut jamais stocké en S3)
  - Config hybride SigV2/SigV4 pour Dell ECS Cloud Temple

Opérations :
  - create   : Génère un token aléatoire, stocke le hash en S3
  - list     : Liste tous les tokens (sans valeur brute)
  - info     : Détails d'un token par client_name
  - revoke   : Supprime un token par client_name
  - validate : Vérifie un token brut et retourne ses infos

Comportement en panne
---------------------
Ce magasin échoue en FERMÉ. Quand S3 devient injoignable, le cache déjà chargé
reste servi pendant `TOKEN_STORE_CACHE_TTL + TOKEN_STORE_STALE_GRACE`, puis
`validate_token` lève `TokenStoreUnavailable` et l'appelant rend un 503. Servir
un cache indéfiniment reviendrait à ignorer les révocations pour toute la durée
de la panne, sans qu'aucun signal ne le dise.

`TOKEN_STORE_FAIL_MODE=fail_open` lève cette limite, au prix explicite de
révocations ignorées tant que la panne dure. `TOKEN_STORE_CACHE_TTL=0` interdit
au contraire de servir depuis le cache, et l'emporte sur `fail_open`.

Ce que ce magasin ne résout pas
-------------------------------
La cohérence ENTRE instances. Chaque processus a son propre cache et son propre
registre de révocations incertaines. Une révocation faite sur une instance ne
parvient aux autres qu'au rechargement suivant de leur cache, donc au plus tard
au bout d'un TTL. Un objet S3 par token évite en revanche le lost-update qui
frappe les magasins à fichier unique : deux mutations portant sur des tokens
différents ne se marchent jamais dessus.
"""

import hashlib
import json
import re
import secrets
import sys
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Tuple

TOKENS_PREFIX = "_tokens/"
CACHE_TTL = 300  # 5 minutes

# Bornes du délai d'attente entre deux tentatives S3 pendant une panne.
BACKOFF_MIN = 1.0
BACKOFF_MAX = 60.0

# Le nom de l'objet EST le hash. Toute entrée dont le contenu ne le confirme
# pas est écartée : elle ne peut plus être authentifiée de façon fiable.
_HASH_RE = re.compile(r"^[0-9a-f]{64}$")

_CODES_OBJET_ABSENT = {"NoSuchKey", "NotFound", "404"}


class TokenStoreUnavailable(RuntimeError):
    """Le magasin de tokens ne peut pas être consulté de façon fiable.

    Ne pas pouvoir vérifier un accès n'est pas la même chose que le refuser :
    l'appelant doit rendre 503, pas 401. Un 401 ferait croire à un token
    invalide et pousserait le client à en demander un autre.
    """


def _est_objet_absent(error: Exception) -> bool:
    """Vrai si l'erreur boto3 signifie « cet objet n'existe pas ».

    La détection se fait sur le code d'erreur structuré et sur le statut HTTP,
    jamais sur le texte du message : un message dépend de la version de botocore
    et de la langue du serveur, et le confondre avec une panne réseau
    transformerait une panne en absence, donc un fail-close en fail-open.
    """
    reponse = getattr(error, "response", None)
    if not isinstance(reponse, dict):
        return False
    code = reponse.get("Error", {}).get("Code")
    if code in _CODES_OBJET_ABSENT:
        return True
    statut = reponse.get("ResponseMetadata", {}).get("HTTPStatusCode")
    return statut == 404


class TokenStore:
    """Gestionnaire de tokens avec backend S3 et cache mémoire."""

    def __init__(self, settings):
        self.settings = settings
        self._cache: Dict[str, dict] = {}  # token_hash -> token_data
        # None tant qu'aucun chargement n'a abouti. Un 0.0 serait ambigu :
        # `time.monotonic()` ne part pas de zéro, et sur un conteneur fraîchement
        # démarré un cache jamais chargé aurait paru récent.
        self._cache_loaded_at: Optional[float] = None
        self._s3_available: bool = False
        # Panne en cours : ne pas retenter S3 à chaque requête entrante.
        self._backoff: float = 0.0
        self._backoff_until: float = 0.0
        self._last_error: Optional[str] = None
        # Un delete_object en échec est ambigu : il a pu aboutir côté serveur.
        # Le token est refusé localement et les rechargements ne le
        # réintroduisent pas, jusqu'à ce qu'un listing confirme son absence.
        self._revocations_incertaines: set = set()
        # Les mutations sont des lire-modifier-écrire. Les sérialiser évite
        # qu'un rechargement concurrent remplace `_cache` entre la lecture et
        # l'écriture. Réentrant : les mutations appellent `_maybe_refresh_cache`,
        # qui prend le même verrou.
        self._lock = threading.RLock()
        self._clients: Optional[Tuple[object, object]] = None

    # =========================================================================
    # Réglages
    # =========================================================================

    @property
    def s3_configured(self) -> bool:
        return bool(self.settings.s3_endpoint_url and self.settings.s3_access_key_id)

    @property
    def cache_ttl(self) -> int:
        """TTL du cache, lu dans la configuration et non figé à 300s."""
        try:
            return max(0, int(getattr(self.settings, "token_store_cache_ttl", CACHE_TTL)))
        except (TypeError, ValueError):
            return CACHE_TTL

    @property
    def fail_mode(self) -> str:
        """`fail_close` (défaut) ou `fail_open`. Lu à chaud, jamais deviné."""
        mode = getattr(self.settings, "token_store_fail_mode", "fail_close")
        return "fail_open" if str(mode).lower() == "fail_open" else "fail_close"

    @property
    def stale_grace(self) -> int:
        """Durée pendant laquelle un cache périmé reste servi malgré la panne."""
        try:
            return max(0, int(getattr(self.settings, "token_store_stale_grace", 300)))
        except (TypeError, ValueError):
            return 300

    # =========================================================================
    # S3 helpers
    # =========================================================================

    def _get_s3_clients(self):
        """Clients boto3 SigV2 (data) et SigV4 (metadata), construits une fois.

        Les construire à chaque appel coûtait une résolution de configuration
        complète par requête entrante pendant une panne, quand
        `_maybe_refresh_cache` retentait sans relâche.
        """
        if self._clients is not None:
            return self._clients

        import boto3
        from botocore.config import Config as BotoConfig

        config_v2 = BotoConfig(
            region_name=self.settings.s3_region_name,
            signature_version="s3",
            s3={"addressing_style": "path"},
            retries={"max_attempts": 3, "mode": "adaptive"},
            connect_timeout=10,
            read_timeout=30,
        )
        config_v4 = BotoConfig(
            region_name=self.settings.s3_region_name,
            signature_version="s3v4",
            s3={"addressing_style": "path", "payload_signing_enabled": False},
            retries={"max_attempts": 3, "mode": "adaptive"},
            connect_timeout=10,
            read_timeout=30,
        )

        kwargs = dict(
            endpoint_url=self.settings.s3_endpoint_url,
            aws_access_key_id=self.settings.s3_access_key_id,
            aws_secret_access_key=self.settings.s3_secret_access_key,
        )

        self._clients = (
            boto3.client("s3", config=config_v2, **kwargs),
            boto3.client("s3", config=config_v4, **kwargs),
        )
        return self._clients

    def _s3_key(self, token_hash: str) -> str:
        return f"{TOKENS_PREFIX}{token_hash}.json"

    # =========================================================================
    # Crypto helpers
    # =========================================================================

    @staticmethod
    def hash_token(token: str) -> str:
        """SHA-256 du token brut."""
        return hashlib.sha256(token.encode()).hexdigest()

    @staticmethod
    def generate_token() -> str:
        """Génère un token aléatoire URL-safe de 43 chars."""
        return secrets.token_urlsafe(32)

    # =========================================================================
    # Suivi de panne
    # =========================================================================

    def _note_failure(self, error: Exception) -> None:
        self._last_error = str(error)
        # Redescend à faux, et c'est ce qui rend `_exiger_s3` utile. Sans cette
        # ligne, le drapeau passait à vrai au premier chargement réussi et n'en
        # redescendait jamais : la garde des mutations gardait un état que rien
        # ne pouvait produire.
        self._s3_available = False
        self._backoff = min(max(self._backoff * 2, BACKOFF_MIN), BACKOFF_MAX)
        self._backoff_until = time.monotonic() + self._backoff
        print(
            f"  ⚠️  Token Store: {error} (nouvel essai dans {self._backoff:.0f}s)",
            file=sys.stderr,
            flush=True,
        )

    def _clear_failure(self) -> None:
        self._backoff = 0.0
        self._backoff_until = 0.0
        self._last_error = None

    def _age(self) -> Optional[float]:
        """Âge du cache en secondes, ou None s'il n'a jamais été chargé."""
        if self._cache_loaded_at is None:
            return None
        return time.monotonic() - self._cache_loaded_at

    # =========================================================================
    # Lecture S3
    # =========================================================================

    def _entree_valide(self, key: str, brut: bytes, ignores: List[str]) -> Optional[dict]:
        """Valide une entrée lue depuis S3, ou l'écarte en le disant.

        Une entrée écartée cesse d'authentifier : c'est le sens fermé. La
        laisser entrer avec des valeurs par défaut reviendrait à fabriquer un
        token à partir d'un objet corrompu.
        """
        attendu = key[len(TOKENS_PREFIX):-len(".json")]
        try:
            data = json.loads(brut.decode())
        except (UnicodeDecodeError, json.JSONDecodeError):
            ignores.append(f"{key}: contenu illisible")
            return None
        if not isinstance(data, dict):
            ignores.append(f"{key}: objet JSON attendu")
            return None
        token_hash = data.get("token_hash")
        if not isinstance(token_hash, str) or not _HASH_RE.match(token_hash):
            ignores.append(f"{key}: token_hash absent ou mal formé")
            return None
        if token_hash != attendu:
            ignores.append(f"{key}: token_hash ne correspond pas au nom de l'objet")
            return None
        permissions = data.get("permissions")
        if not isinstance(permissions, list) or not all(isinstance(p, str) for p in permissions):
            ignores.append(f"{key}: permissions absentes ou mal formées")
            return None
        return data

    def _lire_tout(self) -> Tuple[Dict[str, dict], List[str]]:
        """Lit tous les tokens depuis S3. Rend (entrées, écartées), ou lève.

        Un échec de lecture n'est JAMAIS traité comme un magasin vide : un
        magasin vide et un magasin illisible ont des conséquences opposées, et
        les confondre affichait « 0 token(s) chargés » comme une réussite
        pendant que tout le monde recevait 401.
        """
        client_v2, client_v4 = self._get_s3_clients()
        entrees: Dict[str, dict] = {}
        ignores: List[str] = []
        continuation: Optional[str] = None

        while True:
            kwargs = {
                "Bucket": self.settings.s3_bucket_name,
                "Prefix": TOKENS_PREFIX,
            }
            if continuation:
                kwargs["ContinuationToken"] = continuation
            resp = client_v4.list_objects_v2(**kwargs)

            for obj in resp.get("Contents", []):
                key = obj["Key"]
                if not key.endswith(".json"):
                    continue
                try:
                    r = client_v2.get_object(
                        Bucket=self.settings.s3_bucket_name, Key=key
                    )
                    brut = r["Body"].read()
                except Exception as e:
                    if _est_objet_absent(e):
                        # Révoqué entre le listing et la lecture. Ce n'est pas
                        # une panne, c'est une course normale.
                        continue
                    raise TokenStoreUnavailable(
                        f"lecture de {key} impossible : {e}"
                    ) from e
                data = self._entree_valide(key, brut, ignores)
                if data is not None:
                    entrees[data["token_hash"]] = data

            # `list_objects_v2` rend au plus 1000 clés. Sans cette boucle, les
            # tokens au-delà disparaissaient du cache sans aucun signal.
            if not resp.get("IsTruncated"):
                break
            continuation = resp.get("NextContinuationToken")
            if not continuation:
                break

        return entrees, ignores

    def _migrer_permissions(self, entrees: Dict[str, dict]) -> List[str]:
        """Remplace les permissions legacy read/write par access.

        Une entrée n'est modifiée en mémoire QUE si S3 a accepté l'écriture.
        Muter d'abord et écrire ensuite laissait, sur échec, un cache qui
        affirmait une chose que le magasin ne portait pas.
        """
        client_v2, _ = self._get_s3_clients()
        migres = 0
        echecs: List[str] = []

        for token_hash, data in list(entrees.items()):
            anciennes = data.get("permissions", [])
            if "read" not in anciennes and "write" not in anciennes:
                continue

            nouvelles = (["admin"] if "admin" in anciennes else []) + ["access"]
            copie = dict(data)
            copie["permissions"] = nouvelles

            try:
                client_v2.put_object(
                    Bucket=self.settings.s3_bucket_name,
                    Key=self._s3_key(token_hash),
                    Body=json.dumps(copie, indent=2).encode(),
                    ContentType="application/json",
                )
            except Exception as e:
                echecs.append(f"{data.get('client_name', '?')}: {e}")
                continue

            entrees[token_hash] = copie
            migres += 1

        if migres:
            print(
                f"  🔄 Token Store: {migres} token(s) migrés (read/write → access)",
                file=sys.stderr,
                flush=True,
            )
        for echec in echecs:
            print(
                f"  ⚠️  Token Store: migration non persistée — {echec}",
                file=sys.stderr,
                flush=True,
            )
        return echecs

    def _recharger(self) -> None:
        """Recharge le cache depuis S3. Lève `TokenStoreUnavailable` si S3 ment.

        Le cache n'est remplacé qu'après une lecture complète et réussie :
        l'ancien contenu reste disponible tant que le nouveau n'est pas sûr.
        """
        try:
            entrees, ignores = self._lire_tout()
        except TokenStoreUnavailable as e:
            self._note_failure(e)
            raise
        except Exception as e:
            erreur = TokenStoreUnavailable(
                f"chargement du magasin de tokens impossible : {e}"
            )
            self._note_failure(erreur)
            raise erreur from e

        self._migrer_permissions(entrees)

        # Une révocation au sort incertain ne se réintroduit jamais par un
        # rechargement. Elle ne se lève que lorsque S3 confirme l'absence.
        for token_hash in list(self._revocations_incertaines):
            if token_hash in entrees:
                entrees.pop(token_hash, None)
            else:
                self._revocations_incertaines.discard(token_hash)

        self._cache = entrees
        self._cache_loaded_at = time.monotonic()
        self._s3_available = True
        self._clear_failure()

        print(
            f"  🔑 Token Store: {len(self._cache)} token(s) chargés depuis S3",
            file=sys.stderr,
            flush=True,
        )
        for ignore in ignores:
            print(
                f"  ⚠️  Token Store: entrée écartée — {ignore}",
                file=sys.stderr,
                flush=True,
            )

    # =========================================================================
    # Initialisation / cache
    # =========================================================================

    def initialize(self) -> None:
        """Charge tous les tokens depuis S3 dans le cache. Appelé au démarrage."""
        if not self.s3_configured:
            print(
                "  ⚠️  Token Store: S3 non configuré — seul le bootstrap key fonctionne",
                file=sys.stderr,
                flush=True,
            )
            return
        with self._lock:
            self._recharger()

    def _maybe_refresh_cache(self) -> None:
        """Rafraîchit le cache si le TTL est dépassé, ou garde la porte fermée.

        Ne dépend plus de `_s3_available` : ce drapeau restait faux à vie quand
        S3 était injoignable au démarrage, et le magasin ne se réparait alors
        jamais, même une fois S3 revenu.
        """
        if not self.s3_configured:
            return

        with self._lock:
            age = self._age()
            # `self.cache_ttl > 0` d'abord, et ce n'est pas une précaution de
            # style. Avec un TTL nul, `age <= 0` est vrai juste après un
            # chargement : la condition rendait la main et servait le cache que
            # l'exploitant venait justement d'interdire. Un TTL nul veut dire
            # « recharger à chaque consultation », donc ne jamais court-circuiter.
            if self.cache_ttl > 0 and age is not None and age <= self.cache_ttl:
                return
            if time.monotonic() < self._backoff_until:
                self._garde_cache_perime(age)
                return
            try:
                self._recharger()
            except TokenStoreUnavailable:
                self._garde_cache_perime(self._age())

    def _garde_cache_perime(self, age: Optional[float]) -> None:
        """Décide si un cache périmé peut encore servir pendant une panne."""
        cause = self._last_error or "cause inconnue"

        # Testé en premier, et l'ordre est le fond du sujet : un TTL nul est un
        # refus explicite de servir depuis le cache, et `fail_open` ne doit pas
        # rouvrir par une autre porte ce que l'exploitant vient de fermer. Entre
        # deux réglages qui se contredisent, on retient le plus restrictif.
        if self.cache_ttl == 0:
            raise TokenStoreUnavailable(
                "magasin de tokens injoignable et TOKEN_STORE_CACHE_TTL=0 "
                f"interdit de servir depuis le cache : accès refusé ({cause})"
            )

        # Avant `fail_open` également : il n'y a rien à servir. Rendre 503 dit
        # la vérité, là où un cache vide aurait rendu 401 à tout le monde et
        # poussé les clients à remplacer des tokens valides.
        if age is None:
            raise TokenStoreUnavailable(
                "magasin de tokens jamais chargé et injoignable : "
                f"accès refusé ({cause})"
            )

        if self.fail_mode == "fail_open":
            return

        if age <= self.cache_ttl + self.stale_grace:
            return

        raise TokenStoreUnavailable(
            f"magasin de tokens injoignable depuis {age:.0f}s, "
            f"au-delà de la fenêtre de {self.stale_grace}s : "
            f"accès refusé ({cause})"
        )

    def _exiger_s3(self) -> Optional[dict]:
        """Rend une erreur si une mutation ne peut pas être persistée."""
        if not self.s3_configured:
            return {
                "status": "error",
                "message": "S3 non configuré — mutation impossible.",
            }
        if not self._s3_available:
            return {
                "status": "error",
                "message": "S3 indisponible — mutation impossible.",
            }
        return None

    # =========================================================================
    # Validation (appelé par le middleware)
    # =========================================================================

    @staticmethod
    def _expiration(expires_at) -> Tuple[bool, bool]:
        """Rend (expiré, date_invalide) pour une valeur `expires_at` brute."""
        if expires_at is None:
            return False, False
        if not isinstance(expires_at, str):
            return True, True
        try:
            exp = datetime.fromisoformat(expires_at)
        except ValueError:
            return True, True
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        return exp < datetime.now(timezone.utc), False

    def validate_token(self, token: str) -> Optional[dict]:
        """
        Valide un token brut et retourne ses infos, ou None si invalide.
        Vérifie l'expiration.

        Lève `TokenStoreUnavailable` quand le magasin ne peut plus être
        consulté de façon fiable. L'appelant rend alors 503, pas 401.
        """
        self._maybe_refresh_cache()

        token_hash = self.hash_token(token)
        if token_hash in self._revocations_incertaines:
            return None

        info = self._cache.get(token_hash)
        if info is None:
            return None

        # Une date d'expiration illisible ferme la porte. Un `pass` ici
        # acceptait le token : la seule protection contre un token périmé
        # disparaissait dès que sa date était corrompue.
        expire, _invalide = self._expiration(info.get("expires_at"))
        if expire:
            return None

        return {
            "client_name": info.get("client_name", "unknown"),
            "permissions": list(info.get("permissions") or []),
            "tool_ids": info.get("tool_ids", []),
        }

    # =========================================================================
    # CRUD operations (appelées par le tool token)
    # =========================================================================

    def create(
        self,
        client_name: str,
        permissions: List[str],
        tool_ids: List[str],
        expires_days: int = 90,
        created_by: str = "admin",
        email: str = "",
    ) -> dict:
        """
        Crée un nouveau token. Retourne le token brut (affiché une seule fois).
        """
        with self._lock:
            # Le rafraîchissement passe AVANT la garde de disponibilité : il
            # est ce qui rétablit `_s3_available` quand S3 est revenu. L'ordre
            # inverse refusait la mutation tant qu'aucun rechargement n'avait
            # eu lieu, alors même que S3 répondait.
            #
            # Et sans lui, un cache périmé laissait créer un second token pour
            # un client_name déjà servi : l'unicité n'était vérifiée que contre
            # une photo ancienne du magasin.
            self._maybe_refresh_cache()

            indisponible = self._exiger_s3()
            if indisponible is not None:
                return indisponible

            for data in self._cache.values():
                if data.get("client_name") == client_name:
                    return {
                        "status": "error",
                        "message": f"Un token existe déjà pour '{client_name}'. Révoquez-le d'abord.",
                    }

            raw_token = self.generate_token()
            token_hash = self.hash_token(raw_token)

            now = datetime.now(timezone.utc)
            expires = now + timedelta(days=expires_days) if expires_days > 0 else None

            token_data = {
                "token_hash": token_hash,
                "client_name": client_name,
                "email": email,
                "permissions": permissions,
                "tool_ids": tool_ids,
                "created_at": now.isoformat(),
                "expires_at": expires.isoformat() if expires else None,
                "created_by": created_by,
            }

            try:
                client_v2, _ = self._get_s3_clients()
                client_v2.put_object(
                    Bucket=self.settings.s3_bucket_name,
                    Key=self._s3_key(token_hash),
                    Body=json.dumps(token_data, indent=2).encode(),
                    ContentType="application/json",
                )
            except Exception as e:
                return {"status": "error", "message": f"Erreur S3 lors de la création : {e}"}

            self._cache[token_hash] = token_data

            return {
                "status": "success",
                "token": raw_token,  # ⚠️ Affiché UNE SEULE FOIS
                "token_hash": token_hash[:16] + "...",
                "client_name": client_name,
                "email": email,
                "permissions": permissions,
                "tool_ids": tool_ids,
                "expires_at": expires.isoformat() if expires else None,
                "message": f"Token créé pour '{client_name}'. ⚠️ Sauvegardez le token, il ne sera plus affiché !",
            }

    def _vue(self, data: dict) -> dict:
        """Représentation d'un token pour la console, sans valeur brute."""
        expire, date_invalide = self._expiration(data.get("expires_at"))
        return {
            "client_name": data.get("client_name", "?"),
            "email": data.get("email", ""),
            "permissions": data.get("permissions", []),
            "tool_ids": data.get("tool_ids", []),
            "created_at": data.get("created_at", "?"),
            "expires_at": data.get("expires_at"),
            "expired": expire,
            # La console montrait « valide » pour un token que
            # `validate_token` refuse. Ce drapeau rend l'écart visible.
            "date_invalide": date_invalide,
            "created_by": data.get("created_by", "?"),
            "token_hash_prefix": data.get("token_hash", "?")[:16] + "...",
        }

    def list_tokens(self) -> dict:
        """Liste tous les tokens (sans valeur brute)."""
        self._maybe_refresh_cache()

        tokens = [self._vue(data) for data in self._cache.values()]
        tokens.sort(key=lambda t: t.get("created_at", ""), reverse=True)

        return {
            "status": "success",
            "count": len(tokens),
            "tokens": tokens,
        }

    def info(self, client_name: str) -> dict:
        """Détails d'un token par client_name."""
        self._maybe_refresh_cache()

        for data in self._cache.values():
            if data.get("client_name") == client_name:
                vue = self._vue(data)
                vue["status"] = "success"
                return vue

        return {"status": "error", "message": f"Token '{client_name}' non trouvé."}

    def update(
        self,
        client_name: str,
        permissions: Optional[List[str]] = None,
        tool_ids: Optional[List[str]] = None,
        email: Optional[str] = None,
    ) -> dict:
        """
        Met à jour un token existant (permissions, tool_ids, email).
        Seuls les champs fournis (non-None) sont modifiés.
        """
        with self._lock:
            self._maybe_refresh_cache()

            indisponible = self._exiger_s3()
            if indisponible is not None:
                return indisponible

            target_hash = None
            actuel = None
            for h, data in self._cache.items():
                if data.get("client_name") == client_name:
                    target_hash = h
                    actuel = data
                    break

            if target_hash is None or actuel is None:
                return {"status": "error", "message": f"Token '{client_name}' non trouvé."}

            # Une COPIE, et c'est tout le sujet. Muter l'entrée du cache avant
            # l'écriture S3 rendait une élévation de privilèges active en
            # mémoire alors même que la méthode rendait une erreur.
            copie = dict(actuel)

            changes = []
            if permissions is not None:
                old = actuel.get("permissions", [])
                copie["permissions"] = permissions
                changes.append(f"permissions: {old} → {permissions}")
            if tool_ids is not None:
                old = actuel.get("tool_ids", [])
                copie["tool_ids"] = tool_ids
                changes.append(f"tool_ids: {len(old)} → {len(tool_ids)} outils")
            if email is not None:
                old = actuel.get("email", "")
                copie["email"] = email
                changes.append(f"email: '{old}' → '{email}'")

            if not changes:
                return {"status": "error", "message": "Aucun champ à modifier spécifié."}

            try:
                client_v2, _ = self._get_s3_clients()
                client_v2.put_object(
                    Bucket=self.settings.s3_bucket_name,
                    Key=self._s3_key(target_hash),
                    Body=json.dumps(copie, indent=2).encode(),
                    ContentType="application/json",
                )
            except Exception as e:
                return {"status": "error", "message": f"Erreur S3 lors de la mise à jour : {e}"}

            self._cache[target_hash] = copie

            return {
                "status": "success",
                "client_name": client_name,
                "permissions": copie.get("permissions", []),
                "tool_ids": copie.get("tool_ids", []),
                "email": copie.get("email", ""),
                "changes": changes,
                "message": f"Token '{client_name}' mis à jour : {'; '.join(changes)}",
            }

    def _supprimer(self, token_hash: str) -> Tuple[bool, Optional[str]]:
        """Supprime un objet token en S3. Rend (certain, message d'erreur).

        `certain` est faux quand le sort de la suppression est indéterminé :
        le token est alors refusé localement et inscrit au registre des
        révocations incertaines, que les rechargements respectent.
        """
        client_v2, _ = self._get_s3_clients()
        try:
            client_v2.delete_object(
                Bucket=self.settings.s3_bucket_name,
                Key=self._s3_key(token_hash),
            )
        except Exception as e:
            if _est_objet_absent(e):
                # Déjà absent : la révocation est un fait, pas une incertitude.
                return True, None
            self._revocations_incertaines.add(token_hash)
            return False, str(e)
        return True, None

    def revoke(self, client_name: str) -> dict:
        """Révoque (supprime) un token par client_name."""
        with self._lock:
            self._maybe_refresh_cache()

            indisponible = self._exiger_s3()
            if indisponible is not None:
                # Supprimer du seul cache local aurait annoncé un succès pour
                # une révocation que personne d'autre ne verrait jamais.
                return indisponible

            target_hash = None
            for h, data in self._cache.items():
                if data.get("client_name") == client_name:
                    target_hash = h
                    break

            if target_hash is None:
                return {"status": "error", "message": f"Token '{client_name}' non trouvé."}

            certain, erreur = self._supprimer(target_hash)
            self._cache.pop(target_hash, None)

            if not certain:
                return {
                    "status": "error",
                    "client_name": client_name,
                    "message": (
                        f"Révocation INCERTAINE pour '{client_name}' : {erreur}. "
                        "Le token est refusé par cette instance, mais il peut "
                        "subsister en S3 et rester accepté ailleurs. "
                        "Relancer la révocation une fois S3 rétabli."
                    ),
                }

            self._revocations_incertaines.discard(target_hash)
            return {
                "status": "success",
                "client_name": client_name,
                "message": f"Token '{client_name}' révoqué.",
            }

    def purge_expired(self) -> dict:
        """
        Supprime tous les tokens expirés de S3 et du cache.
        Retourne le nombre de tokens purgés.
        """
        with self._lock:
            self._maybe_refresh_cache()

            indisponible = self._exiger_s3()
            if indisponible is not None:
                return indisponible

            a_purger = []
            for token_hash, data in self._cache.items():
                expire, _invalide = self._expiration(data.get("expires_at"))
                if expire:
                    a_purger.append((token_hash, data.get("client_name", "?")))

            if not a_purger:
                return {
                    "status": "success",
                    "purged": 0,
                    "message": "Aucun token expiré à purger.",
                }

            purged = []
            incertains = []

            for token_hash, nom in a_purger:
                certain, erreur = self._supprimer(token_hash)
                self._cache.pop(token_hash, None)
                if certain:
                    self._revocations_incertaines.discard(token_hash)
                    purged.append(nom)
                else:
                    incertains.append(f"{nom}: {erreur}")

            return {
                "status": "success" if not incertains else "error",
                "purged": len(purged),
                "purged_clients": purged,
                "errors": incertains,
                "message": (
                    f"{len(purged)} token(s) expiré(s) purgé(s)."
                    if not incertains
                    else (
                        f"{len(purged)} token(s) purgé(s), "
                        f"{len(incertains)} révocation(s) INCERTAINE(s) : "
                        + "; ".join(incertains)
                    )
                ),
            }


# =============================================================================
# Singleton global
# =============================================================================

_token_store: Optional[TokenStore] = None


def get_token_store() -> TokenStore:
    """Retourne le singleton TokenStore."""
    global _token_store
    if _token_store is None:
        from ..config import get_settings
        _token_store = TokenStore(get_settings())
    return _token_store


def init_token_store() -> TokenStore:
    """Initialise le TokenStore (charge les tokens depuis S3).

    Une panne au démarrage ne tue pas le serveur : la console, `/health` et la
    clé bootstrap doivent rester joignables pour diagnostiquer. Le magasin
    reste en revanche fermé, puisqu'il n'a jamais rien chargé.
    """
    store = get_token_store()
    try:
        store.initialize()
    except TokenStoreUnavailable as e:
        print(
            f"  ⚠️  Token Store: démarrage sans magasin — {e}",
            file=sys.stderr,
            flush=True,
        )
    return store
