# -*- coding: utf-8 -*-
"""
Magasin de tokens : comportement en panne, intégrité du chargement, mutations.

Ce que ces tests épinglent, et pourquoi il fallait les écrire
-------------------------------------------------------------
Le magasin échoue désormais en FERMÉ. Chaque test ci-dessous correspond à un
chemin par lequel une panne, une corruption ou une course rendait auparavant un
accès accordé, un succès annoncé, ou un magasin vide présenté comme sain. Aucun
ne se contente de vérifier qu'un appel réussit dans le cas nominal : la table
de mutations de la PR montre, correctif par correctif, quelle assertion tombe
quand on remet le comportement d'origine.

Deux tests font exception et le disent : `test_la_cle_bootstrap_...` et
`test_le_verrou_...` épinglent des décisions de conception qui n'ont pas changé.
Ils passent aussi contre l'ancien code. Ils servent de garde, pas de preuve.
"""

import json
import sys
import threading
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.mcp_tools.auth import token_store as ts
from src.mcp_tools.auth.token_store import TokenStore, TokenStoreUnavailable


# =============================================================================
# Harnais
# =============================================================================


class ErreurS3(Exception):
    """Erreur boto3 minimale, avec la forme `response` que le code inspecte."""

    def __init__(self, code=None, statut=None, message="panne"):
        super().__init__(message)
        self.response = {
            "Error": {"Code": code} if code else {},
            "ResponseMetadata": {"HTTPStatusCode": statut} if statut else {},
        }


class Corps:
    def __init__(self, donnees: bytes):
        self._donnees = donnees

    def read(self):
        return self._donnees


class FauxS3:
    """Backend S3 en mémoire, dont chaque opération peut être mise en panne.

    `pannes` porte une exception par opération. La poser après un chargement
    réussi reproduit exactement le scénario qui comptait : le magasin a déjà
    servi, puis S3 tombe.
    """

    def __init__(self, objets=None, taille_page=1000):
        self.objets = dict(objets or {})
        self.pannes = {}
        self.appels = {"list": 0, "get": 0, "put": 0, "delete": 0}
        self.taille_page = taille_page

    def _peut_etre_lever(self, operation):
        erreur = self.pannes.get(operation)
        if erreur is not None:
            raise erreur

    def list_objects_v2(self, Bucket=None, Prefix="", ContinuationToken=None, **kw):
        self.appels["list"] += 1
        self._peut_etre_lever("list")
        cles = sorted(k for k in self.objets if k.startswith(Prefix))
        debut = int(ContinuationToken) if ContinuationToken else 0
        page = cles[debut:debut + self.taille_page]
        suite = debut + self.taille_page
        tronque = suite < len(cles)
        resp = {"Contents": [{"Key": k} for k in page], "IsTruncated": tronque}
        if tronque:
            resp["NextContinuationToken"] = str(suite)
        return resp

    def get_object(self, Bucket=None, Key=None):
        self.appels["get"] += 1
        self._peut_etre_lever("get")
        if Key not in self.objets:
            raise ErreurS3(code="NoSuchKey", statut=404)
        return {"Body": Corps(self.objets[Key])}

    def put_object(self, Bucket=None, Key=None, Body=None, ContentType=None):
        self.appels["put"] += 1
        self._peut_etre_lever("put")
        self.objets[Key] = Body
        return {}

    def delete_object(self, Bucket=None, Key=None):
        self.appels["delete"] += 1
        self._peut_etre_lever("delete")
        self.objets.pop(Key, None)
        return {}


class Reglages:
    def __init__(self, **surcharges):
        self.s3_endpoint_url = "https://s3.test"
        self.s3_access_key_id = "cle"
        self.s3_secret_access_key = "secret"
        self.s3_bucket_name = "seau"
        self.s3_region_name = "fr1"
        self.token_store_cache_ttl = 300
        self.token_store_stale_grace = 300
        self.token_store_fail_mode = "fail_close"
        self.admin_bootstrap_key = "cle-bootstrap-de-test"
        self.__dict__.update(surcharges)


class Horloge:
    """Horloge monotone pilotée, pour franchir un TTL sans attendre."""

    def __init__(self, depart=1000.0):
        self.t = depart

    def __call__(self):
        return self.t

    def avancer(self, secondes):
        self.t += secondes


def entree(client_name, token_hash=None, permissions=None, expires_at="ABSENT",
           tool_ids=None, **extra):
    h = token_hash or TokenStore.hash_token(client_name)
    data = {
        "token_hash": h,
        "client_name": client_name,
        "email": "",
        "permissions": permissions if permissions is not None else ["access"],
        "tool_ids": tool_ids if tool_ids is not None else [],
        "created_at": "2026-01-01T00:00:00+00:00",
        "created_by": "test",
    }
    if expires_at != "ABSENT":
        data["expires_at"] = expires_at
    else:
        data["expires_at"] = (
            datetime.now(timezone.utc) + timedelta(days=30)
        ).isoformat()
    data.update(extra)
    return h, data


def objets(*entrees):
    return {
        f"{ts.TOKENS_PREFIX}{h}.json": json.dumps(d).encode()
        for h, d in entrees
    }


class MagasinMixin:
    def monter(self, objets_s3=None, horloge=None, **reglages):
        self.s3 = FauxS3(objets_s3)
        self.horloge = horloge or Horloge()
        patch_horloge = mock.patch.object(ts.time, "monotonic", self.horloge)
        patch_horloge.start()
        self.addCleanup(patch_horloge.stop)

        store = TokenStore(Reglages(**reglages))
        store._clients = (self.s3, self.s3)
        # La sortie d'erreur du magasin est volontairement bavarde en
        # production. Elle n'apporte rien au diagnostic d'un test qui échoue.
        patch_sortie = mock.patch.object(ts.sys, "stderr", open("/dev/null", "w"))
        patch_sortie.start()
        self.addCleanup(patch_sortie.stop)
        return store


# =============================================================================
# D1 — le fail-open sans borne
# =============================================================================


class PanneApresDemarrage(MagasinMixin, unittest.TestCase):

    def test_le_cache_cesse_d_etre_servi_passe_la_fenetre_de_grace(self):
        """Une panne S3 ne doit pas rendre un token valide indéfiniment.

        C'est le défaut central : un token révoqué en S3 restait accepté aussi
        longtemps que durait la panne, sans qu'aucun signal ne le dise.
        """
        h, d = entree("alice")
        store = self.monter(objets((h, d)))
        store.initialize()
        self.assertIsNotNone(store.validate_token("alice"))

        self.s3.pannes["list"] = ErreurS3(code="ServiceUnavailable", statut=503)

        # Dans la fenêtre TTL + grâce, le cache reste servi : couper net
        # casserait le service à la première micro-coupure.
        self.horloge.avancer(400)
        self.assertIsNotNone(store.validate_token("alice"))

        # Au-delà, la porte se ferme.
        self.horloge.avancer(300)
        with self.assertRaises(TokenStoreUnavailable):
            store.validate_token("alice")

    def test_la_panne_ne_provoque_pas_un_appel_s3_par_requete(self):
        """Sans backoff, chaque requête entrante retentait S3 pendant la panne.

        `_cache_loaded_at` n'étant pas rafraîchi sur échec, la condition de
        rafraîchissement restait vraie en permanence.
        """
        h, d = entree("alice")
        store = self.monter(objets((h, d)))
        store.initialize()
        self.horloge.avancer(400)
        self.s3.pannes["list"] = ErreurS3(code="ServiceUnavailable", statut=503)

        store.validate_token("alice")
        apres_premier_echec = self.s3.appels["list"]

        for _ in range(20):
            store.validate_token("alice")

        self.assertEqual(
            self.s3.appels["list"], apres_premier_echec,
            "le backoff doit empêcher de retenter S3 à chaque requête",
        )


# =============================================================================
# D2 — l'échec de lecture pris pour un magasin vide
# =============================================================================


class LectureIncomplete(MagasinMixin, unittest.TestCase):

    def test_un_echec_de_lecture_ne_vide_pas_le_cache(self):
        """Le listing répond, les lectures échouent : ce n'est pas « 0 token ».

        L'ancien code vidait le cache AVANT la boucle de lecture, dont le corps
        avalait toute erreur. Résultat affiché : « 0 token(s) chargés », comme
        une réussite, et tout le monde en 401.
        """
        h, d = entree("alice")
        store = self.monter(objets((h, d)))
        store.initialize()
        self.assertEqual(len(store._cache), 1)

        self.s3.pannes["get"] = ErreurS3(code="InternalError", statut=500)
        self.horloge.avancer(400)

        self.assertIsNotNone(
            store.validate_token("alice"),
            "le cache précédent doit survivre à un chargement raté",
        )
        self.assertEqual(len(store._cache), 1)

    def test_un_echec_de_lecture_est_compte_comme_une_panne(self):
        """Un chargement partiel ne doit pas rafraîchir l'horodatage du cache."""
        h, d = entree("alice")
        store = self.monter(objets((h, d)))
        store.initialize()
        charge_a = store._cache_loaded_at

        self.s3.pannes["get"] = ErreurS3(code="InternalError", statut=500)
        self.horloge.avancer(400)
        store.validate_token("alice")

        self.assertEqual(
            store._cache_loaded_at, charge_a,
            "un chargement raté ne doit pas rajeunir le cache",
        )
        self.assertIsNotNone(store._last_error)

    def test_objet_disparu_entre_le_listing_et_la_lecture_n_est_pas_une_panne(self):
        """Une révocation concurrente est une course normale, pas une panne.

        Confondre les deux ferait basculer le magasin en 503 chaque fois qu'un
        administrateur révoque un token pendant qu'une autre instance recharge.
        """
        h1, d1 = entree("alice")
        h2, d2 = entree("bob")
        store = self.monter(objets((h1, d1), (h2, d2)))

        vrai_get = self.s3.get_object

        def get_avec_disparition(Bucket=None, Key=None):
            if Key == f"{ts.TOKENS_PREFIX}{h2}.json":
                raise ErreurS3(code="NoSuchKey", statut=404)
            return vrai_get(Bucket=Bucket, Key=Key)

        self.s3.get_object = get_avec_disparition
        store.initialize()

        self.assertIsNotNone(store.validate_token("alice"))
        self.assertIsNone(store.validate_token("bob"))
        self.assertIsNone(store._last_error, "aucune panne ne doit être notée")


# =============================================================================
# D3 — le magasin qui ne se répare jamais
# =============================================================================


class RetablissementApresPanne(MagasinMixin, unittest.TestCase):

    def test_un_magasin_injoignable_au_demarrage_se_repare_quand_s3_revient(self):
        """`_s3_available` restait faux à vie et bloquait tout rafraîchissement.

        Le magasin ne se réparait alors jamais, même une fois S3 revenu : il
        fallait redémarrer le service.
        """
        h, d = entree("alice")
        store = self.monter(objets((h, d)))
        self.s3.pannes["list"] = ErreurS3(code="EndpointConnectionError")

        with self.assertRaises(TokenStoreUnavailable):
            store.initialize()

        self.s3.pannes.pop("list")
        self.horloge.avancer(120)  # au-delà du backoff

        self.assertIsNotNone(
            store.validate_token("alice"),
            "le magasin doit repartir tout seul une fois S3 revenu",
        )


# =============================================================================
# D4 — les révocations qui mentent
# =============================================================================


class Revocation(MagasinMixin, unittest.TestCase):

    def test_pendant_une_panne_la_revocation_ne_pretend_pas_avoir_reussi(self):
        """Supprimer du seul cache local et annoncer un succès est un mensonge.

        L'entrée S3 resterait en place et les autres instances continueraient
        d'accepter le token, pendant que l'administrateur lirait « révoqué ».

        La panne est réelle, pas simulée en forçant `_s3_available` : dans le
        code d'origine ce drapeau passait à vrai au premier chargement réussi
        et n'en redescendait jamais, si bien que l'état n'était pas atteignable.
        C'est `_note_failure` qui le rend atteignable.
        """
        h, d = entree("alice")
        store = self.monter(objets((h, d)))
        store.initialize()

        self.s3.pannes["list"] = ErreurS3(code="ServiceUnavailable", statut=503)
        self.horloge.avancer(400)  # au-delà du TTL, dans la fenêtre de grâce

        resultat = store.revoke("alice")

        self.assertEqual(resultat["status"], "error")
        self.assertIn(h, store._cache, "le token ne doit pas disparaître du cache")
        self.assertEqual(self.s3.appels["delete"], 0)

    def test_une_suppression_en_echec_est_declaree_incertaine(self):
        """Un DELETE en échec a pu aboutir côté serveur. On ne tranche pas."""
        h, d = entree("alice")
        store = self.monter(objets((h, d)))
        store.initialize()
        self.s3.pannes["delete"] = ErreurS3(code="InternalError", statut=500)

        resultat = store.revoke("alice")

        self.assertEqual(resultat["status"], "error")
        self.assertIn("INCERTAINE", resultat["message"])
        self.assertIsNone(
            store.validate_token("alice"),
            "cette instance doit refuser le token malgré l'incertitude",
        )

    def test_une_revocation_incertaine_n_est_jamais_reintroduite_par_un_rechargement(self):
        """Le rechargement voyait l'objet toujours présent et le remettait.

        Retirer du cache puis forcer un rechargement, sans registre, rendait le
        token au premier refresh : la révocation s'annulait toute seule.
        """
        h, d = entree("alice")
        store = self.monter(objets((h, d)))
        store.initialize()
        self.s3.pannes["delete"] = ErreurS3(code="InternalError", statut=500)
        store.revoke("alice")

        self.s3.pannes.pop("delete")
        self.horloge.avancer(400)  # force un rechargement ; l'objet est toujours là

        self.assertIsNone(
            store.validate_token("alice"),
            "un rechargement ne doit pas défaire une révocation incertaine",
        )

    def test_le_registre_se_vide_quand_s3_confirme_l_absence(self):
        """L'incertitude ne dure pas : elle se lève par un fait, pas par le temps."""
        h, d = entree("alice")
        store = self.monter(objets((h, d)))
        store.initialize()
        self.s3.pannes["delete"] = ErreurS3(code="InternalError", statut=500)
        store.revoke("alice")
        self.assertIn(h, store._revocations_incertaines)

        # L'objet finit par disparaître : la suppression avait bien abouti.
        self.s3.objets.pop(f"{ts.TOKENS_PREFIX}{h}.json")
        self.s3.pannes.pop("delete")
        self.horloge.avancer(400)
        store.validate_token("alice")

        self.assertNotIn(h, store._revocations_incertaines)

    def test_un_objet_deja_absent_rend_une_revocation_certaine(self):
        """Supprimer ce qui n'existe plus n'est pas une incertitude."""
        h, d = entree("alice")
        store = self.monter(objets((h, d)))
        store.initialize()
        self.s3.pannes["delete"] = ErreurS3(code="NoSuchKey", statut=404)

        resultat = store.revoke("alice")

        self.assertEqual(resultat["status"], "success")
        self.assertNotIn(h, store._revocations_incertaines)


# =============================================================================
# C1 — la mise à jour qui élève avant d'écrire
# =============================================================================


class MiseAJour(MagasinMixin, unittest.TestCase):

    def test_un_echec_d_ecriture_n_eleve_pas_les_permissions_en_memoire(self):
        """`target_data = data` était une référence dans le cache.

        Les permissions étaient élevées AVANT l'appel S3. Sur échec, la méthode
        rendait une erreur pendant que l'élévation était déjà active pour toute
        requête servie par cette instance.
        """
        h, d = entree("alice", permissions=["access"])
        store = self.monter(objets((h, d)))
        store.initialize()
        self.s3.pannes["put"] = ErreurS3(code="AccessDenied", statut=403)

        resultat = store.update("alice", permissions=["admin", "access"])

        self.assertEqual(resultat["status"], "error")
        self.assertEqual(
            store.validate_token("alice")["permissions"], ["access"],
            "une écriture refusée ne doit rien changer en mémoire",
        )

    def test_une_mise_a_jour_reussie_est_visible(self):
        """Contrepartie du test précédent : le correctif ne casse pas le cas nominal."""
        h, d = entree("alice", permissions=["access"])
        store = self.monter(objets((h, d)))
        store.initialize()

        resultat = store.update("alice", permissions=["admin", "access"])

        self.assertEqual(resultat["status"], "success")
        self.assertEqual(
            store.validate_token("alice")["permissions"], ["admin", "access"]
        )


# =============================================================================
# C5 — la migration qui mute sans persister
# =============================================================================


class MigrationPermissions(MagasinMixin, unittest.TestCase):

    def test_une_migration_non_persistee_ne_change_rien_en_memoire(self):
        """Le cache affirmait `access` alors que S3 portait toujours read/write."""
        h, d = entree("alice", permissions=["read", "write"])
        store = self.monter(objets((h, d)))
        self.s3.pannes["put"] = ErreurS3(code="AccessDenied", statut=403)

        store.initialize()

        self.assertEqual(
            store.validate_token("alice")["permissions"], ["read", "write"],
            "sans écriture acceptée, l'entrée garde ses anciennes permissions",
        )

    def test_une_migration_persistee_est_appliquee_des_deux_cotes(self):
        h, d = entree("alice", permissions=["admin", "read"])
        store = self.monter(objets((h, d)))

        store.initialize()

        self.assertEqual(
            store.validate_token("alice")["permissions"], ["admin", "access"]
        )
        ecrit = json.loads(self.s3.objets[f"{ts.TOKENS_PREFIX}{h}.json"].decode())
        self.assertEqual(ecrit["permissions"], ["admin", "access"])


# =============================================================================
# C6 — la date d'expiration corrompue
# =============================================================================


class DateExpiration(MagasinMixin, unittest.TestCase):

    def test_une_date_illisible_ferme_la_porte(self):
        """`except Exception: pass` puis le token était ACCEPTÉ.

        La seule protection contre un token périmé disparaissait dès que sa
        date était corrompue.
        """
        h, d = entree("alice", expires_at="pas-une-date")
        store = self.monter(objets((h, d)))
        store.initialize()

        self.assertIsNone(store.validate_token("alice"))

    def test_une_date_non_textuelle_ferme_la_porte(self):
        h, d = entree("alice", expires_at=12345)
        store = self.monter(objets((h, d)))
        store.initialize()

        self.assertIsNone(store.validate_token("alice"))

    def test_une_date_sans_fuseau_est_lue_en_utc(self):
        passe = (datetime.now(timezone.utc) - timedelta(days=1)).replace(tzinfo=None)
        h, d = entree("alice", expires_at=passe.isoformat())
        store = self.monter(objets((h, d)))
        store.initialize()

        self.assertIsNone(store.validate_token("alice"))

    def test_l_absence_de_date_vaut_sans_expiration(self):
        h, d = entree("alice", expires_at=None)
        store = self.monter(objets((h, d)))
        store.initialize()

        self.assertIsNotNone(store.validate_token("alice"))

    def test_la_console_signale_une_date_illisible(self):
        """La console montrait « valide » pour un token que l'auth refuse.

        Un administrateur lisait donc l'inverse de ce qui se passait.
        """
        h, d = entree("alice", expires_at="pas-une-date")
        store = self.monter(objets((h, d)))
        store.initialize()

        vue = store.list_tokens()["tokens"][0]
        self.assertTrue(vue["expired"])
        self.assertTrue(vue["date_invalide"])


# =============================================================================
# C7 — l'intégrité du chargement
# =============================================================================


class IntegriteChargement(MagasinMixin, unittest.TestCase):

    def test_un_objet_dont_le_nom_ne_correspond_pas_au_hash_est_ecarte(self):
        """Le nom de l'objet EST le hash. Aucun contrôle ne le vérifiait."""
        h_alice = TokenStore.hash_token("alice")
        _, d = entree("mallory", token_hash=TokenStore.hash_token("mallory"))
        store = self.monter({f"{ts.TOKENS_PREFIX}{h_alice}.json": json.dumps(d).encode()})
        store.initialize()

        self.assertEqual(len(store._cache), 0)
        self.assertIsNone(store.validate_token("alice"))
        self.assertIsNone(store.validate_token("mallory"))

    def test_un_objet_sans_permissions_est_ecarte(self):
        """`info.get("permissions", ["access"])` fabriquait un accès par défaut."""
        h, d = entree("alice")
        del d["permissions"]
        store = self.monter(objets((h, d)))
        store.initialize()

        self.assertIsNone(store.validate_token("alice"))

    def test_un_objet_illisible_est_ecarte_sans_faire_tomber_le_chargement(self):
        h, d = entree("alice")
        corrompu = TokenStore.hash_token("bob")
        s3 = objets((h, d))
        s3[f"{ts.TOKENS_PREFIX}{corrompu}.json"] = b"{ceci n est pas du json"
        store = self.monter(s3)
        store.initialize()

        self.assertIsNotNone(store.validate_token("alice"))
        self.assertIsNone(store.validate_token("bob"))

    def test_un_hash_mal_forme_est_ecarte(self):
        s3 = {f"{ts.TOKENS_PREFIX}PAS_UN_HASH.json": json.dumps(
            {"token_hash": "PAS_UN_HASH", "client_name": "x", "permissions": ["access"]}
        ).encode()}
        store = self.monter(s3)
        store.initialize()

        self.assertEqual(len(store._cache), 0)


# =============================================================================
# C8 — l'unicité vérifiée contre une photo ancienne
# =============================================================================


class UniciteCreation(MagasinMixin, unittest.TestCase):

    def test_la_creation_verifie_l_unicite_contre_s3_et_non_contre_un_cache_perime(self):
        """`create()` n'appelait pas `_maybe_refresh_cache`.

        Un token créé par une autre instance restait invisible jusqu'au TTL, et
        l'unicité de `client_name`, qui est l'invariant du magasin, tombait.
        """
        store = self.monter({})
        store.initialize()
        self.assertEqual(len(store._cache), 0)

        # Une autre instance crée le token pendant ce temps.
        h, d = entree("alice")
        self.s3.objets[f"{ts.TOKENS_PREFIX}{h}.json"] = json.dumps(d).encode()
        self.horloge.avancer(400)

        resultat = store.create("alice", ["access"], [])

        self.assertEqual(resultat["status"], "error")
        self.assertIn("existe déjà", resultat["message"])

    def test_la_creation_refuse_pendant_une_panne(self):
        """Créer un token qu'on ne peut pas persister n'a aucun sens.

        Panne réelle ici aussi : le rafraîchissement échoue, le drapeau de
        disponibilité redescend, la garde des mutations refuse.
        """
        store = self.monter({})
        store.initialize()

        self.s3.pannes["list"] = ErreurS3(code="ServiceUnavailable", statut=503)
        self.horloge.avancer(400)

        resultat = store.create("alice", ["access"], [])

        self.assertEqual(resultat["status"], "error")
        self.assertEqual(self.s3.appels["put"], 0)



    def test_les_mutations_redeviennent_possibles_quand_s3_revient(self):
        """Le drapeau ne doit pas rester bloqué à faux après la panne.

        Le rafraîchissement passe avant la garde précisément pour ça : sans cet
        ordre, la mutation restait refusée tant qu'aucun rechargement n'avait eu
        lieu, alors même que S3 répondait de nouveau.
        """
        store = self.monter({})
        store.initialize()
        self.s3.pannes["list"] = ErreurS3(code="ServiceUnavailable", statut=503)
        self.horloge.avancer(400)
        self.assertEqual(store.create("alice", ["access"], [])["status"], "error")

        self.s3.pannes.pop("list")
        self.horloge.avancer(120)  # au-delà du backoff

        self.assertEqual(store.create("alice", ["access"], [])["status"], "success")


# =============================================================================
# Pagination — les tokens au-delà de la millième clé
# =============================================================================


class Pagination(MagasinMixin, unittest.TestCase):

    def test_les_tokens_au_dela_de_la_premiere_page_sont_charges(self):
        """`list_objects_v2` rend au plus 1000 clés et n'était jamais paginé.

        Au-delà, les tokens disparaissaient du cache sans aucun signal : leurs
        porteurs recevaient 401 alors que le magasin se déclarait sain.
        """
        entrees = [entree(f"client-{i:03d}") for i in range(7)]
        store = self.monter(objets(*entrees))
        self.s3.taille_page = 3

        store.initialize()

        self.assertEqual(len(store._cache), 7)
        for i in range(7):
            self.assertIsNotNone(
                store.validate_token(f"client-{i:03d}"),
                f"client-{i:03d} doit être chargé malgré la pagination",
            )


# =============================================================================
# Réglages de panne : TTL nul, fail_open, jamais chargé
# =============================================================================


class ReglagesDePanne(MagasinMixin, unittest.TestCase):

    def test_un_ttl_nul_interdit_de_servir_le_cache_pendant_la_panne(self):
        h, d = entree("alice")
        store = self.monter(objets((h, d)), token_store_cache_ttl=0)
        store.initialize()
        self.s3.pannes["list"] = ErreurS3(code="ServiceUnavailable", statut=503)

        with self.assertRaises(TokenStoreUnavailable):
            store.validate_token("alice")

    def test_un_ttl_nul_l_emporte_sur_fail_open(self):
        """Deux réglages qui se contredisent : le plus restrictif gagne.

        L'ordre inverse laissait `fail_open` rouvrir la fenêtre que
        l'exploitant venait de fermer par un TTL nul.
        """
        h, d = entree("alice")
        store = self.monter(
            objets((h, d)),
            token_store_cache_ttl=0,
            token_store_fail_mode="fail_open",
        )
        store.initialize()
        self.s3.pannes["list"] = ErreurS3(code="ServiceUnavailable", statut=503)

        with self.assertRaises(TokenStoreUnavailable):
            store.validate_token("alice")

    def test_fail_open_sert_le_cache_perime_aussi_longtemps_que_dure_la_panne(self):
        """Le mode dégradé existe, il est explicite, et il est documenté."""
        h, d = entree("alice")
        store = self.monter(objets((h, d)), token_store_fail_mode="fail_open")
        store.initialize()
        self.s3.pannes["list"] = ErreurS3(code="ServiceUnavailable", statut=503)

        self.horloge.avancer(100_000)
        self.assertIsNotNone(store.validate_token("alice"))

    def test_un_magasin_jamais_charge_refuse_meme_en_fail_open(self):
        """Il n'y a rien à servir : 503 dit la vérité, 401 mentirait.

        Testé avant `fail_open` dans le code, et c'est délibéré : un cache vide
        aurait rendu 401 à tout le monde et poussé les clients à remplacer des
        tokens parfaitement valides.
        """
        store = self.monter({}, token_store_fail_mode="fail_open")
        self.s3.pannes["list"] = ErreurS3(code="EndpointConnectionError")

        with self.assertRaises(TokenStoreUnavailable):
            store.initialize()
        with self.assertRaises(TokenStoreUnavailable):
            store.validate_token("alice")

    def test_s3_non_configure_laisse_le_magasin_muet_sans_lever(self):
        """Sans S3, seule la clé bootstrap fonctionne : ce n'est pas une panne."""
        store = self.monter({}, s3_endpoint_url="", s3_access_key_id="")
        store.initialize()

        self.assertIsNone(store.validate_token("alice"))


# =============================================================================
# Détection d'absence d'objet
# =============================================================================


class DetectionObjetAbsent(unittest.TestCase):

    def test_le_code_d_erreur_structure_fait_foi(self):
        self.assertTrue(ts._est_objet_absent(ErreurS3(code="NoSuchKey")))
        self.assertTrue(ts._est_objet_absent(ErreurS3(statut=404)))
        self.assertFalse(ts._est_objet_absent(ErreurS3(code="AccessDenied", statut=403)))

    def test_le_texte_du_message_ne_fait_pas_foi(self):
        """Un message dépend de botocore et de la langue du serveur.

        S'y fier transformerait une panne réseau en « objet absent », donc un
        fail-close en fail-open.
        """
        self.assertFalse(ts._est_objet_absent(Exception("NoSuchKey: not found")))


# =============================================================================
# Gardes de conception : ces deux tests passent aussi contre l'ancien code
# =============================================================================


class GardesDeConception(MagasinMixin, unittest.TestCase):

    def test_le_verrou_des_mutations_doit_rester_reentrant(self):
        """`create`, `update` et `revoke` prennent le verrou puis appellent
        `_maybe_refresh_cache`, qui le reprend. Un verrou non réentrant
        interbloquerait le fil appelant contre lui-même dès la première
        création de token.
        """
        store = self.monter({})
        self.assertIsInstance(store._lock, type(threading.RLock()))
        acquis = store._lock.acquire(timeout=1)
        self.assertTrue(acquis)
        try:
            self.assertTrue(store._lock.acquire(timeout=1))
            store._lock.release()
        finally:
            store._lock.release()


# =============================================================================
# Le contrat HTTP : 503 et pas 401, 503 et pas 500
# =============================================================================


async def _appeler(app, chemin="/mcp", autorisation=None):
    """Exécute un middleware ASGI et rend (statut, corps)."""
    entetes = []
    if autorisation is not None:
        entetes.append((b"authorization", autorisation.encode()))
    scope = {"type": "http", "path": chemin, "method": "GET", "headers": entetes}
    envoyes = []

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        envoyes.append(message)

    async def suivant(scope, receive, send):
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    await app(scope, receive, send, suivant)

    statut = next(
        (m["status"] for m in envoyes if m["type"] == "http.response.start"), None
    )
    corps = b"".join(
        m.get("body", b"") for m in envoyes if m["type"] == "http.response.body"
    )
    return statut, corps


class ContratHttp(MagasinMixin, unittest.IsolatedAsyncioTestCase):

    def _brancher(self, store):
        """Substitue le singleton : le middleware passe par `get_token_store`."""
        patch = mock.patch.object(ts, "_token_store", store)
        patch.start()
        self.addCleanup(patch.stop)
        # `from ..config import get_settings` lie le nom dans CHAQUE module
        # appelant. Patcher `config.get_settings` n'atteint aucun d'eux : il
        # faut viser les noms liés, sinon le test lit la vraie configuration et
        # la clé bootstrap de test n'est jamais reconnue.
        for cible in (
            "src.mcp_tools.auth.middleware.get_settings",
            "src.mcp_tools.admin.api.get_settings",
        ):
            patch_reglages = mock.patch(cible, return_value=store.settings)
            patch_reglages.start()
            self.addCleanup(patch_reglages.stop)

    async def _via_auth(self, autorisation, chemin="/mcp"):
        from src.mcp_tools.auth import middleware as mw

        async def app(scope, receive, send, suivant):
            await mw.AuthMiddleware(suivant)(scope, receive, send)

        return await _appeler(app, chemin, autorisation)

    async def test_un_magasin_injoignable_rend_503_et_non_401(self):
        """401 affirmerait que le token est invalide. Personne ne le sait.

        Le client qui reçoit 401 conclut que son token est mort et en demande
        un autre. Il faut lui dire que le service ne peut pas répondre.
        """
        h, d = entree("alice")
        store = self.monter(objets((h, d)))
        store.initialize()
        self._brancher(store)

        self.s3.pannes["list"] = ErreurS3(code="ServiceUnavailable", statut=503)
        self.horloge.avancer(1000)

        statut, _ = await self._via_auth("Bearer alice")
        self.assertEqual(statut, 503)

    async def test_un_magasin_injoignable_ne_rend_pas_500(self):
        """Sans bloc `except`, la levée remontait en erreur ASGI non traitée.

        C'est ce que produisait le correctif tant qu'il s'arrêtait au magasin :
        rendre le magasin honnête sans toucher aux appelants remplaçait un
        fail-open silencieux par un 500 tout aussi muet.
        """
        h, d = entree("alice")
        store = self.monter(objets((h, d)))
        store.initialize()
        self._brancher(store)
        self.s3.pannes["list"] = ErreurS3(code="ServiceUnavailable", statut=503)
        self.horloge.avancer(1000)

        statut, corps = await self._via_auth("Bearer alice")
        self.assertNotEqual(statut, 500)
        self.assertNotIn(b"ServiceUnavailable", corps,
                         "la cause reste sur la sortie serveur, pas dans la reponse")

    async def test_un_token_inconnu_rend_toujours_401(self):
        """Le 503 ne doit pas avaler le refus ordinaire."""
        h, d = entree("alice")
        store = self.monter(objets((h, d)))
        store.initialize()
        self._brancher(store)

        statut, _ = await self._via_auth("Bearer inconnu")
        self.assertEqual(statut, 401)

    async def test_un_token_valide_passe(self):
        h, d = entree("alice")
        store = self.monter(objets((h, d)))
        store.initialize()
        self._brancher(store)

        statut, corps = await self._via_auth("Bearer alice")
        self.assertEqual(statut, 200)
        self.assertEqual(corps, b"ok")

    async def test_la_cle_bootstrap_reste_acceptee_pendant_une_panne(self):
        """Décision assumée, pas un défaut, et le seul test ici qui passerait
        aussi contre l'ancien code.

        La clé bootstrap est comparée AVANT toute consultation de S3. Sans
        elle, une panne du magasin rendrait la console et le diagnostic
        inaccessibles au moment précis où on en a besoin. Ce test existe pour
        qu'un durcissement futur ne la déplace pas sans le vouloir.
        """
        store = self.monter({})
        self._brancher(store)
        self.s3.pannes["list"] = ErreurS3(code="EndpointConnectionError")
        with self.assertRaises(TokenStoreUnavailable):
            store.initialize()

        statut, _ = await self._via_auth("Bearer cle-bootstrap-de-test")
        self.assertEqual(statut, 200)

    async def test_l_api_admin_rend_503_quand_le_magasin_est_injoignable(self):
        """Le routeur admin a son propre point de capture.

        Le corriger dans le middleware MCP seulement aurait laissé la console
        rendre 500 sur les mêmes pannes : un remède par niveau.
        """
        from src.mcp_tools.admin import middleware as am

        h, d = entree("alice")
        store = self.monter(objets((h, d)))
        store.initialize()
        self._brancher(store)
        self.s3.pannes["list"] = ErreurS3(code="ServiceUnavailable", statut=503)
        self.horloge.avancer(1000)

        async def app(scope, receive, send, suivant):
            await am.AdminMiddleware(suivant, None)(scope, receive, send)

        statut, _ = await _appeler(
            app, "/admin/api/tokens", autorisation="Bearer alice"
        )
        self.assertEqual(statut, 503)


if __name__ == "__main__":
    unittest.main()
