# -*- coding: utf-8 -*-
"""Table de mutations du magasin de tokens.

Ce que ce script ajoute aux planchers de collecte de la CI, et pourquoi il
existe : un plancher compte des tests COLLECTÉS. Vider le corps d'un test sans
toucher à son nom laisse les deux planchers verts et `pytest` au vert, tout en
retirant la protection. Une relecture l'a démontré en remettant un défaut de
sécurité en place sans qu'aucun garde ne bouge.

Ce script remet chaque correctif dans son état d'origine, un par un, et exige
qu'au moins un test tombe. Il répond donc à la question que les planchers ne
posent pas : « les assertions protègent-elles encore quelque chose ? »

Règles du harnais, chacune payée par une mesure fausse dans une campagne
précédente :
  - la mutation est compilée par `ast.parse` AVANT d'être écrite, sinon un
    `SyntaxError` se lit comme un test qui tombe ;
  - le bytecode est purgé et Python tourne avec `-B`, sinon un `.pyc` fausse
    la mesure ;
  - deux passes identiques sont exigées ;
  - une erreur de COLLECTE n'est pas un échec de test : elle est signalée à
    part, parce qu'elle ne prouve rien.

Une ancre qui ne s'applique plus fait échouer le script, et c'est voulu : un
correctif qu'on déplace se réexamine, il ne se contourne pas.

Usage :  python3 scripts/mutations_magasin_tokens.py
Sortie : 0 si toutes les mutations sont détectées, 1 sinon, 2 si les deux
         passes divergent.
"""

import ast
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

RACINE = Path(__file__).resolve().parent.parent
SOURCE = str(RACINE)
TESTS = "tests/test_token_store.py"

TS = "src/mcp_tools/auth/token_store.py"
MW = "src/mcp_tools/auth/middleware.py"
AM = "src/mcp_tools/admin/middleware.py"

MUTATIONS = [
    dict(id="M01", fichier=TS,
         titre="D1 le cache perime est servi sans borne pendant la panne",
         avant="""        raise TokenStoreUnavailable(
            f"magasin de tokens injoignable depuis {age:.0f}s, "
            f"au-delà de la fenêtre de {self.stale_grace}s : "
            f"accès refusé ({cause})"
        )""",
         apres="""        return"""),

    dict(id="M02", fichier=TS,
         titre="D1 aucun backoff : S3 est retente a chaque requete",
         avant="""            if time.monotonic() < self._backoff_until:
                self._garde_cache_perime(age)
                return""",
         apres="""            if False:
                pass"""),

    dict(id="M03", fichier=TS,
         titre="D2 une lecture en echec est avalee, le magasin parait vide",
         avant="""                    raise TokenStoreUnavailable(
                        f"lecture de {key} impossible : {e}"
                    ) from e""",
         apres="""                    continue"""),

    dict(id="M04", fichier=TS,
         titre="D3 le rafraichissement redevient conditionne a _s3_available",
         avant="""        with self._lock:
            age = self._age()""",
         apres="""        with self._lock:
            if not self._s3_available:
                return
            age = self._age()"""),

    dict(id="M05", fichier=TS,
         titre="D4 revoke supprime du cache local sans S3 et annonce un succes",
         avant="""            indisponible = self._exiger_s3()
            if indisponible is not None:
                # Supprimer du seul cache local aurait annoncé un succès pour
                # une révocation que personne d'autre ne verrait jamais.
                return indisponible

            target_hash = None""",
         apres="""            target_hash = None"""),

    dict(id="M06", fichier=TS,
         titre="D4 une suppression au sort incertain n'est pas memorisee",
         avant="""            self._revocations_incertaines.add(token_hash)
            return False, str(e)""",
         apres="""            return False, str(e)"""),

    dict(id="M07", fichier=TS,
         titre="C1 update mute l'entree du cache au lieu d'une copie",
         avant="""            copie = dict(actuel)""",
         apres="""            copie = actuel"""),

    dict(id="M08", fichier=TS,
         titre="C5 la migration mute en memoire avant l'ecriture S3",
         avant="""            try:
                client_v2.put_object(
                    Bucket=self.settings.s3_bucket_name,
                    Key=self._s3_key(token_hash),
                    Body=json.dumps(copie, indent=2).encode(),
                    ContentType="application/json",
                )
            except Exception as e:
                echecs.append(f"{data.get('client_name', '?')}: {e}")
                continue

            entrees[token_hash] = copie""",
         apres="""            entrees[token_hash] = copie
            try:
                client_v2.put_object(
                    Bucket=self.settings.s3_bucket_name,
                    Key=self._s3_key(token_hash),
                    Body=json.dumps(copie, indent=2).encode(),
                    ContentType="application/json",
                )
            except Exception as e:
                echecs.append(f"{data.get('client_name', '?')}: {e}")
                continue"""),

    dict(id="M09", fichier=TS,
         titre="C6 une date d'expiration illisible laisse passer le token",
         avant="""        try:
            exp = datetime.fromisoformat(expires_at)
        except ValueError:
            return True, True""",
         apres="""        try:
            exp = datetime.fromisoformat(expires_at)
        except ValueError:
            return False, False"""),

    dict(id="M10", fichier=TS,
         titre="C7 le nom de l'objet n'est plus confronte au token_hash",
         avant="""        if token_hash != attendu:
            ignores.append(f"{key}: token_hash ne correspond pas au nom de l'objet")
            return None""",
         apres="""        pass"""),

    dict(id="M11", fichier=TS,
         titre="C7 des permissions absentes redonnent access par defaut",
         avant="""        if _liste_de_chaines(data.get("permissions")) is None:
            ignores.append(f"{key}: permissions absentes ou mal formées")
            return None""",
         apres="""        pass"""),

    dict(id="M12", fichier=TS,
         titre="C8 create verifie l'unicite contre un cache perime",
         avant="""            # Et sans lui, un cache périmé laissait créer un second token pour
            # un client_name déjà servi : l'unicité n'était vérifiée que contre
            # une photo ancienne du magasin.
            self._maybe_refresh_cache()

            indisponible = self._exiger_s3()
            if indisponible is not None:
                return indisponible
""",
         apres="""            indisponible = self._exiger_s3()
            if indisponible is not None:
                return indisponible
"""),

    dict(id="M13", fichier=TS,
         titre="pagination : seule la premiere page de 1000 cles est lue",
         avant="""            if not resp.get("IsTruncated"):
                break
            continuation = resp.get("NextContinuationToken")
            if not continuation:
                break""",
         apres="""            break"""),

    dict(id="M14", fichier=TS,
         titre="ordre : fail_open est evalue avant le TTL nul",
         avant="""        if self.cache_ttl == 0:
            raise TokenStoreUnavailable(
                "magasin de tokens injoignable et TOKEN_STORE_CACHE_TTL=0 "
                f"interdit de servir depuis le cache : accès refusé ({cause})"
            )""",
         apres="""        if self.fail_mode == "fail_open":
            return
        if self.cache_ttl == 0:
            raise TokenStoreUnavailable(
                "magasin de tokens injoignable et TOKEN_STORE_CACHE_TTL=0 "
                f"interdit de servir depuis le cache : accès refusé ({cause})"
            )"""),

    dict(id="M15", fichier=TS,
         titre="TTL nul court-circuite le rafraichissement juste apres un chargement",
         avant="""            if self.cache_ttl > 0 and age is not None and age <= self.cache_ttl:""",
         apres="""            if age is not None and age <= self.cache_ttl:"""),

    dict(id="M16", fichier=TS,
         titre="la detection d'objet absent se fait sur le texte du message",
         avant="""    reponse = getattr(error, "response", None)
    if not isinstance(reponse, dict):
        return False""",
         apres="""    if "NoSuchKey" in str(error):
        return True
    reponse = getattr(error, "response", None)
    if not isinstance(reponse, dict):
        return False"""),

    dict(id="M17", fichier=MW,
         titre="C2 le middleware MCP ne traite plus l'indisponibilite",
         avant="""            try:
                token_info = self._validate_token(token)
            except TokenStoreUnavailable:""",
         apres="""            token_info = self._validate_token(token)
            if False:"""),

    dict(id="M18", fichier=AM,
         titre="C2 le routeur admin ne traite plus l'indisponibilite",
         avant="""            try:
                return await handle_admin_api(
                    scope, receive, _send_suivi, self.mcp_instance
                )
            except TokenStoreUnavailable:
                if reponse_commencee["oui"]:
                    raise
                return await self._send_503(send)""",
         apres="""            return await handle_admin_api(
                scope, receive, _send_suivi, self.mcp_instance
            )"""),
    dict(id="M19", fichier=TS,
         titre="une panne ne remet pas _s3_available a faux (etat inatteignable)",
         avant="""        # Redescend à faux, et c'est ce qui rend `_exiger_s3` utile. Sans cette
        # ligne, le drapeau passait à vrai au premier chargement réussi et n'en
        # redescendait jamais : la garde des mutations gardait un état que rien
        # ne pouvait produire.
        self._s3_available = False""",
         apres="""        pass"""),

    dict(id="M20", fichier=TS,
         titre="la garde de disponibilite repasse avant le rafraichissement (create)",
         avant="""            # Et sans lui, un cache périmé laissait créer un second token pour
            # un client_name déjà servi : l'unicité n'était vérifiée que contre
            # une photo ancienne du magasin.
            self._maybe_refresh_cache()

            indisponible = self._exiger_s3()
            if indisponible is not None:
                return indisponible
""",
         apres="""            indisponible = self._exiger_s3()
            if indisponible is not None:
                return indisponible

            self._maybe_refresh_cache()
"""),
    dict(id="M21", fichier=TS,
         titre="tool_ids n'est plus controle au chargement",
         avant="""        if _liste_de_chaines(data.get("tool_ids", [])) is None:
            ignores.append(f"{key}: tool_ids mal formés")
            return None""",
         apres="""        pass"""),

    dict(id="M22", fichier=TS,
         titre="create() accepte un tool_ids ou des permissions mal types",
         avant="""            permissions_valides = _liste_de_chaines(permissions)
            if permissions_valides is None:
                return {
                    "status": "error",
                    "message": "permissions doit être une liste de chaînes.",
                }
            tool_ids_valides = _liste_de_chaines(tool_ids if tool_ids is not None else [])
            if tool_ids_valides is None:
                return {
                    "status": "error",
                    "message": "tool_ids doit être une liste de chaînes.",
                }
            permissions = permissions_valides
            tool_ids = tool_ids_valides""",
         apres="""            pass"""),

    dict(id="M23", fichier=TS,
         titre="update() accepte un tool_ids mal type",
         avant="""                valides = _liste_de_chaines(tool_ids)
                if valides is None:
                    return {
                        "status": "error",
                        "message": "tool_ids doit être une liste de chaînes.",
                    }
                old = actuel.get("tool_ids", [])
                copie["tool_ids"] = valides
                changes.append(f"tool_ids: {len(old)} → {len(valides)} outils")""",
         apres="""                old = actuel.get("tool_ids", [])
                copie["tool_ids"] = tool_ids
                changes.append(f"tool_ids: {len(old)} → {len(tool_ids)} outils")"""),
]


def purger_bytecode(racine):
    for base, dirs, _ in os.walk(racine):
        for d in list(dirs):
            if d == "__pycache__":
                shutil.rmtree(os.path.join(base, d), ignore_errors=True)
                dirs.remove(d)


def executer(racine):
    purger_bytecode(racine)
    r = subprocess.run(
        [sys.executable, "-B", "-m", "pytest", TESTS, "-q", "--timeout=60",
         "-p", "no:cacheprovider"],
        cwd=racine, capture_output=True, text=True,
    )
    sortie = r.stdout + r.stderr
    if "error" in sortie.lower() and "ERROR" in sortie and "collecting" in sortie:
        return None, sortie
    tombes = sorted(set(re.findall(r"^FAILED (\S+)", sortie, re.M)))
    m = re.search(r"(\d+) failed", sortie)
    n = int(m.group(1)) if m else 0
    if len(tombes) != n:
        return None, sortie
    return tombes, sortie


def une_passe():
    resultats = {}
    for mut in MUTATIONS:
        with tempfile.TemporaryDirectory() as tmp:
            racine = os.path.join(tmp, "arbre")
            shutil.copytree(SOURCE, racine, symlinks=True,
                            ignore=shutil.ignore_patterns("__pycache__", ".git"))
            chemin = os.path.join(racine, mut["fichier"])
            with open(chemin, encoding="utf-8") as f:
                texte = f.read()
            n = texte.count(mut["avant"])
            if n != 1:
                resultats[mut["id"]] = dict(etat="ANCRE", detail=f"{n} occurrence(s)")
                continue
            mute = texte.replace(mut["avant"], mut["apres"], 1)
            try:
                ast.parse(mute)
            except SyntaxError as e:
                resultats[mut["id"]] = dict(etat="SYNTAXE", detail=str(e))
                continue
            with open(chemin, "w", encoding="utf-8") as f:
                f.write(mute)
            tombes, sortie = executer(racine)
            if tombes is None:
                resultats[mut["id"]] = dict(etat="HARNAIS", detail=sortie[-1500:])
            else:
                resultats[mut["id"]] = dict(etat="OK", tombes=tombes)
    return resultats


if __name__ == "__main__":
    p1 = une_passe()
    p2 = une_passe()
    if p1 != p2:
        print("PASSES DIVERGENTES : mesure non fiable")
        for k in sorted(set(p1) | set(p2)):
            if p1.get(k) != p2.get(k):
                print(" ", k, p1.get(k), "!=", p2.get(k))
        sys.exit(2)

    largeur = max(len(m["titre"]) for m in MUTATIONS)
    total_ok = 0
    print(f"{'ID':<5} {'tombes':>6}  mutation")
    print("-" * (largeur + 16))
    for mut in MUTATIONS:
        r = p1[mut["id"]]
        if r["etat"] != "OK":
            print(f"{mut['id']:<5} {r['etat']:>6}  {mut['titre']}")
            print("        ", r.get("detail", "")[:400].replace("\n", "\n         "))
            continue
        n = len(r["tombes"])
        if n:
            total_ok += 1
        print(f"{mut['id']:<5} {n:>6}  {mut['titre']}")
        for t in r["tombes"]:
            print(f"           - {t.split('::')[-1]}")
    print("-" * (largeur + 16))
    print(f"{total_ok}/{len(MUTATIONS)} mutations detectees")
    sys.exit(0 if total_ok == len(MUTATIONS) else 1)
