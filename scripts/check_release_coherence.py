#!/usr/bin/env python3
"""Garde de cohérence version / tag / CHANGELOG.

Le défaut qu'il attrape (vécu le 2026-08-06) : après la publication de v0.5.0,
des commits ont été fusionnés sur `main` sans bump ni tag. `main` portait donc
des changements sous un numéro de version DÉJÀ PUBLIÉ. Conséquence concrète :
la plateforme s'est vu annoncer « déploie v0.5.0 », puis l'artefact a changé —
il a fallu corriger l'annonce après coup. Un déployeur ne peut pas deviner si
`main` vaut le dernier tag ou le dépasse.

Trois invariants, vérifiables sans rien exécuter :

  1. Sur un tag `vX.Y.Z` : le fichier VERSION doit valoir exactement X.Y.Z.
     Attrape « on a tagué le mauvais commit ».
  2. Sur un tag : le CHANGELOG doit porter une entrée `## [X.Y.Z]`.
     Attrape la release publiée sans notes.
  3. Sur `main` : soit HEAD EST le tag correspondant à VERSION, soit VERSION est
     strictement supérieure à tous les tags existants (version en préparation).
     Tout le reste signifie que `main` a dérivé sous une version publiée.

Usage :
    python3 scripts/check_release_coherence.py            # déduit le contexte
    python3 scripts/check_release_coherence.py --tag v1.2.3
"""
from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def git(*args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=ROOT, capture_output=True, text=True, check=False
    ).stdout.strip()


def parse_semver(value: str) -> tuple[int, int, int] | None:
    m = re.fullmatch(r"v?(\d+)\.(\d+)\.(\d+)", value.strip())
    return (int(m[1]), int(m[2]), int(m[3])) if m else None


def erreur(msg: str, remede: str) -> None:
    print(f"\n❌ {msg}\n   → {remede}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--tag", help="Tag en cours de publication (sinon: contrôle de branche)")
    args = ap.parse_args()

    version = (ROOT / "VERSION").read_text().strip()
    changelog = (ROOT / "CHANGELOG.md").read_text()
    echecs = 0

    if parse_semver(version) is None:
        erreur(f"VERSION vaut « {version} », ce n'est pas un semver X.Y.Z.",
               "Corriger le fichier VERSION.")
        return 1

    print(f"  VERSION = {version}")

    # ---- Contrôles liés à un tag -------------------------------------------
    if args.tag:
        attendu = args.tag.lstrip("v")
        if attendu != version:
            erreur(f"Le tag {args.tag} désigne un commit dont VERSION vaut {version}.",
                   f"Taguer le commit qui porte VERSION={attendu}, ou corriger VERSION.")
            echecs += 1
        else:
            print(f"  ok  tag {args.tag} ↔ VERSION {version}")

        if f"## [{version}]" not in changelog:
            erreur(f"Aucune entrée « ## [{version}] » dans CHANGELOG.md.",
                   "Ajouter les notes de version avant de taguer.")
            echecs += 1
        else:
            print(f"  ok  CHANGELOG porte une entrée [{version}]")

        return 1 if echecs else 0

    # ---- Contrôle de branche : main a-t-il dérivé sous une version publiée ? -
    tags = [t for t in git("tag", "--list", "v*").splitlines() if parse_semver(t)]
    if not tags:
        print("  ok  aucun tag de version — rien à comparer")
        return 0

    plus_haut = max(tags, key=lambda t: parse_semver(t))  # type: ignore[arg-type]
    print(f"  tag le plus élevé = {plus_haut}")

    tag_de_cette_version = f"v{version}"
    if tag_de_cette_version in tags:
        commit_tag = git("rev-parse", f"{tag_de_cette_version}^{{commit}}")
        head = git("rev-parse", "HEAD")
        if commit_tag != head:
            erreur(
                f"HEAD porte VERSION={version}, or le tag {tag_de_cette_version} existe "
                f"et pointe un AUTRE commit ({commit_tag[:9]} ≠ {head[:9]}).\n"
                f"   La branche a donc dérivé sous un numéro déjà publié : personne ne peut "
                f"savoir si déployer le tag ou la branche.",
                "Bumper VERSION (+ entrée CHANGELOG) puis publier via ./scripts/release.sh, "
                "ou taguer ce commit s'il doit remplacer la release.",
            )
            echecs += 1
        else:
            print(f"  ok  HEAD est exactement {tag_de_cette_version}")
    else:
        if parse_semver(version) <= parse_semver(plus_haut):  # type: ignore[operator]
            erreur(
                f"VERSION={version} n'est pas supérieure au tag le plus élevé ({plus_haut}), "
                f"et aucun tag v{version} n'existe.",
                "Bumper VERSION au-dessus de " + plus_haut + ".",
            )
            echecs += 1
        else:
            print(f"  ok  VERSION {version} > {plus_haut} — version en préparation, non taguée")

    return 1 if echecs else 0


if __name__ == "__main__":
    sys.exit(main())
