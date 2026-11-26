# -*- coding: utf-8 -*-
"""
Outil: shell — Exécution de commandes dans un conteneur sandbox isolé.

Sécurité : chaque commande est exécutée dans un conteneur Docker éphémère
(Alpine) avec : --read-only, --cap-drop=ALL, --memory, --pids-limit,
--no-new-privileges. Le conteneur est détruit après exécution.

Réseau : par défaut --network=none (isolation totale). Si network=true,
--network=bridge avec DNS configuré (permet pip install, curl, wget...).

Packages Python pré-installés : numpy, pandas, requests, beautifulsoup4,
lxml, pyyaml, scipy, matplotlib, pillow, boto3, tabulate, toml, chardet.

Fallback : si SANDBOX_ENABLED=false (dev local), exécution locale via subprocess.
"""

import asyncio
import sys
import uuid
from typing import Annotated, Optional
from pydantic import Field
from mcp.server.mcpserver import MCPServer, Context
from ..auth.context import check_tool_access
from ..config import get_settings
from ..observability import record_activity, traced_tool
from . import shell_workspace


def _truncate(text: str, max_chars: int) -> str:
    """Tronque le texte si nécessaire, avec indication."""
    if len(text) > max_chars:
        return text[:max_chars] + f"\n... [TRONQUÉ — {len(text)} chars, limite {max_chars}]"
    return text


# Rappel du contrat sandbox (#68). Heuristique : le texte n'affirme pas la cause,
# un chemin peut aussi être faux dès le premier appel.
STATELESS_HINT = (
    "Rappel : chaque appel shell démarre dans un conteneur neuf, détruit à la fin de l'appel. "
    "Si ce chemin venait d'un appel précédent (téléchargement, extraction, cd), il n'existe plus ici. "
    "Enchaîner les étapes dépendantes dans une seule commande "
    "(par exemple curl -LO URL && tar xzf a.tar.gz && cd a && make), "
    "ou conserver le résultat avec l'outil files."
)
CWD_IGNORED_HINT = (
    "cwd est ignoré en sandbox : la commande a démarré dans le répertoire par défaut. "
    "Chaque appel shell démarre dans un conteneur neuf ; écrire cd <répertoire> && ... dans command, "
    "dans le même appel que la création du répertoire."
)
MISSING_PATH = "No such file or directory"
# Indices quand la session a un espace /tmp (#72).
WORKSPACE_HINT = (
    "Seuls les fichiers écrits sous /tmp sont conservés entre les appels shell de cette session MCP ; "
    "le répertoire courant et les variables ne le sont pas : utiliser des chemins absolus sous /tmp "
    "(par exemple cd /tmp/a && make). Un chemin créé par une autre étape, un autre worker, "
    "ou avant l'expiration de l'espace n'existe pas ici : le recréer dans cette session, "
    "ou conserver le résultat avec l'outil files."
)
NEW_WORKSPACE_HINT = (
    "L'espace /tmp de cette session vient d'être créé : aucun fichier d'un appel antérieur n'y figure. "
    + WORKSPACE_HINT
)
CWD_IGNORED_WORKSPACE_HINT = (
    "cwd est ignoré en sandbox : la commande a démarré dans le répertoire par défaut. "
    "Écrire cd <répertoire> && ... dans command."
)
EPHEMERAL_REASONS = {
    "unavailable": "création impossible",
}
CAPACITY_MESSAGE = (
    "Capacité des espaces /tmp de session atteinte : la commande n'a pas été exécutée."
)
CAPACITY_HINT = (
    "Aucun espace /tmp de session n'est libre sur le serveur. Réessayer plus tard : "
    "un espace inactif est libéré après idle_seconds. Ne pas supposer que les fichiers "
    "d'un appel antérieur de cette session existent."
)


def _ephemeral_hint(reason: Optional[str]) -> str:
    cause = EPHEMERAL_REASONS.get(reason or "", "indisponible")
    return (f"L'espace /tmp persistant de cette session n'est pas disponible ({cause}) : "
            "ce /tmp est éphémère et disparaît à la fin de l'appel. " + STATELESS_HINT)


def _stateless_hint(result: dict, cwd: Optional[str], lease=None) -> Optional[str]:
    """Indice si un cwd non vide a été ignoré, si /tmp est éphémère malgré une session,
    ou si un échec signale un chemin absent."""
    missing = result.get("returncode") not in (0, None) and MISSING_PATH in (result.get("stderr") or "")
    if lease is None:
        # Sans session : texte identique à celui d'avant #72.
        if cwd:
            return CWD_IGNORED_HINT
        return STATELESS_HINT if missing else None
    hints = [CWD_IGNORED_WORKSPACE_HINT] if cwd else []
    if lease.workspace is None:
        hints.append(_ephemeral_hint(lease.reason))
    elif missing:
        hints.append(NEW_WORKSPACE_HINT if lease.new else WORKSPACE_HINT)
    return " ".join(hints) or None


def _with_cwd_hint(response: dict, cwd_ignored: bool, lease=None, settings=None) -> dict:
    """Réponse d'erreur : garde l'état de /tmp quand la session a demandé un espace (#72).

    Après un délai dépassé, la commande a pu écrire dans l'espace avant d'être arrêtée.
    """
    if lease is None:
        if cwd_ignored:
            response["hint"] = CWD_IGNORED_HINT
        return response
    hint = _stateless_hint({}, "cwd" if cwd_ignored else None, lease)
    if hint:
        response["hint"] = hint
    response["workspace"] = lease.public(settings)
    return response


# Mapping shell → flag d'exécution inline
SHELL_EXEC_FLAGS = {
    "bash": "-c",
    "sh": "-c",
    "python3": "-c",
    "node": "-e",
}


DOCKER_CLEANUP_TIMEOUT = 15
CLEANUP_CHECKS = 10
CLEANUP_CHECK_INTERVAL = 0.5
# Nettoyages en cours : une référence les garde en vie jusqu'à leur fin.
_CLEANUPS: set = set()


async def _docker_quiet(*args: str) -> tuple[int, bytes]:
    """Commande docker bornée dans le temps ; (-1, b"") si elle échoue ou dépasse le délai."""
    try:
        proc = await asyncio.create_subprocess_exec(
            "docker", *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
    except Exception:
        return -1, b""
    try:
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=DOCKER_CLEANUP_TIMEOUT)
    except BaseException as error:
        try:
            proc.kill()
        except Exception:
            pass
        if isinstance(error, asyncio.CancelledError):
            raise
        return -1, b""
    return proc.returncode, out


async def _kill_container(name: str) -> bool:
    """Force-kill et supprime un conteneur Docker par son nom. Rend True si Docker confirme sa disparition.

    `--rm` fait retirer le conteneur par Docker après `kill` : le retrait peut
    encore être en cours au premier contrôle, d'où quelques contrôles espacés.
    """
    await _docker_quiet("kill", name)
    await _docker_quiet("rm", "-f", name)
    for attempt in range(CLEANUP_CHECKS):
        code, out = await _docker_quiet("ps", "-aq", "--filter", f"name=^{name}$")
        if code == 0 and not out.split():
            return True
        if attempt + 1 < CLEANUP_CHECKS:
            await asyncio.sleep(CLEANUP_CHECK_INTERVAL)
            await _docker_quiet("rm", "-f", name)
    return False


def _start_cleanup(process, container_name: str, cleanups: Optional[list]) -> asyncio.Task:
    """Arrête le client docker run et retire le conteneur, dans une tâche à part.

    Une annulation MCP annule l'appel à chaque attente : un nettoyage attendu
    dans l'appel ne passerait jamais sa première commande docker. La tâche à
    part va au bout, chaque commande bornée par DOCKER_CLEANUP_TIMEOUT.
    """
    async def cleanup() -> bool:
        # process vaut None si l'annulation a interrompu son lancement : le
        # conteneur a pu démarrer quand même, son nom suffit à le retirer.
        if process is not None:
            try:
                process.kill()
            except Exception:
                pass
            try:
                await asyncio.wait_for(process.wait(), timeout=DOCKER_CLEANUP_TIMEOUT)
            except Exception:
                pass
        gone = await _kill_container(container_name)
        if not gone:
            record_activity("sandbox.cleanup_failed", level="error", message="Sandbox non retirée après arrêt",
                            details={"sandbox_id": container_name})
        return gone

    task = asyncio.get_running_loop().create_task(cleanup())
    _CLEANUPS.add(task)
    task.add_done_callback(_CLEANUPS.discard)
    if cleanups is not None:
        cleanups.append(task)
    return task


def _cleanups_succeeded(done) -> bool:
    try:
        return all(result is True for result in done.result())
    except BaseException:
        return False


async def _run_in_sandbox(command: str, shell: str, timeout: int, settings, network: bool = False,
                          workspace_args: Optional[list] = None, cleanups: Optional[list] = None) -> dict:
    """Exécute la commande dans un conteneur Docker éphémère isolé.

    Si network=True, le conteneur a accès au réseau (--network=bridge + DNS).
    Sinon, isolation totale (--network=none).
    Si workspace_args est fourni, le volume de session qu'il monte remplace le tmpfs de /tmp (#72).
    Après un délai dépassé ou une annulation, la tâche de nettoyage est ajoutée à `cleanups`.
    """
    exec_flag = SHELL_EXEC_FLAGS.get(shell, "-c")
    container_name = f"sandbox-{uuid.uuid4().hex[:12]}"
    docker_cmd = [
        "docker", "run", "--rm",
        f"--name={container_name}",
    ]

    # Mode réseau : bridge (avec DNS) ou none (isolé)
    if network:
        docker_cmd.append("--network=bridge")
        for dns in settings.sandbox_dns.split(","):
            dns = dns.strip()
            if dns:
                docker_cmd.append(f"--dns={dns}")
    else:
        docker_cmd.append("--network=none")

    # Quand le réseau est activé (pip install, curl...), on assouplit certaines contraintes :
    # - tmpfs plus grand pour accueillir les téléchargements
    # - tmpfs supplémentaire sur ~/.local pour pip install --user
    # - pids-limit relevé (pip spawne des sous-processus)
    if network:
        tmpfs_size = "256m"
        # Sans exec explicite, Docker ajoute noexec à --tmpfs : /tmp reste non exécutable (#72).
        tmpfs_opts = f"nosuid,nodev,size={tmpfs_size}"
        pids_limit = 50
    else:
        tmpfs_size = settings.sandbox_tmpfs_size
        tmpfs_opts = f"noexec,nosuid,nodev,size={tmpfs_size}"  # noexec pour isolation maximale
        pids_limit = settings.sandbox_pids_limit

    docker_cmd.extend([
        "--read-only",
        f"--memory={settings.sandbox_memory}",
        f"--memory-swap={settings.sandbox_memory}",
        f"--cpus={settings.sandbox_cpus}",
        f"--pids-limit={pids_limit}",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges:true",
    ])
    if workspace_args:
        docker_cmd.extend(workspace_args)
    else:
        docker_cmd.append(f"--tmpfs=/tmp:{tmpfs_opts}")

    # Variables d'environnement pour compatibilité packages Python
    # OPENBLAS_NUM_THREADS=1 évite que numpy/scipy spawne trop de threads (pids-limit)
    docker_cmd.extend([
        "--env=OPENBLAS_NUM_THREADS=1",
        "--env=OPENBLAS_MAIN_FREE=1",
    ])

    # Quand le réseau est activé : permettre pip install + monter tmpfs pour ~/.local et ~/.cache
    if network:
        docker_cmd.extend([
            "--env=PIP_BREAK_SYSTEM_PACKAGES=1",
            "--tmpfs=/home/sandbox/.local:nosuid,nodev,size=128m",
            "--tmpfs=/home/sandbox/.cache:nosuid,nodev,size=64m",
        ])

    docker_cmd.extend([
        "--user=sandbox:sandbox",
        settings.sandbox_image,
    ])
    if workspace_args:
        docker_cmd.extend(shell_workspace.confined_command(shell, exec_flag, command))
    else:
        docker_cmd.extend([shell, exec_flag, command])

    record_activity("sandbox.starting", message="Création de la sandbox", details={"sandbox_id": container_name, "network": network, "timeout": timeout})
    process = None
    try:
        # Lancement sous la même garde que l'attente : une annulation pendant
        # create_subprocess_exec peut survenir après le démarrage du conteneur.
        process = await asyncio.create_subprocess_exec(
            *docker_cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        record_activity("sandbox.started", message="Sandbox démarrée", details={"sandbox_id": container_name})
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        record_activity("sandbox.timeout", level="warning", message="Délai de sandbox dépassé", details={"sandbox_id": container_name, "timeout": timeout})
        # Tuer le process docker run ET le conteneur Docker
        await asyncio.shield(_start_cleanup(process, container_name, cleanups))
        raise  # Re-raise pour que l'appelant gère le message d'erreur
    except asyncio.CancelledError:
        # Le SDK v2 propage l'annulation du client : docker run ne doit pas
        # survivre au call MCP abandonné.
        record_activity("sandbox.cancelled", level="warning", message="Sandbox annulée, nettoyage lancé", details={"sandbox_id": container_name})
        # Pas d'attente ici : l'annulation interromprait le nettoyage (#72).
        _start_cleanup(process, container_name, cleanups)
        raise

    max_chars = settings.tool_max_output_chars
    record_activity("sandbox.completed", level="error" if process.returncode else "info", message="Sandbox terminée", details={"sandbox_id": container_name, "returncode": process.returncode})
    return {
        "status": "success" if process.returncode == 0 else "error",
        "stdout": _truncate(stdout.decode(errors="replace"), max_chars),
        "stderr": _truncate(stderr.decode(errors="replace"), max_chars),
        "returncode": process.returncode,
        "sandbox": True,
    }


async def _run_local(command: str, shell: str, cwd: Optional[str], timeout: int, settings) -> dict:
    """Fallback : exécution locale via subprocess (dev uniquement)."""
    exec_flag = SHELL_EXEC_FLAGS.get(shell, "-c")
    shell_cmd = [shell, exec_flag, command]

    process = await asyncio.create_subprocess_exec(
        *shell_cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=cwd,
    )

    try:
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        try:
            process.kill()
            await process.wait()
        except Exception:
            pass
        raise

    max_chars = settings.tool_max_output_chars
    return {
        "status": "success" if process.returncode == 0 else "error",
        "stdout": _truncate(stdout.decode(errors="replace"), max_chars),
        "stderr": _truncate(stderr.decode(errors="replace"), max_chars),
        "returncode": process.returncode,
        "sandbox": False,
    }


def register(mcp: MCPServer) -> None:
    @mcp.tool()
    @traced_tool("shell")
    async def shell(
        command: Annotated[str, Field(description="Commande complète. En mode sandbox, chaque appel démarre dans un conteneur neuf : le répertoire courant et les variables ne passent pas à l'appel suivant ; les fichiers sous /tmp peuvent être conservés pour la même session MCP, seulement si le champ workspace de la réponse indique persistent=true. Mettre dans une seule commande les étapes qui dépendent d'un cd ou d'une variable (&&, ;, script multiligne).")],
        shell: Annotated[str, Field(default="bash", description="Shell à utiliser : bash, sh, python3 ou node")] = "bash",
        cwd: Annotated[Optional[str], Field(default=None, description="Ignoré en sandbox : le conteneur est neuf à chaque appel et démarre dans le répertoire par défaut. Écrire cd <répertoire> && ... dans command ; un répertoire créé par un appel précédent n'existe que s'il est sous /tmp, dans la même session MCP, et si workspace.persistent valait true pour ces appels.")] = None,
        timeout: Annotated[int, Field(default=30, description="Timeout en secondes (max selon config serveur)")] = 30,
        network: Annotated[bool, Field(default=False, description="⚠️ ÉLÉVATION DE PRIVILÈGE : active l'accès réseau (pour pip install, curl, wget). Retire l'isolation réseau ; /tmp reste non exécutable. Défaut: false (isolé, sans réseau)")] = False,
        ctx: Optional[Context] = None,
    ) -> dict:
        """Exécute une commande dans une sandbox : en mode sandbox, celui des déploiements, chaque appel démarre dans un conteneur neuf et isolé, détruit à la fin de l'appel (sans réseau par défaut, mémoire limitée, non-root). Shells disponibles : bash, sh, python3, node.

        En mode sandbox, si le serveur l'active, les fichiers écrits sous /tmp sont conservés entre les appels de la même session MCP (le même worker), dans une limite de taille, d'inactivité et de durée ; seul le champ workspace de la réponse le confirme et donne ces limites. Si la capacité des espaces du serveur est atteinte, la commande n'est pas exécutée : la réponse est une erreur avec workspace.reason=capacity, réessayer plus tard. Si le serveur ne peut pas créer l'espace pour une autre raison, workspace.persistent vaut false et /tmp est éphémère pour cet appel. Rien d'autre ne passe d'un appel au suivant : répertoire courant, variables, processus et paquets installés disparaissent, donc utiliser des chemins absolus sous /tmp. Rien ne passe à une autre session, donc à une autre étape ou un autre worker. Sans espace persistant (champ workspace absent ou persistent=false), enchaîner les étapes dépendantes dans une seule commande, par exemple curl -LO URL && tar xzf a.tar.gz && cd a && make. Pour transmettre un résultat à une autre étape, l'afficher sur stdout ou l'écrire avec l'outil files. Seul /tmp est inscriptible, en mémoire, non exécutable (lancer un script par bash script.sh) et de taille limitée ; network=true ajoute ~/.local et ~/.cache."""
        # cwd ignoré : l'indice accompagne aussi un échec après tentative sandbox (timeout).
        cwd_ignored = False
        lease = None
        settings = None
        cleanups: list = []
        try:
            check_tool_access("shell")
            settings = get_settings()

            # Bornes de sécurité
            ALLOWED_SHELLS = ("bash", "sh", "python3", "node")
            timeout = max(1, min(timeout, settings.sandbox_max_timeout))
            if shell not in ALLOWED_SHELLS:
                return {"status": "error", "message": f"Shell '{shell}' non autorisé. Valides: {', '.join(ALLOWED_SHELLS)}"}

            if settings.sandbox_enabled:
                cwd_ignored = bool(cwd)
                if cwd:
                    print(f"[shell] WARN: cwd ignoré en mode sandbox (pas de montage volume)", file=sys.stderr)
                # Purge des espaces d'un processus précédent, même sans session ni espace (#72).
                shell_workspace.registry.prepare(settings)
                # Espace de session (#72) : clé tirée de la requête, jamais des arguments.
                # Sans session MCP, ou espaces désactivés, /tmp reste éphémère comme avant.
                key = shell_workspace.key_from_context(ctx)
                if key is not None and settings.shell_workspace_max_count > 0:
                    lease = await shell_workspace.registry.acquire(key, settings)
                if lease is not None and lease.reason == "capacity" and lease.workspace is None:
                    # Décision Root (#72) : capacité pleine = refus explicite, pas de /tmp
                    # éphémère silencieux. La commande ne démarre pas.
                    return {"status": "error", "message": CAPACITY_MESSAGE, "hint": CAPACITY_HINT,
                            "workspace": {**lease.public(settings),
                                          "idle_seconds": settings.shell_workspace_idle_seconds}}
                if lease is not None and lease.workspace is not None:
                    result = await _run_in_sandbox(
                        command, shell, timeout, settings, network=network,
                        workspace_args=shell_workspace.call_args(lease.workspace, settings), cleanups=cleanups)
                else:
                    result = await _run_in_sandbox(command, shell, timeout, settings, network=network)
                hint = _stateless_hint(result, cwd, lease)
                if hint:
                    result["hint"] = hint
                if lease is not None:
                    result["workspace"] = lease.public(settings)
            else:
                result = await _run_local(command, shell, cwd, timeout, settings)

            return result

        except asyncio.TimeoutError:
            return _with_cwd_hint({"status": "error", "message": f"Timeout de {timeout}s dépassé."},
                                  cwd_ignored, lease, settings)
        except FileNotFoundError:
            return {"status": "error", "message": "Docker CLI non trouvé. Vérifiez que le binaire docker est installé et que docker.sock est monté."}
        except Exception as e:
            return _with_cwd_hint({"status": "error", "message": str(e)}, cwd_ignored, lease, settings)
        finally:
            if lease is not None:
                if cleanups:
                    # Le conteneur d'appel peut encore monter l'espace : la
                    # réservation tient jusqu'à la fin de son retrait. Un retrait
                    # non confirmé retire l'espace, compté jusqu'à son démontage.
                    asyncio.gather(*cleanups, return_exceptions=True).add_done_callback(
                        lambda done, lease=lease: shell_workspace.registry.release(
                            lease, orphaned=not _cleanups_succeeded(done)))
                else:
                    shell_workspace.registry.release(lease)
