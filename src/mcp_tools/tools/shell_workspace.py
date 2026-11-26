# -*- coding: utf-8 -*-
"""Espace /tmp de shell conservé dans une session MCP (#72).

En sandbox, chaque appel shell démarre dans un conteneur neuf. Un worker qui
téléchargeait des sources à un appel les perdait à l'appel suivant. Ce module
garde, pour une session MCP, un volume Docker tmpfs borné monté sur /tmp à
chaque appel de cette session. Le conteneur d'appel reste neuf : le répertoire
courant, les variables et les processus ne passent pas d'un appel à l'autre.

Clé : SHA-256 de l'identifiant de session MCP et de l'empreinte du jeton que
`AuthMiddleware` vient de valider pour la requête. Le gestionnaire de sessions
du SDK refuse en 404, avant l'outil, un identifiant qu'il n'a pas émis. Le
même identifiant présenté avec un autre jeton donne une autre clé ; il n'atteint
d'ailleurs pas l'outil, car `AuthMiddleware` lie la session au jeton qui l'a
ouverte et le SDK refuse alors la requête en 404. Une requête
du chemin sans session du SDK (version de protocole hors poignée de main)
n'est pas passée par ce contrôle : elle n'a pas d'espace. Sans identifiant de
session, aucun espace non plus : /tmp reste éphémère comme avant.

Un volume tmpfs perd ses fichiers quand plus aucun conteneur ne le monte. Un
conteneur de maintien, sans réseau ni droit, garde donc le volume monté. Il
s'arrête seul à l'âge maximal, même si ce processus meurt.

La table vit dans ce processus. mcp-tools tourne en un seul processus
(`server.py`, `uvicorn.run(app)`). Un autre processus ne voit pas cette table :
l'espace y est neuf, jamais partagé. Deux instances sur un même démon Docker
doivent porter des `SHELL_WORKSPACE_INSTANCE` distincts : la purge du démarrage
ne retire que les ressources de sa propre instance.
"""

import asyncio
import hashlib
import logging
import re
import sys
import time
import uuid
from dataclasses import dataclass
from typing import Optional

from mcp_types.version import HANDSHAKE_PROTOCOL_VERSIONS

from ..auth.context import current_credential_sha256
from ..observability import record_activity

LABEL = "mcp-tools.shell-workspace"
INSTANCE_LABEL = "mcp-tools.shell-workspace.instance"
HOLDER_ROLE = "holder"
VOLUME_ROLE = "volume"
CALL_ROLE = "call"
MOUNT_POINT = "/tmp"
# Marge du conteneur de maintien au-delà de l'âge maximal : un appel admis juste
# avant l'échéance garde son /tmp jusqu'à sa fin.
HOLDER_MARGIN_SECONDS = 60
SWEEP_INTERVAL_SECONDS = 60
DOCKER_COMMAND_TIMEOUT = 15
SESSION_ID = re.compile(r"[\x21-\x7e]{1,256}")
CREDENTIAL_DIGEST = re.compile(r"[0-9a-f]{64}")
# Identifiants émis par le SDK : uuid4().hex (streamable_http_manager.py).
SDK_SESSION_ID = re.compile(r"\b[0-9a-f]{32}\b")
SDK_SESSION_LOGGERS = ("mcp.server.streamable_http", "mcp.server.streamable_http_manager")
# Mémoire noyau d'une entrée de tmpfs (inode, entrée de répertoire, nom long).
# Mesuré sur Linux 6.8 : 1,5 Kio pour un fichier vide au nom de 246 caractères,
# 1 Kio pour un répertoire ou un lien court. Arrondi au-dessus.
INODE_COST_BYTES = 2048


def short_fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()[:8]


class SessionIdRedaction(logging.Filter):
    """Remplace un identifiant de session MCP par une empreinte courte dans les journaux du SDK."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except Exception:
            return True
        redacted = SDK_SESSION_ID.sub(lambda m: "session:" + short_fingerprint(m.group(0)), message)
        if redacted != message:
            record.msg, record.args = redacted, ()
        return True


def install_session_log_redaction() -> None:
    for name in SDK_SESSION_LOGGERS:
        logger = logging.getLogger(name)
        if not any(isinstance(f, SessionIdRedaction) for f in logger.filters):
            logger.addFilter(SessionIdRedaction())


# Les journaux du SDK portent l'identifiant de session en clair. Depuis #72, cet
# identifiant donne accès à un espace /tmp : il ne doit plus sortir en clair.
install_session_log_redaction()


def workspace_key(session_id: Optional[str], credential_sha256: Optional[str]) -> Optional[str]:
    """Clé d'espace, ou None si la requête n'a pas de session ou de jeton validé."""
    if not isinstance(session_id, str) or not SESSION_ID.fullmatch(session_id):
        return None
    if not isinstance(credential_sha256, str) or not CREDENTIAL_DIGEST.fullmatch(credential_sha256):
        return None
    return hashlib.sha256(f"{session_id}\0{credential_sha256}".encode()).hexdigest()


def key_from_context(ctx) -> Optional[str]:
    """Clé de la requête courante, tirée du transport et de l'authentification, jamais des arguments."""
    if ctx is None:
        return None
    try:
        headers = ctx.headers
    except Exception:
        return None
    if not headers:
        return None
    # Même règle d'aiguillage que StreamableHTTPSessionManager._handle_request :
    # hors de ces versions, la requête prend le chemin sans session et son
    # en-tête mcp-session-id n'a été validé par personne.
    version = headers.get("mcp-protocol-version")
    if version is not None and version not in HANDSHAKE_PROTOCOL_VERSIONS:
        return None
    return workspace_key(headers.get("mcp-session-id"), current_credential_sha256.get())


def fingerprint(key: str) -> str:
    """Empreinte courte pour les journaux. Ne permet pas de retrouver la session."""
    return key[:8]


@dataclass(eq=False)
class Workspace:
    key: str
    volume: str
    holder: str
    size: int
    created: float
    last_used: float
    active: int = 0
    retiring: bool = False
    destroying: bool = False
    retire_reason: str = ""


@dataclass
class Lease:
    """Résultat d'une admission. `workspace` est None quand /tmp est éphémère."""
    workspace: Optional[Workspace]
    new: bool = False
    reason: Optional[str] = None

    def public(self, settings) -> dict:
        """Champ `workspace` de la réponse, sans aucun identifiant."""
        if self.workspace is None:
            return {"persistent": False, "reason": self.reason}
        data, max_entries = tmpfs_layout(self.workspace.size)
        info = {"persistent": True, "path": MOUNT_POINT, "new": self.new,
                "size_bytes": data, "max_entries": max_entries,
                "idle_seconds": settings.shell_workspace_idle_seconds,
                "max_age_seconds": settings.shell_workspace_max_age_seconds}
        if self.reason:
            info["reason"] = self.reason
        return info


def tmpfs_layout(size: int) -> tuple[int, int]:
    """Répartit le budget mémoire d'un espace entre données et métadonnées.

    `size=` ne borne que les pages de données. Sans `nr_inodes`, le noyau fixe
    le nombre d'inodes d'après la RAM de l'hôte, et chaque fichier, répertoire
    ou lien garde en mémoire noyau son inode et son entrée de répertoire. Un
    huitième du budget va donc aux métadonnées, à INODE_COST_BYTES par entrée.
    Rend (octets de données, nombre maximal d'entrées) ; leur somme mémoire
    reste dans `size`.
    """
    max_entries = max(1, size // (8 * INODE_COST_BYTES))
    return size - max_entries * INODE_COST_BYTES, max_entries


def _tmpfs_options(size: int) -> str:
    data, max_entries = tmpfs_layout(size)
    # mode=1777 : mêmes droits que le /tmp tmpfs des appels sans espace.
    return f"size={data},nr_inodes={max_entries},mode=1777,nosuid,nodev,noexec"


def call_args(workspace: Workspace, settings) -> list[str]:
    """Arguments `docker run` d'un appel qui monte l'espace sur /tmp.

    volume-opt : si le volume a disparu entre le contrôle et le montage, Docker
    le recrée vide, mais toujours en tmpfs borné, jamais en volume disque.
    volume-nocopy : le contenu de /tmp ne vient jamais de l'image.
    """
    return [
        "--label", f"{LABEL}={CALL_ROLE}",
        "--label", f"{INSTANCE_LABEL}={settings.shell_workspace_instance}",
        f"--mount=type=volume,src={workspace.volume},dst={MOUNT_POINT},volume-nocopy,"
        f"volume-driver=local,volume-opt=type=tmpfs,volume-opt=device=tmpfs,"
        f"\"volume-opt=o={_tmpfs_options(workspace.size)}\"",
    ]


async def _docker(*args: str, timeout: float = DOCKER_COMMAND_TIMEOUT) -> tuple[int, str]:
    process = await asyncio.create_subprocess_exec(
        "docker", *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
    )
    try:
        stdout, _ = await asyncio.wait_for(process.communicate(), timeout=timeout)
    except BaseException:
        try:
            process.kill()
            await process.wait()
        except Exception:
            pass
        raise
    return process.returncode, stdout.decode(errors="replace")


def _expired(workspace: Workspace, now: float, settings) -> Optional[str]:
    if now - workspace.created >= settings.shell_workspace_max_age_seconds:
        return "expired"
    if workspace.active == 0 and now - workspace.last_used >= settings.shell_workspace_idle_seconds:
        return "expired"
    return None


class WorkspaceRegistry:
    """Table des espaces de ce processus, avec admission bornée et nettoyage.

    Un espace compte dans la capacité de sa création jusqu'à la confirmation de
    son retrait par Docker : volume absent de `docker volume ls`. Docker refuse
    de retirer un volume encore monté, donc un volume absent n'occupe plus de
    mémoire. Un retrait en cours, refusé ou interrompu garde l'espace compté ;
    le nettoyage périodique le retente.
    """

    def __init__(self, clock=time.monotonic):
        self._clock = clock
        self._spaces: dict[str, Workspace] = {}
        # Sortis de la table, encore montés par un appel en cours.
        self._retiring: list[Workspace] = []
        # Sans appel en cours, retrait demandé mais pas encore confirmé.
        self._doomed: list[Workspace] = []
        self._tasks: set[asyncio.Task] = set()
        self._lock: Optional[asyncio.Lock] = None
        self._loop = None
        self._sweeper: Optional[asyncio.Task] = None
        self._purged = False
        self._purge_retry_at = float("-inf")

    # --- état observable (tests, diagnostic) -------------------------------

    def live(self) -> list[Workspace]:
        return list(self._spaces.values()) + self._retiring + self._doomed

    def reserved_bytes(self) -> int:
        return sum(w.size for w in self.live())

    # --- boucle d'événements -----------------------------------------------

    def _bind_loop(self) -> asyncio.Lock:
        loop = asyncio.get_running_loop()
        if self._loop is not loop:
            self._loop = loop
            self._lock = asyncio.Lock()
            self._sweeper = None
        return self._lock

    def _start_sweeper(self, settings) -> None:
        if self._sweeper is None or self._sweeper.done():
            self._sweeper = asyncio.get_running_loop().create_task(self._sweep_forever(settings))

    async def stop(self) -> None:
        """Arrête la tâche de nettoyage et attend les retraits lancés (tests, arrêt propre)."""
        if self._sweeper is not None and not self._sweeper.done():
            self._sweeper.cancel()
            try:
                await self._sweeper
            except asyncio.CancelledError:
                pass
        self._sweeper = None
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)

    async def _sweep_forever(self, settings) -> None:
        while True:
            await asyncio.sleep(SWEEP_INTERVAL_SECONDS)
            try:
                await self.sweep(settings)
            except asyncio.CancelledError:
                raise
            except Exception as error:
                print(f"[shell] WARN: nettoyage des espaces en échec : {type(error).__name__}", file=sys.stderr)

    # --- cycle de vie --------------------------------------------------------

    async def purge_orphans(self, settings) -> bool:
        """Retire les conteneurs et volumes de cette instance laissés par un processus précédent.

        Les conteneurs d'appel sont retirés aussi : un appel orphelin garderait
        sinon le tmpfs monté hors de toute comptabilité. Rend True seulement si
        un second inventaire confirme qu'il ne reste rien.
        """
        instance = f"label={INSTANCE_LABEL}={settings.shell_workspace_instance}"
        containers_query = ("ps", "-aq", "--filter", f"label={LABEL}", "--filter", instance)
        volumes_query = ("volume", "ls", "-q", "--filter", f"label={LABEL}={VOLUME_ROLE}", "--filter", instance)
        code, out = await _docker(*containers_query)
        if code != 0:
            return False
        containers = out.split()
        if containers:
            await _docker("rm", "-f", *containers)
        code, out = await _docker(*volumes_query)
        if code != 0:
            return False
        volumes = out.split()
        for volume in volumes:
            await _docker("volume", "rm", volume)
        if containers or volumes:
            record_activity("shell.workspace.purged", level="warning",
                            message="Espaces shell d'un processus précédent retirés",
                            details={"containers": len(containers), "volumes": len(volumes)})
        code_c, left_c = await _docker(*containers_query)
        code_v, left_v = await _docker(*volumes_query)
        return code_c == 0 and code_v == 0 and not left_c.split() and not left_v.split()

    async def _ensure_purged(self, settings) -> bool:
        """Purge une fois avant toute admission ; retentée au plus une fois par intervalle."""
        if self._purged:
            return True
        now = self._clock()
        if now < self._purge_retry_at:
            return False
        try:
            self._purged = await self.purge_orphans(settings)
        except asyncio.CancelledError:
            raise
        except Exception as error:
            print(f"[shell] WARN: purge des espaces en échec : {type(error).__name__}", file=sys.stderr)
        if not self._purged:
            self._purge_retry_at = now + SWEEP_INTERVAL_SECONDS
            record_activity("shell.workspace.purge_failed", level="error",
                            message="Inventaire des espaces shell incertain : admissions suspendues")
        return self._purged

    async def _create(self, key: str, settings) -> Workspace:
        suffix = uuid.uuid4().hex
        size = settings.shell_workspace_size_bytes
        now = self._clock()
        workspace = Workspace(key=key, volume=f"shellws-{suffix}", holder=f"shellws-holder-{suffix}",
                              size=size, created=now, last_used=now)
        instance = f"{INSTANCE_LABEL}={settings.shell_workspace_instance}"
        lifetime = settings.shell_workspace_max_age_seconds + settings.sandbox_max_timeout + HOLDER_MARGIN_SECONDS
        try:
            code, _ = await _docker(
                "volume", "create", "--driver", "local",
                "--label", f"{LABEL}={VOLUME_ROLE}", "--label", instance,
                "--opt", "type=tmpfs", "--opt", "device=tmpfs", "--opt", f"o={_tmpfs_options(size)}",
                workspace.volume,
            )
            if code != 0:
                raise RuntimeError("volume create")
            # --workdir=/ : le WORKDIR de l'image est sous /tmp, monté ici en lecture seule.
            code, _ = await _docker(
                "run", "-d", "--rm", f"--name={workspace.holder}",
                "--label", f"{LABEL}={HOLDER_ROLE}", "--label", instance,
                "--network=none", "--read-only", "--cap-drop=ALL",
                "--security-opt=no-new-privileges:true",
                "--memory=16m", "--memory-swap=16m", "--cpus=0.05", "--pids-limit=4",
                "--user=sandbox:sandbox", "--workdir=/",
                f"--mount=type=volume,src={workspace.volume},dst={MOUNT_POINT},readonly,volume-nocopy",
                settings.sandbox_image, "sleep", str(lifetime),
            )
            if code != 0:
                raise RuntimeError("holder run")
        except BaseException:
            # Un délai dépassé ou une annulation peut laisser le maintien
            # démarré : l'espace reste compté jusqu'au retrait confirmé.
            workspace.retire_reason = "failed"
            self._doomed.append(workspace)
            raise
        return workspace

    async def _holder_running(self, workspace: Workspace) -> bool:
        try:
            code, out = await _docker("inspect", "--format", "{{.State.Running}}", workspace.holder)
        except Exception:
            return False
        return code == 0 and out.strip() == "true"

    async def _volume_gone(self, volume: str) -> bool:
        code, out = await _docker("volume", "ls", "-q", "--filter", f"name={volume}")
        return code == 0 and volume not in out.split()

    async def _destroy(self, workspace: Workspace) -> bool:
        """Retire un espace de `_doomed` ; il n'en sort qu'après confirmation par Docker."""
        if workspace.destroying or workspace not in self._doomed:
            return False
        workspace.destroying = True
        gone = False
        try:
            await _docker("rm", "-f", workspace.holder)
            await _docker("volume", "rm", workspace.volume)
            gone = await self._volume_gone(workspace.volume)
        except asyncio.CancelledError:
            raise
        except Exception as error:
            print(f"[shell] WARN: retrait d'espace en échec : {type(error).__name__}", file=sys.stderr)
        finally:
            workspace.destroying = False
        if not gone:
            record_activity("shell.workspace.remove_failed", level="warning",
                            message="Retrait d'espace shell non confirmé : espace encore compté",
                            details={"workspace": fingerprint(workspace.key), "reason": workspace.retire_reason})
            return False
        if workspace in self._doomed:
            self._doomed.remove(workspace)
        record_activity("shell.workspace.removed", message="Espace shell retiré",
                        details={"workspace": fingerprint(workspace.key), "reason": workspace.retire_reason})
        return True

    def _retire(self, workspace: Workspace, reason: str) -> None:
        """Sort l'espace de la table. Il reste compté jusqu'au retrait confirmé.

        Sans appel en cours, il passe à détruire. Encore monté par un appel, il
        attend la fin de cet appel dans `_retiring`, puis `release` le détruit.
        """
        workspace.retire_reason = reason
        if self._spaces.get(workspace.key) is workspace:
            del self._spaces[workspace.key]
        if workspace.active == 0:
            if workspace in self._retiring:
                self._retiring.remove(workspace)
            if workspace not in self._doomed:
                self._doomed.append(workspace)
            return
        workspace.retiring = True
        if workspace not in self._retiring:
            self._retiring.append(workspace)

    def _pending(self) -> list[Workspace]:
        return [w for w in self._doomed if not w.destroying]

    async def _destroy_all(self, workspaces: list[Workspace]) -> None:
        for workspace in workspaces:
            await self._destroy(workspace)

    async def acquire(self, key: str, settings) -> Lease:
        """Rend l'espace de la clé, en le créant si la capacité le permet."""
        lock = self._bind_loop()
        async with lock:
            self._start_sweeper(settings)
            if not await self._ensure_purged(settings):
                return Lease(None, reason="unavailable")
            # Les retraits déjà en attente sont retentés par le nettoyage
            # périodique, pas sur le chemin d'un appel.
            already_doomed = list(self._doomed)
            now = self._clock()
            reason = None
            current = self._spaces.get(key)
            if current is not None:
                expired = _expired(current, now, settings)
                if expired is None and not await self._holder_running(current):
                    expired = "lost"
                if expired is not None:
                    reason = expired
                    self._retire(current, expired)
                    current = None
            if current is None:
                size = settings.shell_workspace_size_bytes
                if (len(self.live()) >= settings.shell_workspace_max_count
                        or self.reserved_bytes() + size > settings.shell_workspace_max_total_bytes):
                    record_activity("shell.workspace.refused", level="warning",
                                    message="Espace shell refusé : capacité atteinte",
                                    details={"workspace": fingerprint(key), "live": len(self.live()),
                                             "reserved_bytes": self.reserved_bytes()})
                    lease = Lease(None, reason="capacity")
                else:
                    try:
                        current = await self._create(key, settings)
                    except Exception as error:
                        record_activity("shell.workspace.unavailable", level="error",
                                        message="Espace shell non créé",
                                        details={"workspace": fingerprint(key), "error_type": type(error).__name__})
                        lease = Lease(None, reason="unavailable")
                    else:
                        self._spaces[key] = current
                        record_activity("shell.workspace.created", message="Espace shell créé",
                                        details={"workspace": fingerprint(key), "size_bytes": current.size})
                        lease = Lease(current, new=True, reason=reason)
            else:
                lease = Lease(current)
            if lease.workspace is not None:
                # Réservé sous le verrou : le nettoyage ne peut plus le détruire
                # avant `release`, appelé après la fin confirmée du conteneur d'appel.
                lease.workspace.active += 1
                lease.workspace.last_used = now
            pending = [w for w in self._pending() if w not in already_doomed]
        await self._destroy_all(pending)
        return lease

    def release(self, lease: Lease) -> None:
        """Fin d'appel. Un espace retiré pendant l'appel passe à détruire maintenant."""
        workspace = lease.workspace
        if workspace is None:
            return
        workspace.active -= 1
        workspace.last_used = self._clock()
        if workspace.retiring and workspace.active == 0:
            if workspace in self._retiring:
                self._retiring.remove(workspace)
            if workspace not in self._doomed:
                self._doomed.append(workspace)
            try:
                task = asyncio.get_running_loop().create_task(self._destroy(workspace))
            except RuntimeError:
                return
            self._tasks.add(task)
            task.add_done_callback(self._tasks.discard)

    async def sweep(self, settings) -> None:
        """Détruit les espaces expirés hors appel en cours, et retente les retraits non confirmés."""
        lock = self._bind_loop()
        async with lock:
            await self._ensure_purged(settings)
            now = self._clock()
            for workspace in list(self._spaces.values()):
                expired = _expired(workspace, now, settings)
                if expired is not None:
                    self._retire(workspace, expired)
            pending = self._pending()
        await self._destroy_all(pending)


registry = WorkspaceRegistry()
