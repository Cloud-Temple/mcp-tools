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
import contextvars
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
# Index des pages d'un fichier tmpfs : nœuds de 64 entrées, 576 octets sur
# x86_64. Mesuré sur Linux 6.8 : 585 octets par page et par niveau quand chaque
# page est seule dans son nœud. Arrondi au-dessus.
PAGE_BYTES = 4096
XARRAY_FANOUT = 64
XARRAY_NODE_BYTES = 640


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
    # Nettoyages de conteneurs d'appel en cours : l'espace n'est pas remis tant qu'il en reste.
    cleaning: int = 0


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
                "size_bytes": data, "max_file_bytes": data, "max_entries": max_entries,
                "idle_seconds": settings.shell_workspace_idle_seconds,
                "max_age_seconds": settings.shell_workspace_max_age_seconds}
        if self.reason:
            info["reason"] = self.reason
        return info


def _xarray_height(pages: int) -> int:
    """Hauteur de l'index des pages d'un fichier qui couvre `pages` pages."""
    height = 1
    while XARRAY_FANOUT ** height < pages:
        height += 1
    return height


def tmpfs_layout(size: int) -> tuple[int, int]:
    """Répartit le budget mémoire `size` d'un espace : données, entrées, index des pages.

    `size=` ne borne que les pages de données. Le noyau garde aussi en mémoire :
    - pour chaque fichier, répertoire ou lien, son inode et son entrée de
      répertoire. `nr_inodes` les borne ; un huitième du budget leur revient,
      à INODE_COST_BYTES par entrée ;
    - pour chaque page de données, les nœuds de l'index des pages du fichier.
      Un fichier creux dont les pages sont très espacées alloue au pire un
      nœud par niveau et par page. `--ulimit fsize` borne la taille d'un
      fichier à la taille des données, donc la hauteur de l'index.
    Rend (octets de données, nombre maximal d'entrées). Données, entrées et
    index tiennent ensemble dans `size`.
    """
    max_entries = max(1, size // (8 * INODE_COST_BYTES))
    budget = size - max_entries * INODE_COST_BYTES
    height = 1
    while True:
        pages = max(1, budget // (PAGE_BYTES + height * XARRAY_NODE_BYTES))
        if _xarray_height(pages) <= height:
            return pages * PAGE_BYTES, max_entries
        height += 1


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
    data, _ = tmpfs_layout(workspace.size)
    return [
        "--label", f"{LABEL}={CALL_ROLE}",
        "--label", f"{INSTANCE_LABEL}={settings.shell_workspace_instance}",
        f"--mount=type=volume,src={workspace.volume},dst={MOUNT_POINT},volume-nocopy,"
        f"volume-driver=local,volume-opt=type=tmpfs,volume-opt=device=tmpfs,"
        f"\"volume-opt=o={_tmpfs_options(workspace.size)}\"",
        # Borne la hauteur de l'index des pages, donc sa mémoire (tmpfs_layout).
        f"--ulimit=fsize={data}:{data}",
    ]


# Filtre seccomp ajouté par-dessus le profil Docker dans les appels avec espace.
# Les ACL POSIX et autres attributs étendus d'un tmpfs restent en mémoire noyau
# hors de `nr_inodes` et de `size` : une ACL peut peser 64 Kio par entrée.
# setxattr, lsetxattr, fsetxattr et setxattrat (Linux 6.13) rendent donc
# EOPNOTSUPP, comme sur un système de fichiers sans attributs étendus ; cp -a
# et tar continuent sans eux. Une architecture inconnue, ou un filtre qui ne
# s'installe pas, arrête l'appel avant la commande (code 126).
XATTR_GUARD = """import ctypes, os, platform, struct, sys
ARCHES = {"x86_64": (0xC000003E, (188, 189, 190)), "aarch64": (0xC00000B7, (5, 6, 7))}
if platform.machine() not in ARCHES:
    sys.stderr.write("sandbox: architecture non prise en charge par le filtre xattr\\n")
    sys.exit(126)
arch, numbers = ARCHES[platform.machine()]
numbers = numbers + (463,)
deny, allow = 0x00050000 | 95, 0x7FFF0000
n = len(numbers)
code = [(0x20, 0, 0, 4), (0x15, 1, 0, arch), (0x06, 0, 0, deny), (0x20, 0, 0, 0),
        (0x35, n + 1, 0, 0x40000000)]
code += [(0x15, n - i, 0, number) for i, number in enumerate(numbers)]
code += [(0x06, 0, 0, allow), (0x06, 0, 0, deny)]
program = ctypes.create_string_buffer(b"".join(struct.pack("=HBBI", *c) for c in code))


class Fprog(ctypes.Structure):
    _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.c_void_p)]


libc = ctypes.CDLL(None, use_errno=True)
libc.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_void_p, ctypes.c_ulong, ctypes.c_ulong]
fprog = Fprog(len(code), ctypes.addressof(program))
if libc.prctl(38, 1, None, 0, 0) != 0 or libc.prctl(22, 2, ctypes.byref(fprog), 0, 0) != 0:
    sys.stderr.write("sandbox: filtre xattr non installé\\n")
    sys.exit(126)
os.execvp(sys.argv[1], sys.argv[1:])
"""


def confined_command(shell: str, exec_flag: str, command: str) -> list[str]:
    """Fin de la commande `docker run` d'un appel avec espace : le shell lancé sous XATTR_GUARD."""
    return ["python3", "-I", "-S", "-c", XATTR_GUARD, shell, exec_flag, command]


def background_task(coroutine) -> asyncio.Task:
    """Tâche de fond sans le contexte de l'appel qui la lance : ses événements ne portent ni sa trace ni son acteur."""
    return asyncio.get_running_loop().create_task(coroutine, context=contextvars.Context())


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
        self._purging = False
        self._purge_task: Optional[asyncio.Task] = None
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
            self._sweeper = background_task(self._sweep_forever(settings))

    async def stop(self) -> None:
        """Arrête nettoyage et purge en attente, puis attend les retraits lancés (tests, arrêt propre)."""
        for task in (self._purge_task,):
            if task is not None and not task.done():
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
        self._purge_task = None
        # Une tâche annulée avant son premier pas n'exécute pas son finally.
        self._purging = False
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

    async def _holder_running(self, workspace: Workspace) -> Optional[bool]:
        """True : maintien actif. False : arrêt ou absence confirmés par Docker.
        None : Docker ne répond pas de façon sûre ; l'espace ne doit pas être détruit sur ce seul indice.
        """
        try:
            code, out = await _docker("inspect", "--format", "{{.State.Running}}", workspace.holder)
            if code == 0 and out.strip() in ("true", "false"):
                return out.strip() == "true"
            # inspect échoue aussi bien sur un conteneur absent que sur un démon
            # indisponible : seul un inventaire réussi et vide confirme l'absence.
            code, out = await _docker("ps", "-aq", "--filter", f"name=^{workspace.holder}$")
        except Exception:
            return None
        if code == 0 and not out.split():
            return False
        return None

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
            # Sans appel en cours, un conteneur qui monte encore le volume est un
            # appel dont le nettoyage a échoué : il garderait le tmpfs monté.
            code, out = await _docker("ps", "-aq", "--filter", f"volume={workspace.volume}")
            if code == 0 and out.split():
                await _docker("rm", "-f", *out.split())
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

    def _spawn(self, coroutine) -> None:
        """Lance un retrait ou une purge hors du chemin de l'appel, sans que son annulation l'interrompe."""
        try:
            task = background_task(coroutine)
        except RuntimeError:
            coroutine.close()
            return
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    def prepare(self, settings) -> None:
        """Premier appel sandbox du processus : purge les espaces d'un processus précédent.

        Indépendant des admissions : après un retour à SHELL_WORKSPACE_MAX_COUNT=0
        ou sans session, les anciens conteneurs de maintien sont quand même
        retirés. La purge tourne en tâche de fond : l'appel ne l'attend pas.
        """
        if self._purged or self._purging or self._clock() < self._purge_retry_at:
            return
        self._purging = True
        try:
            self._purge_task = background_task(self._purge_in_background(settings))
        except RuntimeError:
            self._purging = False

    async def _purge_in_background(self, settings) -> None:
        """Retente la purge à chaque intervalle jusqu'à sa confirmation, sans attendre d'appel."""
        try:
            while not self._purged:
                async with self._bind_loop():
                    self._purge_retry_at = float("-inf")
                    await self._ensure_purged(settings)
                if not self._purged:
                    await asyncio.sleep(SWEEP_INTERVAL_SECONDS)
        finally:
            self._purging = False

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
                running = None
                if expired is None:
                    running = await self._holder_running(current)
                    # L'âge maximal a pu passer pendant le contrôle.
                    now = self._clock()
                    expired = _expired(current, now, settings)
                    if expired is None and running is False:
                        expired = "lost"
                if self._spaces.get(key) is not current:
                    # Retiré pendant le contrôle du maintien, hors verrou, par
                    # release(orphaned=True) : il est déjà à détruire.
                    reason = current.retire_reason or "lost"
                    current = None
                elif expired is not None:
                    reason = expired
                    self._retire(current, expired)
                    current = None
                elif running is None or current.cleaning:
                    # Docker incertain, ou nettoyage d'un appel arrêté en cours : l'espace
                    # est gardé tel quel, mais pas remis à cet appel, qui part en éphémère.
                    return Lease(None, reason="unavailable")
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
        # Le retrait d'un espace remplacé ne doit pas suivre la réservation sur
        # le chemin de l'appel : une annulation ici perdrait la réservation, que
        # `release` ne pourrait plus rendre.
        for workspace in pending:
            self._spawn(self._destroy(workspace))
        return lease

    def view(self, lease: Lease) -> Lease:
        """État à annoncer en fin d'appel : un espace retiré pendant l'appel n'est plus promis."""
        workspace = lease.workspace
        if workspace is None or self._spaces.get(workspace.key) is workspace:
            return lease
        return Lease(None, reason=workspace.retire_reason or "lost")

    def release(self, lease: Lease, orphaned: bool = False) -> None:
        """Fin d'appel. Un espace retiré pendant l'appel passe à détruire maintenant.

        `orphaned` : le conteneur d'appel n'a pas pu être retiré et monte peut-être
        encore l'espace. L'espace est retiré : la session en reçoit un neuf, et
        l'ancien reste compté jusqu'à ce que `_destroy` confirme son démontage,
        conteneur orphelin compris.
        """
        workspace = lease.workspace
        if workspace is None:
            return
        workspace.active -= 1
        workspace.last_used = self._clock()
        if orphaned and not workspace.retiring and self._spaces.get(workspace.key) is workspace:
            self._retire(workspace, "orphaned")
            if workspace in self._doomed:
                self._spawn(self._destroy(workspace))
            return
        if workspace.retiring and workspace.active == 0:
            if workspace in self._retiring:
                self._retiring.remove(workspace)
            if workspace not in self._doomed:
                self._doomed.append(workspace)
            self._spawn(self._destroy(workspace))

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
