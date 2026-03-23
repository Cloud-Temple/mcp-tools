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
from mcp.server.fastmcp import FastMCP, Context
from ..auth.context import check_tool_access
from ..config import get_settings


def _truncate(text: str, max_chars: int) -> str:
    """Tronque le texte si nécessaire, avec indication."""
    if len(text) > max_chars:
        return text[:max_chars] + f"\n... [TRONQUÉ — {len(text)} chars, limite {max_chars}]"
    return text


# Mapping shell → flag d'exécution inline
SHELL_EXEC_FLAGS = {
    "bash": "-c",
    "sh": "-c",
    "python3": "-c",
    "node": "-e",
}


async def _kill_container(name: str) -> None:
    """Force-kill et supprime un conteneur Docker par son nom."""
    try:
        proc = await asyncio.create_subprocess_exec(
            "docker", "kill", name,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        await proc.wait()
    except Exception:
        pass
    try:
        proc = await asyncio.create_subprocess_exec(
            "docker", "rm", "-f", name,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        await proc.wait()
    except Exception:
        pass


async def _run_in_sandbox(command: str, shell: str, timeout: int, settings, network: bool = False) -> dict:
    """Exécute la commande dans un conteneur Docker éphémère isolé.
    
    Si network=True, le conteneur a accès au réseau (--network=bridge + DNS).
    Sinon, isolation totale (--network=none).
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
        tmpfs_opts = f"nosuid,nodev,size={tmpfs_size}"  # pas de noexec (pip en a besoin)
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
        f"--tmpfs=/tmp:{tmpfs_opts}",
    ])

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
        shell, exec_flag, command,
    ])

    process = await asyncio.create_subprocess_exec(
        *docker_cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    try:
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        # Tuer le process docker run ET le conteneur Docker
        try:
            process.kill()
            await process.wait()
        except Exception:
            pass
        await _kill_container(container_name)
        raise  # Re-raise pour que l'appelant gère le message d'erreur

    max_chars = settings.tool_max_output_chars
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


def register(mcp: FastMCP) -> None:
    @mcp.tool()
    async def shell(
        command: Annotated[str, Field(description="La commande à exécuter dans le conteneur sandbox")],
        shell: Annotated[str, Field(default="bash", description="Shell à utiliser : bash, sh, python3 ou node")] = "bash",
        cwd: Annotated[Optional[str], Field(default=None, description="Répertoire de travail (ignoré en mode sandbox)")] = None,
        timeout: Annotated[int, Field(default=30, description="Timeout en secondes (max selon config serveur)")] = 30,
        network: Annotated[bool, Field(default=False, description="Activer l'accès réseau (pour pip install, curl, wget). Défaut: false (isolé, sans réseau)")] = False,
        ctx: Optional[Context] = None,
    ) -> dict:
        """Exécute une commande dans un conteneur sandbox isolé (sans réseau, mémoire limitée, non-root). Shells disponibles : bash, sh, python3, node."""
        try:
            check_tool_access("shell")
            settings = get_settings()

            # Bornes de sécurité
            ALLOWED_SHELLS = ("bash", "sh", "python3", "node")
            timeout = max(1, min(timeout, settings.sandbox_max_timeout))
            if shell not in ALLOWED_SHELLS:
                return {"status": "error", "message": f"Shell '{shell}' non autorisé. Valides: {', '.join(ALLOWED_SHELLS)}"}

            if settings.sandbox_enabled:
                if cwd:
                    print(f"[shell] WARN: cwd ignoré en mode sandbox (pas de montage volume)", file=sys.stderr)
                result = await _run_in_sandbox(command, shell, timeout, settings, network=network)
            else:
                result = await _run_local(command, shell, cwd, timeout, settings)

            return result

        except asyncio.TimeoutError:
            return {"status": "error", "message": f"Timeout de {timeout}s dépassé."}
        except FileNotFoundError:
            return {"status": "error", "message": "Docker CLI non trouvé. Vérifiez que le binaire docker est installé et que docker.sock est monté."}
        except Exception as e:
            return {"status": "error", "message": str(e)}
