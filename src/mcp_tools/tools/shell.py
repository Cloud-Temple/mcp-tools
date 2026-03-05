# -*- coding: utf-8 -*-
"""
Outil: shell — Exécution de commandes dans un conteneur sandbox isolé.

Sécurité : chaque commande est exécutée dans un conteneur Docker éphémère
(Alpine) avec : --network=none, --read-only, --cap-drop=ALL, --memory,
--pids-limit, --no-new-privileges. Le conteneur est détruit après exécution.

Fallback : si SANDBOX_ENABLED=false (dev local), exécution locale via subprocess.
"""

import asyncio
import sys
import uuid
from typing import Optional
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


async def _run_in_sandbox(command: str, shell: str, timeout: int, settings) -> dict:
    """Exécute la commande dans un conteneur Docker éphémère isolé."""
    exec_flag = SHELL_EXEC_FLAGS.get(shell, "-c")
    container_name = f"sandbox-{uuid.uuid4().hex[:12]}"
    docker_cmd = [
        "docker", "run", "--rm",
        f"--name={container_name}",
        "--network=none",
        "--read-only",
        f"--memory={settings.sandbox_memory}",
        f"--memory-swap={settings.sandbox_memory}",
        f"--cpus={settings.sandbox_cpus}",
        f"--pids-limit={settings.sandbox_pids_limit}",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges:true",
        f"--tmpfs=/tmp:noexec,nosuid,nodev,size={settings.sandbox_tmpfs_size}",
        "--user=sandbox:sandbox",
        settings.sandbox_image,
        shell, exec_flag, command,
    ]

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
        command: str,
        shell: str = "bash",
        cwd: Optional[str] = None,
        timeout: int = 30,
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
                result = await _run_in_sandbox(command, shell, timeout, settings)
            else:
                result = await _run_local(command, shell, cwd, timeout, settings)

            return result

        except asyncio.TimeoutError:
            return {"status": "error", "message": f"Timeout de {timeout}s dépassé."}
        except FileNotFoundError:
            return {"status": "error", "message": "Docker CLI non trouvé. Vérifiez que le binaire docker est installé et que docker.sock est monté."}
        except Exception as e:
            return {"status": "error", "message": str(e)}
