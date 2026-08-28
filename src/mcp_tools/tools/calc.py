# -*- coding: utf-8 -*-
"""
Outil: calc — Calculs mathématiques dans une sandbox Python isolée.
"""

import uuid
import asyncio
import shutil
from typing import Annotated, Optional
from pydantic import Field
from mcp.server.mcpserver import MCPServer, Context
from ..auth.context import check_tool_access
from ..config import get_settings
from ..observability import record_activity, traced_tool


# Script Python injecté dans la sandbox — pré-importe math et statistics
_CALC_SCRIPT_TEMPLATE = '''
import math
import statistics
try:
    _result = eval({expr_repr})
    print(_result)
except Exception as e:
    print(f"CALC_ERROR: {{e}}")
'''


def register(mcp: MCPServer) -> None:

    @mcp.tool()
    @traced_tool("calc")
    async def calc(
        expr: Annotated[str, Field(description="Expression mathématique Python à évaluer (ex: '(3+5)*2', 'math.sqrt(144)', 'statistics.mean([10,20,30])')")],
        ctx: Optional[Context] = None,
    ) -> dict:
        """Calcule une expression mathématique Python dans une sandbox isolée. Modules math et statistics pré-importés. Ex: '(3+5)*2', 'math.sqrt(144)', 'statistics.mean([10,20,30])'."""
        try:
            check_tool_access("calc")

            settings = get_settings()

            if not expr or not expr.strip():
                return {"status": "error", "message": "Paramètre 'expr' requis (ex: '(3 + 5) * 2', 'math.sqrt(144)')"}

            # Limite de taille de l'expression
            if len(expr) > 1000:
                return {"status": "error", "message": f"Expression trop longue ({len(expr)} chars, max 1000)"}

            # Construire le script Python
            script = _CALC_SCRIPT_TEMPLATE.format(expr_repr=repr(expr))

            # Exécution en sandbox Docker ou fallback local
            if settings.sandbox_enabled and shutil.which("docker"):
                result = await _run_sandbox(script, expr, settings)
            else:
                result = await _run_local(script, expr, settings)

            return result

        except Exception as e:
            return {"status": "error", "message": str(e)}


async def _run_sandbox(script: str, expr: str, settings) -> dict:
    """Exécute le calcul dans un conteneur sandbox Docker éphémère."""
    container_name = f"calc-{uuid.uuid4().hex[:12]}"
    timeout = 10  # 10s max pour un calcul

    cmd = [
        "docker", "run", "--rm",
        "--name", container_name,
        "--network=none",
        "--read-only",
        "--cap-drop=ALL",
        f"--memory={settings.sandbox_memory}",
        f"--cpus={settings.sandbox_cpus}",
        f"--pids-limit={settings.sandbox_pids_limit}",
        "--user=sandbox",
        "--security-opt=no-new-privileges:true",
        f"--tmpfs=/tmp:noexec,nosuid,nodev,size={settings.sandbox_tmpfs_size}",
        settings.sandbox_image,
        "python3", "-c", script,
    ]

    process = None
    try:
        record_activity("sandbox.starting", message="Création de la sandbox", details={"sandbox_id": container_name, "timeout": timeout})
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        record_activity("sandbox.started", message="Sandbox démarrée", details={"sandbox_id": container_name})

        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=timeout + 15,  # marge démarrage conteneur
            )
        except asyncio.TimeoutError:
            record_activity("sandbox.timeout", level="warning", message="Délai de sandbox dépassé", details={"sandbox_id": container_name, "timeout": timeout})
            process.kill()
            # Nettoyage du conteneur
            cleanup = await asyncio.create_subprocess_exec(
                "docker", "kill", container_name,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            await cleanup.wait()
            return {"status": "error", "message": f"Timeout ({timeout}s) — expression trop complexe ?"}

        except asyncio.CancelledError:
            record_activity("sandbox.cancelled", level="warning", message="Sandbox annulée et nettoyée", details={"sandbox_id": container_name})
            try:
                if process is not None:
                    process.kill()
                    await process.wait()
            except Exception:
                pass
            try:
                cleanup = await asyncio.create_subprocess_exec(
                    "docker", "rm", "-f", container_name,
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                await cleanup.wait()
            except Exception:
                pass
            raise

        stdout_str = stdout.decode("utf-8", errors="replace").strip()
        stderr_str = stderr.decode("utf-8", errors="replace").strip()
        record_activity("sandbox.completed", level="error" if process.returncode else "info", message="Sandbox terminée", details={"sandbox_id": container_name, "returncode": process.returncode})

        # Vérifier si erreur Python
        if stdout_str.startswith("CALC_ERROR:"):
            error_msg = stdout_str[len("CALC_ERROR:"):].strip()
            return {"status": "error", "message": error_msg, "sandbox": True}

        if process.returncode != 0:
            return {"status": "error", "message": stderr_str or f"Exit code {process.returncode}", "sandbox": True}

        # Parser le résultat
        return _parse_result(stdout_str, expr, sandbox=True)

    except Exception as e:
        # Nettoyage en cas d'erreur
        try:
            cleanup = await asyncio.create_subprocess_exec(
                "docker", "rm", "-f", container_name,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            await cleanup.wait()
        except Exception:
            pass
        return {"status": "error", "message": str(e)}


async def _run_local(script: str, expr: str, settings) -> dict:
    """Fallback local (dev sans Docker) — exécute Python3 directement."""
    timeout = 10

    try:
        process = await asyncio.create_subprocess_exec(
            "python3", "-c", script,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=timeout,
            )
        except asyncio.TimeoutError:
            process.kill()
            return {"status": "error", "message": f"Timeout ({timeout}s) — expression trop complexe ?"}

        stdout_str = stdout.decode("utf-8", errors="replace").strip()
        stderr_str = stderr.decode("utf-8", errors="replace").strip()

        if stdout_str.startswith("CALC_ERROR:"):
            error_msg = stdout_str[len("CALC_ERROR:"):].strip()
            return {"status": "error", "message": error_msg, "sandbox": False}

        if process.returncode != 0:
            return {"status": "error", "message": stderr_str or f"Exit code {process.returncode}", "sandbox": False}

        return _parse_result(stdout_str, expr, sandbox=False)

    except Exception as e:
        return {"status": "error", "message": str(e)}


def _parse_result(stdout: str, expr: str, sandbox: bool) -> dict:
    """Parse le résultat stdout et tente de le convertir en nombre."""
    # Tenter de convertir en nombre
    try:
        if "." in stdout or "e" in stdout.lower():
            result = float(stdout)
        else:
            result = int(stdout)
    except (ValueError, OverflowError):
        # Résultat non-numérique (ex: liste, string) — garder en texte
        result = stdout

    return {
        "status": "success",
        "expr": expr,
        "result": result,
        "sandbox": sandbox,
    }
