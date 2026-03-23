# -*- coding: utf-8 -*-
"""
Outil: ssh — Exécution de commandes et transfert de fichiers via SSH.

Exécuté dans un conteneur Docker sandbox éphémère AVEC accès réseau
(--network=bridge) pour atteindre les serveurs distants.

Opérations :
  - exec     : Exécuter une commande sur un serveur distant
  - status   : Tester la connectivité SSH
  - upload   : Envoyer du contenu vers un fichier distant (SCP)
  - download : Récupérer le contenu d'un fichier distant (SCP)

Auth :
  - password : via sshpass (mot de passe passé au conteneur)
  - key      : clé privée écrite dans tmpfs du conteneur

Sécurité :
  - Conteneur éphémère (--rm), read-only, non-root, cap-drop=ALL
  - Pas de blocage RFC 1918 (SSH vers infra interne est légitime)
  - Validation stricte du host (anti-injection)
  - Timeout configurable (max 60s)
  - Output tronqué via settings.tool_max_output_chars
  - Clé privée et mot de passe ne sortent jamais du conteneur éphémère
"""

import asyncio
import re
import shlex
import uuid
from typing import Annotated, Optional

from pydantic import Field
from mcp.server.fastmcp import FastMCP, Context
from ..auth.context import check_tool_access
from ..config import get_settings


# =============================================================================
# Constantes
# =============================================================================

ALLOWED_OPERATIONS = ("exec", "status", "upload", "download")
ALLOWED_AUTH_TYPES = ("password", "key")
SSH_MAX_TIMEOUT = 60
SSH_CONNECT_TIMEOUT = 10

# Caractères autorisés dans un hostname/IP
_HOST_PATTERN = re.compile(r"^[a-zA-Z0-9._:\-]+$")

# SSH options communes (désactive la vérification host pour conteneur éphémère)
_SSH_OPTS = (
    "-o StrictHostKeyChecking=no "
    "-o UserKnownHostsFile=/dev/null "
    "-o LogLevel=ERROR "
    "-o BatchMode=yes"
)


# =============================================================================
# Validation
# =============================================================================

def _validate_host(host: str) -> Optional[str]:
    """Valide le hostname/IP. Retourne un message d'erreur ou None si OK."""
    if not host or not host.strip():
        return "Le paramètre 'host' est requis."
    host = host.strip()
    if not _HOST_PATTERN.match(host):
        return f"Host invalide : '{host}'. Seuls les caractères alphanumériques, points, tirets et deux-points sont autorisés."
    return None


def _validate_username(username: str) -> Optional[str]:
    """Valide le nom d'utilisateur SSH."""
    if not username or not username.strip():
        return "Le paramètre 'username' est requis."
    if not re.match(r"^[a-zA-Z0-9._\-]+$", username.strip()):
        return f"Username invalide : '{username}'. Caractères spéciaux interdits."
    return None


# =============================================================================
# Helpers
# =============================================================================

def _truncate(text: str, max_chars: int) -> str:
    """Tronque le texte si nécessaire, avec indication."""
    if len(text) > max_chars:
        return text[:max_chars] + f"\n... [TRONQUÉ — {len(text)} chars, limite {max_chars}]"
    return text


def _build_ssh_script(
    operation: str,
    host: str,
    username: str,
    port: int,
    auth_type: str,
    password: Optional[str],
    private_key: Optional[str],
    command: Optional[str],
    sudo: bool,
    remote_path: Optional[str],
    content: Optional[str],
    connect_timeout: int,
) -> str:
    """
    Construit le script shell exécuté dans le conteneur sandbox.

    Le script :
    1. Configure la clé SSH dans tmpfs si auth_type=key
    2. Exécute l'opération SSH/SCP
    3. Retourne un output structuré avec des marqueurs
    """
    # Pas de "set -e" : on capture explicitement les exit codes
    # (set -e ferait sortir le script avant EXIT=$? en cas d'erreur SSH)
    lines = ["#!/bin/sh", ""]

    # --- Setup clé SSH ---
    if auth_type == "key" and private_key:
        # Écrire la clé privée dans tmpfs (sera détruite avec le conteneur)
        escaped_key = shlex.quote(private_key)
        lines.append(f"echo {escaped_key} > /tmp/ssh_key")
        lines.append("chmod 600 /tmp/ssh_key")
        lines.append("")

    # --- Construction des options SSH ---
    ssh_opts = f"{_SSH_OPTS} -o ConnectTimeout={connect_timeout}"
    if auth_type == "key" and private_key:
        ssh_opts += " -i /tmp/ssh_key"

    ssh_target = f"{shlex.quote(username)}@{shlex.quote(host)}"
    port_flag = f"-p {port}"
    scp_port_flag = f"-P {port}"

    # Préfixe sshpass si auth par mot de passe
    # Sécurité (audit §3.3) : utilise la variable d'environnement SSHPASS
    # au lieu de -p pour masquer le mot de passe de /proc/[pid]/cmdline
    ssh_prefix = ""
    if auth_type == "password" and password:
        escaped_pass = shlex.quote(password)
        lines.append(f"export SSHPASS={escaped_pass}")
        lines.append("")
        ssh_prefix = "sshpass -e "

    # --- Opérations ---
    if operation == "status":
        # Test de connexion simple
        lines.append(f'{ssh_prefix}ssh {ssh_opts} {port_flag} {ssh_target} "echo CONNECTION_OK" 2>/tmp/err')
        lines.append("EXIT=$?")

    elif operation == "exec":
        # Exécution de commande
        escaped_cmd = shlex.quote(command or "echo no_command")
        if sudo:
            if auth_type == "password" and password:
                # sudo avec mot de passe via stdin
                sudo_cmd = f"echo {shlex.quote(password)} | sudo -S {command}"
                escaped_cmd = shlex.quote(sudo_cmd)
            else:
                escaped_cmd = shlex.quote(f"sudo {command}")
        lines.append(f'{ssh_prefix}ssh {ssh_opts} {port_flag} {ssh_target} {escaped_cmd} > /tmp/out 2>/tmp/err')
        lines.append("EXIT=$?")

    elif operation == "upload":
        # Écrire le contenu dans un fichier temporaire puis SCP
        escaped_content = shlex.quote(content or "")
        escaped_remote = shlex.quote(remote_path or "/tmp/upload")
        lines.append(f"printf '%s' {escaped_content} > /tmp/upload_file")
        lines.append(f'{ssh_prefix}scp {ssh_opts} {scp_port_flag} /tmp/upload_file {ssh_target}:{escaped_remote} > /tmp/out 2>/tmp/err')
        lines.append("EXIT=$?")

    elif operation == "download":
        # SCP depuis le serveur distant
        escaped_remote = shlex.quote(remote_path or "")
        lines.append(f'{ssh_prefix}scp {ssh_opts} {scp_port_flag} {ssh_target}:{escaped_remote} /tmp/download_file > /tmp/out 2>/tmp/err')
        lines.append("EXIT=$?")

    # --- Output structuré ---
    lines.append("")
    lines.append('echo "===MCP_STATUS==="')
    lines.append('echo "$EXIT"')
    lines.append('echo "===MCP_STDOUT==="')

    if operation == "status":
        lines.append('echo "CONNECTION_OK"')
    elif operation == "download":
        lines.append('cat /tmp/download_file 2>/dev/null || echo ""')
    elif operation == "exec":
        lines.append('cat /tmp/out 2>/dev/null || echo ""')
    else:
        lines.append('cat /tmp/out 2>/dev/null || echo ""')

    lines.append('echo "===MCP_STDERR==="')
    lines.append('cat /tmp/err 2>/dev/null || echo ""')
    lines.append('echo "===MCP_EXIT==="')
    lines.append('echo "$EXIT"')

    return "\n".join(lines)


def _parse_ssh_output(stdout_text: str) -> dict:
    """
    Parse la sortie structurée du script SSH.
    Extrait : exit_code, stdout, stderr.
    """
    sections = {}
    current_section = None
    current_lines = []

    for line in stdout_text.split("\n"):
        stripped = line.strip()
        if stripped in ("===MCP_STATUS===", "===MCP_STDOUT===",
                        "===MCP_STDERR===", "===MCP_EXIT==="):
            if current_section is not None:
                sections[current_section] = "\n".join(current_lines)
            current_section = stripped.strip("=")
            current_lines = []
        else:
            current_lines.append(line)

    if current_section is not None:
        sections[current_section] = "\n".join(current_lines)

    exit_code = 0
    try:
        exit_code = int(sections.get("MCP_EXIT", "0").strip())
    except ValueError:
        pass

    return {
        "exit_code": exit_code,
        "stdout": sections.get("MCP_STDOUT", "").strip(),
        "stderr": sections.get("MCP_STDERR", "").strip(),
    }


# =============================================================================
# Exécution sandbox Docker
# =============================================================================

async def _kill_container(name: str) -> None:
    """Force-kill et supprime un conteneur Docker par son nom."""
    for cmd in [["docker", "kill", name], ["docker", "rm", "-f", name]]:
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            await proc.wait()
        except Exception:
            pass


async def _run_in_sandbox(
    operation: str,
    host: str,
    username: str,
    port: int,
    auth_type: str,
    password: Optional[str],
    private_key: Optional[str],
    command: Optional[str],
    sudo: bool,
    remote_path: Optional[str],
    content: Optional[str],
    timeout: int,
    settings,
) -> dict:
    """Exécute l'opération SSH dans un conteneur Docker éphémère avec réseau."""
    script = _build_ssh_script(
        operation=operation,
        host=host,
        username=username,
        port=port,
        auth_type=auth_type,
        password=password,
        private_key=private_key,
        command=command,
        sudo=sudo,
        remote_path=remote_path,
        content=content,
        connect_timeout=min(SSH_CONNECT_TIMEOUT, timeout),
    )
    container_name = f"ssh-{uuid.uuid4().hex[:12]}"

    docker_cmd = [
        "docker", "run", "--rm",
        f"--name={container_name}",
        "--network=bridge",
        "--read-only",
        "--cap-drop=ALL",
        f"--memory={settings.sandbox_memory}",
        f"--memory-swap={settings.sandbox_memory}",
        f"--cpus={settings.sandbox_cpus}",
        f"--pids-limit={settings.sandbox_pids_limit}",
        "--security-opt=no-new-privileges:true",
        f"--tmpfs=/tmp:nosuid,nodev,size={settings.sandbox_tmpfs_size}",
        "--user=sandbox:sandbox",
        *[f"--dns={d.strip()}" for d in settings.sandbox_dns.split(",") if d.strip()],
        settings.sandbox_image,
        "sh", "-c", script,
    ]

    process = await asyncio.create_subprocess_exec(
        *docker_cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    # Timeout total = timeout SSH + 15s marge (démarrage conteneur)
    container_timeout = timeout + 15

    try:
        stdout, stderr = await asyncio.wait_for(
            process.communicate(), timeout=container_timeout,
        )
    except asyncio.TimeoutError:
        try:
            process.kill()
            await process.wait()
        except Exception:
            pass
        await _kill_container(container_name)
        raise

    stdout_text = stdout.decode(errors="replace")
    max_chars = settings.tool_max_output_chars
    parsed = _parse_ssh_output(stdout_text)

    result = {
        "status": "success" if parsed["exit_code"] == 0 else "error",
        "operation": operation,
        "host": host,
        "port": port,
        "username": username,
        "exit_code": parsed["exit_code"],
        "sandbox": True,
    }

    if operation == "download" and parsed["exit_code"] == 0:
        result["content"] = _truncate(parsed["stdout"], max_chars)
    elif operation == "status" and parsed["exit_code"] == 0:
        result["message"] = "Connexion SSH réussie"
    elif operation == "upload" and parsed["exit_code"] == 0:
        result["message"] = f"Fichier uploadé vers {remote_path}"
        result["remote_path"] = remote_path
    else:
        result["stdout"] = _truncate(parsed["stdout"], max_chars)

    if parsed["stderr"]:
        result["stderr"] = _truncate(parsed["stderr"], max_chars)

    if parsed["exit_code"] != 0:
        result["message"] = _truncate(
            parsed["stderr"] or parsed["stdout"] or f"SSH exit code {parsed['exit_code']}",
            max_chars,
        )

    return result


async def _run_local(
    operation: str,
    host: str,
    username: str,
    port: int,
    auth_type: str,
    password: Optional[str],
    private_key: Optional[str],
    command: Optional[str],
    sudo: bool,
    remote_path: Optional[str],
    content: Optional[str],
    timeout: int,
    settings,
) -> dict:
    """Fallback : exécution locale via subprocess (dev sans Docker)."""
    # En local, on utilise directement ssh/scp avec les mêmes options
    script = _build_ssh_script(
        operation=operation,
        host=host,
        username=username,
        port=port,
        auth_type=auth_type,
        password=password,
        private_key=private_key,
        command=command,
        sudo=sudo,
        remote_path=remote_path,
        content=content,
        connect_timeout=min(SSH_CONNECT_TIMEOUT, timeout),
    )

    process = await asyncio.create_subprocess_exec(
        "sh", "-c", script,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    try:
        stdout, stderr = await asyncio.wait_for(
            process.communicate(), timeout=timeout + 5,
        )
    except asyncio.TimeoutError:
        try:
            process.kill()
            await process.wait()
        except Exception:
            pass
        raise

    stdout_text = stdout.decode(errors="replace")
    max_chars = settings.tool_max_output_chars
    parsed = _parse_ssh_output(stdout_text)

    result = {
        "status": "success" if parsed["exit_code"] == 0 else "error",
        "operation": operation,
        "host": host,
        "port": port,
        "username": username,
        "exit_code": parsed["exit_code"],
        "sandbox": False,
    }

    if operation == "download" and parsed["exit_code"] == 0:
        result["content"] = _truncate(parsed["stdout"], max_chars)
    elif operation == "status" and parsed["exit_code"] == 0:
        result["message"] = "Connexion SSH réussie"
    elif operation == "upload" and parsed["exit_code"] == 0:
        result["message"] = f"Fichier uploadé vers {remote_path}"
        result["remote_path"] = remote_path
    else:
        result["stdout"] = _truncate(parsed["stdout"], max_chars)

    if parsed["stderr"]:
        result["stderr"] = _truncate(parsed["stderr"], max_chars)

    if parsed["exit_code"] != 0:
        result["message"] = _truncate(
            parsed["stderr"] or parsed["stdout"] or f"SSH exit code {parsed['exit_code']}",
            max_chars,
        )

    return result


# =============================================================================
# Enregistrement MCP
# =============================================================================

def register(mcp: FastMCP) -> None:
    @mcp.tool()
    async def ssh(
        host: Annotated[str, Field(description="Hostname ou IP du serveur SSH cible")],
        username: Annotated[str, Field(description="Nom d'utilisateur SSH pour la connexion")],
        operation: Annotated[str, Field(default="exec", description="Opération : exec (commande), status (test connexion), upload (envoyer fichier), download (récupérer fichier)")] = "exec",
        auth_type: Annotated[str, Field(default="password", description="Type d'authentification : password ou key (clé privée)")] = "password",
        password: Annotated[Optional[str], Field(default=None, description="Mot de passe SSH (requis si auth_type=password)")] = None,
        private_key: Annotated[Optional[str], Field(default=None, description="Clé privée SSH en texte (requis si auth_type=key)")] = None,
        command: Annotated[Optional[str], Field(default=None, description="Commande à exécuter sur le serveur distant (requis pour exec)")] = None,
        sudo: Annotated[bool, Field(default=False, description="Exécuter la commande avec sudo")] = False,
        port: Annotated[int, Field(default=22, description="Port SSH (1-65535, défaut 22)")] = 22,
        remote_path: Annotated[Optional[str], Field(default=None, description="Chemin du fichier distant (requis pour upload/download)")] = None,
        content: Annotated[Optional[str], Field(default=None, description="Contenu du fichier à uploader (requis pour upload, max 1 MB)")] = None,
        timeout: Annotated[int, Field(default=30, description="Timeout en secondes (max 60)")] = 30,
        ctx: Optional[Context] = None,
    ) -> dict:
        """Exécute des commandes ou transfère des fichiers via SSH dans un conteneur sandbox isolé. Opérations : exec, status, upload, download. Auth : password ou key (clé privée)."""
        try:
            check_tool_access("ssh")
            settings = get_settings()

            # --- Validation opération ---
            if operation not in ALLOWED_OPERATIONS:
                return {
                    "status": "error",
                    "message": f"Opération '{operation}' non supportée. Valides : {', '.join(ALLOWED_OPERATIONS)}",
                }

            # --- Validation host ---
            error = _validate_host(host)
            if error:
                return {"status": "error", "message": error}

            # --- Validation username ---
            error = _validate_username(username)
            if error:
                return {"status": "error", "message": error}

            # --- Validation auth ---
            if auth_type not in ALLOWED_AUTH_TYPES:
                return {
                    "status": "error",
                    "message": f"Type d'auth '{auth_type}' non supporté. Valides : {', '.join(ALLOWED_AUTH_TYPES)}",
                }

            if auth_type == "password" and not password:
                return {"status": "error", "message": "Le paramètre 'password' est requis pour auth_type='password'."}

            if auth_type == "key" and not private_key:
                return {"status": "error", "message": "Le paramètre 'private_key' est requis pour auth_type='key'."}

            # --- Validation params par opération ---
            if operation == "exec" and not command:
                return {"status": "error", "message": "Le paramètre 'command' est requis pour l'opération 'exec'."}

            if operation in ("upload", "download") and not remote_path:
                return {"status": "error", "message": f"Le paramètre 'remote_path' est requis pour l'opération '{operation}'."}

            if operation == "upload" and not content:
                return {"status": "error", "message": "Le paramètre 'content' est requis pour l'opération 'upload'."}

            # --- Bornes de sécurité ---
            port = max(1, min(port, 65535))
            timeout = max(1, min(timeout, SSH_MAX_TIMEOUT))

            # Limite taille contenu upload (1 MB en texte)
            if content and len(content) > 1_000_000:
                return {"status": "error", "message": "Contenu trop volumineux (max 1 MB)."}

            # --- Exécution ---
            if settings.sandbox_enabled:
                result = await _run_in_sandbox(
                    operation=operation,
                    host=host,
                    username=username,
                    port=port,
                    auth_type=auth_type,
                    password=password,
                    private_key=private_key,
                    command=command,
                    sudo=sudo,
                    remote_path=remote_path,
                    content=content,
                    timeout=timeout,
                    settings=settings,
                )
            else:
                result = await _run_local(
                    operation=operation,
                    host=host,
                    username=username,
                    port=port,
                    auth_type=auth_type,
                    password=password,
                    private_key=private_key,
                    command=command,
                    sudo=sudo,
                    remote_path=remote_path,
                    content=content,
                    timeout=timeout,
                    settings=settings,
                )

            return result

        except asyncio.TimeoutError:
            return {"status": "error", "message": f"Timeout de {timeout}s dépassé."}
        except FileNotFoundError:
            return {"status": "error", "message": "Docker CLI non trouvé. Vérifiez que docker est installé et docker.sock monté."}
        except Exception as e:
            return {"status": "error", "message": str(e)}
