# -*- coding: utf-8 -*-
"""
Outil: files — Opérations fichiers sur S3 Dell ECS (Cloud Temple).

Exécuté dans un conteneur Docker sandbox éphémère AVEC accès réseau
(--network=bridge) pour atteindre l'endpoint S3. Utilise boto3 avec
la configuration hybride SigV2/SigV4 requise par Dell ECS :
  - SigV2 pour les opérations sur données (PUT/GET/DELETE)
  - SigV4 pour les opérations métadonnées (HEAD/LIST)

Opérations :
  - list     : Lister les objets d'un préfixe S3
  - read     : Lire le contenu d'un objet S3
  - write    : Écrire du contenu dans un objet S3
  - delete   : Supprimer un objet S3
  - info     : Obtenir les métadonnées d'un objet (HEAD)
  - diff     : Comparer le contenu de 2 objets S3

Sécurité :
  - Conteneur éphémère (--rm), read-only, non-root, cap-drop=ALL
  - Credentials S3 ne sortent jamais du conteneur éphémère
  - Output tronqué via settings.tool_max_output_chars
  - Timeout configurable
"""

import asyncio
import json
import uuid
from typing import Optional

from mcp.server.fastmcp import FastMCP, Context
from ..auth.context import check_tool_access
from ..config import get_settings


# =============================================================================
# Constantes
# =============================================================================

ALLOWED_OPERATIONS = ("list", "read", "write", "delete", "info", "diff", "versions", "enable_versioning")
FILES_MAX_TIMEOUT = 60
# Limite de contenu pour write (5 MB en texte)
FILES_MAX_CONTENT_SIZE = 5_000_000
# Nombre max d'objets retournés par list
FILES_MAX_KEYS = 1000


# =============================================================================
# Helpers
# =============================================================================

def _truncate(text: str, max_chars: int) -> str:
    """Tronque le texte si nécessaire, avec indication."""
    if len(text) > max_chars:
        return text[:max_chars] + f"\n... [TRONQUÉ — {len(text)} chars, limite {max_chars}]"
    return text


def _build_python_script(
    operation: str,
    endpoint: str,
    access_key: str,
    secret_key: str,
    bucket: str,
    region: str,
    path: Optional[str],
    path2: Optional[str],
    content: Optional[str],
    prefix: Optional[str],
    max_keys: int,
    max_output_chars: int,
    version_id: Optional[str] = None,
) -> str:
    """
    Construit le script Python exécuté dans le conteneur sandbox.

    Le script utilise boto3 avec la configuration hybride SigV2/SigV4
    requise par Dell ECS Cloud Temple.
    """
    # Sérialiser les paramètres en JSON pour éviter toute injection
    params = {
        "operation": operation,
        "endpoint": endpoint,
        "access_key": access_key,
        "secret_key": secret_key,
        "bucket": bucket,
        "region": region,
        "path": path or "",
        "path2": path2 or "",
        "content": content or "",
        "prefix": prefix or "",
        "max_keys": max_keys,
        "max_output_chars": max_output_chars,
        "version_id": version_id or "",
    }
    params_json = json.dumps(params)

    # Le script Python complet — injecté via stdin pour éviter les problèmes d'escaping
    script = r'''
import sys, json, traceback

try:
    import boto3
    from botocore.config import Config as BotoConfig
except ImportError:
    print(json.dumps({"status": "error", "message": "boto3 non disponible dans la sandbox"}))
    sys.exit(0)

def main():
    params = json.loads(PARAMS_JSON)
    op = params["operation"]
    endpoint = params["endpoint"]
    access_key = params["access_key"]
    secret_key = params["secret_key"]
    bucket = params["bucket"]
    region = params["region"]
    path = params["path"]
    path2 = params["path2"]
    content = params["content"]
    prefix = params["prefix"]
    max_keys = params["max_keys"]
    max_output = params["max_output_chars"]

    # Client SigV2 pour opérations sur données (PUT/GET/DELETE)
    config_v2 = BotoConfig(
        region_name=region,
        signature_version='s3',
        s3={'addressing_style': 'path'},
        retries={'max_attempts': 3, 'mode': 'adaptive'},
        connect_timeout=10,
        read_timeout=30,
    )
    client_v2 = boto3.client(
        's3',
        endpoint_url=endpoint,
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        config=config_v2,
    )

    # Client SigV4 pour opérations métadonnées (HEAD/LIST)
    config_v4 = BotoConfig(
        region_name=region,
        signature_version='s3v4',
        s3={'addressing_style': 'path', 'payload_signing_enabled': False},
        retries={'max_attempts': 3, 'mode': 'adaptive'},
        connect_timeout=10,
        read_timeout=30,
    )
    client_v4 = boto3.client(
        's3',
        endpoint_url=endpoint,
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        config=config_v4,
    )

    result = {"status": "success", "operation": op, "bucket": bucket}

    if op == "list":
        kwargs = {"Bucket": bucket, "MaxKeys": max_keys}
        if prefix:
            kwargs["Prefix"] = prefix
        resp = client_v4.list_objects_v2(**kwargs)
        objects = []
        for obj in resp.get("Contents", []):
            objects.append({
                "key": obj["Key"],
                "size": obj["Size"],
                "last_modified": obj["LastModified"].isoformat(),
            })
        result["objects"] = objects
        result["count"] = len(objects)
        result["truncated"] = resp.get("IsTruncated", False)
        if prefix:
            result["prefix"] = prefix

    elif op == "versions":
        kwargs = {"Bucket": bucket, "MaxKeys": max_keys}
        if path:
            kwargs["Prefix"] = path
        resp = client_v4.list_object_versions(**kwargs)
        versions = []
        for v in resp.get("Versions", []):
            versions.append({
                "key": v["Key"],
                "version_id": v["VersionId"],
                "size": v["Size"],
                "last_modified": v["LastModified"].isoformat(),
                "is_latest": v["IsLatest"],
                "etag": v.get("ETag", ""),
            })
        delete_markers = []
        for dm in resp.get("DeleteMarkers", []):
            delete_markers.append({
                "key": dm["Key"],
                "version_id": dm["VersionId"],
                "last_modified": dm["LastModified"].isoformat(),
                "is_latest": dm["IsLatest"],
            })
        result["path"] = path
        result["versions"] = versions
        result["delete_markers"] = delete_markers
        result["count"] = len(versions)

    elif op == "read":
        get_kwargs = {"Bucket": bucket, "Key": path}
        version_id = params.get("version_id", "")
        if version_id:
            get_kwargs["VersionId"] = version_id
        resp = client_v2.get_object(**get_kwargs)
        body = resp["Body"].read()
        try:
            text = body.decode("utf-8")
        except UnicodeDecodeError:
            import base64
            text = "[BINAIRE — base64]\n" + base64.b64encode(body).decode("ascii")
        if len(text) > max_output:
            text = text[:max_output] + f"\n... [TRONQUÉ — {len(text)} chars, limite {max_output}]"
        result["path"] = path
        result["content"] = text
        result["size"] = resp["ContentLength"]
        result["content_type"] = resp.get("ContentType", "")
        result["last_modified"] = resp["LastModified"].isoformat()

    elif op == "write":
        client_v2.put_object(
            Bucket=bucket,
            Key=path,
            Body=content.encode("utf-8"),
            ContentType="application/octet-stream",
        )
        result["path"] = path
        result["size"] = len(content.encode("utf-8"))
        result["message"] = f"Fichier écrit : {path} ({result['size']} octets)"

    elif op == "delete":
        client_v2.delete_object(Bucket=bucket, Key=path)
        result["path"] = path
        result["message"] = f"Fichier supprimé : {path}"

    elif op == "info":
        resp = client_v4.head_object(Bucket=bucket, Key=path)
        result["path"] = path
        result["size"] = resp["ContentLength"]
        result["content_type"] = resp.get("ContentType", "")
        result["last_modified"] = resp["LastModified"].isoformat()
        result["etag"] = resp.get("ETag", "")
        metadata = resp.get("Metadata", {})
        if metadata:
            result["metadata"] = metadata

    elif op == "enable_versioning":
        # Dell ECS nécessite SigV4 pour put_bucket_versioning
        client_v4.put_bucket_versioning(
            Bucket=bucket,
            VersioningConfiguration={'Status': 'Enabled'},
        )
        # Vérification
        resp = client_v4.get_bucket_versioning(Bucket=bucket)
        status_val = resp.get('Status', 'Unknown')
        result["versioning_status"] = status_val
        result["message"] = f"Versioning {'activé' if status_val == 'Enabled' else 'statut: ' + status_val} sur {bucket}"

    elif op == "diff":
        resp1 = client_v2.get_object(Bucket=bucket, Key=path)
        resp2 = client_v2.get_object(Bucket=bucket, Key=path2)
        text1 = resp1["Body"].read().decode("utf-8", errors="replace")
        text2 = resp2["Body"].read().decode("utf-8", errors="replace")

        import difflib
        diff_lines = list(difflib.unified_diff(
            text1.splitlines(keepends=True),
            text2.splitlines(keepends=True),
            fromfile=path,
            tofile=path2,
        ))
        diff_text = "".join(diff_lines)
        if not diff_text:
            diff_text = "(fichiers identiques)"
        if len(diff_text) > max_output:
            diff_text = diff_text[:max_output] + f"\n... [TRONQUÉ]"

        result["path"] = path
        result["path2"] = path2
        result["diff"] = diff_text
        result["identical"] = len(diff_lines) == 0

    print(json.dumps(result, default=str))

try:
    main()
except Exception as e:
    print(json.dumps({"status": "error", "message": str(e), "traceback": traceback.format_exc()}, default=str))
'''

    # Injecter les paramètres dans le script
    script = script.replace("PARAMS_JSON", repr(params_json))

    return script


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


async def _run_in_sandbox(script: str, timeout: int, settings) -> dict:
    """Exécute le script Python dans un conteneur Docker éphémère avec réseau."""
    container_name = f"files-{uuid.uuid4().hex[:12]}"

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
        "python3", "-c", script,
    ]

    process = await asyncio.create_subprocess_exec(
        *docker_cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    # Timeout total = timeout + 15s marge (démarrage conteneur)
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

    stdout_text = stdout.decode(errors="replace").strip()
    stderr_text = stderr.decode(errors="replace").strip()

    # Parser le JSON de sortie
    if not stdout_text:
        return {
            "status": "error",
            "message": stderr_text or "Pas de sortie du script S3",
            "sandbox": True,
        }

    try:
        result = json.loads(stdout_text)
        result["sandbox"] = True
        return result
    except json.JSONDecodeError:
        return {
            "status": "error",
            "message": f"Sortie non-JSON : {stdout_text[:500]}",
            "stderr": stderr_text[:500] if stderr_text else None,
            "sandbox": True,
        }


async def _run_local(script: str, timeout: int, settings) -> dict:
    """Fallback : exécution locale via subprocess (dev sans Docker)."""
    process = await asyncio.create_subprocess_exec(
        "python3", "-c", script,
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

    stdout_text = stdout.decode(errors="replace").strip()
    stderr_text = stderr.decode(errors="replace").strip()

    if not stdout_text:
        return {
            "status": "error",
            "message": stderr_text or "Pas de sortie du script S3",
            "sandbox": False,
        }

    try:
        result = json.loads(stdout_text)
        result["sandbox"] = False
        return result
    except json.JSONDecodeError:
        return {
            "status": "error",
            "message": f"Sortie non-JSON : {stdout_text[:500]}",
            "stderr": stderr_text[:500] if stderr_text else None,
            "sandbox": False,
        }


# =============================================================================
# Enregistrement MCP
# =============================================================================

def register(mcp: FastMCP) -> None:
    @mcp.tool()
    async def files(
        operation: str,
        path: Optional[str] = None,
        content: Optional[str] = None,
        path2: Optional[str] = None,
        prefix: Optional[str] = None,
        version_id: Optional[str] = None,
        max_keys: int = 100,
        endpoint: Optional[str] = None,
        access_key: Optional[str] = None,
        secret_key: Optional[str] = None,
        bucket: Optional[str] = None,
        region: Optional[str] = None,
        timeout: int = 30,
        ctx: Optional[Context] = None,
    ) -> dict:
        """Opérations fichiers sur S3 Dell ECS dans un conteneur sandbox isolé. Opérations : list, read, write, delete, info, diff, versions. Versioning S3 supporté via version_id. Config hybride SigV2/SigV4 pour Dell ECS Cloud Temple."""
        try:
            check_tool_access("files")
            settings = get_settings()

            # --- Validation opération ---
            if operation not in ALLOWED_OPERATIONS:
                return {
                    "status": "error",
                    "message": f"Opération '{operation}' non supportée. Valides : {', '.join(ALLOWED_OPERATIONS)}",
                }

            # --- Résolution des paramètres S3 (tool params > config Settings) ---
            s3_endpoint = endpoint or settings.s3_endpoint_url
            s3_access_key = access_key or settings.s3_access_key_id
            s3_secret_key = secret_key or settings.s3_secret_access_key
            s3_bucket = bucket or settings.s3_bucket_name
            s3_region = region or settings.s3_region_name

            # Validation des credentials S3
            if not s3_endpoint:
                return {"status": "error", "message": "Endpoint S3 non configuré. Passez 'endpoint' ou configurez S3_ENDPOINT_URL."}
            if not s3_access_key:
                return {"status": "error", "message": "Access key S3 non configurée. Passez 'access_key' ou configurez S3_ACCESS_KEY_ID."}
            if not s3_secret_key:
                return {"status": "error", "message": "Secret key S3 non configurée. Passez 'secret_key' ou configurez S3_SECRET_ACCESS_KEY."}
            if not s3_bucket:
                return {"status": "error", "message": "Bucket S3 non configuré. Passez 'bucket' ou configurez S3_BUCKET_NAME."}

            # --- Validation params par opération ---
            if operation in ("read", "write", "delete", "info") and not path:
                return {"status": "error", "message": f"Le paramètre 'path' est requis pour l'opération '{operation}'."}

            if operation == "write" and not content:
                return {"status": "error", "message": "Le paramètre 'content' est requis pour l'opération 'write'."}

            if operation == "diff":
                if not path:
                    return {"status": "error", "message": "Le paramètre 'path' est requis pour l'opération 'diff'."}
                if not path2:
                    return {"status": "error", "message": "Le paramètre 'path2' est requis pour l'opération 'diff'."}

            # --- Bornes de sécurité ---
            timeout = max(1, min(timeout, FILES_MAX_TIMEOUT))
            max_keys = max(1, min(max_keys, FILES_MAX_KEYS))

            if content and len(content) > FILES_MAX_CONTENT_SIZE:
                return {"status": "error", "message": f"Contenu trop volumineux ({len(content)} chars, max {FILES_MAX_CONTENT_SIZE})."}

            # --- Construction du script Python ---
            script = _build_python_script(
                operation=operation,
                endpoint=s3_endpoint,
                access_key=s3_access_key,
                secret_key=s3_secret_key,
                bucket=s3_bucket,
                region=s3_region,
                path=path,
                path2=path2,
                content=content,
                prefix=prefix,
                max_keys=max_keys,
                max_output_chars=settings.tool_max_output_chars,
                version_id=version_id,
            )

            # --- Exécution ---
            if settings.sandbox_enabled:
                result = await _run_in_sandbox(script, timeout, settings)
            else:
                result = await _run_local(script, timeout, settings)

            return result

        except asyncio.TimeoutError:
            return {"status": "error", "message": f"Timeout de {timeout}s dépassé."}
        except FileNotFoundError:
            return {"status": "error", "message": "Docker CLI non trouvé. Vérifiez que docker est installé et docker.sock monté."}
        except Exception as e:
            return {"status": "error", "message": str(e)}
