# -*- coding: utf-8 -*-
"""
Outil: perplexity — Recherche internet via Perplexity AI.
"""

import httpx
from typing import Annotated, Optional
from pydantic import Field
from mcp.server.mcpserver import MCPServer, Context
from ..auth.context import check_tool_access
from ..config import get_settings
from ..observability import traced_tool


def register(mcp: MCPServer) -> None:
    @mcp.tool()
    @traced_tool("perplexity_search")
    async def perplexity_search(
        query: Annotated[str, Field(description="La question ou requête de recherche à envoyer à Perplexity AI")],
        detail_level: Annotated[str, Field(default="normal", description="Niveau de détail : brief (2-3 phrases), normal (réponse complète), detailed (exploration en profondeur)")] = "normal",
        model: Annotated[Optional[str], Field(default=None, description="Modèle Perplexity à utiliser (optionnel, défaut selon config serveur)")] = None,
        ctx: Optional[Context] = None
    ) -> dict:
        """Recherche internet via Perplexity AI. Niveaux : brief, normal, detailed. Retourne du Markdown avec citations."""
        try:
            check_tool_access("perplexity_search")

            settings = get_settings()
            if not settings.perplexity_api_key:
                return {"status": "error", "message": "Clé API Perplexity non configurée"}

            system_prompts = {
                "brief": "Réponds de manière très concise, en 2 ou 3 phrases maximum.",
                "normal": "Réponds de manière complète mais directe, avec des puces si besoin.",
                "detailed": "Réponds de manière très détaillée, en explorant le sujet en profondeur avec des exemples et des citations."
            }
            sys_prompt = system_prompts.get(detail_level, system_prompts["normal"])
            sys_prompt += " Format ta réponse en Markdown."

            headers = {
                "Authorization": f"Bearer {settings.perplexity_api_key}",
                "Content-Type": "application/json"
            }

            # Modèle : param optionnel, sinon config, sinon défaut
            effective_model = model or settings.perplexity_model

            payload = {
                "model": effective_model,
                "messages": [
                    {"role": "system", "content": sys_prompt},
                    {"role": "user", "content": query}
                ]
            }

            url = f"{settings.perplexity_api_url.rstrip('/')}/chat/completions"
            timeout = float(settings.perplexity_timeout)

            async with httpx.AsyncClient(timeout=timeout) as client:
                resp = await client.post(url, headers=headers, json=payload)
                resp.raise_for_status()
                data = resp.json()

                content = data["choices"][0]["message"]["content"]

                if len(content) > settings.tool_max_output_chars:
                    content = content[:settings.tool_max_output_chars] + "... [TRUNCATED]"

                return {
                    "status": "success",
                    "model": effective_model,
                    "content": content,
                    "citations": data.get("citations", []),
                    "usage": data.get("usage", {})
                }

        except httpx.HTTPStatusError as e:
            return {"status": "error", "message": f"Erreur API HTTP: {e.response.status_code} - {e.response.text[:200]}"}
        except Exception as e:
            return {"status": "error", "message": str(e)}

    @mcp.tool()
    @traced_tool("perplexity_doc")
    async def perplexity_doc(
        query: Annotated[str, Field(description="Technologie, librairie ou API à documenter (ex: 'FastAPI', 'boto3 S3', 'React hooks')")],
        context: Annotated[Optional[str], Field(default=None, description="Contexte spécifique à approfondir (ex: 'authentification JWT', 'gestion des erreurs')")] = None,
        model: Annotated[Optional[str], Field(default=None, description="Modèle Perplexity à utiliser (optionnel, défaut selon config serveur)")] = None,
        ctx: Optional[Context] = None
    ) -> dict:
        """Documentation technique d'une technologie, librairie ou API. Retourne syntaxe, exemples de code et bonnes pratiques."""
        try:
            check_tool_access("perplexity_doc")

            settings = get_settings()
            if not settings.perplexity_api_key:
                return {"status": "error", "message": "Clé API Perplexity non configurée"}

            sys_prompt = (
                "Tu es un expert en documentation technique. "
                "Fournis une réponse structurée avec : "
                "1) Une description concise de la technologie/librairie/API, "
                "2) La syntaxe et les paramètres principaux, "
                "3) Des exemples de code pratiques et fonctionnels, "
                "4) Les bonnes pratiques et pièges courants. "
                "Format ta réponse en Markdown avec des blocs de code."
            )

            user_message = query
            if context:
                user_message += f"\n\nContexte spécifique à approfondir : {context}"

            headers = {
                "Authorization": f"Bearer {settings.perplexity_api_key}",
                "Content-Type": "application/json"
            }

            effective_model = model or settings.perplexity_model

            payload = {
                "model": effective_model,
                "messages": [
                    {"role": "system", "content": sys_prompt},
                    {"role": "user", "content": user_message}
                ]
            }

            url = f"{settings.perplexity_api_url.rstrip('/')}/chat/completions"
            timeout = float(settings.perplexity_timeout)

            async with httpx.AsyncClient(timeout=timeout) as client:
                resp = await client.post(url, headers=headers, json=payload)
                resp.raise_for_status()
                data = resp.json()

                content = data["choices"][0]["message"]["content"]

                if len(content) > settings.tool_max_output_chars:
                    content = content[:settings.tool_max_output_chars] + "... [TRUNCATED]"

                return {
                    "status": "success",
                    "model": effective_model,
                    "query": query,
                    "context": context,
                    "content": content,
                    "citations": data.get("citations", []),
                    "usage": data.get("usage", {})
                }

        except httpx.HTTPStatusError as e:
            return {"status": "error", "message": f"Erreur API HTTP: {e.response.status_code} - {e.response.text[:200]}"}
        except Exception as e:
            return {"status": "error", "message": str(e)}
