# -*- coding: utf-8 -*-
"""
Outil: perplexity — Recherche internet via Perplexity AI.
"""

import httpx
from typing import Optional
from mcp.server.fastmcp import FastMCP, Context
from ..auth.context import check_tool_access
from ..config import get_settings


def register(mcp: FastMCP) -> None:
    @mcp.tool()
    async def perplexity_search(
        query: str,
        detail_level: str = "normal",
        model: Optional[str] = None,
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
            timeout = float(settings.tool_default_timeout)

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
