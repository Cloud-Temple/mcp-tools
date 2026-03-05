# -*- coding: utf-8 -*-
"""
Outil: http — Client HTTP/REST.
"""

import httpx
from typing import Optional, Dict, Any
from mcp.server.fastmcp import FastMCP, Context
from ..auth.context import check_tool_access
from ..config import get_settings


def register(mcp: FastMCP) -> None:
    @mcp.tool()
    async def http(
        url: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        json_body: Optional[Dict[str, Any]] = None,
        timeout: int = 30,
        verify_ssl: bool = True,
        ctx: Optional[Context] = None
    ) -> dict:
        """Client HTTP/REST asynchrone. Méthodes : GET, POST, PUT, DELETE, PATCH, HEAD. Retourne le status code, les headers et le body de la réponse."""
        try:
            check_tool_access("http")

            settings = get_settings()
            timeout = min(timeout, 60)
            method = method.upper()

            if method not in ("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD"):
                return {"status": "error", "message": f"Méthode {method} non autorisée"}

            async with httpx.AsyncClient(verify=verify_ssl, timeout=timeout) as client:
                response = await client.request(
                    method=method,
                    url=url,
                    headers=headers or {},
                    json=json_body
                )

                output_text = response.text
                if len(output_text) > settings.tool_max_output_chars:
                    output_text = output_text[:settings.tool_max_output_chars] + "... [TRUNCATED]"

                return {
                    "status": "success" if response.is_success else "error",
                    "status_code": response.status_code,
                    "headers": dict(response.headers),
                    "text": output_text
                }

        except httpx.TimeoutException:
            return {"status": "error", "message": f"Timeout HTTP après {timeout}s"}
        except Exception as e:
            return {"status": "error", "message": str(e)}
