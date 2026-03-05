# -*- coding: utf-8 -*-
"""
Registre des outils MCP.
"""

from mcp.server.fastmcp import FastMCP

def register_all_tools(mcp: FastMCP) -> None:
    """
    Importe et enregistre tous les modules d'outils auprès de l'instance mcp.
    """
    # Import des sous-modules d'outils
    from . import shell
    from . import ping
    from . import http
    from . import perplexity
    
    # Enregistrement
    shell.register(mcp)
    ping.register(mcp)
    http.register(mcp)
    perplexity.register(mcp)
