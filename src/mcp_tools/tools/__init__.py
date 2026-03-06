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
    from . import network
    from . import http
    from . import perplexity
    from . import date
    from . import calc
    from . import ssh
    from . import files
    
    # Enregistrement
    shell.register(mcp)
    network.register(mcp)
    http.register(mcp)
    perplexity.register(mcp)
    date.register(mcp)
    calc.register(mcp)
    ssh.register(mcp)
    files.register(mcp)
