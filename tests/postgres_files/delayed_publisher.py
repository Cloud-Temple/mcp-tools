"""Serveur de recette instrumenté hors produit, pour le vrai interleaving pré-lock.

Lancer uniquement sur fixture propre après admission. Les commandes de contrôle
sont des fichiers privés locaux au harnais, jamais une route/outils de production.
"""
import asyncio
import json
import os
from pathlib import Path

from src.mcp_tools.storage.files_service import FilesService

original=FilesService.publish
control=Path(os.environ["TOOLS_RECIPE_CONTROL_DIR"])


async def delayed(self,oid,*args):
    arm=control/"arm"
    if arm.exists() and arm.read_text().strip()==oid:
        # publish() est appelé seulement après PUBLICATION_ARMED confirmé ; avant cat.lock().
        fd=os.open(control/"publication_waiting.json",os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,"w") as f:
            json.dump({"operation_id":oid,"site":"before_operation_lock","pid":os.getpid()},f)
        async with asyncio.timeout(50):
            while not (control/"release").exists():
                await asyncio.sleep(.02)
    return await original(self,oid,*args)


FilesService.publish=delayed

if __name__=="__main__":
    import uvicorn
    from src.mcp_tools.server import create_app,settings
    uvicorn.run(create_app(),host=settings.mcp_server_host,port=settings.mcp_server_port)
