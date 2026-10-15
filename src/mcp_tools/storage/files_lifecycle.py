"""Liveness indépendante, readiness fraîche bornée et aucune initialisation SQL implicite."""
import asyncio
import time



class FilesLifecycle:
    def __init__(self):
        self.state = "starting"
        self.checked_at = 0.0
        self.gate = asyncio.Lock()
        self.stopped = False

    async def probe(self, settings, force=False):
        if settings.files_metadata_backend == "s3":
            self.state = "legacy_ready"
            return not self.stopped
        if settings.files_metadata_backend != "postgres" or self.stopped:
            self.state = "configuration_invalid" if not self.stopped else "stopping"
            return False
        async with self.gate:
            if not force and time.monotonic()-self.checked_at < 5:
                return self.state == "ready"
            try:
                from .files_service import get_files_service
                async with asyncio.timeout(2):
                    await get_files_service().ready()
                self.state = "ready"
            except Exception:
                self.state = "dependency_or_contract_unavailable"
            self.checked_at = time.monotonic()
            return self.state == "ready"


lifecycle = FilesLifecycle()


class StorageLifecycleMiddleware:
    def __init__(self, app, settings):
        self.app, self.settings = app, settings

    async def __call__(self, scope, receive, send):
        if scope["type"] != "lifespan":
            return await self.app(scope, receive, send)
        async def storage_receive():
            message = await receive()
            if message["type"] == "lifespan.startup":
                lifecycle.stopped = False
                await lifecycle.probe(self.settings, force=True)
            elif message["type"] == "lifespan.shutdown":
                lifecycle.stopped = True
                lifecycle.state = "stopping"
            return message
        await self.app(scope, storage_receive, send)
