"""Pins versionnés et empreintes ; retries S3 mutants désactivés."""
import asyncio
import hashlib
from .files_credentials import StorageUnavailable

MAX_BYTES = 20_000_000


class Blobs:
    def __init__(self, s):
        import boto3
        from botocore.config import Config
        if s.files_s3_data_signature not in ("s3", "s3v4"):
            raise StorageUnavailable("Signature S3 invalide")
        self.data_signature = s.files_s3_data_signature
        self.bucket = s.s3_bucket_name
        self.prefix = s.files_s3_prefix
        self.clients = {}
        self.slots = asyncio.Semaphore(4)
        self.jobs = set()
        for signature in ("s3", "s3v4"):
            self.clients[signature] = boto3.client("s3", endpoint_url=s.s3_endpoint_url,
                aws_access_key_id=s.s3_access_key_id, aws_secret_access_key=s.s3_secret_access_key,
                config=Config(region_name=s.s3_region_name, signature_version=signature,
                    s3={"addressing_style": "path"}, retries={"total_max_attempts": 1},
                    connect_timeout=s.files_connect_timeout, read_timeout=10))

    async def run(self, work, *, authorize=True):
        # Après timeout/annulation le thread peut encore muter S3 : garder son admission
        # jusqu'à sa vraie fin. La réservation/intention survit indépendamment.
        await self.slots.acquire()
        try:
            from ..auth.access_runtime import refresh_access
            if authorize:
                await refresh_access('files')
        except BaseException:
            self.slots.release()
            raise
        task = asyncio.create_task(asyncio.to_thread(work))
        self.jobs.add(task)
        def finish(t):
            self.jobs.discard(t)
            self.slots.release()
            if not t.cancelled():
                t.exception()  # résultat perdu reste incertain, pas de log secret
        task.add_done_callback(finish)
        try:
            return await asyncio.shield(task)
        except asyncio.CancelledError:
            raise
        except Exception:
            raise StorageUnavailable("S3 indisponible, refusé ou objet non vérifiable") from None

    async def call(self, method, metadata=False, **kwargs):
        c = self.clients["s3v4" if metadata else self.data_signature]
        return await self.run(lambda: getattr(c, method)(Bucket=self.bucket, **kwargs),
                              authorize=method != 'get_bucket_versioning')

    async def ready(self):
        r = await self.call("get_bucket_versioning", metadata=True)
        if r.get("Status") != "Enabled":
            raise StorageUnavailable("Versioning S3 obligatoire")

    async def put(self, key, body, digest):
        await self.ready()
        if len(body) > MAX_BYTES or hashlib.sha256(body).hexdigest() != digest:
            raise StorageUnavailable("Empreinte pré-PUT invalide")
        r = await self.call("put_object", Key=key, Body=body,
                            ContentType="application/octet-stream", Metadata={"sha256": digest})
        v = r.get("VersionId")
        if not isinstance(v, str) or v in ("", "null"):
            raise StorageUnavailable("PUT sans pin versionné ; résultat incertain")
        pin = {"key": key, "version_id": v, "etag": r.get("ETag", ""),
               "sha256": digest, "size": len(body)}
        await self.get(pin)
        return pin

    async def get(self, pin):
        if pin.get("version_id") in (None, "", "null") or not 0 <= pin.get("size", -1) <= MAX_BYTES:
            raise StorageUnavailable("Pin S3 invalide")
        def consume():
            r = self.clients[self.data_signature].get_object(Bucket=self.bucket, Key=pin["key"], VersionId=pin["version_id"])
            body = r["Body"]
            try:
                return r, body.read(pin["size"] + 1)
            finally:
                body.close()
        r, b = await self.run(consume)
        if r.get("VersionId") != pin["version_id"] or len(b) != pin["size"] or hashlib.sha256(b).hexdigest() != pin["sha256"]:
            raise StorageUnavailable("Contenu S3 non conforme au pin catalogue")
        return b

    async def marker(self, pin):
        await self.ready()
        # Clé physique unique par génération ; jamais delete VersionId ni purge.
        r = await self.call("delete_object", Key=pin["key"])
        if r.get("DeleteMarker") is not True or r.get("VersionId") in (None, "", "null"):
            raise StorageUnavailable("Delete marker incertain")
        return {"version_id": r["VersionId"], "key": pin["key"]}

    async def inspect(self, intent):
        r = await self.call("head_object", metadata=True, Key=intent["physical_key"])
        pin = {"key":intent["physical_key"], "version_id":r.get("VersionId"),
            "etag":r.get("ETag", ""), "sha256":intent["sha256"], "size":intent["size"]}
        if r.get("ContentLength") != intent["size"]:
            raise StorageUnavailable("Objet d'intention divergent")
        await self.get(pin)
        return pin

    async def inspect_marker(self, pin):
        r = await self.call("list_object_versions", metadata=True, Prefix=pin["key"], MaxKeys=2)
        matches = [m for m in r.get("DeleteMarkers",[]) if m["Key"]==pin["key"] and m.get("IsLatest") is True]
        if len(matches)!=1 or matches[0].get("VersionId") in (None,"","null"):
            raise StorageUnavailable("Delete marker non observé ; résultat pending")
        return {"key":pin["key"],"version_id":matches[0]["VersionId"]}
