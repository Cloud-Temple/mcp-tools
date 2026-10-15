"""Parcours public files ; le retry inspecte, reconcile révoque et ne republie jamais."""
import asyncio
import base64
import difflib
import hashlib
import json
import uuid
from functools import lru_cache

from ..auth.context import check_tool_access, current_token_info
from ..config import get_settings
from .files_credentials import StorageUnavailable
from .files_postgres import Catalog, Conflict, CommitUnknown, digest
from .files_s3 import Blobs


def key(value):
    if not isinstance(value, str) or not 1 <= len(value.encode("utf-8")) <= 1024 or "\x00" in value:
        raise Conflict("Clé invalide (1–1024 octets UTF-8)")
    return value


def public_ref(row):
    if not row or not row.get("generation"):
        return None
    pin = row["pin"]
    return {"path": row["path"], "key": row["path"], "revision": row["revision"],
        "generation": str(row["generation"]), "version_id": pin["version_id"],
        "etag": pin["etag"], "size": pin["size"], "sha256": pin["sha256"],
        "deleted": row["deleted"], "effect_state": "deleted" if row["deleted"] else "present",
        "durability_state": "unverified"}


class FilesService:
    def __init__(self, s):
        self.s = s
        if s.tool_max_output_chars < 8192:
            raise StorageUnavailable("Budget sortie catalogue insuffisant")
        if s.files_s3_prefix.startswith("_tokens/") or "_tokens/".startswith(s.files_s3_prefix):
            raise StorageUnavailable("Préfixe contenu chevauche magasin tokens")
        if s.files_metadata_backend != "postgres" or not s.files_s3_prefix or len(s.files_s3_prefix.encode()) > 512:
            raise StorageUnavailable("Profil fichiers invalide")
        if not all((s.s3_endpoint_url, s.s3_access_key_id, s.s3_secret_access_key, s.s3_bucket_name)):
            raise StorageUnavailable("Profil S3 incomplet")
        self.catalog = Catalog(s)
        self.blobs = Blobs(s)
        self.calls = asyncio.Semaphore(4)

    async def ready(self):
        async with self.catalog.connection() as c:
            await self.catalog.infrastructure(c)
        await self.blobs.ready()

    def authorize_journal(self, row, admin=False):
        info = current_token_info.get() or {}
        if "admin" in info.get("permissions", []):
            return
        if admin or not info.get("credential_binding") or row["binding"] != info["credential_binding"]:
            raise Conflict("Accès journal refusé")

    async def ref(self, c, path, lock=False):
        if lock:
            await c.execute("SELECT path FROM refs WHERE path=%s FOR UPDATE", (path,))
        return await self.catalog.one(c, "SELECT r.*,g.pin,g.manifest FROM refs r LEFT JOIN generations g ON g.id=r.generation WHERE r.path=%s", (path,))

    def cursor(self, operation, prefix, after):
        return base64.urlsafe_b64encode(json.dumps({"v": 1, "op": operation,
            "profile": self.s.files_s3_prefix, "prefix": prefix, "after": after},
            ensure_ascii=False, separators=(",", ":")).encode()).decode()

    def after(self, cursor, operation, prefix):
        if not cursor:
            return ""
        try:
            if len(cursor) > 8192:
                raise ValueError()
            v = json.loads(base64.b64decode(cursor.encode(), altchars=b"-_", validate=True))
            if set(v) != {"v", "op", "profile", "prefix", "after"} or v["v"] != 1 or v["op"] != operation or v["prefix"] != prefix or v["profile"] != self.s.files_s3_prefix:
                raise ValueError()
            return key(v["after"])
        except Exception:
            raise Conflict("Curseur incompatible") from None

    async def read_operations(self, op, args):
        cat = self.catalog
        path = args.get("path")
        async with cat.connection() as c:
            if op == "list":
                prefix = args.get("prefix") or ""
                if prefix:
                    key(prefix)
                after = self.after(args.get("cursor"), op, prefix)
                n = args["max_keys"]
                rows = await (await c.execute("SELECT r.*,g.pin FROM refs r JOIN generations g ON g.id=r.generation WHERE NOT r.deleted AND starts_with(r.path,%s) AND r.path COLLATE \"C\" > %s COLLATE \"C\" ORDER BY r.path COLLATE \"C\" LIMIT %s", (prefix, after, n+1))).fetchall()
                more = len(rows) > n
                result = {"status": "ok", "objects": [public_ref(r) for r in rows[:n]],
                    "count": min(n, len(rows)), "truncated": more,
                    "next_cursor": self.cursor(op, prefix, rows[n-1]["path"]) if more else None}
                # Taille response bornée : page réduite, dernier curseur réellement rendu.
                while len(json.dumps(result, ensure_ascii=True)) > self.s.tool_max_output_chars and result["objects"]:
                    result["objects"].pop()
                    result["count"] = len(result["objects"])
                    result["truncated"] = True
                    result["next_cursor"] = self.cursor(op, prefix, result["objects"][-1]["path"]) if result["objects"] else None
                if not result["objects"] and rows:
                    raise Conflict("Budget de réponse insuffisant pour une métadonnée")
                return result
            if op == "metadata_batch":
                paths = args.get("paths")
                if not isinstance(paths, list) or not 1 <= len(paths) <= 64:
                    raise Conflict("Batch : 1 à 64 clés requis")
                for p in paths:
                    key(p)
                rows = await (await c.execute("SELECT r.*,g.pin FROM refs r JOIN generations g ON g.id=r.generation WHERE r.path=ANY(%s) AND NOT r.deleted", (paths,))).fetchall()
                found = {r["path"]: public_ref(r) for r in rows}
                result = {"status": "ok", "count": len(paths), "metadata": [found.get(p) or {"path": p, "effect_state": "absent", "durability_state": "unverified"} for p in paths]}
                if len(json.dumps(result, ensure_ascii=True)) > self.s.tool_max_output_chars:
                    raise Conflict("Batch dépasse le budget réponse ; réduire paths")
                return result
            path = key(path)
            # A physical historical version is not permission to undo a logical deletion.
            row = await self.ref(c, path)
            if not row or row["deleted"] or not row["generation"]:
                if op == "versions":
                    return {"status": "ok", "versions": [], "count": 0,
                            "truncated": False, "next_cursor": None}
                return {"status": "ok", "path": path, "effect_state": "absent",
                        "durability_state": "unverified"}
            if op == "versions":
                after = self.after(args.get("cursor"), op, path)
                n = args["max_keys"]
                # UUID lexical : pagination bornée, pas promesse snapshot ni ordre chronologique.
                rows = await (await c.execute("SELECT id,pin,manifest,created_at FROM generations WHERE path=%s AND id::text > %s ORDER BY id::text LIMIT %s", (path, after, n+1))).fetchall()
                data = [{"generation": str(r["id"]), "version_id": r["pin"]["version_id"], "size": r["pin"]["size"], "sha256": r["pin"]["sha256"], "created_at": r["created_at"].isoformat()} for r in rows[:n]]
                result = {"status": "ok", "versions": data, "count": len(data), "truncated": len(rows)>n,
                        "next_cursor": self.cursor(op,path,str(rows[n-1]["id"])) if len(rows)>n else None}
                while len(json.dumps(result,ensure_ascii=True))>self.s.tool_max_output_chars and data:
                    data.pop()
                    result.update(count=len(data),truncated=True,next_cursor=self.cursor(op,path,data[-1]["generation"]) if data else None)
                if not data and rows:
                    raise Conflict("Budget réponse insuffisant")
                return result
            if args.get("version_id"):
                histories = await (await c.execute("SELECT id,pin,manifest FROM generations WHERE path=%s AND pin->>'version_id'=%s LIMIT 2", (path,args["version_id"]))).fetchall()
                if len(histories)!=1:
                    raise Conflict("Version non cataloguée")
                historical = histories[0]
                row = {"path": path, "generation": historical["id"], "pin": historical["pin"], "manifest": historical["manifest"], "revision": row["revision"] if row else 0, "deleted": False}
            if not row or row["deleted"] or not row["generation"]:
                return {"status": "ok", "path": path, "effect_state": "absent", "durability_state": "unverified"}
            if op == "info":
                return {"status": "ok", **public_ref(row)}
            second = await self.ref(c, key(args.get("path2"))) if op == "diff" else None
        body = await self.blobs.get(row["pin"])
        result = {"status": "ok", **public_ref(row)}
        if op == "diff":
            if not second or second["deleted"]:
                raise Conflict("Seconde source absente")
            body2 = await self.blobs.get(second["pin"])
            text = "".join(difflib.unified_diff(body.decode("utf-8").splitlines(True), body2.decode("utf-8").splitlines(True), fromfile=path, tofile=args["path2"]))
            result["diff"] = text[:max(0, self.s.tool_max_output_chars-8192)]
            result["truncated"] = len(text) > self.s.tool_max_output_chars-8192
            return result
        if args.get("if_match") and args["if_match"] != row["pin"]["etag"]:
            raise Conflict("ETag ne correspond pas à la génération")
        offset, limit = args.get("offset"), args.get("limit")
        if offset is not None or limit is not None:
            offset = offset or 0
            limit = limit or min(30000, ((self.s.tool_max_output_chars-8192)//4)*3)
            if type(offset) is not int or type(limit) is not int or not 0 <= offset <= len(body) or not 1 <= limit <= min(30000, ((self.s.tool_max_output_chars-8192)//4)*3):
                raise Conflict("Plage read invalide")
            if offset and not args.get("version_id") and not args.get("if_match"):
                raise Conflict("Reprise read exige version_id ou if_match")
            part = body[offset:offset+limit]
            result.update(encoding="base64", content_base64=base64.b64encode(part).decode(),
                offset=offset, returned_bytes=len(part), next_offset=offset+len(part), end=offset+len(part)==len(body))
        else:
            try:
                text = body.decode("utf-8")
            except UnicodeDecodeError:
                text = "[BINAIRE — base64]\n" + base64.b64encode(body).decode()
            n = max(0, self.s.tool_max_output_chars-8192)
            result.update(content=text[:n], truncated=len(text)>n)
        return result

    async def info(self, oid, certificate=None):
        async with self.catalog.connection() as c:
            row = await self.catalog.one(c, "SELECT * FROM operations WHERE id=%s", (oid,))
            if row is None:
                # Aucun count ni distinction révélant une opération d'un autre binding.
                raise Conflict("Opération inaccessible")
            self.authorize_journal(row)
            ref = await self.ref(c, row["path"])
            effects = await self.catalog.one(c, "SELECT EXISTS(SELECT 1 FROM receipts WHERE operation=%s AND kind='publication') published", (oid,))
            present = effects["published"]
            effect = "present" if present else "not_published" if certificate and not row["publication_allowed"] else "unobserved"
            if present and (not ref or str(ref["operation"]) != oid):
                effect = "conflict"
            history = await (await c.execute("SELECT kind,detail,created_at FROM receipts WHERE operation=%s ORDER BY created_at,id LIMIT 64", (oid,))).fetchall()
            result = {"status": "ok" if certificate else "incomplete", "operation_id": oid,
                "path": row["path"], "phase": row["phase"], "generation": str(row["generation"]),
                "initial_confirmation": row["initial_confirmation"], "remote_result": "uncertain",
                "effect_state": effect, "durability_state": "verified_at_current_observation" if certificate else "unverified",
                "reconciliation_state": "verified_at_current_observation" if certificate else "pending",
                "publication_allowed": row["publication_allowed"], "closed": row["closed"],
                "history_limit": 64, "history_may_be_truncated": len(history)==64,
                "history": [{"kind": h["kind"], "detail": h["detail"], "created_at": h["created_at"].isoformat()} for h in history],
                **({"certificate": certificate} if certificate else {})}
            while len(json.dumps(result,ensure_ascii=True))>self.s.tool_max_output_chars and result["history"]:
                result["history"].pop()
                result["history_may_be_truncated"]=True
            return result

    async def prepare(self, op, args):
        path = key(args.get("path"))
        manifest = []
        body = b""
        async with self.catalog.connection() as c:
            old = await self.ref(c, path)
            expected = old["revision"] if old else 0
            if args.get("expected_revision") is not None and args["expected_revision"] != expected:
                raise Conflict("Révision destination divergente")
            if op == "delete":
                if not old or old["deleted"]:
                    raise Conflict("Fichier absent")
                manifest = [{"path": path, "generation": str(old["generation"]), "pin": old["pin"]}]
            if op == "concat":
                paths = args.get("paths")
                if not isinstance(paths, list) or not 1 <= len(paths) <= 64 or path in paths:
                    raise Conflict("Sources concat invalides")
                sep = args.get("separator", "\n\n")
                if not isinstance(sep, str) or len(sep.encode()) > 65536:
                    raise Conflict("Séparateur concat invalide")
                for p in paths:
                    r = await self.ref(c, key(p))
                    if not r or r["deleted"] or not r["generation"]:
                        raise Conflict("Source concat absente")
                    manifest.append({"path": p, "generation": str(r["generation"]), "pin": r["pin"]})
        if op == "concat":
            parts = []
            size = 0
            for source in manifest:
                b = await self.blobs.get(source["pin"])
                b.decode("utf-8")  # mêmes contraintes texte que concat historique
                size += len(b) + (len(sep.encode()) if parts else 0)
                if size > 5_000_000:
                    raise Conflict("Concat dépasse 5000000 octets")
                parts.append(b)
            body = sep.encode().join(parts)
        elif op == "write":
            text = args.get("content")
            if not isinstance(text, str) or not text or len(text)>5_000_000:
                raise Conflict("Write : 1 à 5000000 caractères UTF-8 requis")
            body = text.encode()
        return expected, body, manifest

    def request(self, op, args):
        binding = (current_token_info.get() or {}).get("credential_binding")
        content = args.get("content")
        return digest({"profile": self.s.files_s3_prefix, "bucket": self.s.s3_bucket_name,
            "operation": op, "path": args.get("path"), "binding": binding,
            "content_sha256": hashlib.sha256(content.encode()).hexdigest() if isinstance(content,str) else None,
            "paths": args.get("paths") if op=="concat" else None,
            "separator": args.get("separator", "\n\n") if op=="concat" else None,
            "expected_revision": args.get("expected_revision")})

    async def phase(self, oid, phase, detail=None):
        cat = self.catalog
        async with cat.connection() as c:
            async with cat.transaction(c):
                row = await cat.lock(c, oid)
                if not row["publication_allowed"] or row["closed"]:
                    raise Conflict("Tentative révoquée")
                await c.execute("UPDATE operations SET phase=%s WHERE id=%s", (phase, oid))
                rid = await cat.receipt(c, oid, phase, detail or {})
            await cat.verify_barrier(c, oid, rid)

    async def mutate(self, op, args, oid):
        cat = self.catalog
        request = self.request(op, args)
        async with cat.connection() as c:
            existing = await cat.one(c, "SELECT * FROM operations WHERE id=%s", (oid,))
            if existing:
                self.authorize_journal(existing)
                if existing["request_digest"] != request:
                    raise Conflict("Même ID, requête divergente")
        if existing:
            return await self.info(oid)  # jamais dispatch de nouveau
        from psycopg.types.json import Jsonb
        expected, body, manifest = await self.prepare(op, args)
        generation, attempt = str(uuid.uuid4()), str(uuid.uuid4())
        physical = self.s.files_s3_prefix + generation
        intent = {"operation": op, "path": args["path"], "expected_revision": expected,
            "generation": generation, "attempt": attempt, "physical_key": physical,
            "sha256": hashlib.sha256(body).hexdigest(), "size": len(body), "sources": manifest,
            "separator_sha256": hashlib.sha256(args.get("separator", "\n\n").encode()).hexdigest() if op=="concat" else None,
            "request_digest": request}
        async with cat.connection() as c:
            async with cat.transaction(c):
                await c.execute("INSERT INTO operations(id,path,binding,request_digest,intent_digest,intent,attempt,generation,expected_revision,phase) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,'INTENT_RESERVED')", (oid,args["path"],(current_token_info.get() or {}).get("credential_binding"), request,digest(intent),Jsonb(intent),attempt,generation,expected))
                await c.execute("INSERT INTO refs(path) VALUES(%s) ON CONFLICT DO NOTHING", (args["path"],))
                dest = await self.ref(c,args["path"],True)
                if dest["revision"] != expected:
                    raise Conflict("CAS réservation divergent")
                rid = await cat.barrier(c,oid,"intent_reserved")
            await cat.verify_barrier(c,oid,rid)
        # Toute phase armée est durable AVANT son effet. Unknown => arrêt, pas retry.
        await self.phase(oid,"CONTENT_DISPATCH_ARMED")
        pin = None
        if op != "delete":
            pin = await self.blobs.put(physical,body,intent["sha256"])
            async with cat.connection() as c:
                async with cat.transaction(c):
                    row = await cat.lock(c,oid)
                    if not row["publication_allowed"]:
                        raise Conflict("Tentative révoquée après PUT")
                    await c.execute("INSERT INTO generations(id,operation,path,pin,manifest) VALUES(%s,%s,%s,%s,%s)", (generation,oid,args["path"],Jsonb(pin),Jsonb(manifest)))
                    await c.execute("UPDATE operations SET phase='CONTENT_VERIFIED' WHERE id=%s",(oid,))
                    rid = await cat.receipt(c,oid,"content_verified",{"sha256":pin["sha256"],"size":pin["size"]})
                await cat.verify_barrier(c,oid,rid)
        else:
            # La suppression ne supprime jamais la version référencée.
            await self.phase(oid,"CONTENT_VERIFIED")
        await self.phase(oid,"PUBLICATION_ARMED")
        certificate = await self.publish(oid,attempt,generation,digest(intent),op)
        if op=="delete":
            marker = await self.blobs.marker(manifest[0]["pin"])
            await self.phase_after_effect(oid,"delete_marker",marker)
        await self.close_published(oid)
        return {"status":"ok","operation":op,"operation_id":oid,"path":args["path"],
            "revision":expected+1,"generation":generation,"effect_state":"deleted" if op=="delete" else "present",
            "durability_state":"verified_at_current_observation","initial_confirmation":"ack_observed_by_server",
            "remote_result":"confirmed","certificate":certificate,
            **({"size":pin["size"],"sha256":pin["sha256"],"version_id":pin["version_id"]} if pin else {})}

    async def publish(self, oid, attempt, generation, intention, op):
        cat = self.catalog
        async with cat.connection() as c:
            async with cat.transaction(c):
                # Point d'entrelacement du harnais : entrée de lock. Aucun état en mémoire ne dispense de cette relecture.
                row = await cat.lock(c,oid)
                if str(row["attempt"])!=attempt or str(row["generation"])!=generation or row["intent_digest"]!=intention or not row["publication_allowed"] or row["closed"] or row["phase"]!="PUBLICATION_ARMED":
                    raise Conflict("Publication originale désormais interdite")
                dest = await self.ref(c,row["path"],True)
                if dest["revision"] != row["expected_revision"]:
                    raise Conflict("CAS publication divergent")
                gen = dest["generation"] if op=="delete" else generation
                changed = await c.execute("UPDATE refs SET revision=revision+1,generation=%s,operation=%s,deleted=%s,updated_at=clock_timestamp() WHERE path=%s AND revision=%s",(gen,oid,op=="delete",row["path"],row["expected_revision"]))
                if changed.rowcount != 1:
                    raise Conflict("CAS publication refusé")
                await c.execute("UPDATE operations SET phase='EFFECT_COMMITTED' WHERE id=%s",(oid,))
                rid = await cat.receipt(c,oid,"publication",{"attempt":attempt,"generation":generation})
            certificate = await cat.verify_barrier(c,oid,rid)
            # Relecture sous verrou après barrière : aucun snapshot préalable ne sert de preuve.
            async with cat.transaction(c):
                observed = await cat.lock(c,oid)
                dest = await self.ref(c,observed["path"],True)
                if str(dest["operation"])!=oid or observed["phase"]!="EFFECT_COMMITTED":
                    raise CommitUnknown("Effet publication divergent")
                await cat.receipt(c,oid,"ack_observed_by_server",{"barrier_id":rid})
            return certificate

    async def phase_after_effect(self, oid, kind, detail):
        async with self.catalog.connection() as c:
            async with self.catalog.transaction(c):
                await self.catalog.lock(c,oid)
                rid = await self.catalog.receipt(c,oid,kind,detail)
            await self.catalog.verify_barrier(c,oid,rid)

    async def close_published(self,oid):
        cat = self.catalog
        async with cat.connection() as c:
            async with cat.transaction(c):
                row = await cat.lock(c,oid)
                if row["phase"]!="EFFECT_COMMITTED":
                    raise CommitUnknown("Effet non établi")
                await c.execute("UPDATE operations SET publication_allowed=false,revocation=COALESCE(revocation,%s),closed=true,phase='BARRIER_OBSERVED' WHERE id=%s",(str(uuid.uuid4()),oid))
                rid = await cat.barrier(c,oid,"close_published")
            await cat.verify_barrier(c,oid,rid)

    async def reconcile(self,oid):
        cat = self.catalog
        # Aucun S3 PUT/DELETE ni publication de remplacement, même après observation d'absence.
        async with cat.connection() as c:
            async with cat.transaction(c):
                row = await cat.lock(c,oid)
                self.authorize_journal(row,admin=True)
                if digest(row["intent"]) != row["intent_digest"] or str(row["attempt"])!=row["intent"]["attempt"] or str(row["generation"])!=row["intent"]["generation"]:
                    raise Conflict("Intention/génération divergente")
                await self.ref(c,row["path"],True)
                revocation = str(row["revocation"] or uuid.uuid4())
                if row["publication_allowed"]:
                    await c.execute("UPDATE operations SET publication_allowed=false,revocation=%s WHERE id=%s",(revocation,oid))
                    await cat.receipt(c,oid,"revocation",{"revocation_id":revocation,"attempt":str(row["attempt"]),"generation":str(row["generation"])})
                rid = await cat.barrier(c,oid,"revocation_barrier")
            certificate = await cat.verify_barrier(c,oid,rid)
            # Une seconde transaction verrouillée lit garde+effet. La garde ne peut jamais être réarmée.
            async with cat.transaction(c):
                current = await cat.lock(c,oid)
                dest = await self.ref(c,current["path"],True)
                if current["publication_allowed"] or str(current["revocation"])!=revocation or current["intent_digest"]!=row["intent_digest"]:
                    raise CommitUnknown("Fence/relecture divergente")
                published = await cat.one(c,"SELECT EXISTS(SELECT 1 FROM receipts WHERE operation=%s AND kind='publication') present",(oid,))
                if published["present"] and str(dest["operation"])!=oid:
                    raise Conflict("Référence concurrente ; inspection requise")
                pinrow = await cat.one(c,"SELECT pin FROM generations WHERE operation=%s",(oid,))
                if pinrow:
                    await self.blobs.get(pinrow["pin"])
                elif current["intent"]["operation"]!="delete" and current["phase"]=="CONTENT_DISPATCH_ARMED":
                    # HEAD/GET compare l'objet attendu au hash pré-PUT ; aucun adoption ni nouveau PUT.
                    try:
                        observed_pin = await self.blobs.inspect(current["intent"])
                    except StorageUnavailable:
                        await cat.receipt(c,oid,"content_observation",{"effect":"unobserved","absence_not_proven":True})
                    else:
                        await cat.receipt(c,oid,"content_observation",{"effect":"present","sha256":observed_pin["sha256"],"version_id":observed_pin["version_id"]})
                elif current["intent"]["operation"]!="delete" and current["phase"] not in ("INTENT_RESERVED", "CONTENT_DISPATCH_ARMED"):
                    raise CommitUnknown("Pin catalogue attendu absent")
                # Un PUT sans ACK peut exister sans pin : absence physique jamais revendiquée ni purgée.
                if current["intent"]["operation"]=="delete" and published["present"]:
                    marker = await cat.one(c,"SELECT EXISTS(SELECT 1 FROM receipts WHERE operation=%s AND kind IN ('delete_marker','delete_marker_observed')) present",(oid,))
                    if not marker["present"]:
                        try:
                            observed_marker = await self.blobs.inspect_marker(current["intent"]["sources"][0]["pin"])
                        except StorageUnavailable:
                            # The current SQL tombstone is authoritative. An unobserved
                            # marker never proves S3 absence and must not trigger a DELETE.
                            await cat.receipt(c,oid,"delete_marker_unobserved",{"absence_not_proven":True})
                        else:
                            await cat.receipt(c,oid,"delete_marker_observed",observed_marker)
                await c.execute("UPDATE operations SET closed=true WHERE id=%s AND NOT publication_allowed AND revocation=%s",(oid,revocation))
                closing = await cat.receipt(c,oid,"reconciliation_closed",{"barrier_id":rid,"revocation_id":revocation,"result":"published" if published["present"] else "not_published"})
            await cat.verify_barrier(c,oid,closing)
        return await self.info(oid,certificate)

    async def dispatch(self,op,args):
        check_tool_access("files")
        if op=="reconcile" and "admin" not in (current_token_info.get() or {}).get("permissions",[]):
            raise Conflict("Permission admin requise")
        oid = args.get("operation_id")
        if oid is not None:
            try:
                oid = str(uuid.UUID(oid))
            except (ValueError, TypeError, AttributeError):
                raise Conflict("operation_id UUID requis") from None
        if op in ("operation_info","reconcile") and oid is None:
            raise Conflict("operation_id requis")
        if op in ("write","concat","delete"):
            oid = oid or str(uuid.uuid4())
        try:
            async with asyncio.timeout(max(1,min(args.get("timeout",30),60))):
                async with self.calls:
                    await self.ready()
                    from ..auth.access_runtime import refresh_access
                    await refresh_access('files')
                    if op in ("write","concat","delete"):
                        return await self.mutate(op,args,oid)
                    if op=="operation_info":
                        return await self.info(oid)
                    if op=="reconcile":
                        return await self.reconcile(oid)
                    if op=="enable_versioning":
                        raise Conflict("Versioning à provisionner par opérateur avant app")
                    if op not in ("list","read","info","diff","versions","metadata_batch"):
                        raise Conflict("Opération non supportée")
                    return {"operation":op, **await self.read_operations(op,args)}
        except Conflict as e:
            if op in ("write", "concat", "delete", "reconcile"):
                return {"status":"incomplete","message":str(e),"remote_result":"uncertain",
                    "durability_state":"unverified","initial_confirmation":"unknown",
                    "reconciliation_state":"pending",**({"operation_id":oid} if oid else {})}
            return {"status":"error","message":str(e),**({"operation_id":oid} if oid else {})}
        except (StorageUnavailable,TimeoutError):
            return {"status":"incomplete","message":"Dépendance/effet non confirmé ; inspection explicite requise",
                "remote_result":"uncertain","effect_state":"unobserved","durability_state":"unverified",
                "initial_confirmation":"unknown","reconciliation_state":"pending",**({"operation_id":oid} if oid else {})}


@lru_cache(maxsize=1)
def get_files_service():
    return FilesService(get_settings())
