"""Transactions libpq courtes, ACK conservateur, garde persistante et barrière WAL."""
import asyncio
import hashlib
import json
import re
import time
import uuid
from contextlib import asynccontextmanager

from .files_credentials import Credentials, StorageUnavailable
from .files_schema import CHECKSUM, VERSION, TABLE_PRIVILEGES


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False,
        separators=(",", ":")).encode()).hexdigest()


class CommitUnknown(StorageUnavailable):
    pass


class Conflict(StorageUnavailable):
    pass


class Catalog:
    def __init__(self, s):
        self.s = s
        self.credentials = Credentials(s)
        self.slots = asyncio.Semaphore(4)
        if not re.fullmatch(r"[a-z][a-z0-9_]{0,62}", s.files_pg_schema):
            raise StorageUnavailable("Schéma invalide")
        if s.files_durability not in ("local", "remote_apply") or not s.files_pg_system_identifier:
            raise StorageUnavailable("Politique de durabilité/cluster requise")
        self.roster = json.loads(s.files_replication_roster)
        if s.files_durability == "remote_apply":
            required = {"id", "name", "role", "address", "slot", "dn"}
            if not isinstance(self.roster, list) or not 1 <= s.files_quorum <= len(self.roster) <= 16:
                raise StorageUnavailable("Roster quorum invalide")
            for member in self.roster:
                if set(member) != required or any(not isinstance(v, str) or not v for v in member.values()) or not re.fullmatch(r"[a-zA-Z][a-zA-Z0-9_]*", member["name"]):
                    raise StorageUnavailable("Identité quorum invalide")
            for key in required:
                if len({m[key] for m in self.roster}) != len(self.roster):
                    raise StorageUnavailable("Identités quorum non distinctes")
        self.policy = digest({"durability": s.files_durability, "roster": self.roster,
            "k": s.files_quorum, "cluster": s.files_pg_system_identifier, "timeline": s.files_pg_timeline})

    @asynccontextmanager
    async def connection(self, service=None, operator=False):
        import psycopg
        from psycopg.rows import dict_row
        from psycopg import sql
        async with self.slots:
            c = None
            try:
                credential = await self.credentials.sql(service)
                if not self.s.files_pg_ca_file:
                    raise StorageUnavailable("CA PostgreSQL requise")
                c = await psycopg.AsyncConnection.connect(**credential, autocommit=True,
                    sslmode="verify-full", sslrootcert=self.s.files_pg_ca_file,
                    target_session_attrs="read-write", connect_timeout=self.s.files_connect_timeout,
                    row_factory=dict_row)
                notices = []
                # Copier les seuls diagnostics sûrs pendant le callback ; Diagnostic ne survit pas forcément.
                c.add_notice_handler(lambda d: notices.append((d.severity_nonlocalized, d.sqlstate)))
                c._tools_notices = notices
                c._tools_operator = operator
                await c.execute(sql.SQL("SET search_path TO {}, pg_catalog").format(sql.Identifier(self.s.files_pg_schema)))
                await c.execute("SET statement_timeout='2000ms'")
                await c.execute("SET lock_timeout='1000ms'")
                await c.execute("SET idle_in_transaction_session_timeout='3000ms'")
                await c.execute("SET synchronous_commit TO " + ("remote_apply" if self.s.files_durability == "remote_apply" else "on"))
                row = await self.one(c, "SELECT current_database() db, current_user role, pg_is_in_recovery() recovery")
                if row["db"] != self.s.files_pg_database or row["recovery"] or row["role"] != self.s.files_pg_role:
                    raise StorageUnavailable("Cible SQL/identité invalide")
                if operator:
                    proof = await self.one(c,"SELECT (SELECT system_identifier::text FROM pg_control_system()) cluster,(SELECT timeline_id FROM pg_control_checkpoint()) timeline,current_setting('fsync')='on' fsync")
                    if proof["cluster"]!=self.s.files_pg_system_identifier or proof["timeline"]!=self.s.files_pg_timeline or not proof["fsync"]:
                        raise StorageUnavailable("Cluster/epoch opérateur invalide")
                if not operator:
                    await self.check_schema(c)
                    await self.infrastructure(c)
                yield c
            except StorageUnavailable:
                raise
            except Exception:
                raise StorageUnavailable("SQL non disponible ou contrat invalide") from None
            finally:
                if c is not None:
                    await c.close()

    @staticmethod
    async def one(c, query, args=()):
        return await (await c.execute(query, args)).fetchone()

    async def check_schema(self, c, role=None):
        role = role or self.s.files_pg_role
        row = await self.one(c, "SELECT version,checksum FROM schema_version WHERE singleton")
        if row != {"version": VERSION, "checksum": CHECKSUM}:
            raise StorageUnavailable("Schema incompatible")
        privileged = await self.one(c, "SELECT rolsuper,rolcreatedb,rolcreaterole,rolreplication,rolbypassrls FROM pg_roles WHERE rolname=%s", (role,))
        if not privileged or any(privileged.values()):
            raise StorageUnavailable("Rôle application privilégié")
        db = await self.one(c, "SELECT has_database_privilege(%s,current_database(),'CREATE') OR has_database_privilege(%s,current_database(),'TEMP') bad, has_database_privilege(%s,current_database(),'CONNECT') usable", (role,)*3)
        if db["bad"] or not db["usable"]:
            raise StorageUnavailable("Privilèges base application invalides")
        public = await self.one(c, "SELECT EXISTS(SELECT 1 FROM pg_database d, LATERAL aclexplode(COALESCE(d.datacl,acldefault('d',d.datdba))) a WHERE d.datname=current_database() AND a.grantee=0) bad")
        if public["bad"]:
            raise StorageUnavailable("Privilèges base PUBLIC non retirés")
        schema = await self.one(c, "SELECT has_schema_privilege(%s,%s,'CREATE') bad, has_schema_privilege(%s,%s,'USAGE') usable", (role,self.s.files_pg_schema)*2)
        if schema["bad"] or not schema["usable"]:
            raise StorageUnavailable("Privilèges schéma application invalides")
        members = await self.one(c, "SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname<>%s AND pg_has_role(%s,oid,'MEMBER')) bad", (role,role))
        if members["bad"]:
            raise StorageUnavailable("Membership application interdite")
        public_create = await self.one(c, "SELECT EXISTS(SELECT 1 FROM pg_namespace WHERE nspname NOT LIKE 'pg_temp_%%' AND has_schema_privilege(%s,oid,'CREATE')) bad", (role,))
        if public_create["bad"]:
            raise StorageUnavailable("CREATE schéma accessible à app")
        owner_role = await self.one(c, "SELECT rolcanlogin,rolsuper,rolcreatedb,rolcreaterole,rolreplication,rolbypassrls FROM pg_roles WHERE rolname=%s", (self.s.files_pg_owner,))
        if not owner_role or any(owner_role.values()):
            raise StorageUnavailable("Owner NOLOGIN non privilégié requis")
        permissions = ["SELECT","INSERT","UPDATE","DELETE","TRUNCATE","REFERENCES","TRIGGER"]
        for table, allowed in TABLE_PRIVILEGES.items():
            qualified = self.s.files_pg_schema + "." + table
            rows = await (await c.execute("SELECT p,has_table_privilege(%s,%s,p) allowed,has_table_privilege(%s,%s,p || ' WITH GRANT OPTION') delegable FROM unnest(%s::text[]) p", (role,qualified,role,qualified,permissions))).fetchall()
            if any(r["allowed"] != (r["p"] in allowed.split(", ")) or r["delegable"] for r in rows):
                raise StorageUnavailable("Grants application incompatibles")
            owner = await self.one(c, "SELECT pg_get_userbyid(relowner) owner, EXISTS(SELECT 1 FROM aclexplode(COALESCE(relacl,acldefault('r',relowner))) a WHERE a.grantee=0) public FROM pg_class WHERE oid=%s::regclass", (qualified,))
            if owner["owner"] != self.s.files_pg_owner or owner["public"]:
                raise StorageUnavailable("Owner/PUBLIC table incompatibles")
        trigger = await self.one(c, "SELECT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='operations'::regclass AND tgname='immutable_operation' AND tgenabled='O') ok")
        if not trigger["ok"]:
            raise StorageUnavailable("Garde SQL absente")

    async def infrastructure(self, c, bound=None):
        # Fonction étroite fournie par opérateur/DBaaS : pas de pg_monitor accordé à app.
        r = await self.one(c, "SELECT files_infrastructure() AS proof")
        p = r["proof"]
        s = self.s
        if not isinstance(p, dict) or str(p.get("system_identifier")) != s.files_pg_system_identifier or p.get("timeline") != s.files_pg_timeline or p.get("recovery") is not False or p.get("fsync") is not True:
            raise StorageUnavailable("Cluster/epoch/durabilité invalides")
        actual = await self.one(c, "SHOW synchronous_commit")
        if next(iter(actual.values())) != ("remote_apply" if s.files_durability == "remote_apply" else "on"):
            raise StorageUnavailable("Durabilité session invalide")
        if s.files_durability == "local":
            return p
        names = "ANY " + str(s.files_quorum) + " (" + ",".join(m["name"] for m in self.roster) + ")"
        if re.sub(r"\s+", "", p.get("standby_names", "")) != re.sub(r"\s+", "", names):
            raise StorageUnavailable("Politique quorum effective invalide")
        eligible = []
        seen = set()
        for configured in self.roster:
            matches = [m for m in p.get("members", []) if all(m.get(k) == configured[k] for k in ("name", "role", "address", "slot", "dn"))]
            if len(matches) != 1:
                continue
            m = matches[0]
            # Probe opérateur doit attester HBA/cert et exclusivité du slot, pas seulement application_name.
            if m.get("authenticated") is not True or m.get("state") != "streaming" or m.get("sync_state") != "quorum" or not m.get("replay_lsn") or m.get("pid") in seen:
                continue
            if bound is not None:
                replay = await self.one(c, "SELECT %s::pg_lsn >= %s::pg_lsn ok", (m["replay_lsn"], bound))
                if not replay["ok"]:
                    continue
            seen.add(m["pid"])
            eligible.append(configured["id"])
        if len(eligible) < s.files_quorum:
            raise StorageUnavailable("Quorum authentifié non disponible")
        return {**p, "eligible": eligible}

    @asynccontextmanager
    async def transaction(self, c):
        # Aucun COMMIT contextuel automatique et aucun replay après résultat inconnu.
        await c.execute("BEGIN ISOLATION LEVEL READ COMMITTED")
        c._tools_notices.clear()
        try:
            yield
        except BaseException:
            try:
                await c.execute("ROLLBACK")
            except Exception:
                pass
            raise
        try:
            await c.execute("COMMIT")
            if c._tools_notices:
                raise CommitUnknown("COMMIT diagnostic inconnu")
            # L'installation ne peut pas dépendre de la probe pas encore créée.
            if not getattr(c, "_tools_operator", False):
                await self.infrastructure(c)
            if c._tools_notices:
                raise CommitUnknown("Diagnostic inconnu après contrôle COMMIT")
        except BaseException as e:
            if isinstance(e, asyncio.CancelledError):
                raise
            raise CommitUnknown("COMMIT/barrière non confirmés ; inspection requise") from None

    async def lock(self, c, operation_id):
        row = await self.one(c, "SELECT * FROM operations WHERE id=%s FOR UPDATE", (operation_id,))
        if row is None:
            raise Conflict("Opération inconnue")
        return row

    async def receipt(self, c, oid, kind, detail):
        from psycopg.types.json import Jsonb
        rid = str(uuid.uuid4())
        await c.execute("INSERT INTO receipts(id,operation,kind,detail) VALUES(%s,%s,%s,%s)", (rid, oid, kind, Jsonb(detail)))
        return rid

    async def barrier(self, c, oid, kind="barrier"):
        rid = await self.receipt(c, oid, kind, {"policy_digest": self.policy})
        return rid

    async def verify_barrier(self, c, oid, rid):
        before = await self.infrastructure(c)
        b = await self.one(c, "SELECT pg_current_wal_flush_lsn()::text bound")
        bound = b["bound"]
        deadline = time.monotonic() + 2
        while True:
            try:
                proof = await self.infrastructure(c, bound)
                break
            except StorageUnavailable:
                if time.monotonic() >= deadline:
                    raise CommitUnknown("Barrière quorum pending") from None
                await asyncio.sleep(.05)
        if (str(before["system_identifier"]), before["timeline"]) != (str(proof["system_identifier"]), proof["timeline"]):
            raise CommitUnknown("Epoch de barrière changé")
        receipt = await self.one(c, "SELECT id FROM receipts WHERE id=%s AND operation=%s", (rid, oid))
        if receipt is None:
            raise CommitUnknown("Barrière non relisible")
        if c._tools_notices:
            raise CommitUnknown("Diagnostic inconnu pendant preuve de barrière")
        return {"barrier_id": rid, "policy_digest": self.policy, "wal_bound": bound,
                "timeline": proof["timeline"], "members": proof.get("eligible", []), "scope": self.s.files_durability}
