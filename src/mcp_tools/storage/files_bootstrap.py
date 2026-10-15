"""Installation explicite du seul schéma Tools ; --check ne produit aucun DDL."""
import argparse
import asyncio
import re

from ..config import get_settings
from .files_credentials import StorageUnavailable
from .files_postgres import Catalog
from .files_schema import CHECKSUM, DDL, TABLE_PRIVILEGES, VERSION


async def install(args):
    from psycopg import sql
    s = get_settings().model_copy(update={"files_pg_schema":args.schema})
    cat = Catalog(s)
    # En Vault, le job utilise son scope/secret propre par FILES_PG_ROLE et FILES_VAULT_PATH.
    service = args.operator_service if s.files_credentials_mode=="direct" else None
    for name in (args.schema,args.app_role,s.files_pg_owner):
        if not re.fullmatch(r"[a-z][a-z0-9_]{0,62}",name):
            raise StorageUnavailable("Identifiant SQL invalide")
    async with cat.connection(service=service,operator=True) as c:
        owner = await cat.one(c,"SELECT rolcanlogin,rolsuper,rolcreatedb,rolcreaterole,rolreplication,rolbypassrls FROM pg_roles WHERE rolname=%s",(s.files_pg_owner,))
        app = await cat.one(c,"SELECT rolcanlogin,rolsuper,rolcreatedb,rolcreaterole,rolreplication,rolbypassrls FROM pg_roles WHERE rolname=%s",(args.app_role,))
        if not owner or any(owner.values()) or not app or not app["rolcanlogin"] or any(v for k,v in app.items() if k!="rolcanlogin"):
            raise StorageUnavailable("Rôles opérateur/application incompatibles")
        exists = await cat.one(c,"SELECT EXISTS(SELECT 1 FROM pg_namespace WHERE nspname=%s) present",(args.schema,))
        if args.check:
            if not exists["present"]:
                raise StorageUnavailable("Schéma absent")
            row = await cat.one(c,sql.SQL("SELECT version,checksum FROM {}.schema_version WHERE singleton").format(sql.Identifier(args.schema)))
            if row!={"version":VERSION,"checksum":CHECKSUM}:
                raise StorageUnavailable("Schéma incompatible")
            await cat.check_schema(c,role=args.app_role)
            await cat.infrastructure(c)
            return {"status":"ok","action":"check","version":VERSION,"checksum":CHECKSUM}
        if exists["present"]:
            raise StorageUnavailable("Schéma existant : utiliser --check, aucun replay installation")
        # Verrou de migration + nouveau schéma, jamais conversion d'un schéma inconnu.
        async with cat.transaction(c):
            await c.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s,0))",("tools-files-install:"+args.schema,))
            await c.execute(sql.SQL("SET LOCAL ROLE {}").format(sql.Identifier(s.files_pg_owner)))
            await c.execute(sql.SQL("CREATE SCHEMA {} AUTHORIZATION {}").format(sql.Identifier(args.schema),sql.Identifier(s.files_pg_owner)))
            await c.execute(sql.SQL("SET LOCAL search_path TO {}, pg_catalog").format(sql.Identifier(args.schema)))
            await c.execute(DDL,prepare=False)
            await c.execute("INSERT INTO schema_version VALUES(true,%s,%s)",(VERSION,CHECKSUM))
            await c.execute(sql.SQL("REVOKE ALL ON SCHEMA {} FROM PUBLIC").format(sql.Identifier(args.schema)))
            await c.execute(sql.SQL("GRANT USAGE ON SCHEMA {} TO {}").format(sql.Identifier(args.schema),sql.Identifier(args.app_role)))
            await c.execute(sql.SQL("REVOKE ALL ON ALL TABLES IN SCHEMA {} FROM PUBLIC").format(sql.Identifier(args.schema)))
            await c.execute(sql.SQL("REVOKE ALL ON ALL FUNCTIONS IN SCHEMA {} FROM PUBLIC").format(sql.Identifier(args.schema)))
            for table,privileges in TABLE_PRIVILEGES.items():
                await c.execute(sql.SQL("GRANT {} ON {}.{} TO {}").format(sql.SQL(privileges),sql.Identifier(args.schema),sql.Identifier(table),sql.Identifier(args.app_role)))
            await c.execute(sql.SQL("ALTER DEFAULT PRIVILEGES IN SCHEMA {} REVOKE ALL ON TABLES FROM PUBLIC").format(sql.Identifier(args.schema)))
            await c.execute(sql.SQL("ALTER DEFAULT PRIVILEGES IN SCHEMA {} REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC").format(sql.Identifier(args.schema)))
        return {"status":"ok","action":"apply","version":VERSION,"checksum":CHECKSUM,
                "next":"installer la probe infrastructure opérateur, retirer membership temporaire puis --check et /ready app"}


def main():
    import json
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--operator-service",default="tools-install")
    parser.add_argument("--app-role",default="tools_files_app")
    parser.add_argument("--schema",default="tools_files")
    group=parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--check",action="store_true")
    group.add_argument("--apply",action="store_true")
    args=parser.parse_args()
    try:
        result=asyncio.run(install(args))
    except Exception:
        result={"status":"incomplete","message":"Installation/contrôle non confirmé ; vérifier cible/schema/grants sous identité autorisée, aucun replay implicite"}
    print(json.dumps(result))
    raise SystemExit(0 if result["status"]=="ok" else 1)


if __name__=="__main__":
    main()
