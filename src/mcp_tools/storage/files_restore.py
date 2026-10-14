"""Projection opérateur fermée vers les seules identités d'une cible neuve."""
import hashlib
import json
import re

from .files_credentials import StorageUnavailable
from .files_schema import TABLE_PRIVILEGES


TABLES = set(TABLE_PRIVILEGES) | {"replication_identities"}
INDEXES = {
    "schema_version_pkey", "operations_pkey", "one_active_path", "generations_pkey",
    "generations_operation_key", "generations_path", "refs_pkey", "receipts_pkey",
    "receipts_operation", "replication_identities_pkey", "replication_identities_role_name_key",
    "replication_identities_address_key", "replication_identities_slot_key", "replication_identities_dn_key",
}


async def structure(c, schema, owner):
    """Empreinte structurelle hors owners/ACL/OID, inventaire fini avant projection."""
    namespace = await (await c.execute("SELECT pg_get_userbyid(nspowner) owner FROM pg_namespace WHERE nspname=%s", (schema,))).fetchone()
    if not namespace or namespace["owner"] != owner:
        raise StorageUnavailable("Owner schéma incompatible avec projection")
    tables = await (await c.execute(
        "SELECT relname,relkind,pg_get_userbyid(relowner) owner FROM pg_class "
        "WHERE relnamespace=(SELECT oid FROM pg_namespace WHERE nspname=%s) ORDER BY relname",
        (schema,))).fetchall()
    if ({r["relname"] for r in tables if r["relkind"] == "r"} != TABLES
            or {r["relname"] for r in tables if r["relkind"] == "i"} != INDEXES
            or any(r["relkind"] not in ("r", "i") or r["owner"] != owner for r in tables)):
        raise StorageUnavailable("Inventaire/owners Tools incompatible avec projection")
    functions = await (await c.execute(
        "SELECT p.proname,pg_get_userbyid(p.proowner) owner,pg_get_functiondef(p.oid) definition "
        "FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname=%s ORDER BY p.proname",
        (schema,))).fetchall()
    if (len(functions) != 2 or {r["proname"] for r in functions} != {"guard_operation", "files_infrastructure"}
            or any(r["owner"] != owner for r in functions)):
        raise StorageUnavailable("Fonctions Tools incompatibles avec projection")
    result = {"functions": [{k: v for k, v in r.items() if k != "owner"} for r in functions]}
    queries = {
        "columns": "SELECT c.relname,a.attname,format_type(a.atttypid,a.atttypmod) type,a.attnotnull,"
                   "a.attidentity,a.attgenerated,pg_get_expr(d.adbin,d.adrelid) expression FROM pg_attribute a "
                   "JOIN pg_class c ON c.oid=a.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace "
                   "LEFT JOIN pg_attrdef d ON d.adrelid=c.oid AND d.adnum=a.attnum "
                   "WHERE n.nspname=%s AND c.relkind='r' AND a.attnum>0 AND NOT a.attisdropped ORDER BY c.relname,a.attnum",
        "constraints": "SELECT c.relname,p.conname,pg_get_constraintdef(p.oid) definition FROM pg_constraint p "
                       "JOIN pg_class c ON c.oid=p.conrelid JOIN pg_namespace n ON n.oid=c.relnamespace "
                       "WHERE n.nspname=%s ORDER BY c.relname,p.conname",
        "indexes": "SELECT c.relname,pg_get_indexdef(c.oid) definition FROM pg_class c "
                   "JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=%s AND c.relkind='i' ORDER BY c.relname",
        "triggers": "SELECT c.relname,t.tgname,pg_get_triggerdef(t.oid) definition,t.tgenabled FROM pg_trigger t "
                    "JOIN pg_class c ON c.oid=t.tgrelid JOIN pg_namespace n ON n.oid=c.relnamespace "
                    "WHERE n.nspname=%s AND NOT t.tgisinternal ORDER BY c.relname,t.tgname",
    }
    for name, query in queries.items():
        result[name] = await (await c.execute(query, (schema,))).fetchall()
    if len(result["triggers"]) != 1 or result["triggers"][0]["tgname"] != "immutable_operation":
        raise StorageUnavailable("Triggers Tools incompatibles avec projection")
    return hashlib.sha256(json.dumps(result, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


async def target_roles(cat, c, settings, app, source_roles):
    owner, installer = settings.files_pg_owner, settings.files_pg_role
    targets = {owner, app, installer}
    if (len(targets) != 3 or targets & {r["rolname"] for r in source_roles}
            or any(not re.fullmatch(r"[a-z][a-z0-9_]{0,62}", n) for n in targets)):
        raise StorageUnavailable("Projection exige trois identités cible distinctes de Source")
    for name in targets:
        row = await cat.one(c, "SELECT rolcanlogin,rolsuper,rolcreatedb,rolcreaterole,rolreplication,rolbypassrls "
                              "FROM pg_roles WHERE rolname=%s", (name,))
        if (not row or row["rolcanlogin"] != (name != owner)
                or any(v for k, v in row.items() if k != "rolcanlogin")):
            raise StorageUnavailable("Rôle cible non borné")
    row = await cat.one(c, "SELECT pg_get_userbyid(datdba) owner FROM pg_database WHERE datname=current_database()")
    if row["owner"] != owner:
        raise StorageUnavailable("Owner cible divergent")
    # pg_database_owner est le membership implicite du seul owner de current_database(),
    # déjà vérifié ci-dessus ; PostgreSQL interdit tout grant de ce rôle ou vers lui.
    row = await cat.one(c, "SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname NOT IN (%s,'pg_database_owner') "
                          "AND pg_has_role(%s,oid,'MEMBER')) bad", (owner, owner))
    if row["bad"]:
        raise StorageUnavailable("Membership owner cible interdit")
    row = await cat.one(c, "SELECT EXISTS(SELECT 1 FROM pg_default_acl WHERE defaclrole="
                          "(SELECT oid FROM pg_roles WHERE rolname=%s)) bad", (owner,))
    if row["bad"]:
        raise StorageUnavailable("Defaults préexistants owner cible interdits")
    membership = await (await c.execute(
        "SELECT pg_get_userbyid(roleid) role,admin_option,inherit_option,set_option FROM pg_auth_members "
        "WHERE member=(SELECT oid FROM pg_roles WHERE rolname=%s)", (installer,))).fetchall()
    if membership != [{"role": owner, "admin_option": False, "inherit_option": False, "set_option": True}]:
        raise StorageUnavailable("Installer exige seulement SET owner cible")
    row = await cat.one(c, "SELECT EXISTS(SELECT 1 FROM pg_auth_members WHERE member="
                          "(SELECT oid FROM pg_roles WHERE rolname=%s)) bad", (app,))
    if row["bad"]:
        raise StorageUnavailable("Membership application cible interdit")
    for name in (app, installer):
        row = await cat.one(c, "SELECT EXISTS(SELECT 1 FROM pg_database WHERE datallowconn "
                              "AND datname<>current_database() AND has_database_privilege(%s,oid,'CONNECT')) bad", (name,))
        if row["bad"]:
            raise StorageUnavailable("Identité cible autorisée sur autre base")


async def project(cat, c, settings, app, expected):
    from psycopg import sql
    owner, schema = settings.files_pg_owner, settings.files_pg_schema
    # Le restore terminé ne vaut pas confirmation : empreinte et droits restent à vérifier.
    if await structure(c, schema, owner) != expected:
        raise StorageUnavailable("Structure restaurée divergente")
    async with cat.transaction(c):
        await c.execute(sql.SQL("SET LOCAL ROLE {}").format(sql.Identifier(owner)))
        await c.execute(sql.SQL("REVOKE ALL ON SCHEMA {} FROM PUBLIC").format(sql.Identifier(schema)))
        await c.execute(sql.SQL("GRANT USAGE ON SCHEMA {} TO {}").format(sql.Identifier(schema), sql.Identifier(app)))
        await c.execute(sql.SQL("REVOKE ALL ON ALL TABLES IN SCHEMA {} FROM PUBLIC").format(sql.Identifier(schema)))
        await c.execute(sql.SQL("REVOKE ALL ON ALL FUNCTIONS IN SCHEMA {} FROM PUBLIC").format(sql.Identifier(schema)))
        for table, privileges in TABLE_PRIVILEGES.items():
            await c.execute(sql.SQL("GRANT {} ON {}.{} TO {}").format(sql.SQL(privileges),
                            sql.Identifier(schema), sql.Identifier(table), sql.Identifier(app)))
        await c.execute(sql.SQL("GRANT EXECUTE ON FUNCTION {}.files_infrastructure() TO {}").format(
                        sql.Identifier(schema), sql.Identifier(app)))
        # Une révocation par schéma ne neutralise pas le default global EXECUTE PUBLIC.
        await c.execute("ALTER DEFAULT PRIVILEGES REVOKE ALL ON TABLES FROM PUBLIC")
        await c.execute("ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC")
        await cat.check_schema(c, role=app)
        await check_acl(c, schema, owner, app)
    async with cat.transaction(c):
        await c.execute(sql.SQL("SET LOCAL ROLE {}").format(sql.Identifier(owner)))
        await cat.check_schema(c, role=app)
        await check_acl(c, schema, owner, app)


async def check_acl(c, schema, owner, app):
    """Chaque grantee/grantor, defaults compris ; pas seulement les droits de l'app."""
    objects = await (await c.execute(
        "SELECT 'schema' kind,nspname name,nspowner owner,nspacl acl,'n'::\"char\" code FROM pg_namespace WHERE nspname=%s "
        "UNION ALL SELECT 'table',relname,relowner,relacl,'r'::\"char\" FROM pg_class "
        "WHERE relnamespace=(SELECT oid FROM pg_namespace WHERE nspname=%s) AND relkind='r' "
        "UNION ALL SELECT 'function',proname,proowner,proacl,'f'::\"char\" FROM pg_proc "
        "WHERE pronamespace=(SELECT oid FROM pg_namespace WHERE nspname=%s)", (schema,) * 3)).fetchall()
    for obj in objects:
        grants = await (await c.execute(
            "SELECT pg_get_userbyid(grantor) grantor,pg_get_userbyid(grantee) grantee,privilege_type,is_grantable "
            "FROM aclexplode(COALESCE(%s::aclitem[],acldefault(%s::\"char\",%s::oid)))",
            (obj["acl"], obj["code"], obj["owner"]))).fetchall()
        allowed = ({"USAGE"} if obj["kind"] == "schema" else
                   set(TABLE_PRIVILEGES.get(obj["name"], "").split(", ")) if obj["kind"] == "table" else
                   {"EXECUTE"} if obj["name"] == "files_infrastructure" else set())
        for grant in grants:
            if grant["grantor"] != owner or grant["grantee"] not in (owner, app):
                raise StorageUnavailable("Grantee/grantor hors contrat cible")
            if grant["grantee"] == app and (grant["is_grantable"] or grant["privilege_type"] not in allowed):
                raise StorageUnavailable("ACL application hors contrat cible")
    defaults = await (await c.execute(
        "SELECT d.defaclnamespace,d.defaclobjtype,pg_get_userbyid(a.grantor) grantor,"
        "pg_get_userbyid(a.grantee) grantee,a.privilege_type FROM pg_default_acl d "
        "CROSS JOIN LATERAL aclexplode(d.defaclacl) a WHERE d.defaclrole=(SELECT oid FROM pg_roles WHERE rolname=%s)",
        (owner,))).fetchall()
    if any(r["defaclnamespace"] != 0 or r["defaclobjtype"] != "f" or r["grantor"] != owner
           or r["grantee"] != owner or r["privilege_type"] != "EXECUTE" for r in defaults):
        raise StorageUnavailable("Defaults cible hors contrat")
