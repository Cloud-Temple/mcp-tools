"""Installer/vérifier les accès PG ; bootstrap offline et purge séparée, sans retry."""
import argparse
import asyncio
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
from uuid import uuid4

from ..config import get_settings
from .postgres_credentials import AccessCredentials
from . import postgres_retention_846 as holds846
from .postgres_schema import CHECKSUM, DDL, VERSION

PRIVILEGES = ('SELECT', 'INSERT', 'UPDATE', 'DELETE', 'TRUNCATE', 'REFERENCES', 'TRIGGER')


def role_name(value):
    if not isinstance(value, str) or not re.fullmatch(r'[a-z][a-z0-9_]{0,62}', value):
        raise ValueError('Identifiant de rôle invalide')
    return value


async def one(c, query, params=()):
    return await (await c.execute(query, params)).fetchone()


# Projection #846 limitée à l'extension et aux triggers d'activity_calls,
# requêtes reprises de files_recovery_contract.snapshot filtrées sur tools_access.
_TABLES_846 = "('activity_calls','retention_846_version','mission_retirements_846','mission_retired_refs_846')"
_PROJECTION_846 = {
    'triggers': '''SELECT t.relname,g.tgname,g.tgenabled,pg_get_triggerdef(g.oid,false) definition
        FROM pg_trigger g JOIN pg_class t ON t.oid=g.tgrelid JOIN pg_namespace n ON n.oid=t.relnamespace
        WHERE n.nspname='tools_access' AND t.relname IN ''' + _TABLES_846 + ''' AND NOT g.tgisinternal
        ORDER BY t.relname COLLATE "C",g.tgname COLLATE "C"''',
    'constraints': '''SELECT t.relname,k.conname,k.contype,pg_get_constraintdef(k.oid) definition
        FROM pg_constraint k JOIN pg_class t ON t.oid=k.conrelid JOIN pg_namespace n ON n.oid=t.relnamespace
        WHERE n.nspname='tools_access' AND t.relname IN ''' + _TABLES_846.replace("'activity_calls',", '') + '''
        ORDER BY t.relname COLLATE "C",k.conname COLLATE "C"''',
    'indexes': '''SELECT t.relname,pg_get_indexdef(i.indexrelid) definition FROM pg_index i
        JOIN pg_class t ON t.oid=i.indrelid JOIN pg_namespace n ON n.oid=t.relnamespace
        WHERE n.nspname='tools_access' AND t.relname IN ''' + _TABLES_846.replace("'activity_calls',", '') + '''
        ORDER BY t.relname COLLATE "C",i.indexrelid::regclass::text COLLATE "C"''',
    'functions': '''SELECT p.proname,p.prosecdef,p.proconfig FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
        WHERE n.nspname='tools_access' AND p.proname=ANY(%s) ORDER BY p.proname COLLATE "C"''',
}


async def projection_846(c):
    """Projection observée ; le kit PG17 l'écrit telle quelle et la compare à CATALOG."""
    await c.execute('SET LOCAL search_path=pg_catalog')
    result = {}
    for name, query in _PROJECTION_846.items():
        rows = await (await c.execute(query, (list(holds846.FUNCTIONS),) if name == 'functions' else ())).fetchall()
        result[name] = [dict(row) for row in rows]
    return result


async def verify_846(c, retention):
    """Marqueur dans les deux sens, puis projection et prosrc exacts de l'extension."""
    present = (await one(c, "SELECT to_regclass('tools_access.retention_846_version') IS NOT NULL present"))['present']
    if present != bool(retention):
        raise ValueError('Profil de rétention 846 et domaine incompatibles')
    if not retention:
        return
    if await one(c, 'SELECT version,checksum,coordination_required FROM tools_access.retention_846_version WHERE singleton') != {
            'version': holds846.VERSION, 'checksum': holds846.CHECKSUM, 'coordination_required': True}:
        raise ValueError('Marqueur de rétention 846 incompatible')
    if await projection_846(c) != holds846.CATALOG:
        raise ValueError('Projection catalogue 846 incompatible')
    sources = await (await c.execute("SELECT p.proname,p.prosrc FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace "
        "WHERE n.nspname='tools_access' AND p.proname=ANY(%s)", (list(holds846.FUNCTIONS),))).fetchall()
    if {row['proname']: row['prosrc'] for row in sources} != holds846.function_sources():
        raise ValueError('Source des routines 846 modifiée')


async def verify(c, owner, app, maintenance, *, retention=False):
    """Contrat d'ACL constaté sur la cible réelle, jamais déduit du seul DDL."""
    from psycopg import sql
    app_routines, maintenance_routines, tables = holds846.routine_profile(retention)
    if len({owner, app, maintenance}) != 3:
        raise ValueError('Rôles distincts requis')
    for name in (owner, app, maintenance):
        row = await one(c, 'SELECT rolcanlogin,rolsuper,rolcreatedb,rolcreaterole,rolreplication,rolbypassrls FROM pg_roles WHERE rolname=%s', (name,))
        if not row or row['rolcanlogin'] != (name != owner) or any(v for k, v in row.items() if k != 'rolcanlogin'):
            raise ValueError('Contrat des rôles invalide')
    await c.execute(sql.SQL('SET LOCAL ROLE {}').format(sql.Identifier(owner)))
    if await one(c, 'SELECT version,checksum FROM tools_access.schema_version WHERE singleton') != {'version': VERSION, 'checksum': CHECKSUM}:
        raise ValueError('Version du schéma incompatible')
    await verify_846(c, retention)
    for name, routines in ((app, app_routines), (maintenance, maintenance_routines)):
        if (await one(c, "SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname<>%s AND pg_has_role(%s,oid,'MEMBER')) bad", (name, name)))['bad']:
            raise ValueError('Membership runtime interdite')
        privileges = await one(c, "SELECT has_database_privilege(%s,current_database(),'CONNECT') usable,has_database_privilege(%s,current_database(),'CREATE') OR has_database_privilege(%s,current_database(),'TEMP') bad", (name, name, name))
        if not privileges['usable'] or privileges['bad']:
            raise ValueError('Droits base runtime invalides')
        if (await one(c, "SELECT EXISTS(SELECT 1 FROM pg_namespace WHERE nspname NOT LIKE 'pg_temp_%%' AND has_schema_privilege(%s,oid,'CREATE')) bad", (name,)))['bad']:
            raise ValueError('CREATE schéma runtime interdit')
        if not (await one(c, "SELECT has_schema_privilege(%s,'tools_access','USAGE') usable", (name,)))['usable']:
            raise ValueError('USAGE du schéma requis')
        allowed = set()
        for signature in routines:
            oid = (await one(c, 'SELECT to_regprocedure(%s)::oid oid', ('tools_access.'+signature,)))['oid']
            if oid is None:
                raise ValueError('Routine requise absente')
            allowed.add(oid)
        functions = await (await c.execute("SELECT p.oid,pg_get_userbyid(p.proowner) owner,has_function_privilege(%s,p.oid,'EXECUTE') allowed,has_function_privilege(%s,p.oid,'EXECUTE WITH GRANT OPTION') delegable FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='tools_access'", (name, name))).fetchall()
        if any(f['owner'] != owner or f['allowed'] != (f['oid'] in allowed) or f['delegable'] for f in functions):
            raise ValueError('Grants des routines incompatibles')
        for table in tables:
            for privilege in PRIVILEGES:
                if (await one(c, 'SELECT has_table_privilege(%s,%s,%s) bad', (name, 'tools_access.'+table, privilege)))['bad']:
                    raise ValueError('Droits directs sur les tables interdits')
    if (await one(c, "SELECT EXISTS(SELECT 1 FROM pg_database d CROSS JOIN LATERAL aclexplode(COALESCE(d.datacl,acldefault('d',d.datdba))) a WHERE d.datname=current_database() AND a.grantee=0) bad"))['bad']:
        raise ValueError('Droits PUBLIC sur la base interdits')


async def install(c, owner, app, maintenance, *, retention):
    """Domaine neuf seulement, dans la transaction de l'appelant ; 846 dans la même."""
    from psycopg import sql
    await c.execute("SELECT pg_advisory_xact_lock(hashtextextended('tools-access-install',31))")
    if (await one(c, "SELECT EXISTS(SELECT 1 FROM pg_namespace WHERE nspname='tools_access') present"))['present']:
        raise ValueError('Schéma existant : vérifier, sans replay installation')
    await c.execute(sql.SQL('SET LOCAL ROLE {}').format(sql.Identifier(owner)))
    await c.execute(DDL, prepare=False)
    await c.execute('INSERT INTO tools_access.schema_version VALUES(true,%s,%s)', (VERSION, CHECKSUM))
    if retention:
        await c.execute(holds846.DDL, prepare=False)
        await c.execute('INSERT INTO tools_access.retention_846_version VALUES(true,%s,%s,true)',
                        (holds846.VERSION, holds846.CHECKSUM))
    app_routines, maintenance_routines, _ = holds846.routine_profile(retention)
    for role, routines in ((app, app_routines), (maintenance, maintenance_routines)):
        await c.execute(sql.SQL('GRANT USAGE ON SCHEMA tools_access TO {}').format(sql.Identifier(role)))
        for signature in routines:
            await c.execute(sql.SQL('GRANT EXECUTE ON FUNCTION tools_access.'+signature+' TO {}').format(sql.Identifier(role)))
    await c.execute('ALTER DEFAULT PRIVILEGES IN SCHEMA tools_access REVOKE ALL ON TABLES FROM PUBLIC')
    await c.execute('ALTER DEFAULT PRIVILEGES IN SCHEMA tools_access REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC')


def write_token(path, raw):
    """Fichier créé uniquement après l'ACK COMMIT ; aucune valeur sur stdout."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as stream:
        stream.write(raw+'\n')
        stream.flush()
        os.fsync(stream.fileno())
    directory = os.open(path.parent, os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


async def operate(args):
    import psycopg
    from psycopg.rows import dict_row
    s = get_settings()
    retention = bool(getattr(s, 'access_mission_retention_enabled', False))
    if any(key.startswith('PG') and value for key, value in os.environ.items()):
        raise ValueError('Variables libpq ambiantes interdites')
    if s.access_backend != 'postgres' or not s.access_pg_ca_file:
        raise ValueError('Profil PG explicite et CA requis')
    owner, app, maintenance = map(role_name, (s.access_pg_owner, args.app_role, args.maintenance_role))
    if len({owner, app, maintenance}) != 3:
        raise ValueError('Rôles distincts requis')
    if args.action != 'purge' and s.access_pg_role in (owner, app, maintenance):
        raise ValueError('Identité opérateur distincte requise')
    token_path = Path(args.token_file) if args.token_file else None
    if args.action == 'bootstrap':
        if token_path is None or token_path.exists() or token_path.is_symlink():
            raise ValueError('Fichier bootstrap neuf requis')
        parent = token_path.parent.stat()
        if parent.st_uid != os.getuid() or parent.st_mode & 0o077:
            raise ValueError('Répertoire bootstrap privé requis')
        for value in (args.tenant_id, args.service_id):
            if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}', value):
                raise ValueError('Tenant et service explicites requis')
    credential = await AccessCredentials(s).sql()
    if credential['user'] != s.access_pg_role or credential['dbname'] != s.access_pg_database:
        raise ValueError('Identité SQL opérateur invalide')
    c = await psycopg.AsyncConnection.connect(**credential, autocommit=True, sslmode='verify-full',
        sslrootcert=s.access_pg_ca_file, target_session_attrs='read-write', connect_timeout=2,
        row_factory=dict_row, options='-c statement_timeout=3000 -c lock_timeout=1000 -c idle_in_transaction_session_timeout=5000')
    raw = None
    try:
        identity = await one(c, 'SELECT current_user role,current_database() db')
        if identity != {'role': s.access_pg_role, 'db': s.access_pg_database}:
            raise ValueError('Cible SQL invalide')
        if args.action == 'purge':
            if s.access_pg_role != maintenance or not 1 <= args.batch <= 500:
                raise ValueError('Identité maintenance et lot borné requis')
            routine = 'purge_expired_846' if retention else 'purge_expired'
            result = await one(c, 'SELECT * FROM tools_access.' + routine + '(%s)', (args.batch,))
            return {'status': 'ok', 'action': 'purge', **result}
        async with c.transaction():
            if args.action == 'install':
                await install(c, owner, app, maintenance, retention=retention)
            await verify(c, owner, app, maintenance, retention=retention)
            if args.action == 'bootstrap':
                await c.execute("SELECT pg_advisory_xact_lock(hashtextextended('tools-access-first-admin',31))")
                if (await one(c, 'SELECT count(*) n FROM tools_access.access_credentials'))['n']:
                    raise ValueError('Premier admin déjà initialisé ; aucune réinitialisation')
                raw = secrets.token_urlsafe(32)
                actor_id, operation_id = str(uuid4()), str(uuid4())
                binding = hashlib.sha256(raw.encode()).hexdigest()
                await c.execute("INSERT INTO tools_access.access_credentials(token_hash,actor_id,tenant_id,service_id,client_name,permissions,tool_ids,expires_at,version) VALUES(%s,%s,%s,%s,'initial-admin',ARRAY['admin'],ARRAY[]::text[],clock_timestamp()+interval '24 hours',1)",
                    (binding, actor_id, args.tenant_id, args.service_id))
                await c.execute("SELECT tools_access.record_admin(c,%s,'access_bootstrap',%s) "
                    "FROM tools_access.access_credentials c WHERE c.token_hash=%s",
                    (operation_id, actor_id, binding))
        if raw is not None:
            write_token(token_path, raw)
        return {'status': 'ok', 'action': args.action, 'schema_version': VERSION, 'checksum': CHECKSUM}
    finally:
        c.pgconn.finish()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('action', choices=('install', 'verify', 'bootstrap', 'purge'))
    p.add_argument('--app-role', default='tools_access_app')
    p.add_argument('--maintenance-role', default='tools_access_maintenance')
    p.add_argument('--token-file')
    p.add_argument('--tenant-id')
    p.add_argument('--service-id')
    p.add_argument('--batch', type=int, default=500)
    args = p.parse_args()
    async def bounded():
        async with asyncio.timeout(30):
            return await operate(args)
    try:
        result = asyncio.run(bounded())
    except Exception:
        result = {'status': 'incomplete', 'message': 'Opération non confirmée : inspecter avant toute reprise, aucun retry automatique'}
    print(json.dumps(result))
    raise SystemExit(0 if result['status'] == 'ok' else 1)


if __name__ == '__main__':
    main()
