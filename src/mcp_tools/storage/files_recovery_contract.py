"""Exact finite recovery projection; no runtime DDL or unknown-schema fallback."""
import hashlib
import json
from pathlib import Path

from .files_credentials import StorageUnavailable
from .files_recovery_schema import DDL, render
from .files_schema import DDL as BASE_DDL

FUNCTIONS = ('guard_retirement', 'capture_retirement', 'generation_visible', 'guard_source_pins',
             'guard_operation')


async def snapshot(c, settings, *, app_role):
    from psycopg import sql

    schema, owner, maintenance = (settings.files_pg_schema, settings.files_pg_owner,
                                  settings.files_recovery_maintenance_role)
    if not maintenance or len({owner, app_role, maintenance}) != 3:
        raise StorageUnavailable('Separate recovery roles required')
    for role in (app_role, maintenance):
        row = await (await c.execute('''SELECT rolcanlogin,rolinherit,rolsuper,rolcreatedb,rolcreaterole,
            rolreplication,rolbypassrls FROM pg_roles WHERE rolname=%s''', (role,))).fetchone()
        if not row or not row['rolcanlogin'] or any(v for k, v in row.items() if k != 'rolcanlogin'):
            raise StorageUnavailable('Recovery role privileges invalid')
        membership = await (await c.execute('''SELECT EXISTS(SELECT 1 FROM pg_auth_members m
            JOIN pg_roles r ON r.oid=m.member WHERE r.rolname=%s) present''', (role,))).fetchone()
        if membership['present']:
            raise StorageUnavailable('Recovery role membership forbidden')
    owner_flags = await (await c.execute('''SELECT rolcanlogin,rolsuper,rolcreatedb,rolcreaterole,
        rolreplication,rolbypassrls FROM pg_roles WHERE rolname=%s''', (owner,))).fetchone()
    if not owner_flags or any(owner_flags.values()):
        raise StorageUnavailable('Recovery owner must be unprivileged NOLOGIN')
    owner_members = await (await c.execute('SELECT EXISTS(SELECT 1 FROM pg_auth_members '
        'WHERE member=%s::regrole) present', (owner,))).fetchone()
    if owner_members['present']:
        raise StorageUnavailable('Recovery owner membership forbidden')
    for role in (app_role, maintenance):
        databases = await (await c.execute('''SELECT EXISTS(SELECT 1 FROM pg_database
            WHERE datallowconn AND datname<>current_database()
              AND has_database_privilege(%s,oid,'CONNECT')) bad,
            has_database_privilege(%s,current_database(),'CREATE') OR
            has_database_privilege(%s,current_database(),'TEMP') write''', (role, role, role))).fetchone()
        if databases['bad'] or databases['write']:
            raise StorageUnavailable('Recovery database scope invalid')
    relation = sql.Identifier(schema, 'blob_retirements').as_string(c)
    allowed = await (await c.execute('''SELECT has_table_privilege(%s,%s,
        'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') OR
        has_any_column_privilege(%s,%s,'SELECT,INSERT,UPDATE,REFERENCES') bad''',
        (app_role, relation, app_role, relation))).fetchone()
    if allowed['bad']:
        raise StorageUnavailable('Application cannot access recovery ledger')
    namespace = await (await c.execute('SELECT oid,pg_get_userbyid(nspowner) owner FROM pg_namespace '
                                       'WHERE nspname=%s', (schema,))).fetchone()
    if namespace is None or namespace['owner'] != owner:
        raise StorageUnavailable('Recovery schema owner invalid')
    queries = {
        'relations': '''SELECT relname,relkind,relrowsecurity,relforcerowsecurity,reloptions,
            pg_get_userbyid(relowner) owner FROM pg_class WHERE relnamespace=%s ORDER BY relname''',
        'columns': '''SELECT t.relname,a.attnum,a.attname,format_type(a.atttypid,a.atttypmod) datatype,
            a.attnotnull,a.attidentity,a.attgenerated,pg_get_expr(d.adbin,d.adrelid) default_value
            FROM pg_class t JOIN pg_attribute a ON a.attrelid=t.oid
            LEFT JOIN pg_attrdef d ON d.adrelid=t.oid AND d.adnum=a.attnum WHERE t.relnamespace=%s
            AND t.relkind='r' AND a.attnum>0 AND NOT a.attisdropped ORDER BY t.relname,a.attnum''',
        'constraints': '''SELECT t.relname,k.conname,k.contype,pg_get_constraintdef(k.oid) definition,
            k.convalidated,k.condeferrable,k.condeferred FROM pg_constraint k
            JOIN pg_class t ON t.oid=k.conrelid WHERE t.relnamespace=%s ORDER BY t.relname,k.conname''',
        'indexes': '''SELECT t.relname,pg_get_indexdef(i.indexrelid) definition,i.indisvalid,i.indisready
            FROM pg_index i JOIN pg_class t ON t.oid=i.indrelid WHERE t.relnamespace=%s
            ORDER BY t.relname,i.indexrelid::regclass::text''',
        'triggers': '''SELECT t.relname,g.tgname,g.tgenabled,pg_get_triggerdef(g.oid,false) definition
            FROM pg_trigger g JOIN pg_class t ON t.oid=g.tgrelid WHERE t.relnamespace=%s
            AND NOT g.tgisinternal ORDER BY t.relname,g.tgname''',
        'policies': "SELECT tablename,policyname,permissive,roles,cmd,qual,with_check FROM pg_policies "
                    "WHERE schemaname=(SELECT nspname FROM pg_namespace WHERE oid=%s) "
                    "ORDER BY tablename,policyname",
        'rules': "SELECT c.relname,r.rulename,pg_get_ruledef(r.oid) definition FROM pg_rewrite r "
                 "JOIN pg_class c ON c.oid=r.ev_class WHERE c.relnamespace=%s ORDER BY c.relname,r.rulename",
        'types': "SELECT typname,typtype,typcategory FROM pg_type WHERE typnamespace=%s "
                 "AND typrelid=0 AND typelem=0 ORDER BY typname",
        'functions': '''SELECT proname,pg_get_function_identity_arguments(oid) arguments,provolatile,
            prosecdef,proleakproof,proconfig,prosrc,pg_get_userbyid(proowner) owner,
            format_type(prorettype,NULL) return_type FROM pg_proc WHERE pronamespace=%s
            AND proname IN ('guard_retirement','capture_retirement','generation_visible','guard_source_pins',
                            'guard_operation')
            ORDER BY proname,pg_get_function_identity_arguments(oid)''',
    }
    projection = {}
    for name, query in queries.items():
        projection[name] = await (await c.execute(query, (namespace['oid'],))).fetchall()
    rendered = render(schema, app_role, maintenance, prefix=settings.files_s3_prefix,
                      recovery_days=settings.files_recovery_days).as_string(c)
    sources = {}
    for name in FUNCTIONS:
        source = BASE_DDL if name == 'guard_operation' else rendered
        qualified = name if name == 'guard_operation' else sql.Identifier(schema).as_string(c) + '.' + name
        marker = 'CREATE FUNCTION ' + qualified + '('
        start = source.index('AS $$', source.index(marker)) + len('AS $$')
        sources[name] = source[start:source.index('$$;', start)]
    if {row['proname'] for row in projection['functions']} != set(FUNCTIONS):
        raise StorageUnavailable('Recovery routines incomplete')
    routines = await (await c.execute('SELECT proname FROM pg_proc WHERE pronamespace=%s',
                                      (namespace['oid'],))).fetchall()
    if sorted(row['proname'] for row in routines) != sorted((*FUNCTIONS, 'files_infrastructure')):
        raise StorageUnavailable('Unknown recovery namespace routine')
    for row in projection['functions']:
        if row['prosrc'] != sources[row['proname']]:
            raise StorageUnavailable('Recovery routine source drift')
        row['prosrc'] = 'BOUND_TO_RENDERED_DDL'
    # Only finite principal and renderer parameters are normalized for fresh domains.
    principals = {owner: 'OWNER', app_role: 'APP', maintenance: 'MAINTENANCE'}
    quoted = await (await c.execute('SELECT quote_ident(%s) schema,quote_literal(%s) prefix',
                                    (schema, settings.files_s3_prefix))).fetchone()
    for rows in projection.values():
        for row in rows:
            if 'owner' in row:
                if row['owner'] != owner:
                    raise StorageUnavailable('Recovery object owner drift')
                row['owner'] = 'OWNER'
            if 'definition' in row:
                row['definition'] = row['definition'].replace(quoted['prefix'], "'S3_PREFIX'")
                row['definition'] = row['definition'].replace(quoted['schema'] + '.', 'SCHEMA.')
    acl = '''SELECT name,CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END grantee,
        pg_get_userbyid(a.grantor) grantor,a.privilege_type,a.is_grantable FROM (
        SELECT 'TABLE:'||t.relname name,coalesce(t.relacl,acldefault('r',t.relowner)) acl
        FROM pg_class t WHERE t.relnamespace=%s AND t.relkind='r'
        UNION ALL SELECT 'FUNCTION:'||p.proname,coalesce(p.proacl,acldefault('f',p.proowner))
        FROM pg_proc p WHERE p.pronamespace=%s AND p.proname=ANY(%s)
        UNION ALL SELECT 'SCHEMA',coalesce(n.nspacl,acldefault('n',n.nspowner)) FROM pg_namespace n WHERE n.oid=%s
        UNION ALL SELECT 'COLUMN:'||t.relname||':'||a.attname,a.attacl FROM pg_attribute a
        JOIN pg_class t ON t.oid=a.attrelid WHERE t.relnamespace=%s AND a.attnum>0 AND NOT a.attisdropped
        ) objects CROSS JOIN LATERAL aclexplode(objects.acl) a ORDER BY 1,2,3,4,5'''
    projection['acl'] = await (await c.execute(acl, (namespace['oid'], namespace['oid'], [*FUNCTIONS, 'files_infrastructure'],
                                                   namespace['oid'], namespace['oid']))).fetchall()
    for row in projection['acl']:
        for name in ('grantee', 'grantor'):
            row[name] = principals.get(row[name], row[name])
    projection['acl'].sort(key=lambda row: json.dumps(row, sort_keys=True))
    defaults = await (await c.execute('''SELECT d.defaclobjtype,pg_get_userbyid(d.defaclrole) owner,
        CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END grantee,
        pg_get_userbyid(a.grantor) grantor,a.privilege_type,a.is_grantable
        FROM pg_default_acl d CROSS JOIN LATERAL aclexplode(d.defaclacl) a
        WHERE d.defaclnamespace=%s OR (d.defaclnamespace=0 AND d.defaclrole=%s::regrole)
        ORDER BY 1,2,3,4,5,6''', (namespace['oid'], owner))).fetchall()
    for row in defaults:
        for name in ('owner', 'grantee', 'grantor'):
            row[name] = principals.get(row[name], row[name])
    projection['defaults'] = sorted(defaults, key=lambda row: json.dumps(row, sort_keys=True))
    return projection


def expected_projection():
    try:
        expected = json.loads(Path(__file__).with_name('files_recovery_contract.json').read_text())
        if (set(expected) != {'format_version', 'ddl_sha256', 'snapshot'} or expected['format_version'] != 1
                or expected['ddl_sha256'] != hashlib.sha256(DDL.encode()).hexdigest()):
            raise StorageUnavailable('Recovery schema/ACL drift')
        return expected['snapshot']
    except (OSError, ValueError, KeyError, TypeError):
        raise StorageUnavailable('Recovery projection unavailable') from None


async def verify(c, settings, *, app_role):
    expected = expected_projection()
    if await snapshot(c, settings, app_role=app_role) != expected:
        raise StorageUnavailable('Recovery schema/ACL drift')
