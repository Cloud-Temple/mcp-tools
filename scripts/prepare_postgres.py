"""Tools-only offline operator preparation. Never imported by the MCP runtime.

Each credential profile contains paths/identity, never a SQL password. Vault is
read with the job's own scope. Role jobs emit private SCRAM verifiers; the
provisioner does not need permission to read application passwords.
"""
import argparse
import asyncio
import base64
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys
from types import SimpleNamespace
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from src.mcp_tools.storage.files_credentials import Credentials, private_text

LOGIN = ('tools_files_app', 'tools_files_install', 'tools_files_backup', 'tools_files_restore',
         'tools_files_maintenance', 'tools_access_app', 'tools_access_install', 'tools_access_maintenance')
OWNERS = ('tools_files_owner', 'tools_access_owner')
PROFILE_KEYS = {'database', 'user', 'hosts', 'pg_ca_file', 'vault_url', 'vault_id',
                'vault_path', 'vault_token_file', 'vault_ca_file'}
SCRAM = re.compile(r'SCRAM-SHA-256\$4096:[A-Za-z0-9+/]{22}==\$[A-Za-z0-9+/]{43}=:[A-Za-z0-9+/]{43}=')


class Refused(ValueError):
    """Public diagnostics never include a credential, conninfo or server error."""


def identifier(value):
    if not isinstance(value, str) or not re.fullmatch(r'[a-z][a-z0-9_]{0,62}', value):
        raise Refused('Invalid Tools identifier')
    return value


def hosts(value):
    if not isinstance(value, str) or not value:
        raise Refused('Explicit target hosts required')
    result = value.split(',')
    if len(result) != len(set(result)) or any(not re.fullmatch(r'[A-Za-z0-9_.:-]+', part) for part in result):
        raise Refused('Invalid target hosts')
    return result


def private_directory(path):
    path = Path(path)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise Refused('Existing owned private directory0700 required')
    return path


def write_new(path, content, mode=0o600):
    path = Path(path)
    private_directory(path.parent)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as output:
        output.write(content.encode() if isinstance(content, str) else content)
        output.flush()
        os.fsync(output.fileno())
    directory = os.open(path.parent, os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def profile(path):
    result = json.loads(private_text(str(path)))
    if not isinstance(result, dict) or set(result) != PROFILE_KEYS:
        raise Refused('Exact private job profile required; no password field')
    identifier(result['database'])
    identifier(result['user'])
    hosts(result['hosts'])
    if any(not isinstance(result[key], str) or not result[key] for key in PROFILE_KEYS):
        raise Refused('Complete job profile required')
    endpoint=urlparse(result['vault_url'])
    if endpoint.scheme!='https' or not endpoint.hostname or endpoint.username or endpoint.password or endpoint.query or endpoint.fragment:
        raise Refused('Vault HTTPS endpoint without embedded credentials required')
    if any(not Path(result[key]).is_absolute() for key in ('pg_ca_file','vault_ca_file','vault_token_file')):
        raise Refused('Explicit absolute credential/CA paths required')
    return result


async def credential(job):
    # This operator's all-Vault jobs do not accept ambient libpq parameters.
    if 'PGSERVICE' in os.environ or any(k.startswith('PG') and v for k, v in os.environ.items()):
        raise Refused('Run operator jobs in an isolated environment without PG variables')
    settings = SimpleNamespace(files_credentials_mode='vault', files_pg_database=job['database'],
        files_pg_role=job['user'], files_vault_url=job['vault_url'], files_vault_id=job['vault_id'],
        files_vault_path=job['vault_path'], files_vault_token_file=job['vault_token_file'],
        files_vault_ca_file=job['vault_ca_file'], files_connect_timeout=2)
    value = await Credentials(settings).sql()
    if (set(value) != {'host', 'port', 'dbname', 'user', 'password'}
            or set(hosts(value['host'])) != set(hosts(job['hosts']))
            or value['dbname'] != job['database'] or value['user'] != job['user']
            or type(value['port']) is not int or value['port'] != 5432):
        raise Refused('Job credential target differs')
    strong_password(value['password'])
    return value


def strong_password(password):
    # Generated ASCII secrets avoid an implicit/inconsistent SASLprep policy.
    if not isinstance(password, str) or not 32 <= len(password) <= 256 or any(not 33 <= ord(c) <= 126 for c in password):
        raise Refused('Vault must supply a generated 32–256 character ASCII password')
    return password


def scram_verifier(password):
    password = strong_password(password)
    salt = secrets.token_bytes(16)
    salted = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 4096)
    stored = hashlib.sha256(hmac.digest(salted, b'Client Key', 'sha256')).digest()
    server = hmac.digest(salted, b'Server Key', 'sha256')
    b64 = lambda value: base64.b64encode(value).decode('ascii')
    return f'SCRAM-SHA-256$4096:{b64(salt)}${b64(stored)}:{b64(server)}'


async def role_verifier(job, destination):
    if job['user'] not in LOGIN:
        raise Refused('One canonical Tools LOGIN role per scoped job required')
    value = await credential(job)
    result = {'role': job['user'], 'database': job['database'], 'hosts': job['hosts'],
              'verifier': scram_verifier(value['password'])}
    write_new(destination, json.dumps(result) + '\n')


async def initial_password(job, destination, server_uid):
    if type(server_uid) is not int or server_uid<0:
        raise Refused('Measured PG UID required for the initial password file')
    if job['user'] != 'tools_prepare' or job['database'] != 'postgres':
        raise Refused('Only local initial provisioner scope accepted')
    value = await credential(job)
    write_new(destination, strong_password(value['password']) + '\n')
    os.chown(destination,server_uid,-1)


def runtime_config(files, access, system_identifier, timeline, destination):
    if (files['user']!='tools_files_app' or access['user']!='tools_access_app'
            or files['database']!=access['database'] or files['hosts']!=access['hosts']
            or files['pg_ca_file']!=access['pg_ca_file'] or files['vault_ca_file']!=access['vault_ca_file']
            or not isinstance(system_identifier,str) or not re.fullmatch(r'[0-9]+',system_identifier)
            or type(timeline) is not int or timeline<1):
        raise Refused('Exact app identities, common endpoint/CA and inspected cluster required')
    values=job_environment(files,system_identifier,timeline)
    # Only these product settings are written: do not copy ambient secrets.
    values={k:v for k,v in values.items() if k.startswith(('FILES_','ACCESS_','HUB_'))}
    for suffix,key in [('URL','vault_url'),('ID','vault_id'),('PATH','vault_path'),
                       ('TOKEN_FILE','vault_token_file'),('CA_FILE','vault_ca_file')]:
        values['ACCESS_VAULT_'+suffix]=access[key]
    values.update(ACCESS_PG_ROLE=access['user'], ACCESS_PG_HOSTS=access['hosts'],
        TOOLS_PG_CA_FILE=files['pg_ca_file'], TOOLS_VAULT_CA_FILE=files['vault_ca_file'],
        TOOLS_FILES_VAULT_TOKEN_FILE=files['vault_token_file'],
        TOOLS_ACCESS_VAULT_TOKEN_FILE=access['vault_token_file'])
    def quoted(value):
        if not isinstance(value,str) or any(ord(c)<32 for c in value):
            raise Refused('Invalid configuration value')
        return "'"+value.replace('\\','\\\\').replace("'","\\'")+"'"
    write_new(destination,''.join(f'{name}={quoted(value)}\n' for name,value in sorted(values.items())))


def hba(database):
    database=identifier(database)
    if database in ('postgres','template0','template1'):
        raise Refused('Dedicated Tools database required')
    return ('local all tools_prepare scram-sha-256\n'
            'hostssl postgres tools_prepare 127.0.0.1/32 scram-sha-256\n'
            'hostssl postgres tools_prepare ::1/128 scram-sha-256\n'
            f'hostssl {database} tools_prepare,{",".join(LOGIN)} 0.0.0.0/0 scram-sha-256\n'
            f'hostssl {database} tools_prepare,{",".join(LOGIN)} ::/0 scram-sha-256\n'
            'host all all 0.0.0.0/0 reject\nhost all all ::/0 reject\n')


@asynccontextmanager
async def connection(job, expected_system_identifier=None):
    import psycopg
    from psycopg.rows import dict_row
    value = await credential(job)  # fresh Vault authorization before any SQL
    c = await psycopg.AsyncConnection.connect(**value, autocommit=True, sslmode='verify-full',
        sslrootcert=job['pg_ca_file'], target_session_attrs='read-write', connect_timeout=2,
        row_factory=dict_row, options='-c statement_timeout=5000 -c lock_timeout=3000')
    try:
        row = await (await c.execute('SELECT current_user AS role,current_database() AS db,pg_is_in_recovery() AS recovery,'
            '(SELECT system_identifier::text FROM pg_control_system()) AS system_identifier,'
            '(SELECT timeline_id FROM pg_control_checkpoint()) AS timeline')).fetchone()
        if (row['role'] != job['user'] or row['db'] != job['database'] or row['recovery']
                or expected_system_identifier is not None and row['system_identifier'] != expected_system_identifier):
            raise Refused('Operator identity or cluster differs')
        yield c, row
    finally:
        await c.close()


async def provision(admin, target, database, verifier_directory, state_directory, system_identifier):
    from psycopg import sql
    database = identifier(database)
    if database in ('postgres', 'template0', 'template1') or admin['database'] != 'postgres' or target['database'] != database:
        raise Refused('New dedicated Tools database required')
    if admin['user'] != target['user'] or set(hosts(admin['hosts'])) != set(hosts(target['hosts'])):
        raise Refused('Provisioner profiles must describe the same role and endpoints')
    if admin['user'] in LOGIN+OWNERS:
        raise Refused('Provisioner must be separate from product roles')
    if not re.fullmatch(r'[0-9]+', system_identifier):
        raise Refused('Inspect and supply the actual system identifier first')
    directory = private_directory(verifier_directory)
    state = private_directory(state_directory)
    if (state/'prepare.pending.json').exists():
        raise Refused('Previous preparation exists; inspect without replay')
    verifiers = {}
    for name in LOGIN:
        item = json.loads(private_text(str(directory/(name+'.json'))))
        if (set(item) != {'role','database','hosts','verifier'} or item['role'] != name
                or item['database'] != database or not SCRAM.fullmatch(item['verifier'])):
            raise Refused('Exact scoped role verifier required')
        hosts(item['hosts'])
        verifiers[name] = item['verifier']
    await credential(target)  # authorize target scope before the first mutation
    async with connection(admin, system_identifier) as (c, observed):
        if await (await c.execute('SELECT rolname FROM pg_roles WHERE rolname=ANY(%s)', (list(LOGIN+OWNERS),))).fetchall():
            raise Refused('Tools role collision; no reset or adoption')
        if await (await c.execute('SELECT datname FROM pg_database WHERE datname=%s', (database,))).fetchone():
            raise Refused('Database exists; no migration or adoption')
        write_new(state/'prepare.pending.json', json.dumps({'database':database, 'system_identifier':system_identifier,
                                                           'state':'outcome_requires_inspection'})+'\n')
        async with c.transaction():
            for name in OWNERS:
                await c.execute(sql.SQL('CREATE ROLE {} NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS').format(sql.Identifier(name)))
            for name, verifier in verifiers.items():
                # Only a client-derived verifier reaches DDL; no plaintext password.
                await c.execute(sql.SQL('CREATE ROLE {} LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD {}').format(sql.Identifier(name), sql.Literal(verifier)))
            for owner in OWNERS:
                await c.execute(sql.SQL('GRANT {} TO {} WITH INHERIT FALSE, SET TRUE').format(sql.Identifier(owner),sql.Identifier(admin['user'])))
        await c.execute(sql.SQL('CREATE DATABASE {} OWNER tools_files_owner TEMPLATE template0 ALLOW_CONNECTIONS false').format(sql.Identifier(database)))
        await c.execute(sql.SQL('REVOKE ALL ON DATABASE {} FROM PUBLIC').format(sql.Identifier(database)))
        for name in ('tools_files_app','tools_files_install','tools_access_app','tools_access_install',
                     'tools_access_maintenance','tools_files_backup',admin['user']):
            await c.execute(sql.SQL('GRANT CONNECT ON DATABASE {} TO {}').format(sql.Identifier(database),sql.Identifier(name)))
        await c.execute(sql.SQL('GRANT CREATE ON DATABASE {} TO tools_access_owner').format(sql.Identifier(database)))
        for owner, installer in zip(OWNERS, ('tools_files_install','tools_access_install')):
            await c.execute(sql.SQL('GRANT {} TO {} WITH INHERIT FALSE, SET TRUE').format(sql.Identifier(owner),sql.Identifier(installer)))
        await c.execute(sql.SQL('ALTER DATABASE {} ALLOW_CONNECTIONS true').format(sql.Identifier(database)))
    async with connection(target, system_identifier) as (c, observed):
        await c.execute('REVOKE CREATE ON SCHEMA public FROM PUBLIC')
        for name in ('tools_files_install','tools_access_install','tools_files_backup','tools_files_restore'):
            await c.execute(sql.SQL('GRANT EXECUTE ON FUNCTION pg_catalog.pg_control_system(), pg_catalog.pg_control_checkpoint() TO {}').format(sql.Identifier(name)))
    write_new(state/'prepare.done.json', json.dumps({'database':database, 'system_identifier':system_identifier,
                'timeline':observed['timeline'], 'state':'roles_only_install_required'})+'\n')


def job_environment(job, system_identifier, timeline):
    # Child process only: never mutate the running process or pass raw passwords.
    values = {k:os.environ[k] for k in ('PATH','LANG','LC_ALL','SYSTEMROOT','TMPDIR') if k in os.environ}
    for prefix in ('FILES','ACCESS'):
        values.update({prefix+'_VAULT_URL':job['vault_url'], prefix+'_VAULT_ID':job['vault_id'],
            prefix+'_VAULT_PATH':job['vault_path'], prefix+'_VAULT_TOKEN_FILE':job['vault_token_file'],
            prefix+'_VAULT_CA_FILE':job['vault_ca_file'], prefix+'_PG_CA_FILE':job['pg_ca_file'],
            prefix+'_PG_ROLE':job['user'], prefix+'_PG_DATABASE':job['database']})
    values.update(FILES_METADATA_BACKEND='postgres', FILES_CREDENTIALS_MODE='vault', ACCESS_BACKEND='postgres',
        ACCESS_PG_HOSTS=job['hosts'], FILES_PG_SYSTEM_IDENTIFIER=system_identifier,
        FILES_PG_TIMELINE=str(timeline), FILES_DURABILITY='local', FILES_PG_SCHEMA='tools_files',
        FILES_PG_OWNER='tools_files_owner', ACCESS_PG_OWNER='tools_access_owner',
        FILES_RECOVERY_ENABLED='false', FILES_MISSION_DEPENDENCIES_ENABLED='false',
        ACCESS_MISSION_RETENTION_ENABLED='false', HUB_ACTIVITY_ENABLED='false')
    return values


async def public_job(job, system_identifier, timeline, module, args):
    process = await asyncio.create_subprocess_exec(sys.executable,'-m',module,*args,cwd=ROOT,
        env=job_environment(job,system_identifier,timeline),stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    try:
        output,_ = await asyncio.wait_for(process.communicate(),60)
    except BaseException:
        if process.returncode is None:
            process.kill()
        await process.wait()
        raise
    try:
        ok = process.returncode == 0 and json.loads(output)['status'] == 'ok'
    except (ValueError, KeyError, TypeError):
        ok = False
    if not ok:
        raise Refused('Public operator job unconfirmed; inspect without replay')


async def install(files, access, provisioner, system_identifier, timeline, state_directory, token_file, tenant_id, service_id):
    private_directory(state_directory)
    if not isinstance(system_identifier,str) or not re.fullmatch(r'[0-9]+',system_identifier) or type(timeline) is not int or timeline<1:
        raise Refused('Observed cluster identity and timeline required')
    if any(not isinstance(value,str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}',value) for value in (tenant_id,service_id)):
        raise Refused('Explicit bootstrap tenant and service required')
    if (Path(state_directory)/'install.pending.json').exists():
        raise Refused('Previous installation exists; use verification/inspection, not replay')
    if files['user'] != 'tools_files_install' or access['user'] != 'tools_access_install' or files['database'] != access['database'] or provisioner['database'] != files['database']:
        raise Refused('Separate canonical installer profiles on one Tools database required')
    private_directory(Path(token_file).parent)
    if Path(token_file).exists():
        raise Refused('New private bootstrap token file required')
    # Probe and authorize all three job targets before the first mutating job.
    for job in (provisioner,files,access):
        async with connection(job,system_identifier) as (_, observed):
            if observed['timeline'] != timeline:
                raise Refused('Timeline differs from operator inspection')
    write_new(Path(state_directory)/'install.pending.json', json.dumps({'state':'inspect_before_retry'})+'\n')
    await public_job(files,system_identifier,timeline,'src.mcp_tools.storage.files_bootstrap',['--apply'])
    async with connection(provisioner,system_identifier) as (c,_):
        await c.execute((ROOT/'docs/postgres/infrastructure.sql').read_text(),prepare=False)
        await c.execute('GRANT USAGE ON SCHEMA tools_files TO tools_files_backup')
        await c.execute('GRANT SELECT ON ALL TABLES IN SCHEMA tools_files TO tools_files_backup')
    await public_job(files,system_identifier,timeline,'src.mcp_tools.storage.files_bootstrap',['--check'])
    for action in ('install','verify','bootstrap'):
        args=[action]
        if action=='bootstrap':
            args+=['--tenant-id',tenant_id,'--service-id',service_id,'--token-file',str(token_file)]
        await public_job(access,system_identifier,timeline,'src.mcp_tools.auth.postgres_operator',args)
    async with connection(provisioner,system_identifier) as (c,_):
        for owner, installer in zip(OWNERS,('tools_files_install','tools_access_install')):
            await c.execute(f'REVOKE {owner} FROM {installer}')  # fixed product identifiers
            await c.execute(f'ALTER ROLE {installer} NOLOGIN')
            from psycopg import sql
            await c.execute(sql.SQL('REVOKE CONNECT ON DATABASE {} FROM {}').format(sql.Identifier(files['database']),sql.Identifier(installer)))
        from psycopg import sql
        await c.execute(sql.SQL('REVOKE CREATE ON DATABASE {} FROM tools_access_owner').format(sql.Identifier(files['database'])))
        for owner in OWNERS:
            await c.execute(sql.SQL('REVOKE {} FROM {}').format(sql.Identifier(owner),sql.Identifier(provisioner['user'])))
    write_new(Path(state_directory)/'install.done.json', json.dumps({'state':'operators_confirmed_readiness_required'})+'\n')


def certificates(directory, names, server_uid, renew=False):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
    directory=private_directory(directory)
    names=hosts(names)
    now=datetime.now(timezone.utc)
    if (directory/'server.crt').exists() and not renew:
        raise Refused('Certificate exists; inspect validity, use explicit renewal')
    if (directory/'ca.key').exists():
        ca_key=serialization.load_pem_private_key(private_text(str(directory/'ca.key')).encode(),None)
        ca=x509.load_pem_x509_certificate((directory/'ca.crt').read_bytes())
        if ca_key.public_key().public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo) != ca.public_key().public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo):
            raise Refused('Existing CA key/certificate differ')
        if ca.not_valid_after_utc <= now+timedelta(days=397):
            raise Refused('CA rotation required before leaf renewal')
    else:
        if renew:
            raise Refused('Renewal requires the existing CA')
        ca_key=ec.generate_private_key(ec.SECP256R1())
        subject=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'Tools local operator CA')])
        ca=x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(ca_key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(minutes=5)).not_valid_after(now+timedelta(days=3650)).add_extension(x509.BasicConstraints(ca=True,path_length=0),critical=True).sign(ca_key,hashes.SHA256())
        write_new(directory/'ca.key',ca_key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
        write_new(directory/'ca.crt',ca.public_bytes(serialization.Encoding.PEM),0o644)
    if renew:
        key=serialization.load_pem_private_key((directory/'server.key').read_bytes(),None)
    else:
        key=ec.generate_private_key(ec.SECP256R1())
    san=[]
    for name in names:
        try: san.append(x509.IPAddress(ipaddress.ip_address(name)))
        except ValueError: san.append(x509.DNSName(name))
    leaf=x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,names[0])])).issuer_name(ca.subject).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(minutes=5)).not_valid_after(now+timedelta(days=397)).add_extension(x509.SubjectAlternativeName(san),critical=False).add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),critical=False).sign(ca_key,hashes.SHA256())
    if not renew:
        write_new(directory/'server.key',key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
        os.chown(directory/'server.key',server_uid,-1)
        write_new(directory/'server.crt',leaf.public_bytes(serialization.Encoding.PEM),0o644)
    else:
        temporary=directory/'server.crt.new'
        write_new(temporary,leaf.public_bytes(serialization.Encoding.PEM),0o644)
        os.replace(temporary,directory/'server.crt')
        fd=os.open(directory,os.O_DIRECTORY)
        try: os.fsync(fd)
        finally: os.close(fd)


def check_material(token_files, ca_files, app_uid, server_key=None, server_uid=None, server_cert=None, expected_hosts=None):
    import ssl
    for filename in token_files:
        info=Path(filename).lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or info.st_uid!=app_uid or not 0<info.st_size<=65536:
            raise Refused('App bearer must be a private regular file owned by the measured app UID')
    for filename in ca_files:
        info=Path(filename).lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o022:
            raise Refused('Read-only trusted CA file required')
        ssl.create_default_context(cafile=str(filename))
    if server_key is not None:
        info=Path(server_key).lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or info.st_uid!=server_uid:
            raise Refused('Server private key owner must match the measured PG UID')
    if server_cert is not None:
        from cryptography import x509
        cert=x509.load_pem_x509_certificate(Path(server_cert).read_bytes())
        now=datetime.now(timezone.utc)
        if not cert.not_valid_before_utc <= now or cert.not_valid_after_utc <= now+timedelta(days=30):
            raise Refused('Server certificate must be renewed before the 30-day margin')
        san=cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        declared=set(san.get_values_for_type(x509.DNSName))|{str(ip) for ip in san.get_values_for_type(x509.IPAddress)}
        if expected_hosts is None or not set(hosts(expected_hosts)) <= declared:
            raise Refused('Certificate SAN does not cover selected endpoints')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=('role-verifier','initial-password','runtime-config','hba','inspect','provision','install','certificates','check-material'))
    for name in ('profile','target-profile','files-profile','access-profile','output','state-dir','verifier-dir','cert-dir','token-file','server-key','server-cert'):
        parser.add_argument('--'+name,type=Path)
    parser.add_argument('--database',default='tools')
    parser.add_argument('--system-identifier')
    parser.add_argument('--timeline',type=int)
    parser.add_argument('--tenant-id')
    parser.add_argument('--service-id')
    parser.add_argument('--hosts',default='postgresql,localhost,127.0.0.1')
    parser.add_argument('--server-uid',type=int)
    parser.add_argument('--app-uid',type=int)
    parser.add_argument('--renew',action='store_true')
    parser.add_argument('--bearer-file',type=Path,action='append',default=[])
    parser.add_argument('--ca-file',type=Path,action='append',default=[])
    args=parser.parse_args()
    async def run():
        if args.action=='role-verifier': await role_verifier(profile(args.profile),args.output)
        elif args.action=='initial-password': await initial_password(profile(args.profile),args.output,args.server_uid)
        elif args.action=='runtime-config': runtime_config(profile(args.files_profile),profile(args.access_profile),args.system_identifier,args.timeline,args.output)
        elif args.action=='hba': write_new(args.output,hba(args.database),0o644)
        elif args.action=='inspect':
            async with connection(profile(args.profile)) as (_,row):
                return {key:row[key] for key in ('system_identifier','timeline','db','role')}
        elif args.action=='provision': await provision(profile(args.profile),profile(args.target_profile),args.database,args.verifier_dir,args.state_dir,args.system_identifier)
        elif args.action=='install': await install(profile(args.files_profile),profile(args.access_profile),profile(args.profile),args.system_identifier,args.timeline,args.state_dir,args.token_file,args.tenant_id,args.service_id)
        elif args.action=='certificates':
            if args.server_uid is None: raise Refused('Measured server UID required')
            certificates(args.cert_dir,args.hosts,args.server_uid,args.renew)
        else:
            if args.app_uid is None or not args.bearer_file or not args.ca_file: raise Refused('Measured UID and explicit materials required')
            check_material(args.bearer_file,args.ca_file,args.app_uid,args.server_key,args.server_uid,args.server_cert,args.hosts)
        return {}
    try:
        result=asyncio.run(asyncio.wait_for(run(),120))
    except Exception:
        print(json.dumps({'status':'incomplete','message':'Operator preparation not confirmed; preserve artifacts and inspect without replay'}))
        return 1
    print(json.dumps({'status':'ok','action':args.action,**result}))
    return 0


if __name__=='__main__':
    raise SystemExit(main())
