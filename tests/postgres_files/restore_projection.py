"""Archive PG17 réelle, isolée : ne qualifie ni Vault, TLS, S3 ni service natif."""
import argparse
import asyncio
import hashlib
import io
import json
import os
import subprocess
import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import psycopg

from src.mcp_tools.config import Settings
from src.mcp_tools.storage import files_backup, files_bootstrap
from src.mcp_tools.storage.files_postgres import Catalog
from src.mcp_tools.storage.files_credentials import StorageUnavailable

IMAGE = "sha256:cae132fc01034fb8c9d1e951eeebd7b242d3e13238be3c28bb8b60b5d79abcc9"
ROOT = Path(__file__).resolve().parents[2]


def run(argv, timeout=30):
    return subprocess.run(argv, check=True, capture_output=True, text=True, timeout=timeout).stdout.strip()


def connect(socket, database="postgres", user="postgres"):
    return psycopg.connect(host=str(socket), dbname=database, user=user, autocommit=True,
                           connect_timeout=2, options="-c statement_timeout=5000 -c lock_timeout=3000")


def cause(error):
    while error.__context__ is not None:
        error = error.__context__
    return error


async def exercise(socket, folder, name, check_stage="both"):
    observed_roles = []
    readonly_checks = []

    class FixtureCatalog(Catalog):
        credential_override = None
        checking = False

        async def check_schema(self, c, role=None):
            if self.checking:
                row = await self.one(c, "SELECT current_user AS role,current_setting('transaction_read_only') AS readonly,current_setting('search_path') AS path")
                assert row['readonly']=='on' and row['path']=='pg_catalog, tools_files'
                expected = self.s.files_pg_role if self.s.files_pg_role=='source_reader' else self.s.files_pg_owner
                assert row['role']==expected
                readonly_checks.append(row)
            await super().check_schema(c,role=role)


        @asynccontextmanager
        async def connection(self, service=None, operator=False):
            async def fixture_credential(service=None):
                return self.credential_override or dict(host=str(socket), dbname=self.s.files_pg_database,
                                                       user=self.s.files_pg_role)
            # Only the credential boundary is synthetic: Catalog, libpq, identity,
            # cluster, transactions, privilege checks and SQL are real. Unix
            # socket trust is this isolated fixture, never a TLS/Vault claim.
            with patch.object(self.credentials, 'sql', fixture_credential):
                async with super().connection(service=service, operator=operator) as c:
                    try:
                        yield c
                    finally:
                        row = await self.one(c, "SELECT current_user AS role,current_setting('transaction_read_only') AS readonly")
                        assert row == {'role': self.s.files_pg_role, 'readonly': 'off'}
                        observed_roles.append(row)

    def snapshot(database):
        with connect(socket, database) as c:
            return [c.execute(query).fetchall() for query in (
                "SELECT nspname,nspowner,nspacl::text FROM pg_namespace ORDER BY oid",
                "SELECT relname,relowner,relacl::text FROM pg_class WHERE relnamespace='tools_files'::regnamespace ORDER BY oid",
                "SELECT proname,proowner,proacl::text FROM pg_proc WHERE pronamespace='tools_files'::regnamespace ORDER BY oid",
                "SELECT * FROM tools_files.schema_version",
                "SELECT * FROM pg_auth_members ORDER BY roleid,member",
                "SELECT rolname,rolcanlogin,rolinherit,rolsuper,rolcreatedb,rolcreaterole,rolreplication,rolbypassrls FROM pg_roles ORDER BY oid")]+[
                    c.execute(psycopg.sql.SQL("SELECT to_jsonb(t) FROM {} t ORDER BY 1").format(
                        psycopg.sql.Identifier('tools_files',table))).fetchall()
                    for (table,) in c.execute("SELECT tablename FROM pg_tables WHERE schemaname='tools_files' ORDER BY tablename").fetchall()]

    async def checked(settings, label, error=None):
        before = snapshot(settings.files_pg_database)
        with patch.object(files_bootstrap, 'Catalog', FixtureCatalog), patch.object(files_bootstrap, 'get_settings', return_value=settings), patch.object(FixtureCatalog,'checking',True):
            args = SimpleNamespace(schema='tools_files', app_role='source_app' if settings.files_pg_database=='source30' else 'copy_app',
                                   operator_service=None, check=True)
            try:
                result = await files_bootstrap.install(args)
            except (StorageUnavailable, psycopg.Error) as refused:
                if error is None:
                    raise
                assert error in str(cause(refused)), (label, type(refused).__name__, str(cause(refused)))
            else:
                assert error is None, (label, 'unexpected success')
                assert result['status']=='ok'
        assert snapshot(settings.files_pg_database)==before, label+' changed ACL/data/memberships'
        return label

    async def check_negatives(settings):
        results=[]
        with connect(socket) as c:
            c.execute('GRANT source_owner TO source_install WITH INHERIT FALSE, SET FALSE')
        results.append(await checked(settings, 'set-false', 'permission denied for schema'))
        with connect(socket) as c:
            c.execute('REVOKE source_owner FROM source_install')
        results.append(await checked(settings, 'membership-revoked', 'permission denied for schema'))
        with connect(socket) as c:
            c.execute('GRANT source_owner TO source_install WITH INHERIT FALSE, SET TRUE')
            c.execute('ALTER ROLE source_install NOLOGIN')
        results.append(await checked(settings, 'installer-retired', 'not permitted to log in'))
        with connect(socket) as c:
            c.execute('ALTER ROLE source_install LOGIN')
            c.execute('GRANT source_owner TO source_app WITH INHERIT FALSE, SET TRUE')
        results.append(await checked(settings, 'app-membership', 'Membership application interdite'))
        with connect(socket) as c:
            c.execute('REVOKE source_owner FROM source_app')
            c.execute('ALTER ROLE source_app NOLOGIN')
        results.append(await checked(settings, 'app-nologin', 'Rôles opérateur/application incompatibles'))
        with connect(socket) as c:
            c.execute('ALTER ROLE source_app LOGIN')
        with connect(socket,'source30') as c:
            c.execute('GRANT CREATE ON SCHEMA tools_files TO source_app')
        results.append(await checked(settings, 'app-ddl', 'Privilèges schéma application invalides'))
        with connect(socket,'source30') as c:
            c.execute('REVOKE CREATE ON SCHEMA tools_files FROM source_app')
            c.execute("UPDATE tools_files.schema_version SET checksum='altered'")
        results.append(await checked(settings, 'checksum', 'Schéma incompatible'))
        with connect(socket,'source30') as c:
            from src.mcp_tools.storage.files_schema import CHECKSUM
            c.execute('UPDATE tools_files.schema_version SET checksum=%s',(CHECKSUM,))
        for label, update, credential, error in (
            ('identity', {'files_pg_role':'source_app'}, {'host':str(socket),'dbname':'source30','user':'source_install'}, 'Cible SQL/identité invalide'),
            ('database', {'files_pg_database':'copy30'}, {'host':str(socket),'dbname':'source30','user':'source_install'}, 'Cible SQL/identité invalide'),
            ('cluster', {'files_pg_system_identifier':'1'}, None, 'Cluster/epoch opérateur invalide')):
            FixtureCatalog.credential_override=credential
            try:
                with patch.object(files_bootstrap,'Catalog',FixtureCatalog),patch.object(files_bootstrap,'get_settings',return_value=settings.model_copy(update=update)):
                    try:
                        await files_bootstrap.install(SimpleNamespace(schema='tools_files',app_role='source_app',operator_service=None,check=True))
                    except StorageUnavailable as refused:
                        assert error in str(refused), (label,str(refused))
                    else:
                        raise AssertionError(label+' accepted')
                results.append(label)
            finally:
                FixtureCatalog.credential_override=None
        # Legacy read grants and a DBA-owned probe: preserve the authenticated
        # role, including when it also has SET owner. No grants to installer.
        with connect(socket) as c:
            c.execute('CREATE ROLE source_reader LOGIN INHERIT')
            c.execute('GRANT CONNECT ON DATABASE source30 TO source_reader')
        with connect(socket,'source30') as c:
            c.execute('GRANT USAGE ON SCHEMA tools_files TO source_reader')
            c.execute('GRANT SELECT ON tools_files.schema_version TO source_reader')
            c.execute('GRANT EXECUTE ON FUNCTION pg_control_system(),pg_control_checkpoint() TO source_reader')
            c.execute('ALTER FUNCTION tools_files.files_infrastructure() OWNER TO postgres')
            c.execute('REVOKE ALL ON FUNCTION tools_files.files_infrastructure() FROM source_owner')
            c.execute('GRANT EXECUTE ON FUNCTION tools_files.files_infrastructure() TO source_reader')
        reader=settings.model_copy(update={'files_pg_role':'source_reader'})
        results.append(await checked(reader,'explicit-read-no-set'))
        with connect(socket) as c:
            c.execute('GRANT source_owner TO source_reader WITH INHERIT TRUE, SET TRUE')
        results.append(await checked(reader,'explicit-read-with-inherit-set-dba-probe'))
        with connect(socket,'source30') as c:
            c.execute('ALTER FUNCTION tools_files.files_infrastructure() OWNER TO source_owner')
            c.execute('REVOKE ALL ON FUNCTION tools_files.files_infrastructure() FROM source_reader')
            c.execute('REVOKE ALL ON tools_files.schema_version FROM source_reader')
            c.execute('REVOKE ALL ON SCHEMA tools_files FROM source_reader')
            c.execute('REVOKE ALL ON FUNCTION pg_control_system(),pg_control_checkpoint() FROM source_reader')
        with connect(socket) as c:
            c.execute('REVOKE source_owner FROM source_reader')
            c.execute('REVOKE CONNECT ON DATABASE source30 FROM source_reader')
            c.execute('DROP ROLE source_reader')
        results.append(await checked(settings,'owner-probe-restored'))
        return results

    content = b"confirmed fixture bytes"

    class PinnedS3:
        def get_object(self, **kwargs):
            assert kwargs == {"Bucket": "fixture", "Key": "files-generations/" + str(generation),
                              "VersionId": "immutable-version"}
            return {"Body": io.BytesIO(content), "VersionId": "immutable-version"}

    async def binary(settings, argv, output):
        process = await asyncio.create_subprocess_exec(
            "docker", "exec", "--user", f"{os.getuid()}:{os.getgid()}",
            "-e", "PGHOST=/fixture-socket", "-e", "PGPORT=5432", "-e", "PGUSER=" + settings.files_pg_role,
            "-e", "PGDATABASE=" + settings.files_pg_database, name, *argv,
            stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)
        try:
            await asyncio.wait_for(process.wait(), 60)
        except BaseException:
            # The owner finally stops the entire exact isolated container, including exec clients.
            process.kill()
            await process.wait()
            raise
        assert process.returncode == 0, "PG binary non-confirmed"
        if output:
            output.chmod(0o600)

    with connect(socket) as c:
        for role in ("source_owner", "copy_owner"):
            c.execute(f"CREATE ROLE {role} NOLOGIN")
        for role in ("source_app", "source_install", "source_backup", "copy_app", "copy_install"):
            c.execute(f"CREATE ROLE {role} LOGIN NOINHERIT")
        for owner, installer, db in (("source_owner", "source_install", "source30"), ("copy_owner", "copy_install", "copy30")):
            c.execute(f"GRANT {owner} TO {installer} WITH INHERIT FALSE, SET TRUE")
            c.execute(f"CREATE DATABASE {db} OWNER {owner}")
            c.execute(f"REVOKE ALL ON DATABASE {db} FROM PUBLIC")
        for db in ("postgres", "template1"):
            c.execute(f"REVOKE ALL ON DATABASE {db} FROM PUBLIC")
        c.execute("GRANT CONNECT ON DATABASE source30 TO source_app,source_install,source_backup")
        c.execute("GRANT CONNECT ON DATABASE copy30 TO copy_app,copy_install")
    for db, owner, installer in (("source30", "source_owner", "source_install"), ("copy30", "copy_owner", "copy_install")):
        with connect(socket, db) as c:
            c.execute("REVOKE ALL ON SCHEMA public FROM PUBLIC")
            c.execute(f"GRANT EXECUTE ON FUNCTION pg_control_system(),pg_control_checkpoint() TO {owner},{installer}")
            if owner == "source_owner":
                c.execute(f"GRANT pg_read_all_stats TO {owner}")
    with connect(socket, "source30") as c:
        cluster, timeline = c.execute("SELECT (pg_control_system()).system_identifier::text,(pg_control_checkpoint()).timeline_id").fetchone()
    with connect(socket, "copy30") as c:
        assert c.execute("SELECT rolname FROM pg_roles WHERE pg_has_role('copy_owner',oid,'MEMBER') ORDER BY rolname").fetchall() == [("copy_owner",), ("pg_database_owner",)]
    common = dict(files_pg_schema="tools_files", files_pg_system_identifier=cluster, files_pg_timeline=timeline,
                  files_durability="local", files_credentials_mode="direct", files_pg_ca_file="/dev/null",
                  s3_endpoint_url="https://fixture.invalid", s3_bucket_name="fixture",
                  s3_access_key_id="fixture", s3_secret_access_key="fixture")
    settings = Settings(_env_file=None, files_pg_database="source30", files_pg_owner="source_owner",
                        files_pg_role="source_install", **common)
    with patch.object(files_bootstrap, "Catalog", FixtureCatalog), patch.object(files_bootstrap, "get_settings", return_value=settings):
        await files_bootstrap.install(SimpleNamespace(schema="tools_files", app_role="source_app", operator_service=None, check=False))
    with connect(socket, "source30") as c:
        sql = (ROOT / "docs/postgres/infrastructure.sql").read_text().replace("tools_files_owner", "source_owner").replace("tools_files_app", "source_app")
        c.execute(sql, prepare=False)
        c.execute("GRANT USAGE ON SCHEMA tools_files TO source_backup")
        c.execute("GRANT SELECT ON ALL TABLES IN SCHEMA tools_files TO source_backup")
        c.execute("GRANT EXECUTE ON FUNCTION tools_files.files_infrastructure(),pg_control_system(),pg_control_checkpoint() TO source_backup")
        c.execute("SET search_path=tools_files,pg_catalog")
        oid, attempt, generation, fence = [uuid.uuid4() for _ in range(4)]
        c.execute("INSERT INTO operations(id,path,request_digest,intent_digest,intent,attempt,generation,expected_revision,phase,publication_allowed,revocation,closed) "
                  "VALUES(%s,'fixture',%s,%s,'{}',%s,%s,0,'EFFECT_COMMITTED',false,%s,true)", (oid, "a" * 64, "b" * 64, attempt, generation, fence))
        c.execute("INSERT INTO generations(id,operation,path,pin,manifest) VALUES(%s,%s,'fixture',%s,'{}')",
                  (generation, oid, psycopg.types.json.Jsonb({"key": "files-generations/" + str(generation),
                    "version_id": "immutable-version", "sha256": hashlib.sha256(content).hexdigest(),
                    "size": len(content)})))
        c.execute("INSERT INTO refs(path,revision,generation,operation,deleted) VALUES('fixture',1,%s,%s,false)", (generation, oid))
        c.execute("INSERT INTO receipts(id,operation,kind,detail) VALUES(%s,%s,'publication','{}')", (uuid.uuid4(), oid))
    checks=[]
    if check_stage in ('both','after-apply'):
        checks.append(await checked(settings,'after-apply'))
        checks.extend(await check_negatives(settings))
    with connect(socket,'source30') as c:
        c.execute("ALTER ROLE source_app NOLOGIN")
    archive = folder / "archive"
    settings = settings.model_copy(update={"files_pg_role": "source_backup"})
    with patch.object(files_backup, "Catalog", FixtureCatalog), patch("boto3.client", return_value=PinnedS3()), patch.object(files_backup, "pg_job", binary):
        with patch.object(files_backup, "get_settings", return_value=settings):
            exported = await files_backup.recipe(SimpleNamespace(action="export", app_role="source_app", archive=str(archive), max_generations=64))
        target = settings.model_copy(update={"files_pg_database": "copy30", "files_pg_owner": "copy_owner", "files_pg_role": "copy_install"})
        with patch.object(files_backup, "get_settings", return_value=target):
            async def refused_before_restore():
                try:
                    await files_backup.recipe(SimpleNamespace(action="import", project_roles=True, app_role="copy_app", archive=str(archive), max_generations=64))
                except StorageUnavailable:
                    pass
                else:
                    raise AssertionError("dangerous target contract accepted")
                with connect(socket, "copy30") as c:
                    assert c.execute("SELECT to_regnamespace('tools_files')").fetchone() == (None,)
            with connect(socket) as c:
                c.execute("GRANT source_owner TO copy_owner WITH INHERIT FALSE, SET TRUE")
            await refused_before_restore()
            with connect(socket) as c:
                c.execute("REVOKE source_owner FROM copy_owner")
            for objects, privilege in (("TABLES", "SELECT"), ("SCHEMAS", "USAGE"), ("FUNCTIONS", "EXECUTE")):
                with connect(socket, "copy30") as c:
                    c.execute(f"ALTER DEFAULT PRIVILEGES FOR ROLE copy_owner GRANT {privilege} ON {objects} TO source_app")
                await refused_before_restore()
                with connect(socket, "copy30") as c:
                    c.execute(f"ALTER DEFAULT PRIVILEGES FOR ROLE copy_owner REVOKE {privilege} ON {objects} FROM source_app")
            imported = await files_backup.recipe(SimpleNamespace(action="import", project_roles=True, app_role="copy_app", archive=str(archive), max_generations=64))
    assert exported["status"] == imported["status"] == "ok"
    if check_stage in ('both','after-import'):
        checks.append(await checked(target,'after-import-without-apply'))
    with connect(socket, "copy30", "copy_app") as c:
        c.execute("SET search_path=tools_files,pg_catalog")
        assert c.execute("SELECT revision,deleted FROM refs WHERE path='fixture'").fetchone() == (1, False)
        assert c.execute("SELECT publication_allowed,closed FROM operations").fetchone() == (False, True)
        assert c.execute("SELECT count(*) FROM receipts").fetchone() == (1,)
        assert c.execute("SELECT has_table_privilege(current_user,'refs','DELETE')").fetchone() == (False,)
        try:
            c.execute("UPDATE operations SET publication_allowed=true,revocation=NULL")
        except psycopg.Error as error:
            assert error.sqlstate == "P0001" and error.diag.message_primary == "immutable operation history"
        else:
            raise AssertionError("immutable history writable")
    for user in ("copy_app", "copy_install"):
        try:
            with connect(socket, "source30", user):
                pass
        except psycopg.OperationalError:
            pass
        else:
            raise AssertionError("copy identity connected Source")
    with connect(socket, "copy30") as c:
        c.execute("REVOKE copy_owner FROM copy_install")
        c.execute("ALTER ROLE copy_install NOLOGIN")
        assert c.execute("SELECT NOT rolcanlogin FROM pg_roles WHERE rolname='copy_install'").fetchone() == (True,)
        assert c.execute("SELECT count(*) FROM pg_auth_members WHERE member=(SELECT oid FROM pg_roles WHERE rolname='copy_install')").fetchone() == (0,)
    return {"archive_real": True, "projection": True, "pins_preserved_software": True,
            "source_connect_denied": True, "history_immutable": True, "installer_closed": True,
            "owner_membership_refused": True, "foreign_defaults_refused": 3,
            "implicit_database_owner_verified": True, "operator_checks": checks,
            "local_role_reset_observations": len(observed_roles), "readonly_checks": readonly_checks, "real_catalog_unix_credentials_only_fixture": True}


async def backup_install(socket, folder, name):
    # Real prepare.install and its real child entrypoints. Only credential and
    # Unix transport are replaced; no SQL, public_job or role/grant is mocked.
    import importlib.util
    import sys
    spec = importlib.util.spec_from_file_location('prepare_fixture', ROOT/'scripts/prepare_postgres.py')
    prep = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(prep)
    spec = importlib.util.spec_from_file_location('unix_credentials', Path(__file__).with_name('unix_credentials.py'))
    seam = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(seam)
    seam.activate(socket)
    startup = folder/'startup'
    startup.mkdir(mode=0o700)
    (startup/'sitecustomize.py').write_text(
        "from unix_credentials import activate\nactivate("+repr(str(socket))+")\n")
    real_spawn = asyncio.create_subprocess_exec
    children = []
    async def spawn(*argv, **kwargs):
        if argv[0] == sys.executable:
            children.append(list(argv))
            kwargs['env'] = dict(kwargs['env'], PYTHONPATH=str(startup)+os.pathsep+
                str(ROOT/'tests/postgres_files')+os.pathsep+str(ROOT))
        return await real_spawn(*argv, **kwargs)
    def job(user, database='tools'):
        return dict(user=user, database=database, hosts='127.0.0.1',
            pg_ca_file='/fixture-not-tls/pg.crt', vault_url='https://fixture.invalid',
            vault_id='fixture', vault_path=user, vault_token_file='/fixture/token',
            vault_ca_file='/fixture-not-tls/vault.crt')
    state = folder/'state'
    state.mkdir(mode=0o700)
    verifiers = folder/'verifiers'
    verifiers.mkdir(mode=0o700)
    for role in prep.LOGIN:
        p = verifiers/(role+'.json')
        p.write_text(json.dumps(dict(role=role,database='tools',hosts='127.0.0.1',
            verifier=prep.scram_verifier('fixture-only-not-a-real-secret-123456'))))
        p.chmod(0o600)
    with connect(socket) as c:
        server_version = c.execute('SHOW server_version').fetchone()[0]
        assert server_version.startswith('17.')
        identity = c.execute('SELECT system_identifier::text FROM pg_control_system()').fetchone()[0]
        timeline = c.execute('SELECT timeline_id FROM pg_control_checkpoint()').fetchone()[0]
        c.execute('CREATE DATABASE neighbor24')
    with connect(socket,'neighbor24') as c:
        c.execute('REVOKE CONNECT ON DATABASE neighbor24 FROM PUBLIC')
        c.execute('CREATE TABLE untouched(value text)')
        c.execute("INSERT INTO untouched VALUES ('neighbor')")
    await prep.provision(job('postgres','postgres'),job('postgres'),'tools',verifiers,state,identity)
    with patch.object(asyncio,'create_subprocess_exec',spawn):
        await prep.install(job('tools_files_install'),job('tools_access_install'),job('postgres'),
            identity,timeline,state,folder/'admin.token','fixture','backup24')
    assert (state/'install.done.json').exists() and len(children)==5
    (folder/'child-entrypoints.json').write_text(json.dumps(children,indent=2))
    with connect(socket,'tools') as c:
        assert c.execute("SELECT pg_has_role('tools_files_backup','tools_files_owner','SET')").fetchone()==(False,)
        assert c.execute("SELECT rolinherit,rolsuper,rolcreatedb,rolcreaterole,rolreplication,rolbypassrls FROM pg_roles WHERE rolname='tools_files_backup'").fetchone()==(False,)*6
        assert c.execute("SELECT count(*) FROM pg_auth_members WHERE member='tools_files_backup'::regrole").fetchone()==(0,)
        acl = c.execute("SELECT has_function_privilege('tools_files_backup','tools_files.files_infrastructure()','EXECUTE')").fetchone()[0]
        grants = c.execute("SELECT pg_get_userbyid(a.grantee),a.privilege_type,a.is_grantable FROM pg_proc p CROSS JOIN LATERAL aclexplode(p.proacl) a WHERE p.oid='tools_files.files_infrastructure()'::regprocedure ORDER BY 1,2").fetchall()
        (folder/'probe-acl.json').write_text(json.dumps(dict(execute=acl,grants=grants)))
        # Seed data is a fixture, not a public/natively authenticated write.
        c.execute("INSERT INTO tools_files.operations(id,path,request_digest,intent_digest,intent,attempt,generation,expected_revision,phase,publication_allowed,revocation,closed) VALUES(%s,'fixture',%s,%s,'{}',%s,%s,0,'EFFECT_COMMITTED',false,%s,true)",
            (uuid.uuid4(),'a'*64,'b'*64,uuid.uuid4(),uuid.uuid4(),uuid.uuid4()))
    def snapshot():
        with connect(socket,'tools') as c:
            return [c.execute(q).fetchall() for q in (
                "SELECT table_name,grantee,privilege_type,is_grantable FROM information_schema.table_privileges WHERE table_schema='tools_files' ORDER BY 1,2,3",
                "SELECT nspacl::text FROM pg_namespace WHERE nspname='tools_files'",
                "SELECT proname,proacl::text FROM pg_proc WHERE pronamespace='tools_files'::regnamespace ORDER BY 1",
                "SELECT * FROM tools_files.operations ORDER BY id",
                "SELECT roleid,member,admin_option,inherit_option,set_option FROM pg_auth_members ORDER BY 1,2")]
    before = snapshot()
    with connect(socket,'neighbor24') as c:
        neighbor = c.execute('SELECT * FROM untouched').fetchall()
        neighbor_acl = c.execute("SELECT relacl::text FROM pg_class WHERE oid='untouched'::regclass").fetchall()
    settings = Settings(_env_file=None, files_metadata_backend='postgres',files_credentials_mode='vault',
        files_pg_role='tools_files_backup',files_pg_database='tools',files_pg_ca_file='/fixture-not-tls/pg.crt',
        files_pg_system_identifier=identity,files_pg_timeline=timeline,files_durability='local',
        s3_endpoint_url='https://fixture.invalid',s3_access_key_id='fixture',
        s3_secret_access_key='fixture',s3_bucket_name='fixture')
    binaries = []
    async def binary(s, argv, output):
        binaries.append(argv[0])
        # Existing fixture transport: real PG17 pg_dump, as the actual backup
        # login, over its private Unix socket. No --role=owner or SQL replacement.
        run(['docker','exec','--user',f'{os.getuid()}:{os.getgid()}',
            '-e','PGHOST=/fixture-socket','-e','PGUSER='+s.files_pg_role,
            '-e','PGDATABASE='+s.files_pg_database,name,*argv],120)
        if output:output.chmod(0o600)
    with patch.object(files_backup,'get_settings',return_value=settings), patch.object(files_backup,'pg_job',binary):
        result = await files_backup.recipe(SimpleNamespace(action='export',archive=str(folder/'archive'),
            app_role='tools_files_app',max_generations=64))
        assert result['status']=='ok' and binaries==['pg_dump']
        listing = run(['docker','exec',name,'pg_restore','--list',str(folder/'archive/domain.dump')])
        assert 'files_infrastructure' in listing and 'operations' in listing
        assert acl and ('tools_files_backup','EXECUTE',False) in grants
        assert all(not grantable for role,_,grantable in grants if role=='tools_files_backup')
        assert snapshot()==before
        denied=[]
        for query in ('CREATE TABLE tools_files.forbidden(x int)',
                      'INSERT INTO tools_files.schema_version VALUES(false,1,\'x\')',
                      'UPDATE tools_files.schema_version SET version=version',
                      'DELETE FROM tools_files.schema_version', 'SET ROLE tools_files_owner'):
            with connect(socket,'tools','tools_files_backup') as c:
                try:c.execute(query)
                except psycopg.Error as error:assert error.sqlstate=='42501';denied.append(query.split()[0])
                else:raise AssertionError('backup gained privilege: '+query)
        try:connect(socket,'neighbor24','tools_files_backup').close()
        except psycopg.OperationalError:denied.append('neighbor')
        else:raise AssertionError('backup connected neighbor')
        with connect(socket,'tools','tools_files_app') as c:
            try:c.execute('CREATE TABLE tools_files.app_forbidden(x int)')
            except psycopg.Error as error:assert error.sqlstate=='42501';denied.append('app-CREATE')
            else:raise AssertionError('app gained DDL')
        assert snapshot()==before
        with connect(socket,'neighbor24') as c:
            assert c.execute('SELECT * FROM untouched').fetchall()==neighbor
            assert c.execute("SELECT relacl::text FROM pg_class WHERE oid='untouched'::regclass").fetchall()==neighbor_acl
        with connect(socket,'tools') as c:c.execute('REVOKE EXECUTE ON FUNCTION tools_files.files_infrastructure() FROM tools_files_backup')
        try:
            await files_backup.recipe(SimpleNamespace(action='export',archive=str(folder/'revoked-archive'),app_role='tools_files_app',max_generations=64))
        except StorageUnavailable as error:assert getattr(cause(error),'sqlstate',None)=='42501'
        else:raise AssertionError('revoked probe admitted export')
        assert binaries==['pg_dump']
    with connect(socket,'tools','tools_files_backup') as c:
        assert c.execute('SELECT count(*) FROM tools_files.schema_version').fetchone()==(1,)
    with connect(socket,'tools') as c:
        c.execute('ALTER ROLE tools_files_backup NOLOGIN')
    try:connect(socket,'tools','tools_files_backup').close()
    except psycopg.OperationalError:pass
    else:raise AssertionError('retired backup logged in')
    return dict(server_version=server_version, pg_dump_version=run(['docker','exec',name,'pg_dump','--version']),
        real_prepare_install=True, real_child_jobs=len(children), backup_execute=True,
        grant_option=False, backup_set_owner=False, export_real_dump_readable=True,
        denied=denied, source_neighbor_acl_unchanged=True, revoked_before_dump=True,
        select_remains_after_execute_revoke=True, nologin_refused=True,
        vault_tls_s3_native=False, fixture_credentials_unix_only=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--results", type=Path, required=True)
    parser.add_argument("--backup-install",action="store_true")
    parser.add_argument("--check-stage",choices=("both","after-apply","after-import"),default="both")
    args = parser.parse_args()
    folder = args.results.resolve()
    folder.mkdir(mode=0o700, exist_ok=False)
    socket = folder / "socket"
    socket.mkdir(mode=0o777)
    socket.chmod(0o777)
    name = "tools30-restore-fixture-" + uuid.uuid4().hex
    report = {"pass": False, "fixture_only": True, "network": "none", "vault_tls_s3_native": False}
    failed = None
    try:
        run(["docker", "image", "inspect", IMAGE])
        run(["docker", "run", "-d", "--init", "--pull", "never", "--name", name, "--network", "none",
             "--restart", "no", "--cpus", "1", "--memory", "768m", "--memory-swap", "768m", "--pids-limit", "128",
             "--tmpfs", "/var/lib/postgresql/data:rw,size=268435456", "--mount", f"type=bind,src={socket},dst=/fixture-socket",
             "--mount", f"type=bind,src={folder},dst={folder}", "-e", "POSTGRES_HOST_AUTH_METHOD=trust",
             "--entrypoint", "/usr/bin/timeout", IMAGE, "--kill-after=10s", "590s", "/usr/local/bin/docker-entrypoint.sh",
             "postgres", "-c", "listen_addresses=", "-c", "unix_socket_directories=/var/run/postgresql,/fixture-socket",
             "-c", "shared_buffers=32MB", "-c", "max_connections=20"])
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            try:
                rows = run(["docker", "top", name, "-eo", "pid,args", "-ww"], 3).splitlines()
                programs = [row.strip().split(None, 1)[1] for row in rows
                            if len(row.strip().split(None, 1)) == 2 and row.strip().split(None, 1)[0].isdigit()]
                booting = any(Path(cmd.split()[0]).name in {"bash", "sh", "docker-entrypoint.sh"}
                              and "docker-entrypoint.sh" in cmd for cmd in programs)
                if not booting and any(Path(cmd.split()[0]).name == "postgres" for cmd in programs):
                    with connect(socket) as c:
                        assert c.execute("SELECT 1").fetchone() == (1,)
                    break
            except psycopg.OperationalError:
                pass
            time.sleep(.2)
        else:
            raise TimeoutError("fixture readiness")
        operation = backup_install(socket, folder, name) if args.backup_install else exercise(socket, folder, name, args.check_stage)
        report.update(asyncio.run(asyncio.wait_for(operation, 400)))
        report["pass"] = True
    except BaseException as error:
        failed = error
        report["failure_type"] = type(error).__name__
        report["cause_type"] = type(cause(error)).__name__
        report["sqlstate"] = getattr(cause(error),"sqlstate",None)
        report["reason"] = str(cause(error))
    finally:
        removed = subprocess.run(["docker", "rm", "--force", name], capture_output=True, text=True, timeout=15)
        absent = subprocess.run(["docker", "inspect", name], capture_output=True, text=True, timeout=5)
        report["cleanup_confirmed"] = removed.returncode == 0 and absent.returncode != 0
        report["pass"] &= report["cleanup_confirmed"]
        (folder / "result.json").write_text(json.dumps(report, indent=2))
        (folder / "result.json").chmod(0o600)
    print(json.dumps(report))
    if failed:
        raise failed
    if not report["pass"]:
        raise RuntimeError("fixture cleanup non-confirmed")


if __name__ == "__main__":
    main()
