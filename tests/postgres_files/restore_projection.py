"""Archive PG17 réelle, isolée : ne qualifie ni Vault, TLS, S3 ni service natif."""
import argparse
import asyncio
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
from psycopg.rows import dict_row

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


async def exercise(socket, folder, name):
    class FixtureCatalog(Catalog):
        @asynccontextmanager
        async def connection(self, service=None, operator=False):
            c = await psycopg.AsyncConnection.connect(host=str(socket), dbname=self.s.files_pg_database,
                                                     user=self.s.files_pg_role, autocommit=True, row_factory=dict_row)
            try:
                await c.execute("SET search_path=tools_files,pg_catalog")
                await c.execute("SET statement_timeout=5000")
                c._tools_operator = operator
                c._tools_notices = []
                c.add_notice_handler(lambda d: c._tools_notices.append((d.severity_nonlocalized, d.sqlstate)))
                yield c
            finally:
                await c.close()

    class Pins:
        def __init__(self, settings):
            pass

        async def get(self, pin):
            assert pin == {"key": "fixture", "version_id": "immutable-version"}
            return b"confirmed fixture bytes"

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
                  files_durability="local", files_credentials_mode="direct")
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
                  (generation, oid, psycopg.types.json.Jsonb({"key": "fixture", "version_id": "immutable-version"})))
        c.execute("INSERT INTO refs(path,revision,generation,operation,deleted) VALUES('fixture',1,%s,%s,false)", (generation, oid))
        c.execute("INSERT INTO receipts(id,operation,kind,detail) VALUES(%s,%s,'publication','{}')", (uuid.uuid4(), oid))
        c.execute("ALTER ROLE source_app NOLOGIN")
    archive = folder / "archive"
    settings = settings.model_copy(update={"files_pg_role": "source_backup"})
    with patch.object(files_backup, "Catalog", FixtureCatalog), patch.object(files_backup, "Blobs", Pins), patch.object(files_backup, "pg_job", binary):
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
            "implicit_database_owner_verified": True}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--results", type=Path, required=True)
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
        report.update(asyncio.run(asyncio.wait_for(exercise(socket, folder, name), 400)))
        report["pass"] = True
    except BaseException as error:
        failed = error
        report["failure_type"] = type(error).__name__
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
