"""Recette opérateur logique bornée, base neuve ; aucune sauvegarde automatique app."""
import argparse
import asyncio
import hashlib
import json
import os
import stat
import tempfile
from pathlib import Path

from ..config import get_settings
from .files_credentials import Credentials, StorageUnavailable, private_text
from .files_postgres import Catalog
from .files_s3 import Blobs


def escaped(value):
    return str(value).replace("\\","\\\\").replace(":","\\:")


async def pg_job(s, argv, output):
    # Auth Vault avant SQL du binaire, identité spécifique au job. Jamais PGPASSWORD/argv secret.
    credentials = await Credentials(s).sql()
    env = {k:v for k,v in os.environ.items() if not k.startswith("PG")}
    env.update(PGSSLMODE="verify-full", PGSSLROOTCERT=s.files_pg_ca_file,
               PGTARGETSESSIONATTRS="read-write", PGCONNECT_TIMEOUT=str(s.files_connect_timeout))
    with tempfile.TemporaryDirectory(prefix="tools-sql-job-") as temp:
        if s.files_credentials_mode=="vault":
            passfile=Path(temp)/"passfile"
            fd=os.open(passfile,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
            with os.fdopen(fd,"w") as f:
                f.write(":".join(escaped(credentials[k]) for k in ("host","port","dbname","user","password"))+"\n")
            env.update(PGHOST=str(credentials["host"]), PGPORT=str(credentials["port"]),
                       PGDATABASE=credentials["dbname"],PGUSER=credentials["user"],PGPASSFILE=str(passfile))
        else:
            env["PGSERVICE"]=s.files_pg_service
            for k in ("PGSERVICEFILE","PGPASSFILE"):
                if k in os.environ:
                    private_text(os.environ[k])  # permissions, pas contenu journalisé
                    env[k]=os.environ[k]
        process=await asyncio.create_subprocess_exec(*argv,env=env,
            stdout=asyncio.subprocess.DEVNULL,stderr=asyncio.subprocess.DEVNULL)
        try:
            await asyncio.wait_for(process.wait(),120)
        except BaseException:
            process.kill()
            await process.wait()
            raise
        if process.returncode:
            raise StorageUnavailable("Job PostgreSQL non confirmé")
    if output:
        os.chmod(output,0o600)


async def recipe(args):
    s=get_settings()
    cat=Catalog(s)
    blobs=Blobs(s)
    destination=Path(args.archive)
    if args.action=="export":
        destination.mkdir(mode=0o700,parents=False,exist_ok=False)
        dump=destination/"domain.dump"
        manifest=destination/"manifest.jsonl"
        async with cat.connection(operator=True) as c:
            await cat.infrastructure(c)
            # Un dump ne restitue pas les rôles : scope fermé aux deux identités du domaine.
            roles=await (await c.execute("SELECT rolname,rolcanlogin,rolsuper,rolcreatedb,rolcreaterole,rolreplication,rolbypassrls FROM pg_roles WHERE rolname=ANY(%s)",([s.files_pg_owner,args.app_role],))).fetchall()
            if len(roles)!=2:
                raise StorageUnavailable("Manifeste rôles incomplet")
            schema=await cat.one(c,"SELECT version,checksum FROM schema_version WHERE singleton")
            fd=os.open(manifest,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
            with os.fdopen(fd,"w") as f:
                f.write(json.dumps({"header":{"database":s.files_pg_database,"cluster":s.files_pg_system_identifier,
                    "timeline":s.files_pg_timeline,"schema":s.files_pg_schema,"schema_version":schema,
                    "roles":roles,"quiesced_operator_assertion":True}},default=str)+"\n")
                after=""
                total=0
                while True:
                    rows=await (await c.execute("SELECT id,pin FROM generations WHERE id::text>%s ORDER BY id::text LIMIT 64",(after,))).fetchall()
                    if not rows:
                        break
                    for row in rows:
                        await blobs.get(row["pin"])
                        f.write(json.dumps({"generation":str(row["id"]),"pin":row["pin"]})+"\n")
                    total+=len(rows)
                    if total>args.max_generations:
                        raise StorageUnavailable("Budget backup dépassé")
                    after=str(rows[-1]["id"])
                # Recenser aussi les clés attendues d'intents inconnus : pas de purge/replay/adoption.
                intents=await (await c.execute("SELECT id,intent,publication_allowed,closed FROM operations WHERE NOT closed ORDER BY id LIMIT 65")).fetchall()
                if len(intents)>64:
                    raise StorageUnavailable("Budget opérations backup dépassé")
                for row in intents:
                    f.write(json.dumps({"pending_operation":row},default=str)+"\n")
                defaults=await (await c.execute("SELECT pg_get_userbyid(defaclrole) role,n.nspname schema,defaclobjtype,defaclacl::text acl FROM pg_default_acl d JOIN pg_namespace n ON n.oid=d.defaclnamespace WHERE n.nspname=%s",(s.files_pg_schema,))).fetchall()
                grants=await (await c.execute("SELECT table_name,grantee,privilege_type,is_grantable FROM information_schema.table_privileges WHERE table_schema=%s ORDER BY table_name,grantee,privilege_type",(s.files_pg_schema,))).fetchall()
                f.write(json.dumps({"grants":grants,"defaults":defaults},default=str)+"\n")
        await pg_job(s,["pg_dump","--format=custom","--schema="+s.files_pg_schema,"--file="+str(dump)],dump)
        # Les hash bornés sont produits en streaming ; répertoire privé, jamais preuve publique brute.
        def file_hash(p):
            h=hashlib.sha256()
            with p.open("rb") as f:
                for b in iter(lambda:f.read(65536),b""):
                    h.update(b)
            return h.hexdigest()
        hashes={p.name:file_hash(p) for p in (dump,manifest)}
        fd=os.open(destination/"hashes.json",os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,"w") as f:
            json.dump(hashes,f)
        return {"status":"ok","action":"export","generations":total,"next":"chiffrer archive ; retenir versions et markers S3 ; vérifier indépendamment avant raccord/cleanup"}
    # Restore ne crée pas de rôles globaux ni de bases : provisionneur autorisé les rétablit AVANT.
    st=destination.lstat()
    if not stat.S_ISDIR(st.st_mode) or st.st_mode & 0o077:
        raise StorageUnavailable("Archive privée requise")
    hashes=json.loads(private_text(str(destination/"hashes.json")))
    for name in ("domain.dump","manifest.jsonl"):
        p=destination/name
        st=p.lstat()
        if not stat.S_ISREG(st.st_mode) or st.st_mode & 0o077:
            raise StorageUnavailable("Artefact archive invalide")
        h=hashlib.sha256()
        with p.open("rb") as f:
            for b in iter(lambda:f.read(65536),b""):
                h.update(b)
        if h.hexdigest()!=hashes.get(name):
            raise StorageUnavailable("Archive incohérente")
    with (destination/"manifest.jsonl").open() as f:
        header=json.loads(next(f))["header"]
        if header["schema"]!=s.files_pg_schema:
            raise StorageUnavailable("Domaine de reprise divergent")
        async with cat.connection(operator=True) as c:
            exists=await cat.one(c,"SELECT EXISTS(SELECT 1 FROM pg_namespace WHERE nspname=%s) present",(s.files_pg_schema,))
            if exists["present"]:
                raise StorageUnavailable("Restore exige cible neuve sans schéma Tools")
            for role in header["roles"]:
                actual=await cat.one(c,"SELECT rolname,rolcanlogin,rolsuper,rolcreatedb,rolcreaterole,rolreplication,rolbypassrls FROM pg_roles WHERE rolname=%s",(role["rolname"],))
                if actual!=role:
                    raise StorageUnavailable("Rôles/grants à rétablir sous provisionneur avant import")
        count=0
        for line in f:
            item=json.loads(line)
            if "pin" in item:
                count+=1
                if count>args.max_generations:
                    raise StorageUnavailable("Budget restore dépassé")
                await blobs.get(item["pin"])  # le pin original doit survivre ; aucune réécriture cachée
    await pg_job(s,["pg_restore","--exit-on-error","--single-transaction","--dbname="+s.files_pg_database,str(destination/"domain.dump")],None)
    return {"status":"ok","action":"import","next":"droits/defaults/probes opérateur ; révocations auth actuelles ; process app neuf /ready + lecture publique et SQL indépendante ; aucun cleanup automatique"}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("action",choices=("export","import"))
    p.add_argument("--archive",required=True)
    p.add_argument("--app-role",default="tools_files_app")
    p.add_argument("--quiesced",action="store_true",required=True,
                   help="Assertion opérateur : tous écrivains/administrateurs de mutation arrêtés")
    p.add_argument("--max-generations",type=int,default=10000)
    args=p.parse_args()
    try:
        if not 1<=args.max_generations<=10000:
            raise StorageUnavailable("Budget invalide")
        async def bounded():
            async with asyncio.timeout(600):
                return await recipe(args)
        result=asyncio.run(bounded())
    except Exception:
        result={"status":"incomplete","message":"Recette non confirmée ; préserver archive/source/cible et inspecter, aucune répétition ou cleanup automatique"}
    print(json.dumps(result))
    raise SystemExit(0 if result["status"]=="ok" else 1)


if __name__=="__main__":
    main()
