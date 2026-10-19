"""Offline preparation/configuration contracts. No SQL, provider or Docker API."""
import asyncio
import base64
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import importlib.util
import inspect
import ipaddress
import json
import os
from pathlib import Path
import shlex
from types import SimpleNamespace

import pytest
import yaml
from dotenv import dotenv_values

from src.mcp_tools.config import Settings

ROOT=Path(__file__).resolve().parent.parent


@pytest.fixture
def prep():
    spec=importlib.util.spec_from_file_location('prepare_tools',ROOT/'scripts/prepare_postgres.py')
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_pg_profile_selects_vault_in_real_settings_despite_legacy_direct_default():
    # This is YAML/profile + application Settings, not a Compose-engine validation.
    path=ROOT/'compose.postgres.yml'
    env=yaml.safe_load(path.read_text())['services']['mcp-tools']['environment'] if path.exists() else {}
    values={key:value for key,value in env.items() if '${' not in str(value)}
    actual=Settings(_env_file=None,**{key.lower():value for key,value in values.items()})
    assert actual.files_metadata_backend=='postgres' and actual.access_backend=='postgres'
    assert actual.files_credentials_mode=='vault'
    assert not actual.hub_activity_enabled and not actual.files_mission_dependencies_enabled
    assert Settings(_env_file=None).files_metadata_backend=='s3'
    assert Settings(_env_file=None).access_backend=='s3'
    mounts=yaml.safe_load(path.read_text())['services']['mcp-tools']['volumes']
    assert len(mounts)==4 and all(row['read_only'] and row['bind']['create_host_path'] is False for row in mounts)
    assert not any('install' in row['target'] or 'prepare' in row['target'] for row in mounts)


def test_local_pg_file_can_start_pg_alone_and_has_one_persistent_tls_server():
    path=ROOT/'compose.postgres-local.yml'
    document=yaml.safe_load(path.read_text()) if path.exists() else {'services':{}}
    assert set(document['services'])=={'postgresql'}
    pg=document['services']['postgresql']
    assert 'digest' in pg['image'] and 'TOOLS_POSTGRES_IMAGE:?' in pg['image']
    assert pg['environment']['POSTGRES_PASSWORD_FILE']=='/run/tools/initial-password'
    assert all('PASSWORD=' not in str(value) for value in pg['environment'].values())
    assert pg['volumes'][0]=='tools_pg_data:/var/lib/postgresql/data'
    assert set(document['volumes'])=={'tools_pg_data'}
    assert 'ssl=on' in pg['command'] and pg['ports']==['127.0.0.1:5432:5432']
    assert all(row['read_only'] for row in pg['volumes'][1:])
    assert set(pg['networks'])<=set(document['networks'])


@pytest.fixture
def model(prep,monkeypatch,tmp_path):
    tmp_path.chmod(0o700)
    for key in tuple(os.environ):
        if key.startswith('PG'):monkeypatch.delenv(key)
    password="CRED-CANARY-'\\;"+'x'*40
    state=SimpleNamespace(reads=[],connections=[],statements=[],children=[],collision=False,
                          database_exists=False,refuse_target=False,fail_commit=False,fail_child=False)
    def job(user,database='tools',host='127.0.0.1'):
        return dict(database=database,user=user,hosts=host,pg_ca_file=str(tmp_path/'pg.crt'),
            vault_url='https://vault.invalid',vault_id='tools',vault_path=user+'/'+database,
            vault_token_file=str(tmp_path/(user+'.token')),vault_ca_file=str(tmp_path/'vault.crt'))
    class Provider:
        def __init__(self,settings):self.s=settings
        async def sql(self):
            state.reads.append(self.s.files_vault_path)
            if state.refuse_target and self.s.files_pg_database=='tools':raise prep.Refused('denied')
            return dict(host='127.0.0.1',port=5432,dbname=self.s.files_pg_database,user=self.s.files_pg_role,password=password)
    monkeypatch.setattr(prep,'Credentials',Provider)
    import psycopg
    class Connection:
        def __init__(self,kw):self.kw=kw
        async def execute(self,statement,params=(),**kwargs):
            self.statement=statement.as_string() if hasattr(statement,'as_string') else statement
            state.statements.append(self.statement)
            if not self.statement.startswith('SELECT'):
                assert (tmp_path/'prepare.pending.json').exists() or (tmp_path/'install.pending.json').exists()
            return self
        async def fetchone(self):
            if 'current_user AS role' in self.statement:
                return dict(role=self.kw['user'],db=self.kw['dbname'],recovery=False,system_identifier='12345',timeline=2)
            return {'datname':'tools'} if state.database_exists else None
        async def fetchall(self):return [{'rolname':'collision'}] if state.collision else []
        async def close(self):pass
        @asynccontextmanager
        async def transaction(self):
            yield
            if state.fail_commit:raise RuntimeError('unconfirmed commit')
    async def connect(**kwargs):
        state.connections.append(kwargs)
        assert kwargs['sslmode']=='verify-full' and kwargs['target_session_attrs']=='read-write'
        assert kwargs['password']==password and 'service' not in kwargs
        return Connection(kwargs)
    monkeypatch.setattr(psycopg.AsyncConnection,'connect',connect)
    class Child:
        returncode=0
        async def communicate(self):
            if state.fail_child:raise TimeoutError('unconfirmed job')
            return b'{"status":"ok"}',b''
        def kill(self):self.returncode=-9
        async def wait(self):return self.returncode
    async def spawn(*argv,**kwargs):
        state.children.append((argv,kwargs['env']))
        return Child()
    monkeypatch.setattr(prep.asyncio,'create_subprocess_exec',spawn)
    for name in prep.LOGIN:
        item=dict(role=name,database='tools',hosts='127.0.0.1',verifier=prep.scram_verifier(password))
        target=tmp_path/(name+'.json');target.write_text(json.dumps(item));target.chmod(0o600)
    state.job,state.password,state.directory=job,password,tmp_path
    return state


def test_scram_matches_rfc7677_transcript_server_and_client_proofs(prep,monkeypatch):
    # RFC7677 section3, standard example; no server/libpq call.
    monkeypatch.setattr(prep,'strong_password',lambda value:value)
    monkeypatch.setattr(prep.secrets,'token_bytes',lambda size:base64.b64decode('W22ZaJ0SNY7soEsUEjb6gQ=='))
    verifier=prep.scram_verifier('pencil')
    stored,server=map(base64.b64decode,verifier.split('$')[2].split(':'))
    nonce='rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0'
    auth=f'n=user,r=rOprNGfwEbeRWgbNEkqO,r={nonce},s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096,c=biws,r={nonce}'.encode()
    assert base64.b64encode(hmac.digest(server,auth,'sha256')).decode()=='6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4='
    signature=hmac.digest(stored,auth,'sha256')
    proof=base64.b64decode('dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=')
    assert hashlib.sha256(bytes(a^b for a,b in zip(proof,signature))).digest()==stored


@pytest.mark.parametrize('value',['short','é'*40,'x'*31,'x'*257,'A'*32+'\n'])
def test_secret_strength_and_ascii_policy_refuses_before_verifier(prep,value):
    with pytest.raises(prep.Refused):prep.scram_verifier(value)


def test_role_scope_emits_private_verifier_not_plaintext_or_sql(prep,model):
    output=model.directory/'result.json'
    asyncio.run(prep.role_verifier(model.job('tools_files_app'),output))
    text=output.read_text()
    assert model.password not in text and prep.SCRAM.fullmatch(json.loads(text)['verifier'])
    assert output.stat().st_mode&0o777==0o600
    assert model.reads==['tools_files_app/tools'] and not model.connections and not model.statements
    with pytest.raises(FileExistsError):asyncio.run(prep.role_verifier(model.job('tools_files_app'),output))


def test_no_raw_password_profile_or_relative_material_paths(prep,model):
    path=model.directory/'profile.json'
    value=model.job('tools_files_app');value['password']='DO-NOT-READ'
    path.write_text(json.dumps(value));path.chmod(0o600)
    with pytest.raises(prep.Refused):prep.profile(path)
    value.pop('password');value['vault_token_file']='relative.token'
    path.write_text(json.dumps(value))
    with pytest.raises(prep.Refused):prep.profile(path)


@pytest.mark.parametrize('change',[{'host':'foreign.invalid'},{'password':''},{'user':'other_role'}])
def test_corrupt_vault_job_identity_or_password_refused_before_sql(prep,model,monkeypatch,change):
    class Moved:
        def __init__(self,*args):pass
        async def sql(self):
            return dict(dict(host='127.0.0.1',port=5432,dbname='tools',user='tools_files_app',password=model.password),**change)
    monkeypatch.setattr(prep,'Credentials',Moved)
    with pytest.raises(prep.Refused):asyncio.run(prep.credential(model.job('tools_files_app')))
    assert not model.connections and not model.statements


def test_initial_password_requires_scoped_provisioner_and_measured_uid(prep,model):
    output=model.directory/'initial-password'
    with pytest.raises(prep.Refused):asyncio.run(prep.initial_password(model.job('tools_files_app'),output,os.geteuid()))
    assert not model.reads
    asyncio.run(prep.initial_password(model.job('tools_prepare','postgres'),output,os.geteuid()))
    assert output.stat().st_uid==os.geteuid() and output.stat().st_mode&0o777==0o600
    assert output.read_text().strip()==model.password and not model.connections


def test_cli_suppresses_provider_errors_and_never_prints_raw_secret(prep,model,monkeypatch,capsys):
    path=model.directory/'job.json';path.write_text(json.dumps(model.job('tools_files_app')));path.chmod(0o600)
    class Refusing:
        def __init__(self,*args):pass
        async def sql(self):raise RuntimeError(model.password)
    monkeypatch.setattr(prep,'Credentials',Refusing)
    monkeypatch.setattr(prep.sys,'argv',['prepare_postgres.py','role-verifier','--profile',str(path),'--output',str(model.directory/'out')])
    assert prep.main()==1
    captured=capsys.readouterr()
    assert model.password not in captured.out+captured.err and 'incomplete' in captured.out


def test_provision_vault_first_scram_only_and_closed_database_before_acl(prep,model):
    admin=model.job('tools_prepare','postgres');target=model.job('tools_prepare')
    asyncio.run(prep.provision(admin,target,'tools',model.directory,model.directory,'12345'))
    statements='\n'.join(model.statements)
    assert model.password not in statements and 'SCRAM-SHA-256$4096:' in statements
    assert model.reads[0]=='tools_prepare/tools' and all('tools_prepare/' in path for path in model.reads)
    assert statements.index('ALLOW_CONNECTIONS false')<statements.index('REVOKE ALL ON DATABASE')<statements.index('ALLOW_CONNECTIONS true')
    assert 'tools_files_restore' not in '\n'.join(s for s in model.statements if 'GRANT CONNECT' in s)
    assert (model.directory/'prepare.done.json').exists()
    with pytest.raises(prep.Refused):asyncio.run(prep.provision(admin,target,'tools',model.directory,model.directory,'12345'))


@pytest.mark.parametrize('failure',['collision','database_exists','refuse_target'])
def test_provision_refusals_have_no_ddl_or_pending_marker(prep,model,failure):
    setattr(model,failure,True)
    with pytest.raises(prep.Refused):
        asyncio.run(prep.provision(model.job('tools_prepare','postgres'),model.job('tools_prepare'),
                                  'tools',model.directory,model.directory,'12345'))
    assert all(row.startswith('SELECT') for row in model.statements)
    assert not (model.directory/'prepare.pending.json').exists()


def test_unconfirmed_commit_preserves_marker_and_refuses_replay(prep,model):
    model.fail_commit=True
    args=(model.job('tools_prepare','postgres'),model.job('tools_prepare'),'tools',model.directory,model.directory,'12345')
    with pytest.raises(RuntimeError):asyncio.run(prep.provision(*args))
    before=len(model.statements)
    assert (model.directory/'prepare.pending.json').exists() and not (model.directory/'prepare.done.json').exists()
    with pytest.raises(prep.Refused):asyncio.run(prep.provision(*args))
    assert len(model.statements)==before


def test_install_scopes_order_and_no_provisioner_secret_in_child_environment(prep,model,monkeypatch):
    monkeypatch.setenv('UNRELATED_SECRET','MUST-NOT-LEAK')
    monkeypatch.setenv('PGHOST','must-not-propagate')
    # A caller with PG variables is refused; child environments are independently minimal.
    with pytest.raises(prep.Refused):asyncio.run(prep.credential(model.job('tools_prepare')))
    monkeypatch.delenv('PGHOST')
    args=(model.job('tools_files_install'),model.job('tools_access_install'),model.job('tools_prepare'),
          '12345',2,model.directory,model.directory/'admin.token','tenant-a','tools-a')
    before=dict(os.environ)
    asyncio.run(prep.install(*args,close_local_provisioner=True))
    assert len(model.children)==5 and dict(os.environ)==before
    assert [argv[3] for argv,env in model.children]==['--apply','--check','install','verify','bootstrap']
    for argv,env in model.children:
        assert model.password not in ' '.join(argv) and model.password not in str(env)
        assert 'UNRELATED_SECRET' not in env and not any(key.startswith('PG') for key in env)
        assert env['FILES_CREDENTIALS_MODE']=='vault' and env['FILES_PG_TIMELINE']=='2'
        assert env['FILES_PG_ROLE'] in ('tools_files_install','tools_access_install')
    assert any('NOLOGIN' in row for row in model.statements)
    assert (model.directory/'install.done.json').exists()


def test_unconfirmed_public_job_stops_without_following_step_or_replay(prep,model):
    model.fail_child=True
    args=(model.job('tools_files_install'),model.job('tools_access_install'),model.job('tools_prepare'),
          '12345',2,model.directory,model.directory/'admin.token','tenant-a','tools-a')
    with pytest.raises(TimeoutError):asyncio.run(prep.install(*args,close_local_provisioner=True))
    assert len(model.children)==1 and (model.directory/'install.pending.json').exists()
    with pytest.raises(prep.Refused):asyncio.run(prep.install(*args,close_local_provisioner=True))
    assert len(model.children)==1
    assert not any('ALTER ROLE tools_prepare' in row for row in model.statements)
    assert not (model.directory/'install.done.json').exists()


def test_runtime_configuration_has_exact_hosts_vault_mode_and_no_secrets(prep,model,monkeypatch):
    monkeypatch.setenv('UNRELATED_SECRET','MUST-NOT-LEAK')
    files=model.job('tools_files_app',host='postgresql');access=model.job('tools_access_app',host='postgresql')
    output=model.directory/'runtime.env'
    prep.runtime_config(files,access,'12345',2,output)
    text=output.read_text();values=dotenv_values(output)
    actual=Settings(_env_file=None,**{key.lower():value for key,value in values.items()})
    assert actual.files_credentials_mode=='vault' and actual.access_pg_hosts=='postgresql'
    assert actual.files_pg_role=='tools_files_app' and actual.access_pg_role=='tools_access_app'
    assert actual.files_pg_timeline==2 and not actual.hub_activity_enabled
    assert model.password not in text and 'MUST-NOT-LEAK' not in text and not model.reads
    with pytest.raises(prep.Refused):prep.runtime_config(files,model.job('tools_access_app',host='localhost'),'12345',2,model.directory/'bad.env')


def test_pki_validity_sans_explicit_renewal_and_material_owners(prep,tmp_path):
    from cryptography import x509
    tmp_path.chmod(0o700)
    prep.certificates(tmp_path,'postgresql,localhost,127.0.0.1',os.geteuid())
    cert=x509.load_pem_x509_certificate((tmp_path/'server.crt').read_bytes())
    assert cert.not_valid_after_utc>datetime.now(timezone.utc)+timedelta(days=396)
    old_ca=(tmp_path/'ca.crt').read_bytes();old_key=(tmp_path/'server.key').read_bytes()
    with pytest.raises(prep.Refused):prep.certificates(tmp_path,'postgresql',os.geteuid())
    prep.certificates(tmp_path,'postgresql,localhost,127.0.0.1',os.geteuid(),renew=True)
    assert (tmp_path/'ca.crt').read_bytes()==old_ca and (tmp_path/'server.key').read_bytes()==old_key
    token=tmp_path/'token';token.write_text('SYNTHETIC');token.chmod(0o600)
    prep.check_material([token],[tmp_path/'ca.crt'],os.geteuid(),tmp_path/'server.key',os.geteuid(),tmp_path/'server.crt','postgresql,127.0.0.1')
    with pytest.raises(prep.Refused):prep.check_material([token],[tmp_path/'ca.crt'],os.geteuid(),server_cert=tmp_path/'server.crt',expected_hosts='foreign.invalid')
    token.chmod(0o644)
    with pytest.raises(prep.Refused):prep.check_material([token],[tmp_path/'ca.crt'],os.geteuid())


def test_hba_is_tls_scram_and_dedicated_to_tools_database(prep):
    text=prep.hba('tools',['127.0.0.1/32'])
    assert 'trust' not in text and 'hostssl tools ' in text and 'scram-sha-256' in text
    assert text.endswith('host all all 0.0.0.0/0 reject\nhost all all ::/0 reject\n')
    with pytest.raises(prep.Refused):prep.hba('postgres',['127.0.0.1/32'])
    with pytest.raises(prep.Refused):prep.hba('tools\ntrust',['127.0.0.1/32'])


@pytest.mark.parametrize('source,configured,accepted',[
    ('172.28.0.1','172.28.0.1',True),('127.0.0.1','127.0.0.1',True),
    ('2001:db8:45::1','2001:db8:45::1',True),
    ('172.28.0.2','172.28.0.1',False),('2001:db8:45::2','2001:db8:45::1',False)])
def test_generated_cli_hba_allows_measured_source_through_provision_transport(prep,model,monkeypatch,capsys,source,configured,accepted):
    """Transport model only: not a PostgreSQL HBA parser or a native proof.

    Generate the actual CLI profile, then gate the real provision orchestration's
    sole mocked transport boundary by first-match TLS/database/role/source rules.
    On the parent, use its existing CLI: gateway/IPv6 fail before any mutation.
    """
    cidr=configured+('/32' if ipaddress.ip_address(configured).version==4 else '/128')
    output=model.directory/'pg_hba.conf'
    argv=['prepare_postgres.py','hba','--database','tools','--output',str(output)]
    if 'operator_cidrs' in inspect.signature(prep.hba).parameters:
        argv+=['--operator-cidr',cidr]
    monkeypatch.setattr(prep.sys,'argv',argv)
    assert prep.main()==0
    assert json.loads(capsys.readouterr().out)['status']=='ok'
    import psycopg
    original=psycopg.AsyncConnection.connect
    async def transport(**kwargs):
        for line in output.read_text().splitlines():
            fields=line.split()
            if len(fields)!=5 or fields[0] not in ('host','hostssl'):continue
            kind,databases,roles,network,method=fields
            if (('all' in databases.split(',') or kwargs['dbname'] in databases.split(','))
                    and ('all' in roles.split(',') or kwargs['user'] in roles.split(','))
                    and ipaddress.ip_address(source) in ipaddress.ip_network(network)
                    and (kind=='host' or kwargs['sslmode']=='verify-full')):
                if method=='scram-sha-256':return await original(**kwargs)
                break
        raise prep.Refused('Transport source rejected by generated profile')
    monkeypatch.setattr(psycopg.AsyncConnection,'connect',transport)
    args=(model.job('tools_prepare','postgres'),model.job('tools_prepare'),
          'tools',model.directory,model.directory,'12345')
    if not accepted:
        with pytest.raises(prep.Refused):asyncio.run(prep.provision(*args))
        assert not model.statements and not (model.directory/'prepare.pending.json').exists()
        return
    asyncio.run(prep.provision(*args))
    assert [row['dbname'] for row in model.connections]==['postgres','tools']
    assert (model.directory/'prepare.done.json').exists()
    assert model.password not in output.read_text()+' '.join(argv)


@pytest.mark.parametrize('cidrs',[[],[''],['not-a-cidr'],['172.28.0.1'],['0.0.0.0/0'],['::/0'],
                                 ['172.28.0.0/24'],['2001:db8::/64'],['0.0.0.0/32'],
                                 ['ff02::1/128'],['fe80::1%eth0/128'],['2001:0db8::1/128'],
                                 ['127.0.0.1/32','127.0.0.1/32']])
def test_hba_refuses_missing_invalid_broad_or_duplicate_sources_before_output(prep,model,monkeypatch,capsys,cidrs):
    output=model.directory/'pg_hba.conf'
    argv=['prepare_postgres.py','hba','--output',str(output)]
    for cidr in cidrs:argv+=['--operator-cidr',cidr]
    monkeypatch.setattr(prep.sys,'argv',argv)
    assert prep.main()==1
    assert 'incomplete' in capsys.readouterr().out
    assert not output.exists() and not model.reads and not model.statements


def test_admin_hba_never_joins_broad_app_rule(prep):
    text=prep.hba('tools',['172.28.0.1/32','2001:db8:45::1/128'])
    for line in text.splitlines():
        if line.startswith('host') and 'tools_prepare' in line:
            assert line.split()[3] in ('172.28.0.1/32','2001:db8:45::1/128')
    assert 'trust' not in text and 'samenet' not in text


def test_local_provisioner_closed_last_after_confirmed_install(prep,model):
    asyncio.run(prep.install(model.job('tools_files_install'),model.job('tools_access_install'),
        model.job('tools_prepare'),'12345',2,model.directory,model.directory/'admin.token','tenant','service',
        close_local_provisioner=True))
    assert len(model.children)==5
    assert model.statements[-1]=='ALTER ROLE tools_prepare NOLOGIN'
    assert 'FROM tools_prepare' in model.statements[-2] and 'REVOKE CONNECT' in model.statements[-2]
    assert (model.directory/'install.done.json').exists()


@pytest.mark.parametrize('user,close',[('tools_prepare',False),('external_admin',True)])
def test_invalid_local_closure_selection_refused_before_authority_or_mutation(prep,model,user,close):
    with pytest.raises(prep.Refused):
        asyncio.run(prep.install(model.job('tools_files_install'),model.job('tools_access_install'),
            model.job(user),'12345',2,model.directory,model.directory/'admin.token','tenant','service',
            close_local_provisioner=close))
    assert not model.reads and not model.connections and not model.children and not model.statements
    assert not (model.directory/'install.pending.json').exists()


def test_external_admin_not_retired(prep,model):
    asyncio.run(prep.install(model.job('tools_files_install'),model.job('tools_access_install'),
        model.job('external_admin'),'12345',2,model.directory,model.directory/'admin.token','tenant','service'))
    assert not any('ALTER ROLE external_admin' in row or 'ALTER ROLE tools_prepare' in row for row in model.statements)


@pytest.mark.parametrize('action',['initial-password','certificates'])
def test_missing_chown_capability_rejected_before_provider_or_any_material(prep,model,monkeypatch,action):
    original=Path.read_text
    def read(path,*args,**kwargs):
        if str(path)=='/proc/self/status':return 'CapEff:\t0000000000000000\n'
        return original(path,*args,**kwargs)
    monkeypatch.setattr(Path,'read_text',read)
    before=set(model.directory.iterdir())
    with pytest.raises(prep.Refused):
        if action=='initial-password':
            asyncio.run(prep.initial_password(model.job('tools_prepare','postgres'),model.directory/'password',os.geteuid()+1))
        else:prep.certificates(model.directory,'postgresql',os.geteuid()+1)
    assert set(model.directory.iterdir())==before and not model.reads and not model.connections


def test_chown_failure_removes_only_own_empty_exclusive_output(prep,model,monkeypatch):
    monkeypatch.setattr(prep,'check_owner_change',lambda uid:None)
    def denied(*args):raise PermissionError('synthetic filesystem owner refusal')
    monkeypatch.setattr(prep.os,'fchown',denied)
    output=model.directory/'password'
    with pytest.raises(PermissionError):
        asyncio.run(prep.initial_password(model.job('tools_prepare','postgres'),output,os.geteuid()+1))
    assert not output.exists() and not model.connections
    output.write_text('PREEXISTING');output.chmod(0o600)
    with pytest.raises(FileExistsError):
        asyncio.run(prep.initial_password(model.job('tools_prepare','postgres'),output,os.geteuid()+1))
    assert output.read_text()=='PREEXISTING'


@pytest.mark.parametrize('status',['Name: python\n','CapEff: not-hex\n',None])
def test_unverifiable_capability_fails_closed_before_secret_read(prep,model,monkeypatch,status):
    original=Path.read_text
    def read(path,*args,**kwargs):
        if str(path)=='/proc/self/status':
            if status is None:raise PermissionError('synthetic inaccessible status')
            return status
        return original(path,*args,**kwargs)
    monkeypatch.setattr(Path,'read_text',read)
    output=model.directory/'password'
    with pytest.raises(prep.Refused):
        asyncio.run(prep.initial_password(model.job('tools_prepare','postgres'),output,os.geteuid()+1))
    assert not output.exists() and not model.reads and not model.connections


def test_unconfirmed_closure_preserves_pending_without_replay_or_success(prep,model):
    model.fail_commit=True
    args=(model.job('tools_files_install'),model.job('tools_access_install'),model.job('tools_prepare'),
          '12345',2,model.directory,model.directory/'admin.token','tenant','service')
    with pytest.raises(RuntimeError):asyncio.run(prep.install(*args,close_local_provisioner=True))
    assert (model.directory/'install.pending.json').exists()
    assert not (model.directory/'install.done.json').exists()
    before=(len(model.statements),len(model.children))
    with pytest.raises(prep.Refused):asyncio.run(prep.install(*args,close_local_provisioner=True))
    assert before==(len(model.statements),len(model.children))


def test_documented_hba_and_local_install_argv_run_without_secret_environment(prep,model,monkeypatch,capsys):
    commands={}
    for block in (ROOT/'docs/postgres/standalone.md').read_text().split('```sh\n')[1:]:
        for line in block.split('```',1)[0].replace('\\\n',' ').splitlines():
            if line.startswith('python scripts/prepare_postgres.py '):
                argv=shlex.split(line)[1:]
                if argv[1] in ('hba','install'):commands[argv[1]]=argv
    replacements={'--operator-cidr':'172.28.0.1/32','--output':str(model.directory/'pg_hba.conf'),
        '--system-identifier':'12345','--timeline':'2','--state-dir':str(model.directory),
        '--token-file':str(model.directory/'admin.token'),'--tenant-id':'tenant','--service-id':'service'}
    for flag,role in [('--profile','tools_prepare'),('--files-profile','tools_files_install'),
                      ('--access-profile','tools_access_install')]:
        path=model.directory/(role+'-profile.json')
        prep.write_new(path,json.dumps(model.job(role)))
        replacements[flag]=str(path)
    before=dict(os.environ)
    for action in ('hba','install'):
        argv=commands[action]
        for flag,value in replacements.items():
            if flag in argv:argv[argv.index(flag)+1]=value
        assert model.password not in ' '.join(argv)
        monkeypatch.setattr(prep.sys,'argv',argv)
        assert prep.main()==0
        assert model.password not in capsys.readouterr().out
    assert dict(os.environ)==before and model.statements[-1]=='ALTER ROLE tools_prepare NOLOGIN'
    assert all(not any(key.startswith('PG') for key in env) for _,env in model.children)
