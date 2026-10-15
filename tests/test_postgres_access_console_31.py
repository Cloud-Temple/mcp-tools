"""Contrat JS de la console PG ; DOM contrôlé, aucun navigateur ni réseau."""
from pathlib import Path
import shutil
import subprocess

import pytest


@pytest.mark.skipif(shutil.which('node') is None, reason='Node requis pour le contrat JavaScript')
def test_console_targets_reference_and_captured_version_and_explicit_identity():
    root = Path(__file__).resolve().parents[1]
    program = r'''
const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const calls = [], elements = new Map();
const row = {client_name:'reader',token_prefix:'abcdef123456',version:4,permissions:['access'],tool_ids:['files']};
function element(id) {
  if (!elements.has(id)) elements.set(id, {value:'',innerHTML:'',disabled:false,
    focus(){},classList:{add(){},remove(){}},closest(){return {hidden:false,after(){}};}});
  return elements.get(id);
}
const context = vm.createContext({console, app:{me:{access_backend:'postgres'},tokens:[row]},
  document:{getElementById:element,querySelector(){return {value:'access'};},querySelectorAll(){return [];},createElement(){return {}; }},
  esc(value){return String(value ?? '');},fmtDate(value){return String(value ?? '');},showToast(){},showModal(){},hideModal(){}});
for (const file of ['api.js','tokens.js']) vm.runInContext(fs.readFileSync('src/mcp_tools/static/js/'+file,'utf8'),context);
context.adminFetch = async (path, options={}) => {
  calls.push({path,...options});
  if (options.method==='POST') return {status:'success',token:'CREATION-ONLY'};
  if (options.method) return {status:'success'};
  if (path==='/admin/api/tokens') return {status:'success',tokens:[row],next_cursor:'opaque-page'};
  return {status:'success',...row};
};
(async()=>{
  vm.runInContext("toolPickerGetSelected = () => ['files']",context);
  await vm.runInContext("showEditTokenForm('abcdef123456')",context);
  row.version = 99;
  await vm.runInContext("doUpdateToken('abcdef123456')",context);
  const update = calls.find(c=>c.method==='PUT');
  assert.equal(update.path,'/admin/api/tokens/abcdef123456');
  assert.equal(JSON.parse(update.body).expected_version,4);
  assert.ok(!('email' in JSON.parse(update.body)));
  await vm.runInContext("apiTokensRevoke('abcdef123456', 99)",context);
  assert.ok(calls.at(-1).path.endsWith('?expected_version=99'));
  await vm.runInContext('showCreateTokenForm()',context);
  for (const [id,value] of Object.entries({tokenClientName:'new-reader',tokenTenant:'tenant',tokenService:'tools',tokenActor:'',tokenExpiresDays:'90',tokenEmail:'legacy@example.invalid'})) element(id).value=value;
  await vm.runInContext('createToken()',context);
  const create = JSON.parse(calls.find(c=>c.method==='POST').body);
  assert.equal(create.tenant_id,'tenant');assert.equal(create.service_id,'tools');
  assert.ok(!('email' in create));
  assert.ok(vm.runInContext('renderTokensView()',context).includes('Page suivante'));
  context.app.me.access_backend='s3';
  await vm.runInContext("apiTokensRevoke('legacy-name', 99)",context);
  assert.equal(calls.at(-1).path,'/admin/api/tokens/legacy-name');
})().catch(error=>{console.error(error);process.exitCode=1;});
'''
    result = subprocess.run(['node', '-e', program], cwd=root, capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
