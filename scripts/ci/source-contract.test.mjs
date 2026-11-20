import {test} from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {readBuildConfig,validateBuildConfig} from '../source-contract.mjs';
import {validateBackendProvenance} from './backend-provenance.mjs';
const root=new URL('../../',import.meta.url);
const config=readBuildConfig(root);
test('source configuration binds the repository and locked dependencies',()=>{
  for(const patch of [{schema:2},{repository:'other/backend'},{rust:'stable'},{cargoLockSha256:'bad'}, {authUi:'native'}, {version:'latest'}])
    assert.throws(()=>validateBuildConfig({...config,...patch}));
});
test('promotion rejects mismatched repository, commit, recipe and package identity',()=>{
  const commit='a'.repeat(40),hash='b'.repeat(64);
  const metadata={schema:2,sourceRepository:config.repository,version:config.version,commit,recipeSha256:hash,
    compatibility:config.compatibility,authUi:'electron',platform:'linux',arch:'x64',
    archive:`xodus-nexus-backend-${config.version}-linux-x86_64.tar.xz`,archiveSha512:'c'.repeat(128),
    files:Object.fromEntries(['LICENSE','xodus-cli','xodus-service'].map(name=>[name,'d'.repeat(64)]))};
  const name=metadata.archive.replace('.tar.xz','.manifest.json');
  validateBackendProvenance(metadata,name,config,commit,hash);
  for(const patch of [{schema:1},{sourceRepository:'domsvoboda/xodus-nexus'},{commit:'e'.repeat(40)},
    {recipeSha256:'f'.repeat(64)}, {version:'0.0.1'}, {arch:'arm64'}, {authUi:'native'}, {archive:'other.tar.xz'},
    {files:{...metadata.files,'../other':'d'.repeat(64)}},{archiveSha512:'invalid'}])
      assert.throws(()=>validateBackendProvenance({...metadata,...patch},name,config,commit,hash));
});
test('required native regressions remain tests in the owned Rust source',()=>{
  const entries=JSON.parse(fs.readFileSync(new URL('scripts/ci/required-regressions.json',root)));
  assert.ok(entries.length>200);
  for(const {file,name} of entries){
    const source=fs.readFileSync(new URL(file,root),'utf8');
    assert.match(source,new RegExp('#\\[(?:tokio::)?test(?:\\([^\\]]*\\))?\\][\\s\\S]{0,300}?(?:async\\s+)?fn\\s+'+name+'\\s*\\('),name);
  }
});
test('account-free gates, keyring serialization and ignored bandwidth fixtures remain enabled',()=>{
  const plan=JSON.parse(fs.readFileSync(new URL('scripts/test-plan.json',root)));
  const has=(crate,filter)=>plan.some(args=>args[0]==='-p'&&args[1]===crate&&args[2]===filter);
  assert.ok(has('xodus-cli',undefined));
  for(const filter of ['credential_','account_state_','content_license_','smbios_','content_ticket_','xbox_delegation_ticket_','ticket_diagnostic_']) assert.ok(has('xodus',filter),filter);
  for(const filter of ['store_','account_metadata_','deadline_tests','connection::router::peer::tests','token_response_tests','pooling_tests']) assert.ok(has('xodus-service',filter),filter);
  for(const filter of ['streaming_','crypt::tests','streaming::tests','package_metadata']) assert.ok(has('msixvc',filter),filter);
  for(const filter of ['keyring_unlock_','keyring_create_','keyring_session_','keyring_persistence_'])
    assert.ok(plan.some(args=>args[1]==='xodus'&&args[2]===filter&&args.includes('--test-threads=1')));
  assert.ok(plan.some(args=>args[1]==='msixvc'&&args[2]==='streaming_bandwidth_'&&args.includes('--ignored')&&args.includes('--test-threads=1')));
});
test('only an explicit main dispatch builds candidates; source pushes run checks only',()=>{
  const workflow=fs.readFileSync(new URL('.github/workflows/backend.yml',root),'utf8');
  assert.match(workflow,/^on:\n(?: {2}.*\n)*? {2}workflow_dispatch:\n/m);
  assert.doesNotMatch(workflow,/^ {2}push:/m);
  assert.doesNotMatch(workflow,/pull_request:/);
  assert.match(workflow,/if: github\.ref == 'refs\/heads\/main'\n/);
  assert.match(workflow,/group: backend-\$\{\{ github\.ref \}\}/);
  assert.doesNotMatch(workflow,/github\.event\./);
  assert.doesNotMatch(workflow,/webkit|libgtk|libsoup/);
  const source=fs.readFileSync(new URL('.github/workflows/checks.yml',root),'utf8');
  assert.match(source,/branches: \[develop, main\]/);
  assert.match(source,/node scripts\/test-backend\.mjs/);
  assert.doesNotMatch(source,/scripts\/build-backend\.mjs|upload-artifact/);
  const release=fs.readFileSync(new URL('.github/workflows/release.yml',root),'utf8');
  assert.match(release,/if: github.ref == 'refs\/heads\/main' && inputs.approve_release/);
  assert.doesNotMatch(release,/\n  push:|\n  pull_request:|build-backend/);
});
