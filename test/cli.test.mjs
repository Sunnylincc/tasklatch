import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
const cli=new URL('../dist/cli.js',import.meta.url).pathname;
const run=(root,...args)=>spawnSync(process.execPath,[cli,...args,'--root',root],{encoding:'utf8'});
const git=(root,...args)=>spawnSync('git',args,{cwd:root,encoding:'utf8'});
test('init, test, and check work; a new disallowed write fails the check',()=>{
  const root=mkdtempSync(join(tmpdir(),'tasklatch-cli-'));
  try {
    let r=run(root,'init');
    assert.equal(r.status,0,r.stderr);
    assert.equal(run(root,'init').status,2,'init should never overwrite files');
    r=run(root,'test'); assert.equal(r.status,0,r.stdout+r.stderr);
    r=run(root,'check'); assert.equal(r.status,0,r.stdout+r.stderr);
    const manifest=JSON.parse(readFileSync(join(root,'.tasklatch/manifest.json'),'utf8'));
    manifest.exposures.push({agent:'example-research-agent',task:'review-code',capability:'github.repository.write'});
    writeFileSync(join(root,'.tasklatch/manifest.json'),JSON.stringify(manifest));
    r=run(root,'check'); assert.equal(r.status,1,r.stdout+r.stderr);
    assert.match(r.stdout,/DENY/);
  } finally { rmSync(root,{recursive:true,force:true}); }
});
test('git baseline regression catches privilege escalation',()=>{
  const root=mkdtempSync(join(tmpdir(),'tasklatch-diff-'));
  try {
    assert.equal(run(root,'init').status,0);
    assert.equal(git(root,'init').status,0);
    assert.equal(git(root,'add','.').status,0);
    const c=git(root,'-c','user.name=Unit Test','-c','user.email=unit-test@example.invalid','commit','-m','Initial test fixture');
    assert.equal(c.status,0,c.stderr);
    const base=git(root,'rev-parse','HEAD').stdout.trim();
    const path=join(root,'.tasklatch/manifest.json');
    const manifest=JSON.parse(readFileSync(path,'utf8'));
    manifest.exposures.push({agent:'example-research-agent',task:'review-code',capability:'github.repository.write'});
    writeFileSync(path,JSON.stringify(manifest));
    const r=run(root,'diff','--base',base,'--format','json');
    assert.equal(r.status,1,r.stdout+r.stderr);
    assert.equal(JSON.parse(r.stdout).added[0].decision,'deny');
  } finally { rmSync(root,{recursive:true,force:true}); }
});
test('rejects traversal and unsafe git revisions',()=>{
  const root=mkdtempSync(join(tmpdir(),'tasklatch-guard-'));
  try {
    assert.equal(run(root,'init').status,0);
    assert.equal(run(root,'check','--policy','../outside.yaml').status,2);
    assert.equal(run(root,'diff','--base','--bad').status,2);
  } finally { rmSync(root,{recursive:true,force:true}); }
});
test('missing inventory never reports safe success',()=>{
  const root=mkdtempSync(join(tmpdir(),'tasklatch-empty-'));
  try {
    assert.equal(run(root,'init').status,0);
    const file=join(root,'.tasklatch/manifest.json');
    writeFileSync(file,JSON.stringify({version:1,exposures:[]}));
    const r=run(root,'check');
    assert.equal(r.status,1);
    assert.match(r.stdout,/does not imply safety/);
  } finally { rmSync(root,{recursive:true,force:true}); }
});
