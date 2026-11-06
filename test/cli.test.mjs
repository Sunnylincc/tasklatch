import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, rmSync, readFileSync, writeFileSync } from 'node:fs';
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

test('removing explicit workflow permissions fails the default diff and reports the regression',()=>{
  const root=mkdtempSync(join(tmpdir(),'tasklatch-workflow-regression-'));
  try {
    assert.equal(run(root,'init').status,0);
    mkdirSync(join(root,'.github/workflows'),{recursive:true});
    const workflow=join(root,'.github/workflows/ci.yml');
    writeFileSync(workflow,'name: CI\npermissions:\n  contents: read\njobs:\n  test:\n    runs-on: ubuntu-latest\n');
    assert.equal(git(root,'init').status,0);
    assert.equal(git(root,'add','.').status,0);
    assert.equal(git(root,'-c','user.name=Unit Test','-c','user.email=unit-test@example.invalid','commit','-m','Baseline').status,0);
    const base=git(root,'rev-parse','HEAD').stdout.trim();
    writeFileSync(workflow,'name: CI\njobs:\n  test:\n    runs-on: ubuntu-latest\n');
    const r=run(root,'diff','--base',base,'--format','json');
    assert.equal(r.status,1,r.stdout+r.stderr);
    const report=JSON.parse(r.stdout);
    assert.ok(report.permissionRegressions.some(x=>x.includes('workflow')));
    assert.ok(report.securityIssues.some(x=>x.includes('inherit unknown defaults')));
    const check=run(root,'check','--format','json');
    assert.equal(check.status,1);
    assert.ok(JSON.parse(check.stdout).securityIssues.length);
  } finally { rmSync(root,{recursive:true,force:true}); }
});
test('removing a job-level permission block fails even when another job remains scoped',()=>{
  const root=mkdtempSync(join(tmpdir(),'tasklatch-job-regression-'));
  try {
    assert.equal(run(root,'init').status,0);
    mkdirSync(join(root,'.github/workflows'),{recursive:true});
    const workflow=join(root,'.github/workflows/ci.yml');
    const initial='name: CI\njobs:\n  build:\n    permissions:\n      contents: read\n    runs-on: ubuntu-latest\n  test:\n    permissions:\n      contents: read\n    runs-on: ubuntu-latest\n';
    writeFileSync(workflow,initial);
    assert.equal(git(root,'init').status,0);assert.equal(git(root,'add','.').status,0);
    assert.equal(git(root,'-c','user.name=Unit Test','-c','user.email=unit-test@example.invalid','commit','-m','Baseline').status,0);
    const base=git(root,'rev-parse','HEAD').stdout.trim();
    writeFileSync(workflow,initial.replace('  build:\n    permissions:\n      contents: read','  build:'));
    const r=run(root,'diff','--base',base,'--format','json');
    assert.equal(r.status,1,r.stdout+r.stderr);
    assert.ok(JSON.parse(r.stdout).permissionRegressions.some(x=>x.includes('job:build')));
  } finally { rmSync(root,{recursive:true,force:true}); }
});
test('check and diff scan all 315 supported workflow files',()=>{
  const root=mkdtempSync(join(tmpdir(),'tasklatch-many-workflows-'));
  try {
    assert.equal(run(root,'init').status,0);
    mkdirSync(join(root,'.github/workflows'),{recursive:true});
    for(let i=0;i<315;i++) writeFileSync(join(root,`.github/workflows/w${String(i).padStart(3,'0')}.yml`),'permissions:\n  contents: read\n');
    const scan=run(root,'scan','--format','json');
    assert.equal(scan.status,0,scan.stderr);
    assert.equal(JSON.parse(scan.stdout).files.length,316);
    const check=run(root,'check','--format','json');
    assert.equal(check.status,0,check.stdout+check.stderr);
    assert.equal(JSON.parse(check.stdout).scannedFiles.length,316);
    assert.equal(git(root,'init').status,0);assert.equal(git(root,'add','.').status,0);
    assert.equal(git(root,'-c','user.name=Unit Test','-c','user.email=unit-test@example.invalid','commit','-m','Baseline').status,0);
    const base=git(root,'rev-parse','HEAD').stdout.trim();
    const diff=run(root,'diff','--base',base,'--format','json');
    assert.equal(diff.status,0,diff.stdout+diff.stderr);
    assert.equal(JSON.parse(diff.stdout).retained,316);
  } finally { rmSync(root,{recursive:true,force:true}); }
});

test('a permission regression in workflow 315 is still detected against the Git baseline',()=>{
  const root=mkdtempSync(join(tmpdir(),'tasklatch-late-workflow-'));
  try {
    assert.equal(run(root,'init').status,0);
    mkdirSync(join(root,'.github/workflows'),{recursive:true});
    for(let i=0;i<315;i++) writeFileSync(join(root,`.github/workflows/w${String(i).padStart(3,'0')}.yml`),'permissions:\n  contents: read\n');
    assert.equal(git(root,'init').status,0);assert.equal(git(root,'add','.').status,0);
    assert.equal(git(root,'-c','user.name=Unit Test','-c','user.email=unit-test@example.invalid','commit','-m','Baseline').status,0);
    const base=git(root,'rev-parse','HEAD').stdout.trim();
    writeFileSync(join(root,'.github/workflows/w314.yml'),'name: Later workflow\njobs:\n  unsafe:\n    runs-on: ubuntu-latest\n');
    const result=run(root,'diff','--base',base,'--format','json');
    assert.equal(result.status,1,result.stdout+result.stderr);
    assert.ok(JSON.parse(result.stdout).permissionRegressions.some(x=>x.includes('w314.yml')));
  }finally{rmSync(root,{recursive:true,force:true});}
});
