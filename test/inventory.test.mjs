import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { scanSources, workingTree } from '../dist/inventory.js';

function fixture(fn) {
  const root=mkdtempSync(join(tmpdir(),'tasklatch-test-'));
  const write=(p,contents)=> { mkdirSync(dirname(join(root,p)),{recursive:true}); writeFileSync(join(root,p),contents); };
  try { fn({root,write}); } finally { rmSync(root,{recursive:true,force:true}); }
}
test('discovers manifest, Claude rules, MCP names, and workflow scopes without launching tools', () => {
  fixture(({root,write})=>{
    const secret='PRIVATE_MOCK_TOKEN_SHOULD_NOT_APPEAR';
    write('.tasklatch/manifest.json',JSON.stringify({version:1,exposures:[{agent:'research-agent',task:'review-code',capability:'github.repository.read'}]}));
    write('.claude/settings.json', JSON.stringify({permissions:{allow:['Read(./src/**)','Bash(npm test)','mcp__github__delete_repository']}}));
    write('.mcp.json',JSON.stringify({mcpServers:{github:{command:'node',env:{GITHUB_TOKEN:secret}}}}));
    write('.github/workflows/ci.yml','name: CI\non: pull_request\npermissions:\n  contents: read\n  id-token: write\njobs:\n  test:\n    runs-on: ubuntu-latest\n');
    const report=scanSources(workingTree(root));
    assert.ok(report.exposures.some(x=>x.agent==='research-agent'&&x.capability==='github.repository.read'));
    assert.ok(report.exposures.some(x=>x.capability==='shell.execute.scoped'));
    assert.ok(report.exposures.some(x=>x.capability==='mcp.server.github.tools_unknown'&&x.kind==='unknown'));
    assert.ok(report.exposures.some(x=>x.capability==='github.repository.read'));
    assert.ok(report.exposures.some(x=>x.capability==='github.oidc.write'));
    assert.ok(!JSON.stringify(report).includes(secret));
  });
});
test('MCP server is never treated as verified effective access', () => {
  fixture(({root,write})=>{
    write('.mcp.json',JSON.stringify({mcpServers:{payments:{url:'https://example.invalid/mcp'}}}));
    const item=scanSources(workingTree(root)).exposures[0];
    assert.equal(item.kind,'unknown');
    assert.match(item.capability,/tools_unknown/);
  });
});
test('no files is reported as unknown coverage', () => {
  fixture(({root})=> {
    const scan=scanSources(workingTree(root));
    assert.equal(scan.exposures.length,0);
    assert.ok(scan.warnings.some(w=>w.includes('does not imply safety')));
  });
});
test('does not follow symlinked manifests', () => {
  fixture(({root,write})=>{
    write('private.json','{}');
    mkdirSync(join(root,'.tasklatch'),{recursive:true});
    symlinkSync(join(root,'private.json'),join(root,'.tasklatch/manifest.json'));
    assert.throws(()=>scanSources(workingTree(root)),/Unsafe source file/);
  });
});

test('scans every supported workflow instead of silently stopping at 300 files', () => {
  fixture(({root,write})=>{
    for (let i=0; i<315; i++) write(`.github/workflows/w${String(i).padStart(3,'0')}.yml`, 'permissions:\n  contents: read\n');
    const scan=scanSources(workingTree(root));
    assert.equal(scan.files.length,315);
    assert.equal(scan.exposures.length,315);
    assert.ok(scan.files.includes('.github/workflows/w314.yml'));
    assert.deepEqual(scan.securityIssues,[]);
  });
});
test('unreadable enumerated sources are explicitly treated as incomplete', () => {
  const scan=scanSources({list:()=>['.mcp.json'],read:()=>undefined});
  assert.match(scan.securityIssues[0],/Incomplete scan/);
  assert.match(scan.warnings[0],/Incomplete scan/);
});
test('missing workflow permissions are blocking but fully job-scoped permissions are recognized', () => {
  fixture(({root,write})=>{
    write('.github/workflows/unsafe.yml','name: Unsafe\njobs:\n  build:\n    runs-on: ubuntu-latest\n');
    const scan=scanSources(workingTree(root));
    assert.match(scan.securityIssues[0],/inherit unknown defaults/);
  });
  fixture(({root,write})=>{
    write('.github/workflows/scoped.yml','name: Scoped\njobs:\n  build:\n    permissions:\n      contents: read\n    runs-on: ubuntu-latest\n');
    const scan=scanSources(workingTree(root));
    assert.deepEqual(scan.securityIssues,[]);
    assert.deepEqual(scan.workflowPermissions['.github/workflows/scoped.yml'],['job:build']);
  });
});


test('quoted and unquoted job names are both counted when checking inherited token permissions', () => {
  fixture(({root,write})=>{
    write('.github/workflows/mixed.yml', 'name: Mixed\njobs:\n  build:\n    permissions:\n      contents: read\n    runs-on: ubuntu-latest\n  "release":\n    runs-on: ubuntu-latest\n');
    const scan=scanSources(workingTree(root));
    assert.deepEqual(scan.workflowPermissions['.github/workflows/mixed.yml'], ['job:build']);
    assert.ok(scan.securityIssues.some(s=>s.includes('jobs without explicit permissions: release')));
  });
  fixture(({root,write})=>{
    write('.github/workflows/scoped-quoted.yml', 'jobs:\n  build:\n    permissions:\n      contents: read\n  "release":\n    permissions:\n      contents: read\n  \'deploy\':\n    permissions:\n      contents: read\n');
    const scan=scanSources(workingTree(root));
    assert.deepEqual(scan.securityIssues, []);
    assert.deepEqual(scan.workflowPermissions['.github/workflows/scoped-quoted.yml'], ['job:build','job:deploy','job:release']);
  });
});

test('unrecognized jobs declarations block the scan rather than disappearing', () => {
  fixture(({root,write})=>{
    write('.github/workflows/unsupported.yml', 'jobs:\n  build:\n    permissions:\n      contents: read\n  "release build":\n    runs-on: ubuntu-latest\n');
    const scan=scanSources(workingTree(root));
    assert.ok(scan.securityIssues.some(s=>s.includes('unrecognized job declaration')));
  });
  fixture(({root,write})=>{
    write('.github/workflows/inline.yml', 'permissions:\n  contents: read\njobs: { build: { runs-on: ubuntu-latest } }\n');
    const scan=scanSources(workingTree(root));
    assert.ok(scan.securityIssues.some(s=>s.includes('unsupported inline jobs declaration')));
  });
});
