import test from 'node:test';
import assert from 'node:assert/strict';
import { parsePolicy } from '../dist/policy.js';
import { diffSnapshots, check, shouldFail } from '../dist/analysis.js';
const mk = (capability) => ({agent:'example-research-agent', task:'review-code', capability, source:'.tasklatch/manifest.json', kind:'declared'});
const p = (allow) => parsePolicy(`version: 1\ndefaults:\n  unlisted: deny\nagents:\n  example-research-agent:\n    tasks:\n      review-code:\n        allow:\n${allow.map(x=>`          - ${x}`).join('\n')}\n        deny:\n          - github.repository.delete`);
test('regression flags new unauthorized capability',()=>{
  const oldPolicy=p(['github.repository.read']);
  const base={exposures:[mk('github.repository.read')],warnings:[],files:[]};
  const head={exposures:[mk('github.repository.read'),mk('github.repository.write')],warnings:[],files:[]};
  const report=diffSnapshots(base,head,oldPolicy,oldPolicy);
  assert.equal(report.added.length,1);
  assert.equal(report.added[0].decision,'deny');
  assert.equal(shouldFail(report.added,'deny'),true);
});
test('policy changes cannot silently grant a newly exposed capability',()=>{
  const base={exposures:[],warnings:[],files:[]};
  const head={exposures:[mk('github.repository.write')],warnings:[],files:[]};
  const report=diffSnapshots(base,head,p(['github.repository.read']),p(['github.repository.read','github.repository.write']));
  assert.equal(report.added[0].decision,'deny');
  assert.ok(report.contractExpansions.some(x=>x.pattern==='github.repository.write'));
});
test('unknown MCP capabilities never become verified allow',()=>{
  const policy=p(['mcp.server.github.tools_unknown']);
  const report=check({exposures:[{...mk('mcp.server.github.tools_unknown'),kind:'unknown'}],files:[],warnings:[]},policy);
  assert.equal(report[0].decision,'unknown');
});
test('removing an explicit deny or approval rule triggers policy review',()=>{
  const before=p(['github.repository.read']);
  const after=parsePolicy(`version: 1\ndefaults:\n  unlisted: deny\nagents:\n  example-research-agent:\n    tasks:\n      review-code:\n        allow:\n          - github.repository.read\n        require_approval:\n          - github.pull_request.merge`);
  const empty={exposures:[],warnings:[],files:[]};
  const report=diffSnapshots(empty,empty,before,after);
  assert.ok(report.contractExpansions.some(x=>x.change==='deny_removed'));
});
test('removing a task contract triggers policy review',()=>{
  const old=p(['github.repository.read']);
  const next=parsePolicy(`version: 1\ndefaults:\n  unlisted: deny\nagents:\n  other:\n    tasks:\n      safe:\n        deny:\n          - github.repository.write`);
  const empty={exposures:[],warnings:[],files:[]};
  const report=diffSnapshots(empty,empty,old,next);
  assert.ok(report.contractExpansions.some(x=>x.change==='contract_removed'));
});
