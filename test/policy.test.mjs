import test from 'node:test';
import assert from 'node:assert/strict';
import { parsePolicy, decide, matches, validateCases } from '../dist/policy.js';
const policy = parsePolicy(`version: 1
defaults:
  unlisted: deny
agents:
  research-agent:
    tasks:
      review-code:
        allow:
          - github.repository.read
          - filesystem.read.*
        deny:
          - github.repository.write
        require_approval:
          - github.pull_request.merge
`);
test('task-scoped contract decisions', () => {
  assert.equal(decide(policy,'research-agent','review-code','github.repository.read').decision,'allow');
  assert.equal(decide(policy,'research-agent','review-code','github.repository.write').decision,'deny');
  assert.equal(decide(policy,'research-agent','review-code','github.pull_request.merge').decision,'approval');
  assert.equal(decide(policy,'research-agent','review-code','vercel.production.deploy').decision,'deny');
  assert.equal(decide(policy,'research-agent','unknown','github.repository.read').decision,'unknown');
  assert.equal(decide(policy,'different-agent','review-code','github.repository.read').decision,'unknown');
});
test('safe glob matching is anchored and literal dots are not regex wildcards', () => {
  assert.equal(matches('filesystem.read.*','filesystem.read.file'),true);
  assert.equal(matches('github.repository.read','githubXrepositoryXread'),false);
  assert.equal(matches('github.repository.read','a-github.repository.read'),false);
  assert.equal(matches('github.*.read','github.repository.read'),true);
});
test('rejects duplicate keys and unsupported YAML constructs', () => {
  assert.throws(() => parsePolicy('version: 1\nversion: 1'), /duplicate key/);
  assert.throws(() => parsePolicy('version: 1\ndefaults: {unlisted: deny}'), /unsupported scalar/);
  assert.throws(() => parsePolicy('version: 1\ndefaults:\n  unlisted: &anchor deny'), /unsupported scalar/);
});
test('rejects unknown fields and invalid contract forms', () => {
  assert.throws(() => parsePolicy(`version: 1\ndefaults:\n  unlisted: allow\nagents:\n  example:\n    tasks:\n      job:\n        allow:\n          - x`), /deny or unknown/);
  assert.throws(() => parsePolicy(`version: 1\ndefaults:\n  unlisted: deny\nagents:\n  example:\n    tasks:\n      job:\n        allow:\n          - "x;cat /etc/passwd"`), /invalid capability pattern/);
});
test('validates policy cases', () => {
  assert.equal(validateCases([{agent:'a',task:'t',capability:'x',expected:'deny'}]).length,1);
  assert.throws(()=> validateCases([{agent:'a',task:'t',capability:'x',expected:'GRANT'}]),/invalid expected/);
});
test('rejects forbidden object prototype keys',()=>{
  assert.throws(()=>parsePolicy(`version: 1\ndefaults:\n  unlisted: deny\nagents:\n  __proto__:\n    tasks:\n      review:\n        allow:\n          - x`),/forbidden key/);
});
