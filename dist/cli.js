#!/usr/bin/env node
import { existsSync, mkdirSync, readFileSync, writeFileSync, statSync } from 'node:fs';
import { dirname, resolve, relative } from 'node:path';
import { check, diffSnapshots, shouldFail } from './analysis.js';
import { scanSources, workingTree, gitRevision } from './inventory.js';
import { decide, parsePolicy, validateCases } from './policy.js';
const HELP = `TaskLatch v0.1 — task-aware authorization checks for AI agents

Usage:
  tasklatch init [--root DIR]
  tasklatch scan [--root DIR] [--format text|json]
  tasklatch check [--root DIR] [--policy FILE] [--fail-on deny|approval|unknown] [--format text|json|markdown]
  tasklatch diff --base GIT_REF [--root DIR] [--policy FILE] [--fail-on deny|approval|unknown] [--format text|json|markdown]
  tasklatch test [--root DIR] [--policy FILE] [--cases FILE]

No tools, MCP servers, prompts, or external commands from discovered configuration are executed.
Scan results are static, best-effort evidence, not proof of runtime enforcement.`;
function args(argv) {
    const [cmd, ...rest] = argv;
    if (!cmd || cmd === '--help' || cmd === '-h')
        return { cmd: 'help', opts: {} };
    const opts = {};
    for (let i = 0; i < rest.length; i++) {
        const arg = rest[i];
        if (!arg.startsWith('--'))
            throw new Error(`Unexpected argument: ${arg}`);
        const name = arg.slice(2);
        if (!['root', 'policy', 'cases', 'base', 'format', 'fail-on'].includes(name))
            throw new Error(`Unknown option: ${arg}`);
        if (opts[name] !== undefined)
            throw new Error(`Duplicate option: ${arg}`);
        if (i + 1 >= rest.length || rest[i + 1].startsWith('--'))
            throw new Error(`Missing value for ${arg}`);
        opts[name] = rest[++i];
    }
    return { cmd, opts };
}
function inside(root, path) {
    const full = resolve(root, path);
    const rel = relative(root, full);
    if (rel === '..' || rel.startsWith('../') || rel.startsWith('..\\') || rel.startsWith('/'))
        throw new Error('Configuration path escapes repository root');
    return full;
}
function readPolicy(root, name, optional = false) {
    const file = inside(root, name);
    if (!existsSync(file)) {
        if (optional)
            return undefined;
        throw new Error(`Policy not found: ${name}. Run tasklatch init, then configure agent contracts.`);
    }
    if (statSync(file).size > 512 * 1024)
        throw new Error('Policy file exceeds safety limit');
    return parsePolicy(readFileSync(file, 'utf8'));
}
function readBasePolicy(root, base, name) {
    // Explicitly scoped: only files inside the repository are allowed.
    const canonical = relative(root, inside(root, name)).replaceAll('\\', '/');
    const reader = gitRevision(root, base);
    // The policy file is not discovered as inventory, so read via git directly.
    const { execFileSync } = requirelessChildProcess();
    try {
        return parsePolicy(execFileSync('git', ['show', `${base}:${canonical}`], { cwd: root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], maxBuffer: 600000 }));
    }
    catch (error) {
        // Missing file is allowed for the initial policy introduction; malformed YAML is not.
        const stderr = String(error.stderr || '');
        if (/does not exist in|exists on disk, but not in|path .* does not exist/i.test(stderr))
            return undefined;
        if (error instanceof Error && /Policy|YAML|agent|defaults|version/.test(error.message))
            throw error;
        throw new Error(`Unable to read baseline policy (${name}) from ${base}`);
    }
}
// Kept separate for import clarity and zero third-party runtime dependencies.
function requirelessChildProcess() {
    return nodeChildProcess;
}
import * as nodeChildProcess from 'node:child_process';
function formatFinding(item) {
    return `${item.decision.toUpperCase().padEnd(8)} ${item.agent}/${item.task} ${item.capability} [${item.kind}] (${item.source}) — ${item.reason}`;
}
const escapeMd = (s) => s.replaceAll('|', '\\|').replaceAll('\n', ' ').replaceAll('`', "'");
function mdTable(findings) {
    if (!findings.length)
        return 'No capability findings. This does not prove that the agent is safe.\n';
    return [
        '| Status | Agent / task | Capability | Evidence |',
        '| --- | --- | --- | --- |',
        ...findings.map(f => `| ${escapeMd(f.decision.toUpperCase())} | ${escapeMd(f.agent)}/${escapeMd(f.task)} | ${escapeMd(f.capability)} | ${escapeMd(f.kind)}; ${escapeMd(f.source)} |`)
    ].join('\n') + '\n';
}
function renderCheck(snapshot, findings, format) {
    if (format === 'json') {
        console.log(JSON.stringify({ findings, warnings: snapshot.warnings, securityIssues: snapshot.securityIssues ?? [], scannedFiles: snapshot.files }, null, 2));
        return;
    }
    if (format === 'markdown') {
        console.log('## TaskLatch authorization check\n\n' + mdTable(findings) + '\n' + (snapshot.securityIssues?.length ? '**Blocking security issues:**\n' + snapshot.securityIssues.map(w => `- ${escapeMd(w)}`).join('\n') + '\n' : '') + snapshot.warnings.map(w => `- ${escapeMd(w)}`).join('\n') + '\n\n*Static checks only; not runtime enforcement.*');
        return;
    }
    console.log(`TaskLatch: ${findings.length} capability exposure(s); ${snapshot.files.length} scanned file(s)`);
    for (const f of findings)
        console.log(formatFinding(f));
    for (const w of snapshot.warnings)
        console.log(`WARN: ${w}`);
    for (const issue of snapshot.securityIssues ?? [])
        console.log(`SECURITY ERROR: ${issue}`);
}
function renderDiff(report, format) {
    if (format === 'json') {
        console.log(JSON.stringify(report, null, 2));
        return;
    }
    if (format === 'markdown') {
        console.log('## TaskLatch permission regression report\n\n' +
            `New: ${report.added.length} | Removed: ${report.removed.length} | Retained: ${report.retained}\n\n` +
            mdTable(report.added) + '\n' +
            (report.permissionRegressions.length ? '**GitHub workflow permission regressions (blocking):**\n' + report.permissionRegressions.map(x => `- ${escapeMd(x)}`).join('\n') + '\n\n' : '') +
            (report.securityIssues.length ? '**Unresolved security coverage (blocking):**\n' + report.securityIssues.map(x => `- ${escapeMd(x)}`).join('\n') + '\n\n' : '') +
            (report.contractExpansions.length ? '**Potential policy weakenings requiring review:**\n' + report.contractExpansions.map(x => `- ${escapeMd(x.agent)}/${escapeMd(x.task)} (${escapeMd(x.change)}): ${escapeMd(x.pattern)}`).join('\n') : 'No potential policy weakening detected.') + '\n\n' +
            report.warnings.map(w => `- ${escapeMd(w)}`).join('\n') + '\n\n*No actual MCP servers or external tools were executed.*');
        return;
    }
    console.log(`TaskLatch diff: ${report.added.length} new, ${report.removed.length} removed, ${report.retained} retained`);
    for (const f of report.added)
        console.log('+ ' + formatFinding(f));
    for (const e of report.removed)
        console.log(`- ${e.agent}/${e.task} ${e.capability}`);
    for (const e of report.contractExpansions)
        console.log(`POLICY REVIEW: ${e.agent}/${e.task} ${e.change} ${e.pattern}`);
    for (const regression of report.permissionRegressions)
        console.log(`PERMISSION REGRESSION: ${regression}`);
    for (const issue of report.securityIssues)
        console.log(`SECURITY ERROR: ${issue}`);
    for (const warning of report.warnings)
        console.log(`WARN: ${warning}`);
}
function init(root) {
    const files = {
        '.tasklatch/policy.yaml': `# Example contract. Replace the demo agent/task with your real identities.\nversion: 1\ndefaults:\n  unlisted: deny\nagents:\n  example-research-agent:\n    tasks:\n      review-code:\n        allow:\n          - github.repository.read\n        deny:\n          - github.repository.write\n          - github.repository.delete\n          - vercel.production.deploy\n        require_approval:\n          - github.pull_request.merge\n`,
        '.tasklatch/manifest.json': JSON.stringify({ version: 1, exposures: [{ agent: 'example-research-agent', task: 'review-code', capability: 'github.repository.read' }] }, null, 2) + '\n',
        '.tasklatch/cases.json': JSON.stringify([
            { name: 'Read is allowed', agent: 'example-research-agent', task: 'review-code', capability: 'github.repository.read', expected: 'allow' },
            { name: 'Write is denied', agent: 'example-research-agent', task: 'review-code', capability: 'github.repository.write', expected: 'deny' },
            { name: 'Merging needs approval', agent: 'example-research-agent', task: 'review-code', capability: 'github.pull_request.merge', expected: 'approval' }
        ], null, 2) + '\n'
    };
    const collisions = Object.keys(files).filter(rel => existsSync(inside(root, rel)));
    if (collisions.length)
        throw new Error('Initialization stopped to avoid overwriting existing files: ' + collisions.join(', '));
    for (const [rel, content] of Object.entries(files)) {
        const target = inside(root, rel);
        mkdirSync(dirname(target), { recursive: true });
        writeFileSync(target, content, { flag: 'wx', mode: 0o644 });
        console.log(`Created ${rel}`);
    }
    console.log('IMPORTANT: Example permissions are not auto-discovered. Replace the manifest and policy with actual agent configuration.');
}
function main() {
    const { cmd, opts } = args(process.argv.slice(2));
    if (cmd === 'help') {
        console.log(HELP);
        return;
    }
    if (!['init', 'scan', 'check', 'diff', 'test'].includes(cmd))
        throw new Error(`Unknown command: ${cmd}\n${HELP}`);
    const root = resolve(opts.root ?? '.');
    const format = opts.format ?? 'text';
    if (!['text', 'json', 'markdown'].includes(format))
        throw new Error('Invalid --format');
    const failOn = (opts['fail-on'] ?? 'deny');
    if (!['deny', 'approval', 'unknown'].includes(failOn))
        throw new Error('Invalid --fail-on');
    const policyName = opts.policy ?? '.tasklatch/policy.yaml';
    if (cmd === 'init') {
        init(root);
        return;
    }
    if (cmd === 'test') {
        const policy = readPolicy(root, policyName);
        const file = inside(root, opts.cases ?? '.tasklatch/cases.json');
        const cases = validateCases(JSON.parse(readFileSync(file, 'utf8')));
        let failures = 0;
        for (const c of cases) {
            const actual = decide(policy, c.agent, c.task, c.capability).decision;
            const pass = actual === c.expected;
            if (!pass)
                failures++;
            console.log(`${pass ? 'PASS' : 'FAIL'} ${c.name ?? `${c.agent}/${c.task} ${c.capability}`} (expected ${c.expected}, got ${actual})`);
        }
        console.log(`${cases.length - failures}/${cases.length} policy cases passed; simulated decisions only`);
        if (failures || cases.length === 0)
            process.exitCode = 1;
        return;
    }
    const snapshot = scanSources(workingTree(root));
    if (cmd === 'scan') {
        if (format === 'json')
            console.log(JSON.stringify(snapshot, null, 2));
        else
            for (const e of snapshot.exposures)
                console.log(`${e.agent}/${e.task} ${e.capability} [${e.kind}] (${e.source})`);
        for (const warning of snapshot.warnings)
            if (format !== 'json')
                console.log('WARN: ' + warning);
        for (const issue of snapshot.securityIssues ?? [])
            if (format !== 'json')
                console.log('SECURITY ERROR: ' + issue);
        if ((snapshot.securityIssues?.length ?? 0) > 0)
            process.exitCode = 1;
        return;
    }
    const policy = readPolicy(root, policyName);
    if (cmd === 'check') {
        const findings = check(snapshot, policy);
        renderCheck(snapshot, findings, format);
        if (shouldFail(findings, failOn) || snapshot.exposures.length === 0 || (snapshot.securityIssues?.length ?? 0) > 0)
            process.exitCode = 1;
        return;
    }
    if (!opts.base)
        throw new Error('diff requires --base GIT_REF');
    const before = scanSources(gitRevision(root, opts.base));
    const oldPolicy = readBasePolicy(root, opts.base, policyName);
    const report = diffSnapshots(before, snapshot, oldPolicy, policy);
    renderDiff(report, format);
    if (shouldFail(report.added, failOn) || report.contractExpansions.length || report.permissionRegressions.length || report.securityIssues.length || snapshot.exposures.length === 0)
        process.exitCode = 1;
}
try {
    main();
}
catch (error) {
    console.error(`TaskLatch error: ${error.message}`);
    process.exitCode = 2;
}
