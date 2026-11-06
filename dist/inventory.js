import { existsSync, lstatSync, readFileSync, readdirSync } from 'node:fs';
import { basename, join, relative, resolve } from 'node:path';
import { execFileSync } from 'node:child_process';
const MAX_SOURCE_BYTES = 512 * 1024;
const MAX_SOURCES = 300;
const knownFiles = ['.tasklatch/manifest.json', '.claude/settings.json', '.mcp.json', '.cursor/mcp.json'];
const isWorkflow = (p) => /^\.github\/workflows\/[a-zA-Z0-9._-]+\.ya?ml$/.test(p);
const sourceRelevant = (p) => knownFiles.includes(p) || isWorkflow(p);
function isInside(root, filename) {
    const rel = relative(resolve(root), resolve(root, filename));
    return rel === '' || (rel !== '..' && !rel.startsWith('..' + '/') && !rel.startsWith('..' + '\\') && !rel.startsWith('/'));
}
export function workingTree(root) {
    return {
        list() {
            const paths = knownFiles.filter(p => existsSync(join(root, p)));
            const workflowFolder = join(root, '.github/workflows');
            if (existsSync(workflowFolder) && lstatSync(workflowFolder).isDirectory() && !lstatSync(workflowFolder).isSymbolicLink()) {
                for (const name of readdirSync(workflowFolder)) {
                    const rel = `.github/workflows/${name}`;
                    if (isWorkflow(rel))
                        paths.push(rel);
                }
            }
            return paths.sort().slice(0, MAX_SOURCES);
        },
        read(path) {
            if (!sourceRelevant(path) || !isInside(root, path))
                return undefined;
            const full = join(root, path);
            if (!existsSync(full))
                return undefined;
            const stat = lstatSync(full);
            if (!stat.isFile() || stat.isSymbolicLink())
                throw new Error(`Unsafe source file: ${path}`);
            if (stat.size > MAX_SOURCE_BYTES)
                throw new Error(`Source file exceeds safety limit: ${path}`);
            return readFileSync(full, 'utf8');
        }
    };
}
function git(root, args) {
    return execFileSync('git', args, { cwd: root, encoding: 'utf8', maxBuffer: 4_000_000, stdio: ['ignore', 'pipe', 'pipe'] });
}
export function gitRevision(root, revision) {
    if (!/^[a-zA-Z0-9][a-zA-Z0-9._/\-]*$/.test(revision) || revision.includes('..'))
        throw new Error('Unsafe git base revision');
    const resolvedSha = git(root, ['rev-parse', '--verify', `${revision}^{commit}`]).trim();
    if (!/^[a-f0-9]{40,64}$/.test(resolvedSha))
        throw new Error('Invalid resolved commit SHA');
    let files;
    return {
        list() {
            if (!files)
                files = git(root, ['ls-tree', '-r', '--name-only', resolvedSha]).split('\n').filter(sourceRelevant).slice(0, MAX_SOURCES).sort();
            return files;
        },
        read(path) {
            if (!sourceRelevant(path))
                return undefined;
            if (!this.list().includes(path))
                return undefined;
            const size = Number(git(root, ['cat-file', '-s', `${resolvedSha}:${path}`]).trim());
            if (!Number.isFinite(size) || size > MAX_SOURCE_BYTES)
                throw new Error(`Source file exceeds safety limit: ${path}`);
            // Never execute files from the target revision.
            return git(root, ['show', `${resolvedSha}:${path}`]);
        }
    };
}
const slug = (raw) => raw.replace(/[^a-zA-Z0-9._-]/g, '_').slice(0, 96);
const add = (items, agent, task, capability, source, kind, note) => {
    items.push({ agent, task, capability, source, kind, ...(note ? { note } : {}) });
};
function parseManifest(content, path, out) {
    const raw = JSON.parse(content);
    if (typeof raw !== 'object' || raw === null || Array.isArray(raw))
        throw new Error(`${path}: manifest must be an object`);
    const manifest = raw;
    if (manifest.version !== 1 || !Array.isArray(manifest.exposures))
        throw new Error(`${path}: expected version 1 and exposures array`);
    if (manifest.exposures.length > 1000)
        throw new Error(`${path}: too many exposures`);
    for (const [i, item] of manifest.exposures.entries()) {
        if (typeof item !== 'object' || item === null || Array.isArray(item))
            throw new Error(`${path}: exposure ${i} must be an object`);
        const entry = item;
        for (const field of ['agent', 'task', 'capability']) {
            if (typeof entry[field] !== 'string' || !/^[a-zA-Z0-9._*:-]+$/.test(entry[field]))
                throw new Error(`${path}: invalid ${field} in exposure ${i}`);
        }
        add(out, entry.agent, entry.task, entry.capability, path, 'declared', 'Manifest assertion; not independently verified');
    }
}
function parseClaude(content, path, out, warnings) {
    const config = JSON.parse(content);
    if (typeof config !== 'object' || config === null || Array.isArray(config))
        throw new Error(`${path}: invalid JSON object`);
    const obj = config;
    const permissions = obj.permissions;
    if (typeof permissions !== 'object' || permissions === null || Array.isArray(permissions)) {
        warnings.push(`${path}: no static permissions list found`);
        return;
    }
    const allow = permissions.allow;
    if (!Array.isArray(allow)) {
        warnings.push(`${path}: no permissions.allow array found`);
        return;
    }
    for (const item of allow) {
        if (typeof item !== 'string') {
            warnings.push(`${path}: non-string permission ignored`);
            continue;
        }
        const name = item.split('(')[0]?.trim() ?? '';
        const hasScope = item.includes('(');
        if (name === 'Read')
            add(out, 'claude-code', 'unscoped', 'filesystem.read', path, 'inferred');
        else if (name === 'Write' || name === 'Edit')
            add(out, 'claude-code', 'unscoped', 'filesystem.write', path, 'inferred');
        else if (name === 'Bash')
            add(out, 'claude-code', 'unscoped', hasScope ? 'shell.execute.scoped' : 'shell.execute.unrestricted', path, 'inferred', 'Actual OS permissions are not verified');
        else if (name === 'WebFetch')
            add(out, 'claude-code', 'unscoped', 'network.fetch', path, 'inferred');
        else if (name.startsWith('mcp__'))
            add(out, 'claude-code', 'unscoped', 'mcp.tool.unclassified', path, 'unknown', 'Tool capability cannot be inferred from its name');
        else
            add(out, 'claude-code', 'unscoped', `agent.tool.${slug(name)}`, path, 'unknown', 'Tool semantics not recognized');
    }
    if ('additionalDirectories' in permissions)
        warnings.push(`${path}: additionalDirectories may expand filesystem access`);
}
function parseMcp(content, path, out, warnings) {
    const config = JSON.parse(content);
    if (typeof config !== 'object' || config === null || Array.isArray(config))
        throw new Error(`${path}: invalid JSON object`);
    const servers = config.mcpServers;
    if (typeof servers !== 'object' || servers === null || Array.isArray(servers)) {
        warnings.push(`${path}: no mcpServers mapping found`);
        return;
    }
    for (const name of Object.keys(servers)) {
        // Server configuration is not the same thing as effective tool permission.
        add(out, 'mcp-client', 'unscoped', `mcp.server.${slug(name)}.tools_unknown`, path, 'unknown', 'MCP server tools were not launched or queried');
    }
}
function parseWorkflow(content, path, out, warnings) {
    const lines = content.split(/\r?\n/);
    const agent = `workflow:${slug(basename(path).replace(/\.ya?ml$/, ''))}`;
    let blockIndent = -1;
    let found = false;
    for (let i = 0; i < lines.length; i++) {
        const raw = lines[i];
        const indent = raw.length - raw.trimStart().length;
        const line = raw.trim();
        if (line.startsWith('#') || line === '')
            continue;
        if (blockIndent >= 0 && indent <= blockIndent)
            blockIndent = -1;
        if (/^permissions\s*:/.test(line)) {
            found = true;
            const value = line.slice(line.indexOf(':') + 1).trim();
            if (value === '')
                blockIndent = indent;
            else if (/^(read-all|write-all)$/.test(value))
                add(out, agent, 'ci', `github.token.${value}`, `${path}:${i + 1}`, 'inferred');
            else {
                add(out, agent, 'ci', 'github.permissions.unparsed', `${path}:${i + 1}`, 'unknown', 'Inline/dynamic workflow permissions are not interpreted');
            }
            continue;
        }
        if (blockIndent >= 0 && indent > blockIndent) {
            const match = /^([a-z-]+):\s*(read|write|none)(?:\s+#.*)?$/.exec(line);
            if (!match) {
                add(out, agent, 'ci', 'github.permissions.unparsed', `${path}:${i + 1}`, 'unknown', 'Dynamic or unsupported permission declaration');
                continue;
            }
            const scope = match[1];
            const access = match[2];
            if (access === 'none')
                continue;
            const cap = scope === 'contents' ? `github.repository.${access}` : scope === 'id-token' ? `github.oidc.${access}` : `github.${scope}.${access}`;
            add(out, agent, 'ci', cap, `${path}:${i + 1}`, 'inferred', scope === 'id-token' ? 'OIDC trust relationships are not evaluated' : undefined);
        }
    }
    if (!found)
        warnings.push(`${path}: no explicit GitHub token permissions; effective defaults are unknown`);
}
export function scanSources(reader) {
    const exposures = [];
    const warnings = [];
    const files = reader.list();
    for (const path of files) {
        const content = reader.read(path);
        if (content === undefined)
            continue;
        try {
            if (path === '.tasklatch/manifest.json')
                parseManifest(content, path, exposures);
            else if (path === '.claude/settings.json')
                parseClaude(content, path, exposures, warnings);
            else if (path === '.mcp.json' || path === '.cursor/mcp.json')
                parseMcp(content, path, exposures, warnings);
            else if (isWorkflow(path))
                parseWorkflow(content, path, exposures, warnings);
        }
        catch (err) {
            throw new Error(`Scan failed in ${path}: ${err.message}`);
        }
    }
    const uniq = new Map();
    for (const ex of exposures)
        uniq.set([ex.agent, ex.task, ex.capability, ex.source, ex.kind].join('|'), ex);
    if (!files.length || !uniq.size)
        warnings.push('No supported capability exposures discovered; absence of findings does not imply safety');
    return { exposures: [...uniq.values()].sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b))), warnings, files };
}
