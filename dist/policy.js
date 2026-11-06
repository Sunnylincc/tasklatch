import { parsePolicyYaml } from './yaml.js';
function object(value, path) {
    if (typeof value !== 'object' || value === null || Array.isArray(value))
        throw new Error(`${path} must be a mapping`);
    return value;
}
function onlyKeys(obj, keys, path) {
    const extra = Object.keys(obj).filter(key => !keys.includes(key));
    if (extra.length)
        throw new Error(`${path} has unsupported field(s): ${extra.join(', ')}`);
}
function patterns(value, path) {
    if (!Array.isArray(value))
        throw new Error(`${path} must be a list`);
    if (value.length > 500)
        throw new Error(`${path}: too many capability patterns`);
    for (const item of value)
        if (typeof item !== 'string' || item.length > 160 || !/^[a-zA-Z0-9._*:-]+$/.test(item))
            throw new Error(`${path}: invalid capability pattern`);
    return value;
}
export function validatePolicy(raw) {
    const root = object(raw, 'Policy');
    onlyKeys(root, ['version', 'defaults', 'agents'], 'Policy');
    if (root.version !== 1)
        throw new Error('Policy version must equal 1');
    const defaultsRaw = object(root.defaults, 'defaults');
    onlyKeys(defaultsRaw, ['unlisted'], 'defaults');
    if (defaultsRaw.unlisted !== 'deny' && defaultsRaw.unlisted !== 'unknown')
        throw new Error('defaults.unlisted must be deny or unknown');
    const agentsRaw = object(root.agents, 'agents');
    if (Object.keys(agentsRaw).length === 0)
        throw new Error('Policy must declare at least one agent');
    const agents = Object.create(null);
    for (const [agentId, agentValue] of Object.entries(agentsRaw)) {
        if (['__proto__', 'prototype', 'constructor'].includes(agentId) || !/^[a-zA-Z0-9._:-]+$/.test(agentId))
            throw new Error(`Invalid agent ID: ${agentId}`);
        const agent = object(agentValue, `agents.${agentId}`);
        onlyKeys(agent, ['tasks'], `agents.${agentId}`);
        const tasksRaw = object(agent.tasks, `agents.${agentId}.tasks`);
        if (!Object.keys(tasksRaw).length)
            throw new Error(`Agent ${agentId} must declare at least one task`);
        const tasks = Object.create(null);
        for (const [taskId, taskValue] of Object.entries(tasksRaw)) {
            if (['__proto__', 'prototype', 'constructor'].includes(taskId) || !/^[a-zA-Z0-9._:-]+$/.test(taskId))
                throw new Error(`Invalid task ID: ${taskId}`);
            const path = `agents.${agentId}.tasks.${taskId}`;
            const task = object(taskValue, path);
            onlyKeys(task, ['allow', 'deny', 'require_approval'], path);
            tasks[taskId] = {
                allow: task.allow === undefined ? [] : patterns(task.allow, `${path}.allow`),
                deny: task.deny === undefined ? [] : patterns(task.deny, `${path}.deny`),
                require_approval: task.require_approval === undefined ? [] : patterns(task.require_approval, `${path}.require_approval`)
            };
        }
        agents[agentId] = { tasks };
    }
    return { version: 1, defaults: { unlisted: defaultsRaw.unlisted }, agents };
}
export function parsePolicy(input) { return validatePolicy(parsePolicyYaml(input)); }
export function matches(pattern, capability) {
    const escaped = pattern.split('*').map(part => part.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('.*');
    return new RegExp(`^${escaped}$`).test(capability);
}
export function decide(policy, agent, task, capability) {
    if (!policy)
        return { decision: 'unknown', reason: 'No policy was available for this revision' };
    const contract = policy.agents[agent]?.tasks[task];
    if (!contract)
        return { decision: 'unknown', reason: 'No contract exists for this agent and task' };
    if (contract.deny.some(p => matches(p, capability)))
        return { decision: 'deny', reason: 'Matches an explicit deny rule' };
    if (contract.require_approval.some(p => matches(p, capability)))
        return { decision: 'approval', reason: 'Requires approval under this task contract' };
    if (contract.allow.some(p => matches(p, capability)))
        return { decision: 'allow', reason: 'Allowed by the task contract' };
    return { decision: policy.defaults.unlisted, reason: `Unlisted capability: ${policy.defaults.unlisted}` };
}
export function validateCases(raw) {
    if (!Array.isArray(raw))
        throw new Error('Test cases must be a JSON array');
    return raw.map((item, index) => {
        const v = object(item, `Case ${index + 1}`);
        onlyKeys(v, ['name', 'agent', 'task', 'capability', 'expected'], `Case ${index + 1}`);
        for (const field of ['agent', 'task', 'capability'])
            if (typeof v[field] !== 'string' || !v[field])
                throw new Error(`Case ${index + 1}: ${field} must be a string`);
        if (!['allow', 'deny', 'approval', 'unknown'].includes(String(v.expected)))
            throw new Error(`Case ${index + 1}: invalid expected decision`);
        return { agent: v.agent, task: v.task, capability: v.capability, expected: v.expected, name: typeof v.name === 'string' ? v.name : undefined };
    });
}
