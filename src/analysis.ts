import type { Exposure, Finding, Policy, Snapshot, Decision } from './types.js';
import { decide } from './policy.js';

function finding(ex: Exposure, policy: Policy | undefined): Finding {
  const evaluated = decide(policy, ex.agent, ex.task, ex.capability);
  const decision: Decision = ex.kind === 'unknown' ? 'unknown' : evaluated.decision;
  return {
    ...ex,
    decision,
    reason: ex.kind === 'unknown' ? 'Capability semantics are unknown; cannot confirm authorization' : evaluated.reason
  };
}
export function check(snapshot: Snapshot, policy: Policy | undefined): Finding[] {
  return snapshot.exposures.map(ex => finding(ex, policy));
}
const key = (ex: Exposure): string => `${ex.agent}\0${ex.task}\0${ex.capability}\0${ex.kind}`;
export interface DiffReport {
  added: Finding[];
  removed: Exposure[];
  retained: number;
  contractExpansions: Array<{agent:string; task:string; pattern:string; change: string}>;
  warnings: string[];
}
export function diffSnapshots(before: Snapshot, after: Snapshot, baseline: Policy | undefined, current: Policy | undefined): DiffReport {
  const baseMap = new Map(before.exposures.map(e => [key(e), e]));
  const headMap = new Map(after.exposures.map(e => [key(e), e]));
  const added = [...headMap.entries()].filter(([k]) => !baseMap.has(k)).map(([,e]) => {
    const now = finding(e, current);
    const prev = finding(e, baseline);
    if (baseline && prev.decision === 'deny' && now.decision === 'allow') {
      return {...now, decision: 'deny' as const, reason: 'New capability is forbidden by the baseline policy despite a policy change'};
    }
    return now;
  });
  const removed = [...baseMap.entries()].filter(([k]) => !headMap.has(k)).map(([,e]) => e);
  const contractExpansions: DiffReport['contractExpansions'] = [];
  if (baseline && current) {
    if (baseline.defaults.unlisted === 'deny' && current.defaults.unlisted === 'unknown') {
      contractExpansions.push({agent: '*', task: '*', pattern: 'defaults.unlisted', change: 'default_weakened'});
    }
    for (const [agent, spec] of Object.entries(current.agents)) for (const [task, contract] of Object.entries(spec.tasks)) {
      const old = baseline.agents[agent]?.tasks[task];
      if (!old) {
        if (contract.allow.length) contractExpansions.push({agent, task, pattern: contract.allow.join(', '), change: 'new_contract_allow_list'});
        continue;
      }
      for (const pattern of contract.allow) {
        if (!old.allow.includes(pattern)) contractExpansions.push({agent, task, pattern, change:'allow_added'});
      }
      for (const pattern of old.deny) {
        if (!contract.deny.includes(pattern)) contractExpansions.push({agent, task, pattern, change:'deny_removed'});
      }
      for (const pattern of old.require_approval) {
        if (!contract.require_approval.includes(pattern) && !contract.deny.includes(pattern)) contractExpansions.push({agent, task, pattern, change:'approval_removed'});
      }
    }
    for (const [agent, spec] of Object.entries(baseline.agents)) for (const task of Object.keys(spec.tasks)) {
      if (!current.agents[agent]?.tasks[task]) contractExpansions.push({agent, task, pattern: '*', change: 'contract_removed'});
    }
  }
  return {
    added, removed, retained: before.exposures.length - removed.length,
    contractExpansions,
    warnings: [...before.warnings.map(w=>`Base: ${w}`), ...after.warnings.map(w=>`Head: ${w}`)]
  };
}
export const shouldFail = (findings: Finding[], failOn: 'deny'|'approval'|'unknown'): boolean => {
  const failing: Decision[] = failOn === 'deny' ? ['deny'] : failOn === 'approval' ? ['deny','approval'] : ['deny','approval','unknown'];
  return findings.some(f => failing.includes(f.decision));
};
