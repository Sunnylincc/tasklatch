import type { Exposure, Finding, Policy, Snapshot } from './types.js';
export declare function check(snapshot: Snapshot, policy: Policy | undefined): Finding[];
export interface DiffReport {
    added: Finding[];
    removed: Exposure[];
    retained: number;
    contractExpansions: Array<{
        agent: string;
        task: string;
        pattern: string;
        change: string;
    }>;
    warnings: string[];
    /** Changes that may broaden inherited GitHub token permissions. */
    permissionRegressions: string[];
    /** Unresolved source coverage / authorization uncertainty in either snapshot. */
    securityIssues: string[];
}
export declare function diffSnapshots(before: Snapshot, after: Snapshot, baseline: Policy | undefined, current: Policy | undefined): DiffReport;
export declare const shouldFail: (findings: Finding[], failOn: "deny" | "approval" | "unknown") => boolean;
