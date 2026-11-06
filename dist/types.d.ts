export type Decision = 'allow' | 'deny' | 'approval' | 'unknown';
export type ExposureKind = 'declared' | 'inferred' | 'unknown';
export interface TaskContract {
    allow: string[];
    deny: string[];
    require_approval: string[];
}
export interface Policy {
    version: number;
    defaults: {
        unlisted: 'deny' | 'unknown';
    };
    agents: Record<string, {
        tasks: Record<string, TaskContract>;
    }>;
}
export interface Exposure {
    agent: string;
    task: string;
    capability: string;
    source: string;
    kind: ExposureKind;
    note?: string;
}
export interface Finding {
    agent: string;
    task: string;
    capability: string;
    source: string;
    kind: ExposureKind;
    decision: Decision;
    reason: string;
}
export interface PolicyCase {
    agent: string;
    task: string;
    capability: string;
    expected: Decision;
    name?: string;
}
export interface Snapshot {
    exposures: Exposure[];
    warnings: string[];
    files: string[];
    /** Explicit permission declaration scopes for each supported GitHub workflow. */
    workflowPermissions?: Record<string, string[]>;
    /** Coverage gaps that must never be treated as a successful security check. */
    securityIssues?: string[];
}
