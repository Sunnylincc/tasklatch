import type { Decision, Policy, PolicyCase } from './types.js';
export declare function validatePolicy(raw: unknown): Policy;
export declare function parsePolicy(input: string): Policy;
export declare function matches(pattern: string, capability: string): boolean;
export declare function decide(policy: Policy | undefined, agent: string, task: string, capability: string): {
    decision: Decision;
    reason: string;
};
export declare function validateCases(raw: unknown): PolicyCase[];
