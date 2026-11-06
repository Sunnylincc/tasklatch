/** A deliberately restricted YAML subset for auditable permission contracts.
 * No tags, anchors, aliases, flow mappings, implicit objects, or executable features.
 * Nested maps and lists of scalar strings only; two-space indentation.
 */
export declare function parsePolicyYaml(input: string): unknown;
