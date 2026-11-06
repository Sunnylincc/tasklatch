import type { Snapshot } from './types.js';
export interface SourceReader {
    list(): string[];
    read(path: string): string | undefined;
}
export declare function workingTree(root: string): SourceReader;
export declare function gitRevision(root: string, revision: string): SourceReader;
export declare function scanSources(reader: SourceReader): Snapshot;
