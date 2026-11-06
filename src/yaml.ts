/** A deliberately restricted YAML subset for auditable permission contracts.
 * No tags, anchors, aliases, flow mappings, implicit objects, or executable features.
 * Nested maps and lists of scalar strings only; two-space indentation.
 */
export function parsePolicyYaml(input: string): unknown {
  type Container = Record<string, unknown> | unknown[];
  const significant = input.split(/\r?\n/).map((raw, idx) => ({ raw, line: idx + 1 }))
    .filter(({raw}) => raw.trim() !== '' && !raw.trimStart().startsWith('#'));
  const root: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
  const stack: Array<{ indent: number; value: Container }> = [{indent: -2, value: root}];
  for (let i = 0; i < significant.length; i++) {
    const {raw, line} = significant[i]!;
    if (/\t/.test(raw)) throw new Error(`YAML line ${line}: tabs are not supported`);
    const indent = raw.length - raw.trimStart().length;
    if (indent % 2 !== 0) throw new Error(`YAML line ${line}: use two-space indentation`);
    while (stack.length > 1 && stack[stack.length - 1]!.indent >= indent) stack.pop();
    const parent = stack[stack.length - 1]!;
    if (indent !== parent.indent + 2) throw new Error(`YAML line ${line}: invalid indentation`);
    const content = raw.trim();
    if (content.startsWith('- ')) {
      if (!Array.isArray(parent.value)) throw new Error(`YAML line ${line}: list item outside list`);
      parent.value.push(parseScalar(content.slice(2), line));
      continue;
    }
    if (Array.isArray(parent.value)) throw new Error(`YAML line ${line}: only string list entries are supported`);
    const match = /^([A-Za-z0-9_.:-]+):(?:\s+(.*))?$/.exec(content);
    if (!match) throw new Error(`YAML line ${line}: unsupported mapping syntax`);
    const key = match[1]!;
    if (['__proto__', 'prototype', 'constructor'].includes(key)) throw new Error(`YAML line ${line}: forbidden key`);
    if (Object.prototype.hasOwnProperty.call(parent.value, key)) throw new Error(`YAML line ${line}: duplicate key ${key}`);
    const rhs = match[2];
    let value: unknown;
    if (rhs === undefined || rhs === '') {
      const next = significant[i + 1]?.raw;
      if (next === undefined) throw new Error(`YAML line ${line}: expected indented content`);
      const nextIndent = next.length - next.trimStart().length;
      if (nextIndent !== indent + 2) throw new Error(`YAML line ${line}: expected indented content`);
      value = next.trim().startsWith('- ') ? [] : Object.create(null);
    } else value = parseScalar(rhs, line);
    parent.value[key] = value;
    if (typeof value === 'object' && value !== null) stack.push({indent, value: value as Container});
  }
  return root;
}

function parseScalar(value: string, line: number): string | number | boolean {
  const raw = value.trim();
  if (raw.length === 0) throw new Error(`YAML line ${line}: empty scalar`);
  if (raw.includes('#')) throw new Error(`YAML line ${line}: inline comments are unsupported`);
  if (raw === 'true') return true;
  if (raw === 'false') return false;
  if (/^[0-9]+$/.test(raw)) return Number(raw);
  if (raw.startsWith('"') && raw.endsWith('"')) {
    try { return JSON.parse(raw) as string; } catch { throw new Error(`YAML line ${line}: invalid quoted string`); }
  }
  if (raw.startsWith("'") && raw.endsWith("'")) return raw.slice(1, -1).replace(/''/g, "'");
  if (/[\[\]{}&!|<>`]/.test(raw) || raw.startsWith('*') || raw.includes(': ')) throw new Error(`YAML line ${line}: unsupported scalar syntax`);
  return raw;
}
