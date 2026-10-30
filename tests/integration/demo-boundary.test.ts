import { describe, expect, it } from 'vitest';
import { existsSync, readFileSync, readdirSync, mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { parse } from '@babel/parser';

// Traverse re-exports and dynamic imports; external modules require review.
function inspectGraph(entry: string, root = process.cwd()) {
  const seen = new Set<string>();
  const violations: string[] = [];
  function visit(file: string) {
    if (seen.has(file)) return;
    seen.add(file);
    const ast = parse(readFileSync(file, 'utf8'), { sourceType: 'module', plugins: ['typescript', 'jsx'] });
    function check(value: unknown) {
      if (!value || typeof value !== 'object') return;
      if (Array.isArray(value)) { value.forEach(check); return; }
      const node = value as Record<string, unknown>;
      if (node.type === 'Identifier' && ['process', 'fetch', 'XMLHttpRequest', 'WebSocket', 'eval'].includes(String(node.name))) violations.push(`${file}: forbidden capability ${node.name}`);
      let specifier: string | undefined;
      if (['ImportDeclaration', 'ExportNamedDeclaration', 'ExportAllDeclaration'].includes(String(node.type)) && node.source) specifier = String((node.source as { value: string }).value);
      if (node.type === 'ImportExpression') {
        const argument = node.source as { type: string; value?: string };
        if (argument.type !== 'StringLiteral') violations.push(`${file}: nonliteral import`);
        else specifier = argument.value;
      }
      if (node.type === 'CallExpression' && (node.callee as { name?: string })?.name === 'require') violations.push(`${file}: require is not allowed`);
      if (specifier) {
        if (/(?:^|\/)(?:private|personal|repositories|providers)(?:\/|$)|supabase|server-only|\.env/i.test(specifier)) violations.push(`${file}: private adapter ${specifier}`);
        if (specifier.startsWith('.') || specifier.startsWith('@/')) {
          const base = specifier.startsWith('@/') ? path.join(root, 'src', specifier.slice(2)) : path.resolve(path.dirname(file), specifier);
          const target = ['', '.ts', '.tsx', '.css', '/index.ts', '/index.tsx'].map(ext => base + ext).find(candidate => existsSync(candidate));
          if (!target) violations.push(`${file}: unresolved ${specifier}`);
          else if (!target.endsWith('.css')) visit(target);
        } else if (!['react', 'next', 'next/link', 'next/navigation', 'motion/react'].includes(specifier)) violations.push(`${file}: unreviewed external ${specifier}`);
      }
      Object.values(node).forEach(check);
    }
    check(ast);
  }
  visit(entry);
  return violations;
}
describe('public sample dependency boundary', () => {
  it('keeps every demo entry and shared layout free of personal adapters and env access', () => {
    const src = path.resolve('src');
    expect(existsSync(path.join(src, 'app/(demo)/demo/page.tsx'))).toBe(true);
    const entries = readdirSync(src, { recursive: true }).map(String).filter(f => /(?:page|layout)\.tsx$/.test(f));
    expect(entries.length).toBeGreaterThan(1);
    for (const entry of entries) expect(inspectGraph(path.join(src, entry))).toEqual([]);
  });
  it.each([
    ["export { data } from './providers/secret'", 'private adapter'],
    ["export const data = process['env']['SECRET']", 'forbidden capability'],
    ["const target = './secret'; export const data = import(target)", 'nonliteral import'],
    ["export const data = fetch('https://provider.invalid')", 'forbidden capability'],
    ["export { data } from '@unreviewed/sdk'", 'unreviewed external'],
  ])('rejects a transitive capability introduced as %s', (badImport, reason) => {
    const root = mkdtempSync(path.join(tmpdir(), 'jls-boundary-'));
    try {
      mkdirSync(path.join(root, 'providers'));
      writeFileSync(path.join(root, 'entry.ts'), "export { data } from './bridge'");
      writeFileSync(path.join(root, 'bridge.ts'), badImport);
      writeFileSync(path.join(root, 'providers/secret.ts'), 'export const data = 1');
      expect(inspectGraph(path.join(root, 'entry.ts'), root).some(value => value.includes(reason))).toBe(true);
    } finally { rmSync(root, { recursive: true, force: true }); }
  });
});
