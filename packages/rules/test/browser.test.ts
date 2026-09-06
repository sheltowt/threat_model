import { describe, expect, it } from 'vitest';
import { readFileSync, existsSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildGraph, builtinCatalog, parseModelText } from 'tmac-core/browser';
import { analyze, builtinRules } from 'tmac-rules/browser';

const ROOT = fileURLToPath(new URL('../../..', import.meta.url));

function nodeImportsReachableFrom(entry: string): Map<string, string[]> {
  const found = new Map<string, string[]>();
  const seen = new Set<string>();
  const visit = (file: string): void => {
    const abs = resolve(file);
    if (seen.has(abs) || !existsSync(abs)) return;
    seen.add(abs);
    const source = readFileSync(abs, 'utf8');
    const specifiers = [...source.matchAll(/from\s+['"]([^'"]+)['"]/g)].map((m) => m[1]!);
    const nodeSpecifiers = specifiers.filter((s) => s.startsWith('node:'));
    if (nodeSpecifiers.length > 0) found.set(abs.replace(ROOT, ''), [...new Set(nodeSpecifiers)]);
    for (const specifier of specifiers) {
      if (specifier.startsWith('.')) visit(join(dirname(abs), specifier));
      // A cross-package import resolves through dist, which the walker follows.
      else if (specifier.startsWith('tmac-core/browser')) {
        visit(join(ROOT, 'packages/core/dist/browser.js'));
      } else if (specifier === 'tmac-core') {
        visit(join(ROOT, 'packages/core/dist/index.js'));
      }
    }
  };
  visit(entry);
  return found;
}

describe('browser entry point', () => {
  it('reaches no Node built-in, including through tmac-core', () => {
    const entry = join(ROOT, 'packages/rules/dist/browser.js');
    if (!existsSync(entry)) throw new Error('build the workspace first: npm run build');
    expect(Object.fromEntries(nodeImportsReachableFrom(entry))).toEqual({});
  });
});

describe('the compiled-in rule library', () => {
  const rules = builtinRules();

  it('parses every rule at import time', () => {
    expect(rules.length).toBeGreaterThan(40);
  });

  it('matches what the filesystem loader produces', async () => {
    // Two sources for the same library is a drift risk; assert they agree.
    const { loadRules } = await import('tmac-rules');
    const fromDisk = loadRules().rules;
    expect(rules.map((r) => r.id)).toEqual(fromDisk.map((r) => r.id));
    expect(rules.map((r) => r.match)).toEqual(fromDisk.map((r) => r.match));
  });

  it('is cached, so repeated calls do not re-parse', () => {
    expect(builtinRules()).toBe(rules);
  });

  it('cites the file each rule came from', () => {
    for (const rule of rules) expect(rule.source).toContain(rule.id);
  });
});

describe('analysing entirely in memory', () => {
  it('produces the same findings as the filesystem path', async () => {
    const source = readFileSync(
      join(ROOT, 'examples/payment-service/threatmodel.yaml'),
      'utf8',
    );
    const catalog = builtinCatalog();
    const { model } = parseModelText(source, catalog, { source: 'pasted' });
    const inMemory = analyze(buildGraph(model, catalog), builtinRules());

    const { loadModel } = await import('tmac-core');
    const { loadRules } = await import('tmac-rules');
    const loaded = loadModel(join(ROOT, 'examples/payment-service/threatmodel.yaml'));
    const onDisk = analyze(buildGraph(loaded.model, loaded.catalog), loadRules().rules);

    expect(inMemory.risks.map((r) => r.id)).toEqual(onDisk.risks.map((r) => r.id));
    expect(inMemory.risks.map((r) => r.severity)).toEqual(onDisk.risks.map((r) => r.severity));
    expect(inMemory.stats).toEqual(onDisk.stats);
  });
});
