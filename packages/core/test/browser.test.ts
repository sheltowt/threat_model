import { describe, expect, it } from 'vitest';
import { readFileSync, existsSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildGraph, builtinCatalog, parseModelText, tryParseModelText } from '@tmc/core/browser';

const ROOT = fileURLToPath(new URL('../../..', import.meta.url));

/**
 * Walk the import graph of a built entry point and collect every `node:` specifier.
 *
 * The browser entries exist so the editor can run the real schema, graph and rules
 * rather than a second implementation that drifts. A single `node:fs` anywhere in
 * the reachable graph breaks the bundle, and it breaks it at bundle time with an
 * error that points at the wrong place, so it is worth asserting directly.
 */
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
    if (nodeSpecifiers.length > 0) {
      found.set(abs.replace(ROOT, ''), [...new Set(nodeSpecifiers)]);
    }

    for (const specifier of specifiers) {
      if (!specifier.startsWith('.')) continue;
      visit(join(dirname(abs), specifier));
    }
  };

  visit(entry);
  return found;
}

describe('browser entry point', () => {
  it('reaches no Node built-in', () => {
    const entry = join(ROOT, 'packages/core/dist/browser.js');
    if (!existsSync(entry)) {
      throw new Error('build the workspace first: npm run build');
    }
    expect(Object.fromEntries(nodeImportsReachableFrom(entry))).toEqual({});
  });

  it('is not what the default entry does, which is allowed to read files', () => {
    // Guards the test itself: if the walker found nothing anywhere it would be inert.
    const entry = join(ROOT, 'packages/core/dist/index.js');
    expect(nodeImportsReachableFrom(entry).size).toBeGreaterThan(0);
  });
});

describe('parsing without a filesystem', () => {
  const catalog = builtinCatalog();

  const MODEL = `
schema: tmc/1.0
meta:
  title: In memory
data_assets:
  secret:
    classification: strictly-confidential
    credentials: true
elements:
  api:
    technology: web-service-rest
    internet_facing: true
    processes: [secret]
  db:
    technology: database
    stores: [secret]
flows:
  - id: api_db
    from: api
    to: db
    protocol: sql-access-protocol
    sends: [secret]
`;

  it('carries the whole built-in catalogue', () => {
    expect(catalog.technologies.size).toBeGreaterThan(50);
    expect(catalog.protocols.size).toBeGreaterThan(40);
    expect(catalog.technologies.get('database')?.attrs['vulnerable_to_query_injection']).toBe(true);
  });

  it('parses text into a validated model', () => {
    const { model, diagnostics } = parseModelText(MODEL, catalog, { source: 'pasted' });
    expect(diagnostics.filter((d) => d.severity === 'error')).toEqual([]);
    expect(Object.keys(model.elements).sort()).toEqual(['api', 'db']);
  });

  it('builds the same graph the CLI would', () => {
    const { model } = parseModelText(MODEL, catalog);
    const graph = buildGraph(model, catalog);
    expect(graph.elementById.get('db')?.confidentiality).toBe('strictly-confidential');
    expect(graph.flowById.get('api_db')?.carries_credentials).toBe(true);
    expect(graph.elementById.get('db')?.internet_reachable).toBe(true);
  });

  it('reports diagnostics instead of throwing when asked not to throw', () => {
    const result = tryParseModelText('schema: tmc/1.0\nmeta: {}\n', catalog, { source: 'pasted' });
    expect(result.ok).toBe(false);
    expect(result.diagnostics.length).toBeGreaterThan(0);
    expect(result.model).toBeUndefined();
  });

  it('names an unknown technology and suggests the near miss', () => {
    const result = tryParseModelText(
      'schema: tmc/1.0\nmeta:\n  title: t\nelements:\n  a:\n    technology: databse\n',
      catalog,
    );
    expect(result.ok).toBe(false);
    const d = result.diagnostics.find((x) => x.code === 'unknown-technology');
    expect(d?.hint).toContain('database');
  });
});
