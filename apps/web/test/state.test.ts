import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { EMPTY, evaluateModel, urlTarget } from '../src/state/model.js';
import { DEFAULT_ROUTE, formatHash, parseHash } from '../src/state/selection.js';

const EXAMPLE = readFileSync(
  fileURLToPath(new URL('../../../examples/payment-service/threatmodel.yaml', import.meta.url)),
  'utf8',
);

describe('evaluateModel', () => {
  it('parses and analyses the example entirely in memory', () => {
    const state = evaluateModel('example.yaml', EXAMPLE);
    expect(state.ok).toBe(true);
    expect(state.graph?.elements.length).toBe(8);
    expect(state.analysis?.risks.length).toBeGreaterThan(0);
    expect(state.diagnostics.filter((d) => d.severity === 'error')).toEqual([]);
  });

  it('agrees with what the CLI would report for the same file', async () => {
    // The editor exists to show the same answers, so this is the assertion that
    // matters most about it.
    const { buildGraph, loadModel } = await import('tmac-core');
    const { analyze, loadRules } = await import('tmac-rules');
    const path = fileURLToPath(
      new URL('../../../examples/payment-service/threatmodel.yaml', import.meta.url),
    );
    const loaded = loadModel(path);
    const fromDisk = analyze(buildGraph(loaded.model, loaded.catalog), loadRules().rules);
    const inBrowser = evaluateModel('example.yaml', EXAMPLE);

    expect(inBrowser.analysis?.risks.map((r) => r.id)).toEqual(
      fromDisk.risks.map((r) => r.id),
    );
    expect(inBrowser.analysis?.stats).toEqual(fromDisk.stats);
  });

  it('reports diagnostics rather than throwing on a broken model', () => {
    // A half-typed model is the normal state of an editor and must not blank it.
    const state = evaluateModel('typing.yaml', 'schema: tmac/1.0\nmeta:\n  titl');
    expect(state.ok).toBe(false);
    expect(state.diagnostics.length).toBeGreaterThan(0);
    expect(state.graph).toBeUndefined();
  });

  it('survives text that is not YAML at all', () => {
    const state = evaluateModel('nope.yaml', '\t: [unclosed');
    expect(state.ok).toBe(false);
    expect(state.diagnostics[0]?.code).toBeDefined();
  });

  it('keeps the text even when it does not parse, so nothing is lost', () => {
    const text = 'schema: tmac/1.0\nbroken';
    expect(evaluateModel('x.yaml', text).text).toBe(text);
  });

  it('records how long the work took', () => {
    expect(evaluateModel('example.yaml', EXAMPLE).elapsedMs).toBeGreaterThanOrEqual(0);
  });

  it('starts empty', () => {
    expect(EMPTY.ok).toBe(false);
    expect(EMPTY.text).toBe('');
  });
});

describe('url target', () => {
  it('reads a model url from the query string', () => {
    expect(urlTarget('?model=https://example.test/tm.yaml')).toEqual({
      kind: 'url',
      value: 'https://example.test/tm.yaml',
    });
  });

  it('reports nothing when there is no model parameter', () => {
    expect(urlTarget('')).toEqual({ kind: 'none' });
    expect(urlTarget('?other=1')).toEqual({ kind: 'none' });
  });
});

describe('routing', () => {
  it('round-trips a route through the hash', () => {
    const route = { tab: 'risks' as const, selection: { kind: 'risk' as const, id: 'r@a' } };
    expect(parseHash(formatHash(route))).toEqual(route);
  });

  it('falls back to the default tab for nonsense', () => {
    expect(parseHash('#tab=nope')).toEqual(DEFAULT_ROUTE);
    expect(parseHash('')).toEqual(DEFAULT_ROUTE);
  });

  it('carries an element selection', () => {
    expect(parseHash('#tab=diagram&element=payment_api')).toEqual({
      tab: 'diagram',
      selection: { kind: 'element', id: 'payment_api' },
    });
  });

  it('keeps one selection, not several', () => {
    const route = parseHash('#tab=risks&risk=a@b&element=c');
    expect(route.selection).toEqual({ kind: 'risk', id: 'a@b' });
  });

  it('produces a hash a browser will accept', () => {
    const hash = formatHash({ tab: 'diagram', selection: { kind: 'flow', id: 'a_to_b' } });
    expect(hash.startsWith('#')).toBe(true);
    expect(hash).toContain('flow=a_to_b');
  });
});
