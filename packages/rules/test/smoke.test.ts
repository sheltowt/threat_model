import { describe, expect, it } from 'vitest';
import { fileURLToPath } from 'node:url';
import { buildGraph, loadModel } from 'tmac-core';
import { analyze, loadRules } from 'tmac-rules';

const example = fileURLToPath(
  new URL('../../../examples/payment-service/threatmodel.yaml', import.meta.url),
);

describe('end to end', () => {
  it('loads the example model and produces risks', () => {
    const { model, catalog, diagnostics } = loadModel(example);
    expect(diagnostics.filter((d) => d.severity === 'error')).toEqual([]);

    const graph = buildGraph(model, catalog);
    expect(graph.elements.length).toBe(8);
    expect(graph.flows.length).toBe(7);

    const { rules, errors } = loadRules();
    expect(errors).toEqual([]);
    expect(rules.length).toBeGreaterThan(0);

    const analysis = analyze(graph, rules);
    expect(analysis.warnings.filter((w) => w.code === 'rule-error')).toEqual([]);
    expect(analysis.risks.length).toBeGreaterThan(0);
  });
});
