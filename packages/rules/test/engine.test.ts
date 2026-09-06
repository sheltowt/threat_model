import { describe, expect, it } from 'vitest';
import { fileURLToPath } from 'node:url';
import { buildGraph, loadModel, type ModelGraph } from '@tmc/core';
import { analyze, calculateSeverity, ruleSchema, type LoadedRule } from '@tmc/rules';

const fixture = (name: string) =>
  fileURLToPath(new URL(`../../core/test/fixtures/${name}`, import.meta.url));

function graphOf(name: string): ModelGraph {
  const { model, catalog } = loadModel(fixture(name));
  return buildGraph(model, catalog);
}

/** Build a rule in-line so engine tests do not move when the library grows. */
function rule(partial: Record<string, unknown>): LoadedRule {
  const parsed = ruleSchema.parse({
    title: 'Test rule',
    stride: 'tampering',
    function: 'architecture',
    detection_logic: 'test',
    false_positives: 'test',
    mitigation: 'test',
    ...partial,
  });
  return { ...parsed, source: 'inline', builtin: false };
}

describe('severity', () => {
  it('is the product of likelihood and impact', () => {
    expect(calculateSeverity('unlikely', 'low')).toBe('low');
    expect(calculateSeverity('unlikely', 'medium')).toBe('medium');
    expect(calculateSeverity('likely', 'medium')).toBe('elevated');
    expect(calculateSeverity('very-likely', 'high')).toBe('high');
    expect(calculateSeverity('frequent', 'very-high')).toBe('critical');
  });

  it('gives the same answer whichever rule asks', () => {
    expect(calculateSeverity('likely', 'high')).toBe(calculateSeverity('very-likely', 'medium'));
  });
});

describe('firing and confidence', () => {
  const g = () => graphOf('minimal.yaml');

  it('fires on every matching candidate', () => {
    const a = analyze(g(), [rule({ id: 'always', scope: 'element', match: 'true' })]);
    expect(a.risks).toHaveLength(2);
    expect(a.risks.map((r) => r.id).sort()).toEqual(['always@a', 'always@b']);
  });

  it('does not fire when the condition is definitely false', () => {
    const a = analyze(g(), [rule({ id: 'never', scope: 'element', match: 'false' })]);
    expect(a.risks).toEqual([]);
  });

  it('marks a finding low confidence when the condition cannot be settled', () => {
    const a = analyze(g(), [
      rule({ id: 'gap', scope: 'element', match: '!element.controls.hardened' }),
    ]);
    expect(a.risks).toHaveLength(2);
    expect(a.risks.every((r) => r.confidence === 'low')).toBe(true);
    expect(a.risks[0]?.unknowns).toEqual(['element.controls.hardened']);
    expect(a.stats.lowConfidenceRisks).toBe(2);
  });

  it('marks a finding high confidence when the control is recorded absent', () => {
    const { model, catalog } = loadModel(fixture('minimal.yaml'));
    model.elements['a']!.controls.hardened = false;
    const a = analyze(buildGraph(model, catalog), [
      rule({ id: 'gap', scope: 'element', match: '!element.controls.hardened' }),
    ]);
    const onA = a.risks.find((r) => r.id === 'gap@a')!;
    expect(onA.confidence).toBe('high');
    expect(onA.unknowns).toEqual([]);
  });

  it('reports a rule that hits a type error instead of aborting the run', () => {
    const a = analyze(g(), [
      rule({ id: 'broken', scope: 'element', match: 'element.name > 5' }),
      rule({ id: 'fine', scope: 'element', match: 'true' }),
    ]);
    expect(a.warnings.some((w) => w.code === 'rule-error')).toBe(true);
    expect(a.risks.map((r) => r.rule)).toEqual(['fine', 'fine']);
  });

  it('skips a rule the model disables', () => {
    const { model, catalog } = loadModel(fixture('minimal.yaml'));
    model.disabled_rules['always'] = 'not relevant to this system';
    const a = analyze(buildGraph(model, catalog), [
      rule({ id: 'always', scope: 'element', match: 'true' }),
    ]);
    expect(a.risks).toEqual([]);
    expect(a.stats.rulesSkipped).toBe(1);
  });
});

describe('scopes', () => {
  it('flow scope sees both endpoints', () => {
    const a = analyze(graphOf('minimal.yaml'), [
      rule({
        id: 'r',
        scope: 'flow',
        match: 'flow.to.technology.vulnerable_to_query_injection',
        risk_title: '{{ flow.from.id }} to {{ flow.to.id }}',
      }),
    ]);
    expect(a.risks).toHaveLength(1);
    expect(a.risks[0]?.title).toBe('a to b');
  });

  it('model scope fires at most once', () => {
    const a = analyze(graphOf('minimal.yaml'), [
      rule({ id: 'r', scope: 'model', match: 'model.element_count > 1' }),
    ]);
    expect(a.risks).toHaveLength(1);
    expect(a.risks[0]?.subject.kind).toBe('model');
  });

  it('data scope iterates data assets', () => {
    const a = analyze(graphOf('parent.yaml'), [
      rule({ id: 'r', scope: 'data', match: 'data.credentials' }),
    ]);
    expect(a.risks.map((r) => r.id)).toEqual(['r@secret']);
  });

  it('element scope excludes out-of-scope elements without the rule asking', () => {
    const { model, catalog } = loadModel(fixture('minimal.yaml'));
    model.elements['b']!.out_of_scope = true;
    const a = analyze(buildGraph(model, catalog), [
      rule({ id: 'r', scope: 'element', match: 'true' }),
    ]);
    expect(a.risks.map((r) => r.id)).toEqual(['r@a']);
  });
});

describe('ratings', () => {
  it('accepts a literal', () => {
    const a = analyze(graphOf('minimal.yaml'), [
      rule({ id: 'r', scope: 'element', match: 'true', likelihood: 'frequent', impact: 'very-high' }),
    ]);
    expect(a.risks[0]?.severity).toBe('critical');
  });

  it('accepts an expression', () => {
    const a = analyze(graphOf('parent.yaml'), [
      rule({
        id: 'r',
        scope: 'element',
        match: 'true',
        likelihood: "element.internet_facing ? 'frequent' : 'unlikely'",
        impact: 'very-high',
      }),
    ]);
    const api = a.risks.find((r) => r.id === 'r@api')!;
    const db = a.risks.find((r) => r.id === 'r@db')!;
    expect(api.likelihood).toBe('frequent');
    expect(db.likelihood).toBe('unlikely');
  });

  it('warns and falls back when an expression yields something unusable', () => {
    const a = analyze(graphOf('minimal.yaml'), [
      rule({ id: 'r', scope: 'element', match: 'true', likelihood: "'nonsense'" }),
    ]);
    expect(a.warnings.some((w) => w.code === 'rating')).toBe(true);
    expect(a.risks[0]?.likelihood).toBe('likely');
  });
});

describe('risk tracking', () => {
  const withTracking = (tracking: Record<string, unknown>) => {
    const { model, catalog } = loadModel(fixture('minimal.yaml'));
    Object.assign(model.risk_tracking, tracking);
    return buildGraph(model, catalog);
  };

  it('attaches a status and takes the risk off the open list', () => {
    const a = analyze(
      withTracking({ 'r@a': { status: 'mitigated', justification: 'fixed in PR 12' } }),
      [rule({ id: 'r', scope: 'element', match: 'true' })],
    );
    const onA = a.risks.find((x) => x.id === 'r@a')!;
    expect(onA.status).toBe('mitigated');
    expect(onA.tracking?.justification).toBe('fixed in PR 12');
    expect(a.stats.openRisks).toBe(1);
  });

  it('supports a wildcard key', () => {
    const a = analyze(withTracking({ 'r@*': { status: 'accepted' } }), [
      rule({ id: 'r', scope: 'element', match: 'true' }),
    ]);
    expect(a.risks.every((x) => x.status === 'accepted')).toBe(true);
    expect(a.stats.openRisks).toBe(0);
  });

  it('warns about a key that matches nothing, because it is now lying', () => {
    const a = analyze(withTracking({ 'r@ghost': { status: 'accepted' } }), [
      rule({ id: 'r', scope: 'element', match: 'true' }),
    ]);
    expect(a.warnings.some((w) => w.code.startsWith('orphaned-tracking'))).toBe(true);
  });

  it('survives a change of rule wording, because the id is built from ids alone', () => {
    const before = analyze(withTracking({ 'r@a': { status: 'accepted' } }), [
      rule({ id: 'r', scope: 'element', match: 'true', title: 'One wording' }),
    ]);
    const after = analyze(withTracking({ 'r@a': { status: 'accepted' } }), [
      rule({ id: 'r', scope: 'element', match: 'true', title: 'A completely different wording' }),
    ]);
    expect(before.risks.map((x) => x.id)).toEqual(after.risks.map((x) => x.id));
    expect(after.risks.find((x) => x.id === 'r@a')?.status).toBe('accepted');
  });
});

describe('assumptions', () => {
  const suppressing = (suppresses: string[]) => {
    const { model, catalog } = loadModel(fixture('minimal.yaml'));
    model.assumptions.push({ id: 'A1', text: 'out of scope for us', suppresses });
    return buildGraph(model, catalog);
  };

  it('keeps a suppressed risk visible but off the open list', () => {
    const a = analyze(suppressing(['r@a']), [rule({ id: 'r', scope: 'element', match: 'true' })]);
    const onA = a.risks.find((x) => x.id === 'r@a')!;
    expect(onA.suppressed_by).toBe('A1');
    expect(a.risks).toHaveLength(2);
    expect(a.stats.openRisks).toBe(1);
  });

  it('warns about an assumption that hides nothing', () => {
    const a = analyze(suppressing(['r@ghost']), [
      rule({ id: 'r', scope: 'element', match: 'true' }),
    ]);
    expect(a.warnings.some((w) => w.code === 'unused-suppression')).toBe(true);
  });
});

describe('manual threats', () => {
  it('joins the generated risks in one list', () => {
    const { model, catalog } = loadModel(fixture('minimal.yaml'));
    model.manual_threats.push({
      id: 'T-1',
      title: 'Reviewed by hand',
      element: 'a',
      severity: 'high',
      tags: [],
    });
    const a = analyze(buildGraph(model, catalog), []);
    expect(a.risks).toHaveLength(1);
    expect(a.risks[0]?.id).toBe('manual@T-1');
    expect(a.risks[0]?.severity).toBe('high');
  });
});

describe('ordering', () => {
  it('puts the worst first and is deterministic', () => {
    const rules = [
      rule({ id: 'low', scope: 'element', match: 'true', likelihood: 'unlikely', impact: 'low' }),
      rule({
        id: 'bad',
        scope: 'element',
        match: 'true',
        likelihood: 'frequent',
        impact: 'very-high',
      }),
    ];
    const a = analyze(graphOf('minimal.yaml'), rules);
    expect(a.risks[0]?.severity).toBe('critical');
    expect(a.risks.map((r) => r.id)).toEqual(analyze(graphOf('minimal.yaml'), rules).risks.map((r) => r.id));
  });
});
