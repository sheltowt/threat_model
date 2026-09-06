import { describe, expect, it } from 'vitest';
import { buildGraph, builtinCatalog, modelSchema, type Model } from '@tmc/core';
import { CONTROL_NAMES } from '@tmc/core';
import { analyze, loadRules, type LoadedRule } from '@tmc/rules';

const { rules } = loadRules();

/** Every control set to the same value, for the two extremes below. */
function allControls(value: boolean): Record<string, boolean> {
  return Object.fromEntries(CONTROL_NAMES.map((name) => [name, value]));
}

/**
 * One system, described three ways.
 *
 * `bare` records no control at all, so every control-dependent rule should be
 * uncertain rather than confident. `insecure` records them all absent, so the same
 * rules should be confident. `hardened` records them all present, so they should be
 * silent. Comparing the three exercises all fifty rules at once and checks the
 * property that matters more than any individual rule: that recording what you know
 * moves findings, and in the right direction.
 */
function system(controls: Record<string, boolean>): Model {
  return modelSchema.parse({
    schema: 'tmc/1.0',
    meta: { title: 'Property fixture', business_criticality: 'critical' },
    data_assets: {
      secrets: {
        classification: 'strictly-confidential',
        integrity: 'mission-critical',
        availability: 'critical',
        quantity: 'many',
        credentials: true,
      },
      personal: {
        classification: 'confidential',
        integrity: 'critical',
        quantity: 'very-many',
        pii: true,
        regulations: ['gdpr'],
      },
    },
    elements: {
      user: { kind: 'actor', technology: 'browser', human: true, internet_facing: true },
      web: {
        technology: 'web-application',
        machine: 'container',
        internet_facing: true,
        custom_code: true,
        multi_tenant: true,
        processes: ['personal', 'secrets'],
        accepts_formats: ['json', 'xml', 'file', 'serialization'],
        controls,
      },
      api: {
        technology: 'web-service-rest',
        machine: 'container',
        custom_code: true,
        processes: ['personal', 'secrets'],
        accepts_formats: ['json'],
        controls,
      },
      db: {
        technology: 'database',
        machine: 'virtual',
        stores: ['personal', 'secrets'],
        controls,
      },
      ci: { technology: 'build-pipeline', machine: 'container', usage: 'devops', controls },
      repo: { technology: 'sourcecode-repository', usage: 'devops', stores: ['secrets'], controls },
    },
    flows: [
      {
        id: 'user_web',
        from: 'user',
        to: 'web',
        protocol: 'http',
        authentication: 'session-id',
        authorization: 'end-user-identity',
        sends: ['personal', 'secrets'],
        controls,
      },
      {
        id: 'web_api',
        from: 'web',
        to: 'api',
        protocol: 'http',
        authentication: 'token',
        authorization: 'end-user-identity',
        sends: ['personal'],
        controls,
      },
      {
        id: 'api_db',
        from: 'api',
        to: 'db',
        protocol: 'sql-access-protocol',
        authentication: 'credentials',
        authorization: 'technical-user',
        sends: ['personal', 'secrets'],
        controls,
      },
      // Deliberately left unauthenticated, so authentication rules have a real
      // target and the breadth check below is testing breadth rather than a fixture
      // that is uniformly broken in one dimension.
      { id: 'ci_repo', from: 'ci', to: 'repo', protocol: 'https', receives: ['secrets'], controls },
    ],
    trust_boundaries: {
      outside: { type: 'network-untrusted', contains: ['user'] },
      prod: { type: 'network-cloud-provider', contains: ['web', 'api', 'db', 'ci', 'repo'] },
    },
  });
}

function analyzeSystem(controls: Record<string, boolean>) {
  const model = system(controls);
  const graph = buildGraph(model, builtinCatalog());
  return { graph, analysis: analyze(graph, rules) };
}

const bare = analyzeSystem({});
const insecure = analyzeSystem(allControls(false));
const hardened = analyzeSystem(allControls(true));

describe('the whole library runs cleanly', () => {
  it.each([
    ['nothing recorded', bare],
    ['every control absent', insecure],
    ['every control present', hardened],
  ])('raises no rule error on a model with %s', (_label, run) => {
    const errors = run.analysis.warnings.filter((w) => w.code === 'rule-error');
    expect(errors.map((e) => e.message)).toEqual([]);
  });

  it.each([
    ['nothing recorded', bare],
    ['every control absent', insecure],
    ['every control present', hardened],
  ])('produces no unusable rating on a model with %s', (_label, run) => {
    expect(run.analysis.warnings.filter((w) => w.code === 'rating')).toEqual([]);
  });
});

describe('recording controls moves findings in the right direction', () => {
  it('turns uncertainty into confirmation when controls are recorded absent', () => {
    // Same system, same flaws; the only change is that someone wrote them down.
    expect(insecure.analysis.stats.lowConfidenceRisks).toBeLessThan(
      bare.analysis.stats.lowConfidenceRisks,
    );
  });

  it('produces fewer risks once controls are recorded present', () => {
    expect(hardened.analysis.risks.length).toBeLessThan(insecure.analysis.risks.length);
  });

  it('leaves almost nothing uncertain once every control is recorded', () => {
    const uncertain = hardened.analysis.stats.lowConfidenceRisks;
    expect(uncertain).toBeLessThanOrEqual(bare.analysis.stats.lowConfidenceRisks / 4);
  });

  it('never reports a low-confidence finding without naming the gap', () => {
    for (const run of [bare, insecure, hardened]) {
      for (const risk of run.analysis.risks) {
        if (risk.confidence !== 'low') continue;
        expect(risk.unknowns.length, `${risk.id} should name its gap`).toBeGreaterThan(0);
      }
    }
  });
});

describe('no rule is too broad', () => {
  const eligible = (rule: LoadedRule, graph: typeof bare.graph) => {
    switch (rule.scope) {
      case 'element':
        return graph.inScope.length;
      case 'flow':
        return graph.flows.length;
      case 'boundary':
        return graph.boundaries.length;
      case 'data':
        return graph.data.length;
      case 'model':
        return 1;
    }
  };

  it('no rule fires on every candidate of a deliberately insecure model', () => {
    // A rule that always fires carries no information, and it is the commonest way
    // a generated threat model becomes something everybody scrolls past.
    const counts = new Map<string, number>();
    for (const risk of insecure.analysis.risks) {
      counts.set(risk.rule, (counts.get(risk.rule) ?? 0) + 1);
    }
    const tooBroad: string[] = [];
    for (const rule of rules) {
      if (rule.scope === 'model') continue;
      const fired = counts.get(rule.id) ?? 0;
      const possible = eligible(rule, insecure.graph);
      if (possible > 2 && fired === possible) tooBroad.push(`${rule.id} (${fired}/${possible})`);
    }
    expect(tooBroad).toEqual([]);
  });

  it('stays quiet on a hardened system for most rules', () => {
    const firing = new Set(hardened.analysis.risks.map((r) => r.rule));
    expect(firing.size).toBeLessThan(rules.length / 2);
  });
});

describe('every finding is actionable', () => {
  it('carries a mitigation, a subject and a stable id', () => {
    for (const risk of insecure.analysis.risks) {
      expect(risk.mitigation.trim().length, `${risk.id} mitigation`).toBeGreaterThan(10);
      expect(risk.subject.id.length).toBeGreaterThan(0);
      expect(risk.id).toContain('@');
    }
  });

  it('gives every finding a distinct id', () => {
    const ids = insecure.analysis.risks.map((r) => r.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it('produces the same ids on a second run', () => {
    const again = analyzeSystem(allControls(false));
    expect(again.analysis.risks.map((r) => r.id)).toEqual(
      insecure.analysis.risks.map((r) => r.id),
    );
  });
});
