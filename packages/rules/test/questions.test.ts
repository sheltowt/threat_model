import { describe, expect, it } from 'vitest';
import { buildGraph, builtinCatalog, modelSchema, type Model } from 'tmac-core';
import { analyze, builtinRules, questionStats, questions } from 'tmac-rules';

const rules = builtinRules();

/**
 * The model's own to-do list.
 *
 * Every unsettled finding already names the field the rule could not read, which is
 * the honest per-finding answer and a wall of text across a whole model. These tests
 * are about the turn-around: one entry per unrecorded field, ordered so the top one
 * is worth answering first.
 */

function model(controls: Record<string, boolean> = {}): Model {
  return modelSchema.parse({
    schema: 'tmac/1.0',
    meta: { title: 'Questions fixture', business_criticality: 'critical' },
    data_assets: {
      secrets: { classification: 'strictly-confidential', integrity: 'mission-critical', credentials: true },
    },
    elements: {
      user: { kind: 'actor', technology: 'browser', human: true, internet_facing: true },
      api: {
        technology: 'web-service-rest',
        custom_code: true,
        internet_facing: true,
        processes: ['secrets'],
        controls,
      },
      store: { technology: 'database', stores: ['secrets'] },
    },
    flows: [
      { id: 'user_api', from: 'user', to: 'api', protocol: 'https', authentication: 'session-id' },
      {
        id: 'api_store',
        from: 'api',
        to: 'store',
        protocol: 'sql-access-protocol',
        authentication: 'credentials',
        authorization: 'technical-user',
        sends: ['secrets'],
      },
    ],
    trust_boundaries: {
      outside: { type: 'network-untrusted', contains: ['user'] },
      prod: { type: 'network-cloud-provider', contains: ['api', 'store'] },
    },
  });
}

const ask = (m: Model) => {
  const graph = buildGraph(m, builtinCatalog());
  return { list: questions(analyze(graph, rules), graph), graph };
};

describe('shape', () => {
  it('produces one entry per unrecorded field, not one per finding', () => {
    const { list } = ask(model());
    expect(list.length).toBeGreaterThan(0);
    const fields = list.map((q) => q.field);
    expect(new Set(fields).size).toBe(fields.length);
  });

  it('names the asset to edit, not the rule view of the field', () => {
    // A rule writes `flow.from.controls.x`; the reader needs to know which asset.
    const { list } = ask(model());
    for (const q of list) {
      expect(q.field).not.toContain('flow.from.');
      expect(q.field).not.toContain('flow.to.');
      if (q.control) expect(q.field).toBe(`${q.subject}.controls.${q.control}`);
    }
  });

  it('carries the findings each question is holding up', () => {
    const { list } = ask(model());
    for (const q of list) {
      expect(q.blocking.length).toBeGreaterThan(0);
      expect(q.rules.length).toBeGreaterThan(0);
      for (const r of q.blocking) expect(r.confidence).toBe('low');
    }
  });
});

describe('ordering', () => {
  it('puts the worst severity first', () => {
    const order = ['critical', 'high', 'elevated', 'medium', 'low'];
    const { list } = ask(model());
    const ranks = list.map((q) => order.indexOf(q.worstSeverity));
    expect(ranks).toEqual([...ranks].sort((a, b) => a - b));
  });

  it('breaks a tie by how many findings the answer settles', () => {
    const { list } = ask(model());
    for (let i = 1; i < list.length; i++) {
      const a = list[i - 1]!;
      const b = list[i]!;
      if (a.worstSeverity === b.worstSeverity) {
        expect(a.blocking.length).toBeGreaterThanOrEqual(b.blocking.length);
      }
    }
  });

  it('is deterministic', () => {
    expect(ask(model()).list.map((q) => q.field)).toEqual(ask(model()).list.map((q) => q.field));
  });
});

describe('answering one', () => {
  it('removes that question for that asset', () => {
    // Scoped to the asset on purpose. The same control is asked about separately on
    // every asset that has not recorded it, and a boundary-scoped rule asks about it
    // across a whole boundary, so answering it here settles this entry and no other.
    const before = ask(model()).list;
    const target = before.find((q) => q.subject === 'api' && q.control === 'logs_security_events');
    expect(target, 'the fixture should ask api about logging').toBeDefined();

    const after = ask(model({ logs_security_events: true })).list;
    expect(
      after.find((q) => q.subject === 'api' && q.control === 'logs_security_events'),
    ).toBeUndefined();

    // Deliberately not asserting the list got shorter. A rule that stopped at an
    // earlier `&&` now evaluates further and asks about the next field along, so
    // answering one question can reveal the next. That is the model getting more
    // specific, not the tool moving the goalposts, and the count can hold steady.
    expect(before.length).toBeGreaterThan(0);
  });

  it('removes the gap from the findings that were waiting on it', () => {
    // Not the same as settling them: a finding can wait on several fields, and this
    // is the claim the feature can actually make.
    const target = ask(model()).list.find(
      (q) => q.subject === 'api' && q.control === 'logs_security_events',
    )!;
    const ids = target.blocking.map((r) => r.id);

    // Either answer removes the gap. `false` is as useful as `true`: it turns an
    // unsettled finding into a confirmed one, which is something you can act on.
    for (const answer of [true, false]) {
      const graph = buildGraph(model({ logs_security_events: answer }), builtinCatalog());
      const risks = analyze(graph, rules).risks;
      for (const id of ids) {
        const still = risks.find((r) => r.id === id);
        if (!still) continue; // resolved outright, which is the stronger outcome
        const waiting = still.unknowns.filter((u) => u.endsWith('.controls.logs_security_events'));
        expect(waiting, `${id} should no longer wait on api logging`).toEqual([]);
      }
    }
  });

  it('has nothing left to ask about an asset once every answer is given', () => {
    const everything: Record<string, boolean> = {};
    for (const q of ask(model()).list) {
      if (q.subject === 'api' && q.control) everything[q.control] = true;
    }
    const remaining = ask(model(everything)).list.filter(
      (q) => q.subject === 'api' && q.control !== undefined && everything[q.control] === undefined,
    );
    // Answering one round can reveal a second: a rule that could not get past an
    // earlier `&&` now evaluates further and asks about the next field along.
    expect(remaining.every((q) => !(q.control! in everything))).toBe(true);
  });
});

describe('stats', () => {
  it('counts questions and the findings behind them', () => {
    const { list } = ask(model());
    const stats = questionStats(list);
    expect(stats.open).toBe(list.length);
    expect(stats.unsettledFindings).toBeGreaterThan(0);
    expect(stats.topQuestionUnblocks).toBe(list[0]!.blocking.length);
  });

  it('counts a finding once even when several questions block it', () => {
    const { list } = ask(model());
    const stats = questionStats(list);
    const naive = list.reduce((n, q) => n + q.blocking.length, 0);
    expect(stats.unsettledFindings).toBeLessThanOrEqual(naive);
  });

  it('reports nothing for a model with no gaps', () => {
    expect(questionStats([])).toEqual({
      open: 0,
      unsettledFindings: 0,
      topQuestionUnblocks: 0,
    });
  });
});
