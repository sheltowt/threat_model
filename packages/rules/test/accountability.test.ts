import { describe, expect, it } from 'vitest';
import { buildGraph, builtinCatalog, modelSchema, type Model } from 'tmac-core';
import { analyze, builtinRules } from 'tmac-rules';

const rules = builtinRules();

/**
 * The repudiation and denial-of-service rules, which were the two thinnest parts of
 * the library: three rules between them, and neither of the two filed under
 * repudiation was actually about attribution.
 */

type Controls = Record<string, boolean>;

/** One asset and one caller, with everything else held constant. */
function model(overrides: {
  controls?: Controls;
  callerControls?: Controls;
  availability?: string;
  integrity?: string;
  formats?: string[];
  internetFacing?: boolean;
  authorization?: string;
  storeAvailability?: string;
}): Model {
  return modelSchema.parse({
    schema: 'tmac/1.0',
    meta: { title: 'Accountability fixture', business_criticality: 'critical' },
    data_assets: {
      ledger: {
        classification: 'confidential',
        integrity: overrides.integrity ?? 'critical',
        availability: overrides.availability ?? 'critical',
      },
    },
    elements: {
      user: { kind: 'actor', technology: 'browser', human: true, internet_facing: true },
      api: {
        technology: 'web-service-rest',
        custom_code: true,
        internet_facing: overrides.internetFacing ?? true,
        processes: ['ledger'],
        accepts_formats: overrides.formats ?? ['json'],
        controls: overrides.callerControls ?? {},
      },
      store: {
        technology: 'database',
        stores: ['ledger'],
        ...(overrides.storeAvailability ? { availability: overrides.storeAvailability } : {}),
        controls: overrides.controls ?? {},
      },
    },
    flows: [
      { id: 'user_api', from: 'user', to: 'api', protocol: 'https', authentication: 'session-id' },
      {
        id: 'api_store',
        from: 'api',
        to: 'store',
        protocol: 'sql-access-protocol-encrypted',
        authentication: 'credentials',
        authorization: overrides.authorization ?? 'technical-user',
        sends: ['ledger'],
      },
    ],
    trust_boundaries: {
      outside: { type: 'network-untrusted', contains: ['user'] },
      prod: { type: 'network-cloud-provider', contains: ['api', 'store'] },
    },
  });
}

function firesOn(m: Model, ruleId: string): { count: number; confidence: string[] } {
  const analysis = analyze(buildGraph(m, builtinCatalog()), rules);
  const hits = analysis.risks.filter((r) => r.rule === ruleId);
  return { count: hits.length, confidence: hits.map((h) => h.confidence) };
}

describe('missing-audit-log', () => {
  it('fires on custom code holding integrity-critical data', () => {
    expect(firesOn(model({}), 'missing-audit-log').count).toBeGreaterThan(0);
  });

  it('goes quiet on the element that records logging', () => {
    const m = model({ callerControls: { logs_security_events: true } });
    const analysis = analyze(buildGraph(m, builtinCatalog()), rules);
    const onApi = analysis.risks.filter(
      (r) => r.rule === 'missing-audit-log' && r.subject.id === 'api',
    );
    expect(onApi).toHaveLength(0);
  });

  it('does not ask a monitoring tool to log itself', () => {
    const m = modelSchema.parse({
      schema: 'tmac/1.0',
      meta: { title: 'm' },
      data_assets: { ledger: { integrity: 'mission-critical' } },
      elements: {
        collector: { technology: 'monitoring', custom_code: true, processes: ['ledger'] },
      },
    });
    expect(firesOn(m, 'missing-audit-log').count).toBe(0);
  });
});

describe('unprotected-audit-log', () => {
  it('fires only where logging was actually claimed', () => {
    const claimed = model({ controls: { logs_security_events: true } });
    expect(firesOn(claimed, 'unprotected-audit-log').count).toBe(1);
  });

  /**
   * The bug this rule shipped with, kept as a test.
   *
   * Without the `known()` guard the condition is unsettled wherever nobody mentioned
   * logging, so it asked "is your log protected?" of every element in the model,
   * including a human actor. Seven findings on an eight-element model, all noise.
   */
  it('says nothing about an element that never mentioned logging', () => {
    expect(firesOn(model({}), 'unprotected-audit-log').count).toBe(0);
  });

  it('goes quiet once the log is protected', () => {
    const m = model({ controls: { logs_security_events: true, log_integrity_protected: true } });
    expect(firesOn(m, 'unprotected-audit-log').count).toBe(0);
  });

  it('is confirmed, not unsettled, when protection is recorded absent', () => {
    const m = model({ controls: { logs_security_events: true, log_integrity_protected: false } });
    expect(firesOn(m, 'unprotected-audit-log').confidence).toEqual(['high']);
  });
});

describe('lost-user-attribution', () => {
  it('fires when a service-account hop is not logged by its caller', () => {
    expect(firesOn(model({}), 'lost-user-attribution').count).toBe(1);
  });

  it('goes quiet when the caller records the correlation', () => {
    const m = model({ callerControls: { logs_security_events: true } });
    expect(firesOn(m, 'lost-user-attribution').count).toBe(0);
  });

  it('goes quiet when the user identity is propagated instead', () => {
    const m = model({ authorization: 'end-user-identity' });
    expect(firesOn(m, 'lost-user-attribution').count).toBe(0);
  });
});

describe('single-point-of-failure', () => {
  it('fires on an availability-critical asset with no redundancy recorded', () => {
    expect(firesOn(model({}), 'single-point-of-failure').count).toBeGreaterThan(0);
  });

  it('goes quiet once redundancy is recorded', () => {
    const m = model({
      controls: { redundant: true },
      callerControls: { redundant: true },
    });
    expect(firesOn(m, 'single-point-of-failure').count).toBe(0);
  });

  it('ignores an asset the model does not claim to need', () => {
    const m = model({ availability: 'operational' });
    expect(firesOn(m, 'single-point-of-failure').count).toBe(0);
  });
});

describe('unbounded-input-size', () => {
  it('fires on internet-reachable custom code parsing attacker-sized input', () => {
    expect(firesOn(model({ formats: ['file'] }), 'unbounded-input-size').count).toBe(1);
  });

  it('goes quiet once a bound is recorded', () => {
    const m = model({ formats: ['file'], callerControls: { checks_input_bounds: true } });
    expect(firesOn(m, 'unbounded-input-size').count).toBe(0);
  });

  it('ignores a format whose size the attacker does not choose', () => {
    const m = model({ formats: ['csv'] });
    expect(firesOn(m, 'unbounded-input-size').count).toBe(0);
  });
});

describe('availability-dependency-inversion', () => {
  it('fires when a critical asset calls something rated lower', () => {
    const m = model({ availability: 'critical', storeAvailability: 'operational' });
    expect(firesOn(m, 'availability-dependency-inversion').count).toBe(1);
  });

  it('is always confirmed, because it reads ratings rather than controls', () => {
    const m = model({ availability: 'critical', storeAvailability: 'operational' });
    expect(firesOn(m, 'availability-dependency-inversion').confidence).toEqual(['high']);
  });

  it('goes quiet when the dependency matches', () => {
    const m = model({ availability: 'critical', storeAvailability: 'critical' });
    expect(firesOn(m, 'availability-dependency-inversion').count).toBe(0);
  });
});

describe('coverage across STRIDE', () => {
  it('no category is left with a token rule or two', () => {
    // The gap this file exists to close: repudiation had two rules, neither of which
    // was about attribution, and denial of service had one.
    const counts = new Map<string, number>();
    for (const rule of rules) counts.set(rule.stride, (counts.get(rule.stride) ?? 0) + 1);
    for (const category of [
      'spoofing',
      'tampering',
      'repudiation',
      'information-disclosure',
      'denial-of-service',
      'elevation-of-privilege',
    ]) {
      expect(counts.get(category) ?? 0, `${category} is thin`).toBeGreaterThanOrEqual(4);
    }
  });
});
