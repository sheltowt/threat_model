import { readFileSync, readdirSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { CONTROL_NAMES, buildGraph, builtinCatalog, modelSchema, type Model } from 'tmac-core';
import { analyze, builtinRules } from 'tmac-rules';

const rules = builtinRules();

/**
 * Every control the schema offers must drive at least one rule.
 *
 * Inviting somebody to record a control and then never reading it is worse than not
 * offering it: they do the work of finding out, write it down, and nothing changes.
 * Nine controls sat unread for the whole life of the project before this test.
 */
describe('the schema and the rule library agree', () => {
  it('has no control that no rule reads', () => {
    const ruleText = readdirSync(resolve('packages/rules/rules'))
      .map((f) => readFileSync(resolve('packages/rules/rules', f), 'utf8'))
      .join('\n');
    const unread = CONTROL_NAMES.filter((name) => !ruleText.includes(`controls.${name}`));
    expect(unread, 'these controls can be recorded but change nothing').toEqual([]);
  });

  it('has no rule reading a control the schema does not define', () => {
    const known = new Set<string>(CONTROL_NAMES);
    const ruleText = readdirSync(resolve('packages/rules/rules'))
      .map((f) => readFileSync(resolve('packages/rules/rules', f), 'utf8'))
      .join('\n');
    const referenced = [...ruleText.matchAll(/controls\.([a-z_]+)/g)].map((m) => m[1]!);
    const unknown = [...new Set(referenced)].filter((name) => !known.has(name));
    // A control that does not exist reads as unknown for ever, so the rule would
    // fire at low confidence on everything and never resolve.
    expect(unknown, 'these would silently never resolve').toEqual([]);
  });

  it('does not offer two ways to say the same thing', () => {
    // `uses_vpn` as a control duplicated `vpn` on the flow, and only the flow field
    // was ever read. A tunnel is a property of a route, not of an asset.
    expect(CONTROL_NAMES).not.toContain('uses_vpn');
  });
});

type Controls = Record<string, boolean>;

function model(o: {
  flowControls?: Controls;
  targetControls?: Controls;
  callerControls?: Controls;
  authentication?: string;
  authorization?: string;
  protocol?: string;
  formats?: string[];
  classification?: string;
}): Model {
  return modelSchema.parse({
    schema: 'tmac/1.0',
    meta: { title: 'Controls fixture', business_criticality: 'critical' },
    data_assets: { records: { classification: o.classification ?? 'confidential' } },
    elements: {
      user: { kind: 'actor', technology: 'browser', human: true, internet_facing: true },
      web: {
        technology: 'web-application',
        custom_code: true,
        internet_facing: true,
        processes: ['records'],
        accepts_formats: o.formats ?? ['json'],
        controls: o.callerControls ?? {},
      },
      store: {
        technology: 'database',
        stores: ['records'],
        controls: o.targetControls ?? {},
      },
    },
    flows: [
      // Fully specified, so only the flow under test varies. Leaving its
      // authorization unset made it trip the authorisation rules by itself.
      {
        id: 'user_web',
        from: 'user',
        to: 'web',
        protocol: 'https',
        authentication: 'session-id',
        authorization: 'end-user-identity',
        controls: { authenticates_destination: true, authenticates_source: true },
      },
      {
        id: 'web_store',
        from: 'web',
        to: 'store',
        protocol: o.protocol ?? 'sql-access-protocol-encrypted',
        authentication: o.authentication ?? 'credentials',
        authorization: o.authorization ?? 'technical-user',
        sends: ['records'],
        controls: o.flowControls ?? {},
      },
    ],
    trust_boundaries: {
      outside: { type: 'network-untrusted', contains: ['user'] },
      web_tier: { type: 'network-cloud-provider', contains: ['web'] },
      data_tier: { type: 'network-cloud-security-group', contains: ['store'] },
    },
  });
}

const fires = (m: Model, id: string) =>
  analyze(buildGraph(m, builtinCatalog()), rules).risks.filter((r) => r.rule === id);

describe('unverified-server-identity', () => {
  it('fires on an encrypted hop that does not verify who answered', () => {
    expect(fires(model({}), 'unverified-server-identity')).toHaveLength(1);
  });

  it('goes quiet once verification is recorded', () => {
    const m = model({ flowControls: { authenticates_destination: true } });
    expect(fires(m, 'unverified-server-identity')).toHaveLength(0);
  });

  it('says nothing about an unencrypted link, which has a different problem', () => {
    const m = model({ protocol: 'sql-access-protocol' });
    expect(fires(m, 'unverified-server-identity')).toHaveLength(0);
  });
});

describe('missing-mutual-authentication', () => {
  it('fires when the receiving service does not verify its caller', () => {
    expect(fires(model({}), 'missing-mutual-authentication').length).toBeGreaterThan(0);
  });

  it('goes quiet once the receiver records that it verifies', () => {
    const m = model({ targetControls: { authenticates_source: true } });
    expect(fires(m, 'missing-mutual-authentication')).toHaveLength(0);
  });

  it('treats a client certificate as the control in action', () => {
    const m = model({ authentication: 'client-certificate' });
    expect(fires(m, 'missing-mutual-authentication')).toHaveLength(0);
  });
});

describe('missing-certificate-revocation-check', () => {
  it('fires where client certificates are accepted without a revocation check', () => {
    const m = model({ authentication: 'client-certificate' });
    expect(fires(m, 'missing-certificate-revocation-check')).toHaveLength(1);
  });

  it('goes quiet once revocation is checked', () => {
    const m = model({
      authentication: 'client-certificate',
      flowControls: { checks_certificate_revocation: true },
    });
    expect(fires(m, 'missing-certificate-revocation-check')).toHaveLength(0);
  });

  it('says nothing where certificates are not used at all', () => {
    expect(fires(model({}), 'missing-certificate-revocation-check')).toHaveLength(0);
  });
});

describe('authentication-without-authorization', () => {
  it('fires when a caller is identified but nothing checks its permissions', () => {
    const m = model({ authorization: 'none' });
    expect(fires(m, 'authentication-without-authorization')).toHaveLength(1);
  });

  it('goes quiet once an authorisation check is recorded', () => {
    const m = model({ authorization: 'none', targetControls: { authorizes_source: true } });
    expect(fires(m, 'authentication-without-authorization')).toHaveLength(0);
  });

  it('says nothing about an unauthenticated link, which missing-authentication covers', () => {
    const m = model({ authentication: 'none', authorization: 'none' });
    expect(fires(m, 'authentication-without-authorization')).toHaveLength(0);
  });
});

describe('excessive-privilege', () => {
  it('fires on a valuable asset that can reach further', () => {
    expect(fires(model({}), 'excessive-privilege').map((r) => r.subject.id)).toContain('web');
  });

  it('spares a leaf datastore, which has no onward journey to constrain', () => {
    // The refinement that stopped this rule firing on five of seven assets.
    expect(fires(model({}), 'excessive-privilege').map((r) => r.subject.id)).not.toContain('store');
  });

  it('goes quiet once least privilege is recorded', () => {
    const m = model({ callerControls: { implements_least_privilege: true } });
    expect(fires(m, 'excessive-privilege').map((r) => r.subject.id)).not.toContain('web');
  });
});

describe('weak-session-identifier', () => {
  it('fires on a session-authenticated app with no strength guarantee', () => {
    expect(fires(model({}), 'weak-session-identifier')).toHaveLength(1);
  });

  it('goes quiet once strong identifiers are recorded', () => {
    const m = model({ callerControls: { uses_strong_session_ids: true } });
    expect(fires(m, 'weak-session-identifier')).toHaveLength(0);
  });
});

describe('missing-content-type-validation', () => {
  it('fires only where more than one format is accepted', () => {
    expect(fires(model({ formats: ['json'] }), 'missing-content-type-validation')).toHaveLength(0);
    expect(
      fires(model({ formats: ['json', 'xml'] }), 'missing-content-type-validation'),
    ).toHaveLength(1);
  });

  it('goes quiet once the type is checked', () => {
    const m = model({
      formats: ['json', 'xml'],
      callerControls: { validates_content_type: true },
    });
    expect(fires(m, 'missing-content-type-validation')).toHaveLength(0);
  });
});

describe('unsanitized-stored-content', () => {
  it('fires on a web app writing submitted content to a store', () => {
    expect(fires(model({}), 'unsanitized-stored-content')).toHaveLength(1);
  });

  it('goes quiet when output is encoded', () => {
    const m = model({ callerControls: { encodes_output: true } });
    expect(fires(m, 'unsanitized-stored-content')).toHaveLength(0);
  });

  it('goes quiet when input is sanitised', () => {
    const m = model({ callerControls: { sanitizes_input: true } });
    expect(fires(m, 'unsanitized-stored-content')).toHaveLength(0);
  });
});
