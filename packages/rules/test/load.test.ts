import { describe, expect, it } from 'vitest';
import { mkdtempSync, mkdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { loadRules } from 'tmac-rules';

/** Write one rule file into a fresh directory and load it alongside the built-ins. */
function withRule(body: string, name = 'test.rule.yaml') {
  const dir = mkdtempSync(join(tmpdir(), 'tmac-rules-'));
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, name), body, 'utf8');
  return loadRules([dir]);
}

const VALID = `
id: test-rule
title: Test rule
stride: tampering
function: architecture
detection_logic: A thing.
false_positives: Another thing.
mitigation: Fix it.
scope: flow
match: |
  !flow.protocol.encrypted
`;

describe('the built-in library', () => {
  const { rules, errors } = loadRules();

  it('loads with no errors', () => {
    expect(errors).toEqual([]);
  });

  it('is substantial', () => {
    expect(rules.length).toBeGreaterThan(40);
  });

  it('has unique ids matching their file names', () => {
    const seen = new Set<string>();
    for (const rule of rules) {
      expect(seen.has(rule.id), `duplicate id ${rule.id}`).toBe(false);
      seen.add(rule.id);
      expect(rule.source).toContain(rule.id);
    }
  });

  it('requires the three prose fields on every rule', () => {
    // A rule whose author cannot say when it is wrong is not ready to fire at anyone.
    for (const rule of rules) {
      expect(rule.detection_logic.trim().length, `${rule.id} detection_logic`).toBeGreaterThan(20);
      expect(rule.false_positives.trim().length, `${rule.id} false_positives`).toBeGreaterThan(20);
      expect(rule.mitigation.trim().length, `${rule.id} mitigation`).toBeGreaterThan(20);
    }
  });

  it('marks every built-in as such', () => {
    expect(rules.every((r) => r.builtin)).toBe(true);
  });

  it('covers all six STRIDE categories', () => {
    const covered = new Set(rules.map((r) => r.stride));
    for (const category of [
      'spoofing',
      'tampering',
      'repudiation',
      'information-disclosure',
      'denial-of-service',
      'elevation-of-privilege',
    ]) {
      expect(covered, `no rule covers ${category}`).toContain(category);
    }
  });

  it('includes privacy rules carrying a LINDDUN category', () => {
    expect(rules.some((r) => r.linddun !== undefined)).toBe(true);
  });
});

describe('project rules', () => {
  it('loads a valid one and marks it as not built in', () => {
    const { rules, errors } = withRule(VALID);
    expect(errors).toEqual([]);
    const mine = rules.find((r) => r.id === 'test-rule');
    expect(mine).toBeDefined();
    expect(mine?.builtin).toBe(false);
  });

  it('lets a project rule replace a built-in of the same id', () => {
    const { rules, errors } = withRule(VALID.replace('id: test-rule', 'id: unencrypted-communication'));
    expect(errors).toEqual([]);
    const replaced = rules.filter((r) => r.id === 'unencrypted-communication');
    expect(replaced).toHaveLength(1);
    expect(replaced[0]?.builtin).toBe(false);
  });

  it('reports a schema violation with the field name', () => {
    const { errors } = withRule(VALID.replace('stride: tampering', 'stride: nonsense'));
    expect(errors.length).toBeGreaterThan(0);
    expect(errors.some((e) => e.message.includes('stride'))).toBe(true);
  });

  it('rejects a rule missing its false positives note', () => {
    const { errors } = withRule(VALID.replace('false_positives: Another thing.\n', ''));
    expect(errors.some((e) => e.message.includes('false_positives'))).toBe(true);
  });

  it('reports a syntax error in the condition at load time, not at first use', () => {
    const { errors } = withRule(VALID.replace('!flow.protocol.encrypted', 'flow.protocol.('));
    expect(errors.length).toBeGreaterThan(0);
    expect(errors[0]?.file).toContain('test.rule.yaml');
  });

  it('reports malformed YAML against the file', () => {
    const { errors } = withRule('id: broken\n  bad: [indent\n');
    expect(errors.length).toBeGreaterThan(0);
    expect(errors[0]?.message).toMatch(/YAML|indent|flow sequence/i);
  });
});

describe('scope binding checks', () => {
  // An expression that reads an undefined name yields UNKNOWN rather than raising,
  // which is right for an unrecorded field and catastrophic for a mistyped scope
  // variable: the rule loads, runs, matches nothing, and reports nothing, for ever.
  it('rejects an element variable used in a flow rule', () => {
    const { errors } = withRule(VALID.replace('!flow.protocol.encrypted', 'element.internet_facing'));
    expect(errors.length).toBeGreaterThan(0);
    expect(errors[0]?.message).toContain('element');
    expect(errors[0]?.message).toContain('flow scope');
  });

  it('rejects a flow variable used in an element rule', () => {
    const { errors } = withRule(
      VALID.replace('scope: flow', 'scope: element').replace(
        '!flow.protocol.encrypted',
        'flow.vpn',
      ),
    );
    expect(errors.length).toBeGreaterThan(0);
    expect(errors[0]?.message).toContain('not available to a element rule');
  });

  it('names what is available instead', () => {
    const { errors } = withRule(VALID.replace('!flow.protocol.encrypted', 'boundary.is_network'));
    expect(errors[0]?.message).toContain('Available: flow, model');
  });

  it('accepts both element aliases', () => {
    for (const alias of ['element.internet_facing', 'el.internet_facing']) {
      const { errors } = withRule(
        VALID.replace('scope: flow', 'scope: element').replace('!flow.protocol.encrypted', alias),
      );
      expect(errors, `alias ${alias} should be accepted`).toEqual([]);
    }
  });

  it('accepts model in every scope', () => {
    for (const scope of ['element', 'flow', 'boundary', 'data', 'model']) {
      const { errors } = withRule(
        VALID.replace('scope: flow', `scope: ${scope}`).replace(
          '!flow.protocol.encrypted',
          'model.element_count > 0',
        ),
      );
      expect(errors, `model should be bound in ${scope} scope`).toEqual([]);
    }
  });

  it('does not mistake a macro variable for an unbound name', () => {
    const { errors } = withRule(
      VALID.replace('!flow.protocol.encrypted', 'flow.carries.exists(d, d.credentials)'),
    );
    expect(errors).toEqual([]);
  });

  it('does not mistake a function name for an unbound name', () => {
    const { errors } = withRule(
      VALID.replace('!flow.protocol.encrypted', 'size(flow.carries) > 0 && known(flow.vpn)'),
    );
    expect(errors).toEqual([]);
  });

  it('checks the rating expressions too', () => {
    const { errors } = withRule(`${VALID}likelihood: |\n  element.raa >= 90 ? 'likely' : 'unlikely'\n`);
    expect(errors.length).toBeGreaterThan(0);
    expect(errors[0]?.message).toContain('likelihood');
  });

  it('leaves a literal rating alone', () => {
    const { errors } = withRule(`${VALID}likelihood: frequent\nimpact: very-high\n`);
    expect(errors).toEqual([]);
  });

  it('checks the risk title template', () => {
    const { errors } = withRule(`${VALID}risk_title: "problem at {{ element.name }}"\n`);
    expect(errors.length).toBeGreaterThan(0);
    expect(errors[0]?.message).toContain('risk_title');
  });
});
