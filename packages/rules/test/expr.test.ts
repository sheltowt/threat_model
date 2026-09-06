import { describe, expect, it } from 'vitest';
import {
  ExpressionRuntimeError,
  ExpressionSyntaxError,
  UNKNOWN,
  evaluate,
  parseExpression,
  triState,
} from '@tmc/rules';

const run = (src: string, scope: Record<string, unknown> = {}) =>
  evaluate(parseExpression(src), scope);
const state = (src: string, scope: Record<string, unknown> = {}) => triState(run(src, scope));

describe('literals and arithmetic', () => {
  it('evaluates scalars', () => {
    expect(run('1')).toBe(1);
    expect(run('1.5')).toBe(1.5);
    expect(run('"a"')).toBe('a');
    expect(run("'a'")).toBe('a');
    expect(run('true')).toBe(true);
    expect(run('null')).toBe(null);
  });

  it('applies the usual precedence', () => {
    expect(run('1 + 2 * 3')).toBe(7);
    expect(run('(1 + 2) * 3')).toBe(9);
    expect(run('-2 + 1')).toBe(-1);
    expect(run('7 % 3')).toBe(1);
  });

  it('rejects division by zero rather than yielding Infinity', () => {
    expect(() => run('1 / 0')).toThrow(ExpressionRuntimeError);
  });

  it('concatenates strings and lists', () => {
    expect(run('"a" + "b"')).toBe('ab');
    expect(run('[1] + [2]')).toEqual([1, 2]);
  });

  it('refuses to add mismatched types', () => {
    expect(() => run('1 + "a"')).toThrow(ExpressionRuntimeError);
  });
});

describe('ordered enum comparison', () => {
  // The defect that ruled out cel-js: plain string comparison puts "internal"
  // after "confidential" because i > c, which inverts the security meaning.
  it('compares confidentiality by rank, not spelling', () => {
    expect(run("'internal' < 'confidential'")).toBe(true);
    expect(run("'strictly-confidential' > 'confidential'")).toBe(true);
    expect(run("'confidential' >= 'confidential'")).toBe(true);
    expect(run("'public' < 'internal'")).toBe(true);
  });

  it('compares criticality by rank', () => {
    expect(run("'archive' < 'mission-critical'")).toBe(true);
    expect(run("'critical' > 'important'")).toBe(true);
  });

  it('falls back to lexical order for strings outside any ordered enum', () => {
    expect(run("'apple' < 'banana'")).toBe(true);
  });

  it('orders authentication strength', () => {
    expect(run("'none' < 'two-factor'")).toBe(true);
    expect(run("'credentials' < 'client-certificate'")).toBe(true);
  });
});

describe('three-valued logic', () => {
  const scope = { el: { known_true: true, known_false: false, controls: {} } };

  it('reads an absent field as unknown, not as an error', () => {
    expect(state('el.controls.hardened', scope)).toBe('unknown');
    expect(state('el.missing.deeply.nested', scope)).toBe('unknown');
  });

  it('propagates unknown through negation', () => {
    expect(state('!el.controls.hardened', scope)).toBe('unknown');
  });

  it('follows Kleene truth tables for and', () => {
    expect(state('el.controls.hardened && el.known_false', scope)).toBe('false');
    expect(state('el.controls.hardened && el.known_true', scope)).toBe('unknown');
    expect(state('el.known_false && el.controls.hardened', scope)).toBe('false');
  });

  it('follows Kleene truth tables for or', () => {
    expect(state('el.controls.hardened || el.known_true', scope)).toBe('true');
    expect(state('el.controls.hardened || el.known_false', scope)).toBe('unknown');
  });

  it('leaves comparison against unknown unresolved', () => {
    expect(state('el.controls.hardened == true', scope)).toBe('unknown');
  });

  it('resolves a ternary on an unknown condition only when both arms agree', () => {
    expect(run("el.controls.hardened ? 'a' : 'a'", scope)).toBe('a');
    expect(run("el.controls.hardened ? 'a' : 'b'", scope)).toBe(UNKNOWN);
  });

  it('distinguishes recorded-false from unrecorded', () => {
    expect(state('el.known_false', scope)).toBe('false');
    expect(run('known(el.known_false)', scope)).toBe(true);
    expect(run('known(el.controls.hardened)', scope)).toBe(false);
    expect(run('default(el.controls.hardened, false)', scope)).toBe(false);
  });
});

describe('macros', () => {
  const scope = {
    data: [
      { id: 'a', pii: true, classification: 'restricted' },
      { id: 'b', pii: false, classification: 'public' },
    ],
    partial: [{ known: true }, {}],
  };

  it('exists finds a definite hit', () => {
    expect(run('data.exists(d, d.pii)', scope)).toBe(true);
    expect(run("data.exists(d, d.id == 'z')", scope)).toBe(false);
  });

  it('all requires every item', () => {
    expect(run("data.all(d, d.classification <= 'restricted')", scope)).toBe(true);
    expect(run('data.all(d, d.pii)', scope)).toBe(false);
  });

  it('none inverts exists', () => {
    expect(run("data.none(d, d.id == 'z')", scope)).toBe(true);
    expect(run('data.none(d, d.pii)', scope)).toBe(false);
  });

  it('exists_one counts exactly one', () => {
    expect(run('data.exists_one(d, d.pii)', scope)).toBe(true);
    expect(run('data.exists_one(d, true)', scope)).toBe(false);
  });

  it('filter and map produce lists', () => {
    expect(run('size(data.filter(d, d.pii))', scope)).toBe(1);
    expect(run('data.map(d, d.id)', scope)).toEqual(['a', 'b']);
  });

  it('a definite hit beats an unknown sibling', () => {
    expect(triState(run('partial.exists(p, p.known)', scope))).toBe('true');
  });

  it('an unknown sibling blocks a definite negative', () => {
    expect(triState(run('partial.exists(p, p.absent)', scope))).toBe('unknown');
  });

  it('refuses to iterate a non-list', () => {
    expect(() => run('data.exists(d, d)', { data: 5 })).toThrow(ExpressionRuntimeError);
  });
});

describe('functions', () => {
  it('measures size across types', () => {
    expect(run('size("abc")')).toBe(3);
    expect(run('size([1,2])')).toBe(2);
    expect(run('size(x)', { x: { a: 1, b: 2 } })).toBe(2);
  });

  it('handles strings', () => {
    expect(run('lower("AB")')).toBe('ab');
    expect(run('upper("ab")')).toBe('AB');
    expect(run('contains("abc", "b")')).toBe(true);
    expect(run('startsWith("abc", "a")')).toBe(true);
    expect(run('endsWith("abc", "c")')).toBe(true);
    expect(run('matches("abc", "^a.c$")')).toBe(true);
  });

  it('rejects an unknown function by name', () => {
    expect(() => run('eval("1")')).toThrow(/unknown function/);
    expect(() => run('require("fs")')).toThrow(/unknown function/);
  });

  it('caps the regex pattern length', () => {
    expect(() => run(`matches("a", "${'a'.repeat(201)}")`)).toThrow(/longer than 200/);
  });
});

describe('membership', () => {
  it('tests list membership', () => {
    expect(run("'pci-dss' in ['pci-dss', 'gdpr']")).toBe(true);
    expect(run("'sox' in ['pci-dss']")).toBe(false);
  });

  it('tests map keys', () => {
    expect(run("'a' in m", { m: { a: 1 } })).toBe(true);
    expect(run("'b' in m", { m: { a: 1 } })).toBe(false);
  });
});

describe('sandbox', () => {
  // These are the escapes a rule file from an untrusted repository would attempt.
  it('refuses to read prototype-reaching properties', () => {
    expect(() => run('x.__proto__', { x: {} })).toThrow(/not readable/);
    expect(() => run('x.constructor', { x: {} })).toThrow(/not readable/);
    expect(() => run('x["constructor"]', { x: {} })).toThrow(/not readable/);
  });

  it('refuses to read a function-valued property', () => {
    expect(() => run('x.toString', { x: { toString: () => 'no' } })).toThrow(/not readable/);
  });

  it('does not inherit properties from the prototype chain', () => {
    expect(run('x.hasOwnProperty', { x: {} })).toBe(UNKNOWN);
    expect(run('x.valueOf', { x: {} })).toBe(UNKNOWN);
  });

  it('has no syntax for assignment or statements', () => {
    expect(() => parseExpression('x = 1')).toThrow(ExpressionSyntaxError);
    expect(() => parseExpression('x; y')).toThrow(ExpressionSyntaxError);
  });

  it('rejects an arbitrary method call', () => {
    expect(() => parseExpression('x.somethingElse(1)')).toThrow(/is not a macro/);
  });

  it('bounds evaluation work', () => {
    const big = Array.from({ length: 400 }, (_, i) => ({ i }));
    expect(() =>
      evaluate(parseExpression('a.all(x, a.all(y, a.exists(z, z.i == x.i)))'), { a: big }, {
        maxSteps: 5000,
      }),
    ).toThrow(/evaluation steps/);
  });

  it('caps expression length', () => {
    expect(() => parseExpression(`${'1 + '.repeat(2100)}1`)).toThrow(/8000 characters/);
  });

  it('leaves the scope untouched', () => {
    const scope = { x: { a: 1 } };
    run('x.a', scope);
    expect(scope).toEqual({ x: { a: 1 } });
  });
});

describe('syntax errors', () => {
  it('reports an unterminated string', () => {
    expect(() => parseExpression('"abc')).toThrow(/unterminated string/);
  });

  it('reports a missing bracket', () => {
    expect(() => parseExpression('(1 + 2')).toThrow(/expected "\)"/);
  });

  it('reports trailing input', () => {
    expect(() => parseExpression('1 2')).toThrow(/after a complete expression/);
  });

  it('names the available macros when one is misspelled', () => {
    expect(() => parseExpression('list.exsts(d, d)')).toThrow(/exists, exists_one, all, none/);
  });

  it('accepts comments', () => {
    expect(run('1 + # trailing note\n 2')).toBe(3);
    expect(run('1 + // another\n 2')).toBe(3);
  });
});

describe('unknown tracking', () => {
  it('names the fields that could not be settled', () => {
    const unknowns = new Set<string>();
    evaluate(
      parseExpression('!el.controls.hardened && !el.controls.monitored'),
      { el: { controls: {} } },
      { unknowns },
    );
    expect([...unknowns].sort()).toEqual(['el.controls.hardened', 'el.controls.monitored']);
  });

  it('does not record a field that was recorded', () => {
    const unknowns = new Set<string>();
    evaluate(parseExpression('el.controls.hardened'), { el: { controls: { hardened: false } } }, {
      unknowns,
    });
    expect([...unknowns]).toEqual([]);
  });
});
