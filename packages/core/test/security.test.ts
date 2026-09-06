import { describe, expect, it } from 'vitest';
import { fileURLToPath } from 'node:url';
import { validateModel } from '@tmc/core';

const fixture = (name: string) => fileURLToPath(new URL(`./fixtures/${name}`, import.meta.url));

/**
 * A model file arrives in a repository and is not trusted. `includes` is the one
 * place this tool copies keys out of a YAML document into an object it already
 * holds, which is exactly the shape of a prototype pollution sink.
 *
 * Reported by CodeQL as js/prototype-pollution-utility.
 */
describe('include merging', () => {
  it('refuses a key that reaches the prototype chain', () => {
    const result = validateModel(fixture('pollute-parent.yaml'));
    expect(result.ok).toBe(false);
    const d = result.diagnostics.find((x) => x.code === 'unsafe-key');
    expect(d?.message).toContain('__proto__');
    expect(d?.severity).toBe('error');
  });

  it('does not pollute the prototype while doing so', () => {
    validateModel(fixture('pollute-parent.yaml'));
    expect(({} as Record<string, unknown>)['polluted']).toBeUndefined();
    expect(Object.prototype).not.toHaveProperty('polluted');
  });

  it('leaves an ordinary include working', () => {
    const result = validateModel(fixture('parent.yaml'));
    expect(result.ok).toBe(true);
  });
});
