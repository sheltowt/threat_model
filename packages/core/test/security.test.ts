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

  it('refuses constructor and prototype as well', () => {
    const result = validateModel(fixture('pollute-ctor-parent.yaml'));
    expect(result.ok).toBe(false);
    const refused = result.diagnostics
      .filter((d) => d.code === 'unsafe-key')
      .map((d) => d.path);
    expect(refused).toContain('constructor');
    expect(refused).toContain('prototype');
  });

  it('still merges an ordinary key into an existing document', () => {
    // The guard must not have broken the thing it guards. `parent.yaml` merges two
    // included files, one of which contributes a key the parent does not have.
    const result = validateModel(fixture('parent.yaml'));
    expect(result.ok).toBe(true);
    expect(Object.keys(result.result!.model.elements).sort()).toEqual(['api', 'db']);
    expect(result.result!.model.flows).toHaveLength(1);
  });
});

/**
 * Worth recording, because it bounds what the guard above is actually protecting.
 *
 * Zod's compiled parser assigns model fields with plain property assignment, so a
 * prototype that was *already* polluted before parsing would still be read through.
 * That is not something this project can fix in its own code, and it is why the key
 * filter on the include merge is the primary defence rather than the `defineProperty`
 * hardening beside it: the filter stops the pollution happening at all.
 */
describe('scope of the guard', () => {
  it('keeps an inherited property out of the parsed model', () => {
    Object.defineProperty(Object.prototype, 'injected_field', {
      configurable: true,
      value: 'from the prototype',
      enumerable: false,
      writable: true,
    });
    try {
      const result = validateModel(fixture('parent.yaml'));
      expect(result.ok).toBe(true);
      // An inherited value must not be mistaken for something the model declared.
      expect(Object.prototype.hasOwnProperty.call(result.result!.model, 'injected_field')).toBe(
        false,
      );
    } finally {
      delete (Object.prototype as Record<string, unknown>)['injected_field'];
    }
  });
});
