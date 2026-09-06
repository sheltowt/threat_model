import { describe, expect, it } from 'vitest';
import { fileURLToPath } from 'node:url';
import { ModelError, loadModel, validateModel } from 'tmac-core';

const fixture = (name: string) => fileURLToPath(new URL(`./fixtures/${name}`, import.meta.url));

describe('loading', () => {
  it('applies schema defaults', () => {
    const { model } = loadModel(fixture('minimal.yaml'));
    expect(model.meta.business_criticality).toBe('important');
    expect(model.elements['a']?.size).toBe('application');
    expect(model.elements['a']?.out_of_scope).toBe(false);
    expect(model.flows[0]?.authentication).toBe('none');
  });

  it('leaves an unrecorded control absent rather than false', () => {
    // The whole tri-state design rests on this: a default of false here would
    // reintroduce exactly the noise pytm suffers from.
    const { model } = loadModel(fixture('minimal.yaml'));
    expect(model.elements['a']?.controls).toEqual({});
    expect('hardened' in (model.elements['a']?.controls ?? {})).toBe(false);
  });

  it('merges includes and lets the including file win on scalars', () => {
    const { model, sources } = loadModel(fixture('parent.yaml'));
    expect(Object.keys(model.elements).sort()).toEqual(['api', 'db']);
    expect(model.flows).toHaveLength(1);
    expect(model.meta.title).toBe('Split model');
    expect(sources).toHaveLength(3);
  });

  it('rejects an unknown data asset reference and suggests the near miss', () => {
    const result = validateModel(fixture('bad-reference.yaml'));
    expect(result.ok).toBe(false);
    const d = result.diagnostics.find((x) => x.code === 'unknown-reference');
    expect(d?.message).toContain('card_dat');
    expect(d?.hint).toContain('card_data');
  });

  it('rejects an unknown key rather than ignoring it', () => {
    const result = validateModel(fixture('unknown-key.yaml'));
    expect(result.ok).toBe(false);
    expect(result.diagnostics.some((d) => d.code === 'schema')).toBe(true);
  });

  it('throws a ModelError carrying every diagnostic', () => {
    expect(() => loadModel(fixture('bad-reference.yaml'))).toThrow(ModelError);
  });

  it('reports a missing file rather than throwing an opaque error', () => {
    const result = validateModel(fixture('nope.yaml'));
    expect(result.ok).toBe(false);
    expect(result.diagnostics[0]?.code).toBe('unreadable');
  });
});
