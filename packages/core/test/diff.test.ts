import { describe, expect, it } from 'vitest';
import { fileURLToPath } from 'node:url';
import { diffModels, formatDiff, loadModel } from '@tmc/core';

const fixture = (name: string) => fileURLToPath(new URL(`./fixtures/${name}`, import.meta.url));
const modelOf = (name: string) => loadModel(fixture(name)).model;

describe('semantic diff', () => {
  it('reports nothing for an unchanged model', () => {
    const m = modelOf('minimal.yaml');
    const d = diffModels(m, structuredClone(m));
    expect(d.changes).toEqual([]);
    expect(formatDiff(d)).toBe('No semantic changes.');
  });

  it('flags a control being turned off as security relevant', () => {
    const before = modelOf('minimal.yaml');
    const after = structuredClone(before);
    after.elements['a']!.controls.validates_input = false;
    const d = diffModels(before, after);
    const change = d.changes.find((c) => c.field === 'controls.validates_input');
    expect(change?.securityRelevant).toBe(true);
    expect(d.summary.securityRelevant).toBe(1);
  });

  it('flags a new element and a removed one', () => {
    const before = modelOf('minimal.yaml');
    const after = structuredClone(before);
    after.elements['c'] = structuredClone(after.elements['a']!);
    delete after.elements['b'];
    const d = diffModels(before, after);
    expect(d.summary.added).toBe(1);
    expect(d.summary.removed).toBe(1);
  });

  it('treats a description edit as not security relevant', () => {
    const before = modelOf('minimal.yaml');
    const after = structuredClone(before);
    after.elements['a']!.description = 'now with prose';
    const d = diffModels(before, after);
    expect(d.changes).toHaveLength(1);
    expect(d.changes[0]?.securityRelevant).toBe(false);
  });

  it('ignores the order of a list', () => {
    const before = modelOf('parent.yaml');
    const after = structuredClone(before);
    after.elements['api']!.tags = [];
    const d = diffModels(before, after);
    expect(d.changes).toEqual([]);
  });

  it('detects a protocol downgrade on a flow', () => {
    const before = modelOf('minimal.yaml');
    const after = structuredClone(before);
    after.flows[0]!.protocol = 'http';
    const d = diffModels(before, after);
    const change = d.changes.find((c) => c.category === 'flow' && c.field === 'protocol');
    expect(change?.securityRelevant).toBe(true);
    expect(formatDiff(d)).toContain('!');
  });
});
