import { describe, expect, it } from 'vitest';
import { fileURLToPath } from 'node:url';
import { buildGraph, loadModel } from 'tmac-core';

const fixture = (name: string) => fileURLToPath(new URL(`./fixtures/${name}`, import.meta.url));
const graphOf = (name: string) => {
  const { model, catalog } = loadModel(fixture(name));
  return buildGraph(model, catalog);
};

describe('derived element properties', () => {
  it('takes the element kind from the technology catalogue when unstated', () => {
    const g = graphOf('minimal.yaml');
    expect(g.elementById.get('a')?.kind).toBe('process');
    expect(g.elementById.get('b')?.kind).toBe('datastore');
  });

  it('exposes catalogue attributes as definite booleans, never unknown', () => {
    // Closed-world: a technology that does not declare an attribute has it false.
    const g = graphOf('minimal.yaml');
    const tech = g.elementById.get('b')!.technology;
    expect(tech['vulnerable_to_query_injection']).toBe(true);
    expect(tech['vulnerable_to_xss']).toBe(false);
    expect('vulnerable_to_xss' in tech).toBe(true);
  });

  it('derives a rating from the data an element holds', () => {
    const g = graphOf('parent.yaml');
    expect(g.elementById.get('db')?.confidentiality).toBe('strictly-confidential');
    expect(g.elementById.get('api')?.confidentiality).toBe('strictly-confidential');
  });

  it('links data assets back to the elements that touch them', () => {
    const g = graphOf('parent.yaml');
    const secret = g.dataById.get('secret')!;
    expect(secret.processed_by.map((e) => e.id)).toEqual(['api']);
    expect(secret.stored_by.map((e) => e.id)).toEqual(['db']);
    expect(secret.sent_via.map((f) => f.id)).toEqual(['api_to_db']);
    expect(secret.orphaned).toBe(false);
  });
});

describe('boundaries', () => {
  it('nests boundaries and lists members transitively', () => {
    const g = graphOf('boundaries.yaml');
    const outer = g.boundaryById.get('outer')!;
    expect(outer.nested.map((b) => b.id)).toEqual(['inner']);
    expect(outer.members.map((e) => e.id)).toEqual(['edge']);
    expect(outer.all_members.map((e) => e.id).sort()).toEqual(['deep', 'edge', 'mid']);
  });

  it('records the boundary chain innermost first', () => {
    const g = graphOf('boundaries.yaml');
    expect(g.elementById.get('mid')?.boundaries.map((b) => b.id)).toEqual(['inner', 'outer']);
  });

  it('sets a parent link on a nested boundary', () => {
    const g = graphOf('boundaries.yaml');
    expect(g.boundaryById.get('inner')?.parent?.id).toBe('outer');
    expect(g.boundaryById.get('outer')?.parent).toBeUndefined();
  });
});

describe('flows', () => {
  it('resolves protocol attributes', () => {
    const g = graphOf('minimal.yaml');
    const f = g.flowById.get('a_to_b')!;
    expect(f.protocol['encrypted']).toBe(false);
    expect(f.protocol['database_access']).toBe(true);
    expect(f.process_local).toBe(false);
  });

  it('detects a boundary crossing', () => {
    const g = graphOf('boundaries.yaml');
    expect(g.flowById.get('edge_to_mid')?.crosses_boundary).toBe(true);
    expect(g.flowById.get('mid_to_deep')?.crosses_boundary).toBe(false);
  });

  it('summarises what a link carries', () => {
    const g = graphOf('parent.yaml');
    const f = g.flowById.get('api_to_db')!;
    expect(f.max_classification).toBe('strictly-confidential');
    expect(f.carries_credentials).toBe(true);
    expect(f.carries.map((d) => d.id)).toEqual(['secret']);
  });
});

describe('internet reachability', () => {
  it('follows flows outward from an internet-facing element', () => {
    const g = graphOf('boundaries.yaml');
    expect(g.elementById.get('edge')?.internet_reachable).toBe(true);
    expect(g.elementById.get('mid')?.internet_reachable).toBe(true);
    expect(g.elementById.get('deep')?.internet_reachable).toBe(true);
  });

  it('does not mark an element reachable only by an inbound flow', () => {
    const g = graphOf('minimal.yaml');
    expect(g.elementById.get('a')?.internet_reachable).toBe(false);
    expect(g.elementById.get('b')?.internet_reachable).toBe(false);
  });
});

describe('relative attacker attractiveness', () => {
  it('scores every element between 0 and 100', () => {
    const g = graphOf('boundaries.yaml');
    for (const el of g.elements) {
      expect(el.raa).toBeGreaterThanOrEqual(0);
      expect(el.raa).toBeLessThanOrEqual(100);
    }
  });

  it('ranks the store of sensitive data above a bare front end', () => {
    const g = graphOf('parent.yaml');
    expect(g.elementById.get('db')!.raa).toBeGreaterThan(0);
  });

  it('is stable across two builds of the same model', () => {
    const a = graphOf('boundaries.yaml').elements.map((e) => `${e.id}:${e.raa}`);
    const b = graphOf('boundaries.yaml').elements.map((e) => `${e.id}:${e.raa}`);
    expect(a).toEqual(b);
  });
});
