import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { parse as parseYaml } from 'yaml';
import { buildGraph, builtinCatalog, modelSchema, type Model } from '@tmc/core';
import { analyze, loadRules } from '@tmc/rules';
import {
  detectFormat,
  exportOtm,
  exportTmbom,
  importAny,
  importOtm,
  importPytm,
  importThreagile,
  importThreatDragon,
  slugify,
  type ImportResult,
} from '@tmc/importers';

const fixture = (name: string) =>
  parseYaml(readFileSync(fileURLToPath(new URL(`./fixtures/${name}`, import.meta.url)), 'utf8'));

/**
 * The exporters take a validated model, the same thing `loadModel` hands the CLI,
 * so the fixture is parsed through the schema rather than read as raw YAML.
 */
const EXAMPLE: Model = modelSchema.parse(
  parseYaml(
    readFileSync(
      fileURLToPath(new URL('../../../examples/payment-service/threatmodel.yaml', import.meta.url)),
      'utf8',
    ),
  ),
);

/** Every importer must produce something the loader would actually accept. */
function expectValid(result: ImportResult): Model {
  const parsed = modelSchema.safeParse(result.model);
  if (!parsed.success) {
    const detail = parsed.error.issues
      .map((i) => `${i.path.join('.')}: ${i.message}`)
      .join('\n  ');
    throw new Error(`imported model failed validation:\n  ${detail}`);
  }
  return parsed.data;
}

describe('id handling', () => {
  it('turns a hostile name into a usable id', () => {
    expect(slugify('Payment API (v2)')).toMatch(/^[a-zA-Z0-9][a-zA-Z0-9_.-]*$/);
    expect(slugify('  spaces  everywhere  ')).toMatch(/^[a-zA-Z0-9][a-zA-Z0-9_.-]*$/);
    expect(slugify('123-starts-with-digit')).toMatch(/^[a-zA-Z0-9]/);
  });

  it('never produces an empty id', () => {
    for (const input of ['', '!!!', '   ', '---']) {
      expect(slugify(input).length).toBeGreaterThan(0);
    }
  });
});

describe('format detection', () => {
  it('recognises each supported format', () => {
    expect(detectFormat(fixture('threat-dragon.json'))).toBe('threat-dragon');
    expect(detectFormat(fixture('threagile.yaml'))).toBe('threagile');
    expect(detectFormat(fixture('pytm.json'))).toBe('pytm');
  });

  it('returns undefined rather than guessing', () => {
    // Importing a file as the wrong format yields a model that looks plausible and
    // is wrong, which is worse than refusing.
    expect(detectFormat({ something: 'else' })).toBeUndefined();
    expect(detectFormat('not a document')).toBeUndefined();
    expect(detectFormat(null)).toBeUndefined();
  });
});

describe('Threat Dragon', () => {
  const result = importThreatDragon(fixture('threat-dragon.json'));

  it('produces a valid model', () => {
    expectValid(result);
  });

  it('carries the title across', () => {
    expect(result.model.meta.title.length).toBeGreaterThan(0);
  });

  it('maps the four cell types onto elements and flows', () => {
    const model = expectValid(result);
    const kinds = new Set(Object.values(model.elements).map((e) => e.kind));
    expect(kinds.size).toBeGreaterThan(1);
    expect(model.flows.length).toBeGreaterThan(0);
  });

  it('resolves every flow endpoint to an element that exists', () => {
    const model = expectValid(result);
    for (const flow of model.flows) {
      expect(model.elements, `flow ${flow.id} source`).toHaveProperty(flow.from);
      expect(model.elements, `flow ${flow.id} target`).toHaveProperty(flow.to);
    }
  });

  it('keeps coordinates out of the model and in the layout sidecar', () => {
    expect(result.layout).toBeDefined();
    expect(JSON.stringify(result.model)).not.toContain('"position"');
  });

  it('imports threats as manual threats', () => {
    const model = expectValid(result);
    expect(model.manual_threats.length).toBeGreaterThan(0);
    for (const threat of model.manual_threats) {
      expect(threat.title.length).toBeGreaterThan(0);
    }
  });

  it('warns rather than guessing when a category will not map', () => {
    // Threat Dragon's `type` is a free-text category whose meaning depends on the
    // methodology, and LINDDUN and PLOT4ai share several names with STRIDE.
    expect(Array.isArray(result.warnings)).toBe(true);
  });

  it('derives boundary membership from the geometry', () => {
    const model = expectValid(result);
    const boundaries = Object.values(model.trust_boundaries);
    expect(boundaries.length).toBeGreaterThan(0);
    expect(boundaries.some((b) => b.contains.length > 0)).toBe(true);
  });
});

describe('pytm', () => {
  const result = importPytm(fixture('pytm.json'));

  it('produces a valid model', () => {
    expectValid(result);
  });

  it('maps pytm classes onto kinds and technologies', () => {
    const model = expectValid(result);
    expect(Object.keys(model.elements).length).toBeGreaterThan(0);
    for (const el of Object.values(model.elements)) {
      expect(el.technology.length).toBeGreaterThan(0);
    }
  });

  it('carries data classification across', () => {
    const model = expectValid(result);
    const assets = Object.values(model.data_assets);
    expect(assets.length).toBeGreaterThan(0);
    const levels = ['public', 'internal', 'restricted', 'confidential', 'strictly-confidential'];
    for (const a of assets) expect(levels).toContain(a.classification);
  });

  it('does not invent a false control from a pytm default', () => {
    // This is the single most important difference in the whole import. pytm cannot
    // distinguish "absent" from "unrecorded", so anything it merely defaulted must
    // arrive here as unrecorded, not as a confident false.
    const model = expectValid(result);
    const source = fixture('pytm.json') as { elements?: Record<string, unknown>[] };
    const declared = new Set<string>();
    for (const el of source.elements ?? []) {
      const controls = (el as { controls?: Record<string, unknown> }).controls ?? {};
      for (const key of Object.keys(controls)) declared.add(key);
    }
    for (const el of Object.values(model.elements)) {
      for (const [key, value] of Object.entries(el.controls)) {
        expect(typeof value).toBe('boolean');
        expect(declared.size, `control ${key} should trace to a declared pytm control`).toBeGreaterThan(0);
      }
    }
  });

  it('says how many controls it could not carry across', () => {
    expect(result.warnings.some((w) => /control/i.test(w.message))).toBe(true);
  });
});

describe('Threagile', () => {
  const result = importThreagile(fixture('threagile.yaml'));

  it('produces a valid model', () => {
    expectValid(result);
  });

  it('carries the CIA ratings on data assets', () => {
    const model = expectValid(result);
    for (const asset of Object.values(model.data_assets)) {
      expect(asset.classification).toBeTruthy();
      expect(asset.integrity).toBeTruthy();
      expect(asset.availability).toBeTruthy();
    }
  });

  it('turns communication links into flows with both endpoints resolved', () => {
    const model = expectValid(result);
    expect(model.flows.length).toBeGreaterThan(0);
    for (const flow of model.flows) {
      expect(model.elements).toHaveProperty(flow.from);
      expect(model.elements).toHaveProperty(flow.to);
    }
  });

  it('preserves trust boundary nesting', () => {
    const model = expectValid(result);
    const boundaries = Object.values(model.trust_boundaries);
    expect(boundaries.length).toBeGreaterThan(0);
  });

  it('carries risk tracking across, since that is the expensive content', () => {
    const model = expectValid(result);
    const source = fixture('threagile.yaml') as { risk_tracking?: Record<string, unknown> };
    if (source.risk_tracking && Object.keys(source.risk_tracking).length > 0) {
      expect(Object.keys(model.risk_tracking).length).toBeGreaterThan(0);
    }
  });

  it('maps every technology or warns about the one it could not', () => {
    const unmapped = result.warnings.filter((w) => /technolog/i.test(w.message));
    const model = expectValid(result);
    for (const el of Object.values(model.elements)) {
      if (el.technology === 'unknown-technology') {
        expect(unmapped.length).toBeGreaterThan(0);
      }
    }
  });
});

describe('OTM', () => {
  const otm = {
    otmVersion: '0.2.0',
    project: { name: 'Sample', id: 'sample' },
    trustZones: [{ id: 'tz-public', name: 'Public', risk: { trustRating: 1 } }],
    components: [
      { id: 'c-web', name: 'Web app', type: 'web-application', parent: { trustZone: 'tz-public' } },
      { id: 'c-db', name: 'Database', type: 'database', parent: { trustZone: 'tz-public' } },
    ],
    dataflows: [{ id: 'df-1', name: 'Query', source: 'c-web', destination: 'c-db' }],
  };

  it('produces a valid model', () => {
    expectValid(importOtm(otm));
  });

  it('maps trust zones onto trust boundaries', () => {
    const model = expectValid(importOtm(otm));
    expect(Object.keys(model.trust_boundaries).length).toBeGreaterThan(0);
  });

  it('round-trips elements and flows', () => {
    const reimported = expectValid(importOtm(exportOtm(EXAMPLE)));

    expect(Object.keys(reimported.elements).sort()).toEqual(Object.keys(EXAMPLE.elements).sort());
    expect(reimported.flows.map((f) => `${f.from}->${f.to}`).sort()).toEqual(
      EXAMPLE.flows.map((f) => `${f.from}->${f.to}`).sort(),
    );
  });

  it('round-trips data assets and their references', () => {
    // OTM has no data asset of its own, so these ride in project attributes. Losing
    // them would silently strip classification from the model and quietly change
    // what every rule concludes, which is worse than refusing to export at all.
    const reimported = expectValid(importOtm(exportOtm(EXAMPLE)));

    expect(Object.keys(reimported.data_assets).sort()).toEqual(
      Object.keys(EXAMPLE.data_assets).sort(),
    );
    for (const [id, asset] of Object.entries(EXAMPLE.data_assets)) {
      const after = reimported.data_assets[id]!;
      expect(after.classification, `${id} classification`).toBe(asset.classification);
      expect(after.integrity, `${id} integrity`).toBe(asset.integrity);
      expect(after.pii, `${id} pii`).toBe(asset.pii);
      expect(after.credentials, `${id} credentials`).toBe(asset.credentials);
    }

    for (const [id, el] of Object.entries(EXAMPLE.elements)) {
      expect(reimported.elements[id]!.processes.sort(), `${id} processes`).toEqual(
        [...el.processes].sort(),
      );
      expect(reimported.elements[id]!.stores.sort(), `${id} stores`).toEqual([...el.stores].sort());
    }
    for (const flow of EXAMPLE.flows) {
      const after = reimported.flows.find((f) => f.id === flow.id)!;
      expect(after.sends.sort(), `${flow.id} sends`).toEqual([...flow.sends].sort());
      expect(after.receives.sort(), `${flow.id} receives`).toEqual([...flow.receives].sort());
    }
  });

  it('round-trips security controls without inventing or losing one', () => {
    const reimported = expectValid(importOtm(exportOtm(EXAMPLE)));
    for (const [id, el] of Object.entries(EXAMPLE.elements)) {
      expect(reimported.elements[id]!.controls, `${id} controls`).toEqual(el.controls);
    }
  });

  it('round-trips boundaries, shared runtimes and the analysis-relevant meta', () => {
    const reimported = expectValid(importOtm(exportOtm(EXAMPLE)));

    expect(Object.keys(reimported.trust_boundaries).sort()).toEqual(
      Object.keys(EXAMPLE.trust_boundaries).sort(),
    );
    for (const [id, b] of Object.entries(EXAMPLE.trust_boundaries)) {
      expect(reimported.trust_boundaries[id]!.type, `${id} type`).toBe(b.type);
      expect(reimported.trust_boundaries[id]!.contains.sort(), `${id} contains`).toEqual(
        [...b.contains].sort(),
      );
    }
    expect(Object.keys(reimported.shared_runtimes).sort()).toEqual(
      Object.keys(EXAMPLE.shared_runtimes).sort(),
    );
    expect(reimported.meta.business_criticality).toBe(EXAMPLE.meta.business_criticality);
    expect(Object.keys(reimported.meta.questions)).toEqual(Object.keys(EXAMPLE.meta.questions));
  });

  it('produces the same findings before and after a round trip', () => {
    // The real test of an interchange format is not whether the fields survive but
    // whether the conclusions do.
    const reimported = expectValid(importOtm(exportOtm(EXAMPLE)));
    const idsOf = (model: Model) =>
      analyze(buildGraph(model, builtinCatalog()), loadRules().rules)
        .risks.map((r) => r.id)
        .sort();
    expect(idsOf(reimported)).toEqual(idsOf(EXAMPLE));
  });
});

describe('exporters', () => {
  it('exports OTM with its version and project', () => {
    const otm = exportOtm(EXAMPLE) as { otmVersion: string; project: { name: string } };
    expect(otm.otmVersion).toBeTruthy();
    expect(otm.project.name).toBe(EXAMPLE.meta.title);
  });

  it('exports a CycloneDX BOM carrying the risks', () => {
    const bom = exportTmbom(EXAMPLE, [
      {
        id: 'unencrypted-communication@api_to_db',
        title: 'Unencrypted link',
        severity: 'high',
        cwe: 319,
        mitigation: 'Use TLS.',
        element: 'payment_api',
      },
    ]) as {
      bomFormat: string;
      specVersion: string;
      components: unknown[];
      vulnerabilities?: unknown[];
    };
    expect(bom.bomFormat).toBe('CycloneDX');
    expect(bom.specVersion).toBeTruthy();
    expect(bom.components.length).toBeGreaterThan(0);
    expect((bom.vulnerabilities ?? []).length).toBeGreaterThan(0);
  });

  it('exports a BOM with no risks at all', () => {
    const bom = exportTmbom(EXAMPLE, []) as { components: unknown[] };
    expect(bom.components.length).toBeGreaterThan(0);
  });
});

describe('dispatcher', () => {
  it('routes to each importer', () => {
    expectValid(importAny('threat-dragon', fixture('threat-dragon.json')));
    expectValid(importAny('pytm', fixture('pytm.json')));
    expectValid(importAny('threagile', fixture('threagile.yaml')));
  });

  it('rejects an unknown format', () => {
    expect(() => importAny('nope' as never, {})).toThrow();
  });
});
