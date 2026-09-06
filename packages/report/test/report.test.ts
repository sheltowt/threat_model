import { describe, expect, it } from 'vitest';
import { analyze } from 'tmac-rules';
import {
  risksJson,
  statsJson,
  technicalAssetsJson,
  toHtml,
  toMarkdown,
  toSarif,
} from 'tmac-report';
import { readFileSync } from 'node:fs';
import { EXAMPLE, FIXED_NOW, expectGolden, fixture, goldenPath } from './helper.js';

/**
 * A relative path, because the golden file is committed and an absolute one would
 * only ever match the machine that generated it.
 */
const MODEL_PATH = 'examples/payment-service/threatmodel.yaml';
const MODEL_TEXT = readFileSync(EXAMPLE, 'utf8');

const opts = { generatedAt: FIXED_NOW };

describe('risks.json', () => {
  it('matches the committed output', () => {
    const { analysis, graph } = fixture();
    expectGolden(
      goldenPath('risks.json'),
      `${JSON.stringify(risksJson(analysis, graph, opts), null, 2)}\n`,
    );
  });

  it('is byte-identical across two runs, given a fixed timestamp', () => {
    const { analysis, graph } = fixture();
    expect(JSON.stringify(risksJson(analysis, graph, opts))).toBe(
      JSON.stringify(risksJson(analysis, graph, opts)),
    );
  });

  it('orders risks worst first', () => {
    const { analysis, graph } = fixture();
    const out = risksJson(analysis, graph, opts) as { risks: { severity: string }[] };
    const order = ['critical', 'high', 'elevated', 'medium', 'low'];
    const ranks = out.risks.map((r) => order.indexOf(r.severity));
    expect(ranks).toEqual([...ranks].sort((a, b) => a - b));
  });

  it('carries the fields a consumer needs to act', () => {
    const { analysis, graph } = fixture();
    const out = risksJson(analysis, graph, opts) as { risks: Record<string, unknown>[] };
    const first = out.risks[0]!;
    for (const key of ['id', 'rule', 'title', 'severity', 'confidence', 'status', 'mitigation']) {
      expect(first, `risks[0] should carry ${key}`).toHaveProperty(key);
    }
  });

  it('reports the model gap behind a low-confidence finding', () => {
    const { analysis, graph } = fixture();
    const out = risksJson(analysis, graph, opts) as {
      risks: { confidence: string; unknowns?: string[] }[];
    };
    const uncertain = out.risks.filter((r) => r.confidence === 'low');
    expect(uncertain.length).toBeGreaterThan(0);
    for (const r of uncertain) {
      expect(r.unknowns?.length ?? 0).toBeGreaterThan(0);
    }
  });
});

describe('stats.json and technical-assets.json', () => {
  it('match the committed output', () => {
    const { analysis, graph } = fixture();
    expectGolden(
      goldenPath('stats.json'),
      `${JSON.stringify(statsJson(analysis, graph, opts), null, 2)}\n`,
    );
    expectGolden(
      goldenPath('technical-assets.json'),
      `${JSON.stringify(technicalAssetsJson(graph, opts), null, 2)}\n`,
    );
  });

  it('counts every element in the asset export', () => {
    const { graph } = fixture();
    const out = technicalAssetsJson(graph, opts) as Record<string, unknown>;
    const assets = (out['technical_assets'] ?? out['assets'] ?? []) as unknown[];
    expect(assets).toHaveLength(graph.elements.length);
  });
});

describe('SARIF', () => {
  it('matches the committed output', () => {
    const { analysis, graph, rules } = fixture();
    expectGolden(
      goldenPath('risks.sarif'),
      `${JSON.stringify(
        toSarif(analysis, graph, {
          ...opts,
          modelPath: MODEL_PATH,
          modelText: MODEL_TEXT,
          rules,
        }),
        null,
        2,
      )}\n`,
    );
  });

  it('declares the 2.1.0 schema and the tool', () => {
    const { analysis, graph } = fixture();
    const sarif = toSarif(analysis, graph, opts);
    expect(sarif.version).toBe('2.1.0');
    expect(sarif.$schema).toContain('sarif');
    const driver = sarif.runs[0]!['tool'] as { driver: { name: string; rules: unknown[] } };
    expect(driver.driver.name).toBe('tmac');
    expect(driver.driver.rules.length).toBeGreaterThan(0);
  });

  it('uses only the three levels SARIF consumers understand', () => {
    const { analysis, graph } = fixture();
    const results = toSarif(analysis, graph, opts).runs[0]!['results'] as { level: string }[];
    for (const r of results) {
      expect(['error', 'warning', 'note']).toContain(r.level);
    }
  });

  it('carries security-severity, which is what code scanning sorts on', () => {
    const { analysis, graph } = fixture();
    const results = toSarif(analysis, graph, opts).runs[0]!['results'] as {
      properties: { 'security-severity': string };
    }[];
    for (const r of results) {
      const score = Number(r.properties['security-severity']);
      expect(Number.isFinite(score)).toBe(true);
      expect(score).toBeGreaterThan(0);
      expect(score).toBeLessThanOrEqual(10);
    }
  });

  it('locates a result at a real line of the model file', () => {
    // Without a line, code scanning pins every finding to the top of the file and
    // the reader has to go hunting for the element it is about.
    const { analysis, graph } = fixture();
    const run = toSarif(analysis, graph, {
      ...opts,
      modelPath: MODEL_PATH,
      modelText: MODEL_TEXT,
    }).runs[0]!;
    const located = (run['results'] as {
      locations?: { physicalLocation?: { region?: { startLine?: number } } }[];
    }[]).filter((r) => r.locations?.[0]?.physicalLocation?.region?.startLine !== undefined);
    expect(located.length).toBeGreaterThan(0);
    const lineCount = MODEL_TEXT.split('\n').length;
    for (const r of located) {
      const line = r.locations![0]!.physicalLocation!.region!.startLine!;
      expect(line).toBeGreaterThan(0);
      expect(line).toBeLessThanOrEqual(lineCount);
    }
  });

  it('omits the region rather than guessing when it has no model text', () => {
    const { analysis, graph } = fixture();
    const run = toSarif(analysis, graph, { ...opts, modelPath: MODEL_PATH }).runs[0]!;
    for (const r of run['results'] as {
      locations?: { physicalLocation?: { region?: unknown } }[];
    }[]) {
      expect(r.locations?.[0]?.physicalLocation?.region).toBeUndefined();
    }
  });

  it('gives every result a rule that exists in the driver', () => {
    const { analysis, graph } = fixture();
    const run = toSarif(analysis, graph, opts).runs[0]!;
    const ids = new Set(
      ((run['tool'] as { driver: { rules: { id: string }[] } }).driver.rules).map((r) => r.id),
    );
    for (const r of run['results'] as { ruleId: string }[]) {
      expect(ids, `rule ${r.ruleId} should be declared`).toContain(r.ruleId);
    }
  });

  it('suppresses a resolved risk rather than dropping it', () => {
    // Losing an accepted risk from the upload is how a decision becomes invisible.
    const { graph, rules } = fixture();
    const tracked = {
      ...graph,
      risk_tracking: { '*': { status: 'accepted' as const, justification: 'reviewed' } },
    };
    const analysis = analyze(tracked, rules);
    const results = toSarif(analysis, tracked, { ...opts, showMitigated: true }).runs[0]![
      'results'
    ] as { suppressions?: unknown[] }[];
    expect(results.length).toBeGreaterThan(0);
    expect(results.every((r) => (r.suppressions?.length ?? 0) > 0)).toBe(true);
  });
});

describe('Markdown', () => {
  it('matches the committed output', () => {
    const { analysis, graph } = fixture();
    expectGolden(goldenPath('report.md'), toMarkdown(analysis, graph, opts));
  });

  it('leads with a severity summary', () => {
    const { analysis, graph } = fixture();
    const md = toMarkdown(analysis, graph, opts);
    expect(md).toContain(graph.meta.title);
    expect(md.toLowerCase()).toContain('severity');
  });

  it('explains the low-confidence findings as model gaps', () => {
    const { analysis, graph } = fixture();
    const md = toMarkdown(analysis, graph, opts).toLowerCase();
    expect(md).toContain('confidence');
    expect(md).toMatch(/not recorded|model gap|unrecorded|have not/);
  });

  it('carries the open questions rather than losing them', () => {
    const { analysis, graph } = fixture();
    const md = toMarkdown(analysis, graph, opts);
    expect(md).toContain('settlement batch require the full pan');
  });

  it('links diagrams when paths are supplied', () => {
    const { analysis, graph } = fixture();
    const md = toMarkdown(analysis, graph, {
      ...opts,
      includeDiagrams: true,
      diagramPaths: { dataFlow: 'dfd.svg', dataAssets: 'assets.svg' },
    });
    expect(md).toContain('dfd.svg');
    expect(md).toContain('assets.svg');
  });
});

describe('HTML', () => {
  it('is a self-contained document', () => {
    const { analysis, graph } = fixture();
    const html = toHtml(analysis, graph, opts);
    expect(html).toContain('<!doctype html>');
    expect(html).toContain('</html>');
  });

  it('loads no external script, stylesheet or font', () => {
    // A report is often opened from a filesystem, sometimes on an air-gapped host,
    // and it must never phone anywhere to render.
    const { analysis, graph } = fixture();
    const html = toHtml(analysis, graph, opts);
    expect(html).not.toMatch(/<script[^>]+\ssrc=/i);
    expect(html).not.toMatch(/<link[^>]+rel=["']?stylesheet/i);
    expect(html).not.toMatch(/@import/i);
    expect(html).not.toMatch(/<img[^>]+src=["']https?:/i);
  });

  it('defines its palette as tokens and answers both themes', () => {
    const { analysis, graph } = fixture();
    const html = toHtml(analysis, graph, opts);
    expect(html).toContain(':root');
    expect(html).toContain('prefers-color-scheme');
  });

  it('encodes severity as text as well as colour', () => {
    // Colour alone fails anyone who cannot distinguish it, and fails a mono printout.
    const { analysis, graph } = fixture();
    const html = toHtml(analysis, graph, opts);
    for (const severity of ['high', 'elevated', 'medium']) {
      expect(html).toContain(severity);
    }
  });

  it('carries a print stylesheet, because this becomes the PDF', () => {
    const { analysis, graph } = fixture();
    expect(toHtml(analysis, graph, opts)).toContain('@media print');
  });

  it('embeds supplied SVG inline', () => {
    const { analysis, graph } = fixture();
    const html = toHtml(analysis, graph, {
      ...opts,
      includeDiagrams: true,
      diagrams: { dataFlow: '<svg id="marker-dfd"></svg>' },
    });
    expect(html).toContain('marker-dfd');
  });

  it('escapes a hostile name rather than injecting markup', () => {
    const { analysis, graph } = fixture();
    const hostile = {
      ...graph,
      meta: { ...graph.meta, title: '<script>alert(1)</script>' },
    };
    const html = toHtml(analysis, hostile, opts);
    expect(html).not.toContain('<script>alert(1)</script>');
    expect(html).toMatch(/&lt;script&gt;/);
  });
});
