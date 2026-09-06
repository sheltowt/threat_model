import { describe, expect, it } from 'vitest';
import { fileURLToPath } from 'node:url';
import { dataAssetDot, dataFlowDot, renderSvg } from 'tmac-render';
import { analyze, loadRules } from 'tmac-rules';
import { EXAMPLE, graphOf } from './helper.js';
import { expectGolden } from './golden.js';

const golden = (name: string) => fileURLToPath(new URL(`./golden/${name}`, import.meta.url));

function risksFor(file: string) {
  const graph = graphOf(file);
  const { rules } = loadRules();
  return analyze(graph, rules).risks;
}

describe('data flow diagram', () => {
  it('matches the committed output for the example model', () => {
    expectGolden(golden('data-flow.dot'), dataFlowDot(graphOf(EXAMPLE)));
  });

  it('is deterministic across two builds of the same model', () => {
    expect(dataFlowDot(graphOf(EXAMPLE))).toBe(dataFlowDot(graphOf(EXAMPLE)));
  });

  it('emits one cluster per trust boundary, nested as the model nests them', () => {
    const dot = dataFlowDot(graphOf(EXAMPLE));
    for (const id of ['internet', 'vpc', 'web_tier', 'data_tier']) {
      expect(dot, `boundary ${id} should appear as a cluster`).toContain(`cluster_${id}`);
    }
    // web_tier is nested inside vpc, so its cluster must open after vpc's.
    expect(dot.indexOf('cluster_vpc')).toBeLessThan(dot.indexOf('cluster_web_tier'));
  });

  it('shows every in-scope element and every flow', () => {
    const graph = graphOf(EXAMPLE);
    const dot = dataFlowDot(graph);
    for (const el of graph.elements) expect(dot).toContain(el.id);
    for (const flow of graph.flows) expect(dot).toContain(flow.from.id);
  });

  it('distinguishes an out-of-scope element', () => {
    const dot = dataFlowDot(graphOf(EXAMPLE));
    // The card processor is out of scope and must not read as a normal asset.
    const processorLine = dot.split('\n').find((l) => l.includes('"processor"'));
    expect(processorLine).toBeDefined();
    expect(processorLine).toMatch(/dashed|dotted|grey|gray/i);
  });

  it('colours an unencrypted link differently from an encrypted one', () => {
    const edges = dataFlowDot(graphOf(EXAMPLE))
      .split('\n')
      .filter((l) => l.includes('->'));
    const plain = edges.find((l) => l.includes('"payment_api" -> "token_store"'));
    const tls = edges.find((l) => l.includes('"storefront" -> "payment_api"'));
    expect(plain).toBeDefined();
    expect(tls).toBeDefined();

    const colourOf = (line: string) => /color="(#[0-9a-f]{6})"/i.exec(line)?.[1];
    expect(colourOf(plain!)).not.toBe(colourOf(tls!));
  });

  it('weights a link carrying credentials more heavily than a routine one', () => {
    const edges = dataFlowDot(graphOf(EXAMPLE))
      .split('\n')
      .filter((l) => l.includes('->'));
    const penOf = (needle: string) => {
      const line = edges.find((l) => l.includes(needle))!;
      return Number(/penwidth=([\d.]+)/.exec(line)?.[1] ?? 0);
    };
    // The processor hop carries the processor credentials; the audit write does not.
    expect(penOf('"payment_api" -> "processor"')).toBeGreaterThan(
      penOf('"payment_api" -> "audit_store"'),
    );
  });

  it('accepts risks and still produces valid output', () => {
    const dot = dataFlowDot(graphOf(EXAMPLE), { risks: risksFor(EXAMPLE) });
    expect(dot.startsWith('digraph')).toBe(true);
    expect(dot.trimEnd().endsWith('}')).toBe(true);
  });

  it('honours a left-to-right layout', () => {
    const dot = dataFlowDot(graphOf(EXAMPLE), { layout: 'left-to-right' });
    expect(dot).toContain('rankdir');
  });
});

describe('data asset diagram', () => {
  it('matches the committed output for the example model', () => {
    expectGolden(golden('data-assets.dot'), dataAssetDot(graphOf(EXAMPLE)));
  });

  it('names every data asset', () => {
    const graph = graphOf(EXAMPLE);
    const dot = dataAssetDot(graph);
    for (const d of graph.data) expect(dot).toContain(d.id);
  });
});

describe('svg rendering', () => {
  it('renders through WASM Graphviz with no system dependency', async () => {
    const svg = await renderSvg(dataFlowDot(graphOf(EXAMPLE)));
    expect(svg).toContain('<svg');
    expect(svg).toContain('</svg>');
  });

  it('carries a theme block so the diagram reads on a dark page', async () => {
    const svg = await renderSvg(dataFlowDot(graphOf(EXAMPLE)));
    expect(svg).toContain('prefers-color-scheme');
  });

  it('loads nothing from the network', async () => {
    const svg = await renderSvg(dataFlowDot(graphOf(EXAMPLE)));
    expect(svg).not.toMatch(/<script[^>]+src=/);
    expect(svg).not.toMatch(/xlink:href="https?:/);
  });

  it('reports a malformed diagram rather than emitting broken SVG', async () => {
    await expect(renderSvg('digraph { this is not valid ]')).rejects.toThrow();
  });
});
