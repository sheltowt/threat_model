/**
 * Graphviz DOT generation for the two diagrams tmac draws: the data flow diagram and
 * the data asset matrix.
 *
 * Everything a model author can write reaches the output through `escapeLabel`.
 * Threat Dragon and pytm have both shipped label-injection bugs where a crafted name
 * in a model file closed the quoted string and appended attributes (or, worse, an
 * `image=` pointing at an arbitrary path). There is exactly one place in this file
 * that turns user text into DOT and it is that function; nothing else interpolates.
 */

import type {
  BoundaryNode,
  DataAssetNode,
  ElementNode,
  FlowNode,
  ModelGraph,
} from 'tmac-core';

/**
 * The shape of a risk this package needs, kept structural so `tmac-render` does not
 * depend on `tmac-rules`. A `Risk` from the engine satisfies it.
 */
export interface RenderRisk {
  id: string;
  severity: string;
  subject: { kind: string; id: string; name?: string };
  most_relevant_element?: string | undefined;
  most_relevant_flow?: string | undefined;
}

export interface DotOptions {
  /** When supplied, nodes are coloured by worst touching risk instead of by RAA. */
  risks?: readonly RenderRisk[];
  layout?: 'dot' | 'left-to-right';
  /** Draw edge labels and the second line of node labels. Default true. */
  showLabels?: boolean;
  dpi?: number;
}

const FONT = 'Helvetica,Arial,sans-serif';

/** Worst first, matching `SEVERITY` reversed. */
const SEVERITY_ORDER = ['critical', 'high', 'elevated', 'medium', 'low'] as const;

interface Swatch {
  fill: string;
  border: string;
  font: string;
}

const SEVERITY_COLOURS: Record<string, Swatch> = {
  critical: { fill: '#f5c6cb', border: '#8b1a1a', font: '#3d0a0a' },
  high: { fill: '#fad7c3', border: '#c0392b', font: '#4a1400' },
  elevated: { fill: '#fce8c3', border: '#c87f0a', font: '#4a3000' },
  medium: { fill: '#fbf3c4', border: '#a8880b', font: '#42360a' },
  low: { fill: '#dfeaf5', border: '#4a7fbf', font: '#123047' },
};

const NO_RISK: Swatch = { fill: '#f1f3f5', border: '#868e96', font: '#212529' };

/** Light-to-dark ramp for Relative Attacker Attractiveness. */
const RAA_RAMP: readonly Swatch[] = [
  { fill: '#eef2f7', border: '#94a3b8', font: '#1f2937' },
  { fill: '#d8e3f0', border: '#7f9cbb', font: '#1f2937' },
  { fill: '#b6cce4', border: '#5f83ad', font: '#132234' },
  { fill: '#86aad3', border: '#436f9f', font: '#0b1620' },
  { fill: '#4a7fbf', border: '#2c5a8f', font: '#ffffff' },
];

const CLASSIFICATION_COLOURS: Record<string, Swatch> = {
  public: { fill: '#eceff1', border: '#64748b', font: '#1f2937' },
  internal: { fill: '#dbeafe', border: '#2563eb', font: '#12294a' },
  restricted: { fill: '#e5dbfa', border: '#7c3aed', font: '#2a1450' },
  confidential: { fill: '#fde4c8', border: '#c87f0a', font: '#4a3000' },
  'strictly-confidential': { fill: '#f7c9c9', border: '#b91c1c', font: '#3d0a0a' },
};

const OUT_OF_SCOPE_BORDER = '#9aa0a6';
const EDGE_NORMAL = '#4b5563';
const EDGE_UNENCRYPTED = '#c0392b';
const CLUSTER_BORDER = '#94a3b8';
const CLUSTER_FILL = '#8a8a8a1f';
const CLUSTER_FONT = '#475569';
const EDGE_FONT = '#374151';

/**
 * Turn arbitrary model text into the body of a DOT double-quoted string.
 *
 * Order matters. Backslashes go first, otherwise the escapes added afterwards get
 * escaped themselves. `"` would end the string. A literal newline is illegal inside a
 * quoted DOT string, so it becomes the `\n` centring escape. Remaining C0/C1 control
 * characters are dropped rather than escaped, because no label needs them and a bare
 * one can upset downstream SVG consumers.
 *
 * `<` and `>` are left alone deliberately: an HTML-like label is one that *begins*
 * with an unquoted `<`, and everything here is quoted, so angle brackets are inert
 * text. `{`, `}` and `|` are likewise only structural inside record shapes, which
 * this module never emits.
 */
export function escapeLabel(value: unknown): string {
  if (value === undefined || value === null) return '';
  return String(value)
    .replace(/\\/g, '\\\\')
    .replace(/"/g, '\\"')
    .replace(/\r\n?/g, '\n')
    .replace(/\n/g, '\\n')
    .replace(/\t/g, ' ')
    // eslint-disable-next-line no-control-regex
    .replace(/[\u0000-\u001f\u007f-\u009f]/g, '');
}

/** A quoted DOT string, safe for ids, labels and attribute values alike. */
function q(value: unknown): string {
  return `"${escapeLabel(value)}"`;
}

/** Join label lines, letting `escapeLabel` turn the newlines into `\n` escapes. */
function lines(...parts: (string | undefined | false)[]): string {
  return escapeLabel(parts.filter((p): p is string => Boolean(p)).join('\n'));
}

function attrs(pairs: Record<string, string | number | undefined>): string {
  const out: string[] = [];
  for (const [key, value] of Object.entries(pairs)) {
    if (value === undefined) continue;
    out.push(`${key}=${typeof value === 'number' ? String(value) : `"${value}"`}`);
  }
  return out.join(', ');
}

/**
 * A cluster name must be a DOT identifier, so it is derived rather than quoted: a
 * boundary id maps to `[A-Za-z0-9_]` and collisions get a numeric suffix. The human
 * name reaches the diagram through the cluster's `label`, escaped like everything
 * else.
 */
function clusterNamer(): (id: string) => string {
  const used = new Map<string, number>();
  return (id: string) => {
    const base = `cluster_${id.replace(/[^A-Za-z0-9_]/g, '_')}`;
    const seen = used.get(base) ?? 0;
    used.set(base, seen + 1);
    return seen === 0 ? base : `${base}_${seen}`;
  };
}

function raaSwatch(raa: number): Swatch {
  const idx = Math.min(RAA_RAMP.length - 1, Math.max(0, Math.floor(raa / 20)));
  return RAA_RAMP[idx] ?? RAA_RAMP[0]!;
}

function severityRank(severity: string): number {
  const idx = SEVERITY_ORDER.indexOf(severity as (typeof SEVERITY_ORDER)[number]);
  return idx === -1 ? SEVERITY_ORDER.length : idx;
}

interface RiskIndex {
  worstByElement: Map<string, string>;
  worstByFlow: Map<string, string>;
  countByElement: Map<string, number>;
}

/**
 * Index risks by the element and flow they point at. A risk counts against an
 * element when the element is the subject, when it is the `most_relevant_element`,
 * or both; the same risk is never counted twice for one element.
 */
function indexRisks(risks: readonly RenderRisk[]): RiskIndex {
  const worstByElement = new Map<string, string>();
  const worstByFlow = new Map<string, string>();
  const countByElement = new Map<string, number>();

  const keep = (map: Map<string, string>, key: string, severity: string) => {
    const current = map.get(key);
    if (current === undefined || severityRank(severity) < severityRank(current)) {
      map.set(key, severity);
    }
  };

  for (const risk of risks) {
    const elements = new Set<string>();
    if (risk.subject.kind === 'element') elements.add(risk.subject.id);
    if (risk.most_relevant_element) elements.add(risk.most_relevant_element);
    for (const id of elements) {
      keep(worstByElement, id, risk.severity);
      countByElement.set(id, (countByElement.get(id) ?? 0) + 1);
    }
    const flows = new Set<string>();
    if (risk.subject.kind === 'flow') flows.add(risk.subject.id);
    if (risk.most_relevant_flow) flows.add(risk.most_relevant_flow);
    for (const id of flows) keep(worstByFlow, id, risk.severity);
  }

  return { worstByElement, worstByFlow, countByElement };
}

function shapeAttrsFor(el: ElementNode): { shape: string; style: string } {
  switch (el.kind) {
    case 'actor':
      return { shape: 'box', style: 'rounded,filled' };
    case 'datastore':
      return { shape: 'cylinder', style: 'filled' };
    case 'external':
      return { shape: 'box', style: 'filled,dashed' };
    case 'process':
    default:
      return { shape: 'ellipse', style: 'filled' };
  }
}

function elementNodeLine(
  el: ElementNode,
  indent: string,
  index: RiskIndex | undefined,
  showLabels: boolean,
): string {
  const { shape, style } = shapeAttrsFor(el);

  let swatch: Swatch;
  if (index) {
    const worst = index.worstByElement.get(el.id);
    swatch = worst ? (SEVERITY_COLOURS[worst] ?? NO_RISK) : NO_RISK;
  } else {
    swatch = raaSwatch(el.raa);
  }

  const detail = index
    ? (() => {
        const n = index.countByElement.get(el.id) ?? 0;
        const worst = index.worstByElement.get(el.id);
        return n === 0 ? 'no risks' : `${n} risk${n === 1 ? '' : 's'} · worst ${worst}`;
      })()
    : `RAA ${el.raa} · ${el.technology.id}`;

  const label = showLabels ? lines(el.name, detail) : escapeLabel(el.name);

  // Out of scope reads as "we did not look here", so it loses its colour and its
  // border goes grey and dashed whatever the risk picture says.
  const outOfScope = el.out_of_scope;
  const finalStyle = outOfScope
    ? `${style.replace(',dashed', '')},dashed`
    : style;

  return `${indent}${q(el.id)} [${attrs({
    label,
    shape,
    style: finalStyle,
    fillcolor: outOfScope ? '#f1f3f5' : swatch.fill,
    color: outOfScope ? OUT_OF_SCOPE_BORDER : swatch.border,
    fontcolor: outOfScope ? '#6b7280' : swatch.font,
    penwidth: outOfScope ? 1 : 1.4,
    tooltip: lines(
      el.name,
      el.description ?? '',
      `kind: ${el.kind}`,
      `technology: ${el.technology.id}`,
      `RAA: ${el.raa}`,
    ),
  })}];`;
}

function edgeLine(
  flow: FlowNode,
  index: RiskIndex | undefined,
  showLabels: boolean,
): string {
  const encrypted = flow.protocol['encrypted'] === true;
  const exposed = !encrypted && flow.crosses_network_boundary && !flow.process_local;

  // Anything an attacker on the wire would consider worth the effort gets weight.
  const heavy = flow.carries_credentials || flow.max_classification === 'strictly-confidential';

  let colour = exposed ? EDGE_UNENCRYPTED : EDGE_NORMAL;
  if (index) {
    const worst = index.worstByFlow.get(flow.id);
    if (worst) colour = SEVERITY_COLOURS[worst]?.border ?? colour;
  }

  const label = showLabels
    ? lines(flow.protocol.id, flow.name !== flow.protocol.id ? flow.name : undefined)
    : escapeLabel(flow.protocol.id);

  return `  ${q(flow.from.id)} -> ${q(flow.to.id)} [${attrs({
    label,
    color: colour,
    fontcolor: EDGE_FONT,
    fontsize: 9,
    penwidth: heavy ? 2.4 : 1,
    style: flow.is_response ? 'dashed' : undefined,
    tooltip: lines(
      flow.name,
      `protocol: ${flow.protocol.id}${encrypted ? ' (encrypted)' : ''}`,
      `auth: ${flow.authentication} / ${flow.authorization}`,
      flow.carries.length > 0 ? `carries: ${flow.carries.map((d) => d.id).join(', ')}` : undefined,
    ),
  })}];`;
}

function boundaryBlock(
  boundary: BoundaryNode,
  depth: number,
  emitted: Set<string>,
  name: (id: string) => string,
  index: RiskIndex | undefined,
  showLabels: boolean,
): string[] {
  const indent = '  '.repeat(depth);
  const inner = '  '.repeat(depth + 1);
  const out: string[] = [];

  out.push(`${indent}subgraph ${name(boundary.id)} {`);
  out.push(
    `${inner}graph [${attrs({
      label: lines(boundary.name, showLabels ? boundary.type : undefined),
      style: 'rounded,filled',
      fillcolor: CLUSTER_FILL,
      color: CLUSTER_BORDER,
      fontcolor: CLUSTER_FONT,
      fontsize: 10,
      labeljust: 'l',
      penwidth: boundary.is_network ? 1.6 : 1,
    })}];`,
  );

  for (const nested of boundary.nested) {
    out.push(...boundaryBlock(nested, depth + 1, emitted, name, index, showLabels));
  }
  for (const el of boundary.members) {
    if (emitted.has(el.id)) continue;
    emitted.add(el.id);
    out.push(elementNodeLine(el, inner, index, showLabels));
  }
  out.push(`${indent}}`);
  return out;
}

/** DOT for the data flow diagram: elements, flows and trust boundary clusters. */
export function dataFlowDot(graph: ModelGraph, options: DotOptions = {}): string {
  const showLabels = options.showLabels !== false;
  const index = options.risks ? indexRisks(options.risks) : undefined;
  const name = clusterNamer();
  const emitted = new Set<string>();

  const out: string[] = [];
  out.push(`digraph ${q(graph.meta.title || 'threat model')} {`);
  out.push(
    `  graph [${attrs({
      rankdir: options.layout === 'left-to-right' ? 'LR' : 'TB',
      bgcolor: 'transparent',
      fontname: FONT,
      fontsize: 12,
      splines: 'spline',
      nodesep: 0.5,
      ranksep: 0.65,
      compound: 'true',
      dpi: options.dpi,
      label: showLabels ? escapeLabel(graph.meta.title) : undefined,
      labelloc: showLabels ? 't' : undefined,
      fontcolor: CLUSTER_FONT,
    })}];`,
  );
  out.push(`  node [${attrs({ fontname: FONT, fontsize: 11, margin: '0.16,0.08' })}];`);
  out.push(`  edge [${attrs({ fontname: FONT, fontsize: 9, arrowsize: 0.7 })}];`);
  out.push('');

  // Only roots are walked; `boundaryBlock` recurses into `nested`, which is how a
  // nested boundary becomes a nested cluster rather than a sibling.
  for (const boundary of graph.boundaries) {
    if (boundary.parent) continue;
    out.push(...boundaryBlock(boundary, 1, emitted, name, index, showLabels));
  }

  const loose = graph.elements.filter((el) => !emitted.has(el.id));
  if (loose.length > 0) {
    out.push('');
    for (const el of loose) {
      emitted.add(el.id);
      out.push(elementNodeLine(el, '  ', index, showLabels));
    }
  }

  out.push('');
  for (const flow of graph.flows) out.push(edgeLine(flow, index, showLabels));

  out.push('}');
  return out.join('\n') + '\n';
}

function assetSwatch(asset: DataAssetNode): Swatch {
  return CLASSIFICATION_COLOURS[asset.classification] ?? NO_RISK;
}

/**
 * DOT for the data asset matrix: assets on the right, the elements that touch them on
 * the left, one edge per processes/stores relationship coloured by classification.
 */
export function dataAssetDot(graph: ModelGraph, options: DotOptions = {}): string {
  const showLabels = options.showLabels !== false;
  const out: string[] = [];

  out.push(`digraph ${q(`${graph.meta.title || 'threat model'} data assets`)} {`);
  out.push(
    `  graph [${attrs({
      rankdir: 'LR',
      bgcolor: 'transparent',
      fontname: FONT,
      fontsize: 12,
      nodesep: 0.24,
      ranksep: 2.0,
      dpi: options.dpi,
      label: showLabels ? escapeLabel(`${graph.meta.title} — data assets`) : undefined,
      labelloc: showLabels ? 't' : undefined,
      fontcolor: CLUSTER_FONT,
    })}];`,
  );
  out.push(`  node [${attrs({ fontname: FONT, fontsize: 11, margin: '0.16,0.08' })}];`);
  out.push(`  edge [${attrs({ fontname: FONT, fontsize: 9, arrowsize: 0.6 })}];`);
  out.push('');

  const clusterAttrs = (label: string) =>
    `    graph [${attrs({
      label,
      style: 'rounded,filled',
      fillcolor: CLUSTER_FILL,
      color: CLUSTER_BORDER,
      fontcolor: CLUSTER_FONT,
      fontsize: 10,
      labeljust: 'l',
    })}];`;

  // Elements first so they land in the left column under rankdir=LR.
  out.push('  subgraph cluster_elements {');
  out.push(clusterAttrs('Elements'));
  for (const el of graph.elements) {
    const { shape } = shapeAttrsFor(el);
    out.push(
      `    ${q(`el:${el.id}`)} [${attrs({
        label: showLabels ? lines(el.name, el.technology.id) : escapeLabel(el.name),
        shape,
        style: el.out_of_scope ? 'filled,dashed' : 'filled',
        fillcolor: '#f1f3f5',
        color: el.out_of_scope ? OUT_OF_SCOPE_BORDER : '#868e96',
        fontcolor: el.out_of_scope ? '#6b7280' : '#212529',
        tooltip: lines(el.name, el.description ?? ''),
      })}];`,
    );
  }
  out.push('  }');
  out.push('');

  out.push('  subgraph cluster_data {');
  out.push(clusterAttrs('Data assets'));
  for (const asset of graph.data) {
    const swatch = assetSwatch(asset);
    const badges = [
      asset.pii ? 'PII' : undefined,
      asset.credentials ? 'credentials' : undefined,
      ...asset.regulations,
    ].filter((b): b is string => Boolean(b));
    out.push(
      `    ${q(`data:${asset.id}`)} [${attrs({
        label: showLabels
          ? lines(asset.id, asset.classification, badges.length > 0 ? badges.join(' · ') : undefined)
          : escapeLabel(asset.id),
        shape: 'note',
        style: asset.orphaned ? 'filled,dashed' : 'filled',
        fillcolor: swatch.fill,
        color: asset.orphaned ? OUT_OF_SCOPE_BORDER : swatch.border,
        fontcolor: swatch.font,
        penwidth: 1.4,
        tooltip: lines(
          asset.id,
          asset.description ?? '',
          `classification: ${asset.classification}`,
          `integrity: ${asset.integrity}`,
          `availability: ${asset.availability}`,
        ),
      })}];`,
    );
  }
  out.push('  }');
  out.push('');

  // One edge per relationship, deduplicated: an element that both processes and
  // stores an asset gets a single edge labelled "processes, stores".
  const relations = new Map<string, { el: ElementNode; asset: DataAssetNode; how: string[] }>();
  const record = (el: ElementNode, asset: DataAssetNode, how: string) => {
    const key = `${el.id} ${asset.id}`;
    const existing = relations.get(key);
    if (existing) {
      if (!existing.how.includes(how)) existing.how.push(how);
    } else {
      relations.set(key, { el, asset, how: [how] });
    }
  };
  for (const el of graph.elements) {
    for (const asset of el.processes) record(el, asset, 'processes');
    for (const asset of el.stores) record(el, asset, 'stores');
  }

  for (const { el, asset, how } of relations.values()) {
    const swatch = assetSwatch(asset);
    out.push(
      `  ${q(`el:${el.id}`)} -> ${q(`data:${asset.id}`)} [${attrs({
        label: showLabels ? escapeLabel(how.join(', ')) : undefined,
        color: swatch.border,
        fontcolor: EDGE_FONT,
        fontsize: 9,
        // Storage is the durable exposure, so it is drawn heavier than processing.
        penwidth: how.includes('stores') ? 2 : 1,
        style: el.out_of_scope ? 'dashed' : undefined,
      })}];`,
    );
  }

  out.push('}');
  return out.join('\n') + '\n';
}
