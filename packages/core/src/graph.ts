import type { Catalog, ProtocolEntry, TechnologyEntry } from './catalog-core.js';
import {
  CONFIDENTIALITY,
  CRITICALITY,

  isNetworkBoundary,
  rankOf,
  type BoundaryType,
  type Confidentiality,
  type Criticality,
  type ElementKind,
} from './enums.js';
import type {
  Assumption,
  Controls,
  DataAsset,
  ElementDef,
  FlowDef,
  ManualThreat,
  Model,
  RiskTracking,
} from './schema.js';

/**
 * A technology or protocol as a rule sees it: `.id` plus every catalogue attribute
 * as a plain boolean. Attributes absent from the catalogue read as `false`, so
 * `tech.vulnerable_to_query_injection` is safe on any technology.
 */
export interface TechnologyView {
  id: string;
  kind: ElementKind;
  [attr: string]: string | boolean;
}
export interface ProtocolView {
  id: string;
  [attr: string]: string | boolean;
}

export interface DataAssetNode extends DataAsset {
  id: string;
  processed_by: ElementNode[];
  stored_by: ElementNode[];
  sent_via: FlowNode[];
  received_via: FlowNode[];
  /** True when no element processes or stores it and no flow carries it. */
  orphaned: boolean;
}

export interface BoundaryNode {
  id: string;
  name: string;
  description: string | undefined;
  type: BoundaryType;
  is_network: boolean;
  /** Elements listed directly on this boundary. */
  members: ElementNode[];
  /** Members of this boundary and of every boundary nested inside it. */
  all_members: ElementNode[];
  nested: BoundaryNode[];
  parent: BoundaryNode | undefined;
  tags: string[];
}

export interface ElementNode {
  id: string;
  name: string;
  description: string | undefined;
  kind: ElementKind;
  technology: TechnologyView;
  size: ElementDef['size'];
  machine: ElementDef['machine'];
  usage: ElementDef['usage'];
  internet_facing: boolean;
  human: boolean;
  custom_code: boolean;
  multi_tenant: boolean;
  out_of_scope: boolean;
  encryption: ElementDef['encryption'];
  owner: string | undefined;
  controls: Controls;
  tags: string[];

  processes: DataAssetNode[];
  stores: DataAssetNode[];
  /** Everything the element touches, whether processed, stored or in transit. */
  handles: DataAssetNode[];
  accepts_formats: string[];

  /** Explicit rating when the author gave one, else the highest of what it holds. */
  confidentiality: Confidentiality;
  integrity: Criticality;
  availability: Criticality;

  boundary: BoundaryNode | undefined;
  /** Innermost boundary first, up to the outermost. */
  boundaries: BoundaryNode[];
  shared_runtimes: SharedRuntimeNode[];

  incoming: FlowNode[];
  outgoing: FlowNode[];

  /** Reachable over one or more flows starting from an internet-facing element. */
  internet_reachable: boolean;
  /** Relative Attacker Attractiveness, 0 to 100. See computeRaa. */
  raa: number;
}

export interface FlowNode {
  id: string;
  name: string;
  description: string | undefined;
  from: ElementNode;
  to: ElementNode;
  protocol: ProtocolView;
  authentication: FlowDef['authentication'];
  authorization: FlowDef['authorization'];
  usage: FlowDef['usage'];
  vpn: boolean;
  ip_filtered: boolean;
  readonly: boolean;
  is_response: boolean;
  controls: Controls;
  tags: string[];

  sends: DataAssetNode[];
  receives: DataAssetNode[];
  /** Everything the link carries in either direction. */
  carries: DataAssetNode[];
  max_classification: Confidentiality;
  max_integrity: Criticality;
  carries_credentials: boolean;
  carries_pii: boolean;

  /** Endpoints sit in different boundaries. */
  crosses_boundary: boolean;
  /** The boundary crossed separates networks, so the traffic is on a wire. */
  crosses_network_boundary: boolean;
  /** Runs inside one process or host, so network controls do not apply. */
  process_local: boolean;
  from_internet: boolean;
}

export interface SharedRuntimeNode {
  id: string;
  name: string;
  description: string | undefined;
  runs: ElementNode[];
  tags: string[];
}

export interface ModelGraph {
  meta: Model['meta'];
  elements: ElementNode[];
  flows: FlowNode[];
  boundaries: BoundaryNode[];
  data: DataAssetNode[];
  shared_runtimes: SharedRuntimeNode[];
  assumptions: Assumption[];
  manual_threats: ManualThreat[];
  risk_tracking: Record<string, RiskTracking>;
  disabled_rules: Record<string, string>;

  elementById: Map<string, ElementNode>;
  flowById: Map<string, FlowNode>;
  boundaryById: Map<string, BoundaryNode>;
  dataById: Map<string, DataAssetNode>;

  /** Elements that count for analysis, i.e. everything not marked out of scope. */
  inScope: ElementNode[];
}

/**
 * Project a catalogue entry into the flat object a rule sees.
 *
 * Every attribute name known to the catalogue is populated, defaulting to false, so
 * `tech.vulnerable_to_query_injection` reads as a definite `false` on a technology
 * that does not declare it. Catalogue attributes are closed-world: silence means
 * absent. Security controls are the opposite, open-world, where silence means nobody
 * has said and the evaluator must return UNKNOWN. Conflating the two is what makes
 * pytm noisy, so the distinction is enforced here at the boundary.
 */
function viewOf<T extends { id: string; attrs: Record<string, boolean> }>(
  entry: T | undefined,
  fallbackId: string,
  allAttributes: readonly string[],
  extra: Record<string, string> = {},
): Record<string, string | boolean> {
  const view: Record<string, string | boolean> = { id: entry?.id ?? fallbackId, ...extra };
  for (const name of allAttributes) view[name] = false;
  for (const [k, v] of Object.entries(entry?.attrs ?? {})) view[k] = v;
  return view;
}

function maxBy<T extends string>(
  order: readonly T[],
  values: readonly T[],
  floor: T,
): T {
  let best = order.indexOf(floor);
  for (const v of values) {
    const idx = order.indexOf(v);
    if (idx > best) best = idx;
  }
  return order[best] ?? floor;
}

/**
 * Relative Attacker Attractiveness, adapted from Threagile.
 *
 * The score answers "if an attacker had one foothold to spend, where would they
 * want it". It is the sensitivity of everything an element touches, weighted by how
 * much of it there is, discounted for elements that only pass data through, and then
 * normalised across the model so the numbers are comparable within one report and
 * meaningless between two.
 */
function computeRaa(elements: ElementNode[]): void {
  const conf = (c: Confidentiality) => rankOf(c, 'confidentiality') ?? 0;
  const crit = (c: Criticality) => rankOf(c, 'criticality') ?? 0;
  const qty = (q: DataAsset['quantity']) => (rankOf(q, 'quantity') ?? 0) + 1;

  const raw = new Map<string, number>();
  for (const el of elements) {
    let score = conf(el.confidentiality) + crit(el.integrity) + crit(el.availability);
    for (const d of el.processes) score += (conf(d.classification) + crit(d.integrity)) * qty(d.quantity) * 0.5;
    // Data at rest is worth more to an attacker than data in flight.
    for (const d of el.stores) score += (conf(d.classification) + crit(d.integrity)) * qty(d.quantity);
    for (const f of el.incoming) score += conf(f.max_classification) * 0.25;
    for (const f of el.outgoing) score += conf(f.max_classification) * 0.25;

    // Pass-through infrastructure holds little of its own.
    const t = el.technology;
    if (t['load_balancer'] === true || t['reverse_proxy'] === true) score /= 5.5;
    else if (t['monitoring'] === true) score /= 5;
    else if (t['gateway'] === true) score /= 2;
    if (el.out_of_scope) score /= 3;

    raw.set(el.id, score);
  }

  const values = [...raw.values()];
  const max = Math.max(...values, 1);
  const min = Math.min(...values, 0);
  const span = max - min || 1;
  for (const el of elements) {
    el.raa = Math.round(((raw.get(el.id)! - min) / span) * 100);
  }

  // An element that can reach a more attractive neighbour inherits part of its pull,
  // because a foothold here is a step towards the real target.
  const bumped = new Map<string, number>();
  for (const el of elements) {
    let best = el.raa;
    for (const f of el.outgoing) if (f.to.raa > best) best = f.to.raa;
    bumped.set(el.id, el.raa + Math.round((best - el.raa) / 3));
  }
  for (const el of elements) el.raa = Math.min(100, bumped.get(el.id)!);
}

/** Mark every element reachable by following flows out of an internet-facing one. */
function markInternetReachable(elements: ElementNode[]): void {
  const queue: ElementNode[] = [];
  for (const el of elements) {
    if (el.internet_facing) {
      el.internet_reachable = true;
      queue.push(el);
    }
  }
  while (queue.length > 0) {
    const el = queue.pop()!;
    for (const f of el.outgoing) {
      if (!f.to.internet_reachable) {
        f.to.internet_reachable = true;
        queue.push(f.to);
      }
    }
  }
}

/** Build the analysis graph. The model must already have passed `loadModel`. */
export function buildGraph(model: Model, catalog: Catalog): ModelGraph {
  const dataById = new Map<string, DataAssetNode>();
  for (const [id, def] of Object.entries(model.data_assets)) {
    dataById.set(id, {
      ...def,
      id,
      processed_by: [],
      stored_by: [],
      sent_via: [],
      received_via: [],
      orphaned: true,
    });
  }

  const elementById = new Map<string, ElementNode>();
  for (const [id, def] of Object.entries(model.elements)) {
    const tech: TechnologyEntry | undefined = catalog.technologies.get(def.technology);
    const processes = def.processes.map((d) => dataById.get(d)!).filter(Boolean);
    const stores = def.stores.map((d) => dataById.get(d)!).filter(Boolean);
    const held = [...new Set([...processes, ...stores])];

    const node: ElementNode = {
      id,
      name: def.name ?? id,
      description: def.description,
      kind: def.kind ?? tech?.kind ?? 'process',
      technology: viewOf(tech, def.technology, catalog.technologyAttributes, {
        kind: tech?.kind ?? 'process',
      }) as TechnologyView,
      size: def.size,
      machine: def.machine,
      usage: def.usage,
      internet_facing: def.internet_facing,
      human: def.human,
      custom_code: def.custom_code,
      multi_tenant: def.multi_tenant,
      out_of_scope: def.out_of_scope,
      encryption: def.encryption,
      owner: def.owner,
      controls: def.controls,
      tags: def.tags,
      processes,
      stores,
      handles: held,
      accepts_formats: def.accepts_formats,
      confidentiality:
        def.confidentiality ??
        maxBy(CONFIDENTIALITY, held.map((d) => d.classification), 'public'),
      integrity: def.integrity ?? maxBy(CRITICALITY, held.map((d) => d.integrity), 'archive'),
      availability:
        def.availability ?? maxBy(CRITICALITY, held.map((d) => d.availability), 'archive'),
      boundary: undefined,
      boundaries: [],
      shared_runtimes: [],
      incoming: [],
      outgoing: [],
      internet_reachable: false,
      raa: 0,
    };
    elementById.set(id, node);
    for (const d of processes) d.processed_by.push(node);
    for (const d of stores) d.stored_by.push(node);
  }

  // Boundaries, then parent links, then transitive membership.
  const boundaryById = new Map<string, BoundaryNode>();
  for (const [id, def] of Object.entries(model.trust_boundaries)) {
    boundaryById.set(id, {
      id,
      name: def.name ?? id,
      description: def.description,
      type: def.type,
      is_network: isNetworkBoundary(def.type),
      members: def.contains.map((e) => elementById.get(e)!).filter(Boolean),
      all_members: [],
      nested: [],
      parent: undefined,
      tags: def.tags,
    });
  }
  for (const [id, def] of Object.entries(model.trust_boundaries)) {
    const b = boundaryById.get(id)!;
    for (const childId of def.nested) {
      const child = boundaryById.get(childId);
      if (!child) continue;
      b.nested.push(child);
      child.parent = b;
    }
  }
  const collectMembers = (b: BoundaryNode, seen = new Set<string>()): ElementNode[] => {
    if (seen.has(b.id)) return [];
    seen.add(b.id);
    const out = [...b.members];
    for (const child of b.nested) out.push(...collectMembers(child, seen));
    return out;
  };
  for (const b of boundaryById.values()) b.all_members = [...new Set(collectMembers(b))];

  for (const b of boundaryById.values()) {
    for (const el of b.members) {
      el.boundary = b;
      const chain: BoundaryNode[] = [];
      let cur: BoundaryNode | undefined = b;
      const guard = new Set<string>();
      while (cur && !guard.has(cur.id)) {
        guard.add(cur.id);
        chain.push(cur);
        cur = cur.parent;
      }
      el.boundaries = chain;
    }
  }

  const sharedRuntimes: SharedRuntimeNode[] = [];
  for (const [id, def] of Object.entries(model.shared_runtimes)) {
    const node: SharedRuntimeNode = {
      id,
      name: def.name ?? id,
      description: def.description,
      runs: def.runs.map((e) => elementById.get(e)!).filter(Boolean),
      tags: def.tags,
    };
    sharedRuntimes.push(node);
    for (const el of node.runs) el.shared_runtimes.push(node);
  }

  const flowById = new Map<string, FlowNode>();
  for (const def of model.flows) {
    const from = elementById.get(def.from);
    const to = elementById.get(def.to);
    if (!from || !to) continue;
    const proto: ProtocolEntry | undefined = catalog.protocols.get(def.protocol);
    const sends = def.sends.map((d) => dataById.get(d)!).filter(Boolean);
    const receives = def.receives.map((d) => dataById.get(d)!).filter(Boolean);
    const carries = [...new Set([...sends, ...receives])];

    const sharedBoundary = from.boundaries.find((b) =>
      to.boundaries.some((other) => other.id === b.id),
    );
    // The boundaries an attacker would have to be inside to see this traffic.
    const crossed = [
      ...from.boundaries.filter((b) => b.id !== sharedBoundary?.id),
      ...to.boundaries.filter((b) => b.id !== sharedBoundary?.id),
    ];
    const processLocal = proto?.attrs['process_local'] === true;

    const node: FlowNode = {
      id: def.id,
      name: def.name ?? def.id,
      description: def.description,
      from,
      to,
      protocol: viewOf(proto, def.protocol, catalog.protocolAttributes) as ProtocolView,
      authentication: def.authentication,
      authorization: def.authorization,
      usage: def.usage,
      vpn: def.vpn,
      ip_filtered: def.ip_filtered,
      readonly: def.readonly,
      is_response: def.is_response,
      controls: def.controls,
      tags: def.tags,
      sends,
      receives,
      carries,
      max_classification: maxBy(CONFIDENTIALITY, carries.map((d) => d.classification), 'public'),
      max_integrity: maxBy(CRITICALITY, carries.map((d) => d.integrity), 'archive'),
      carries_credentials: carries.some((d) => d.credentials),
      carries_pii: carries.some((d) => d.pii),
      crosses_boundary: from.boundary?.id !== to.boundary?.id,
      crosses_network_boundary:
        !processLocal &&
        (crossed.some((b) => b.is_network) || from.boundary?.id !== to.boundary?.id),
      process_local: processLocal,
      from_internet: from.internet_facing || from.boundary?.type === 'network-untrusted',
    };
    flowById.set(node.id, node);
    from.outgoing.push(node);
    to.incoming.push(node);
    for (const d of sends) d.sent_via.push(node);
    for (const d of receives) d.received_via.push(node);
  }

  const elements = [...elementById.values()];
  for (const d of dataById.values()) {
    d.orphaned =
      d.processed_by.length === 0 &&
      d.stored_by.length === 0 &&
      d.sent_via.length === 0 &&
      d.received_via.length === 0;
  }

  markInternetReachable(elements);
  computeRaa(elements);

  return {
    meta: model.meta,
    elements,
    flows: [...flowById.values()],
    boundaries: [...boundaryById.values()],
    data: [...dataById.values()],
    shared_runtimes: sharedRuntimes,
    assumptions: model.assumptions,
    manual_threats: model.manual_threats,
    risk_tracking: model.risk_tracking,
    disabled_rules: model.disabled_rules,
    elementById,
    flowById,
    boundaryById,
    dataById,
    inScope: elements.filter((e) => !e.out_of_scope),
  };
}

