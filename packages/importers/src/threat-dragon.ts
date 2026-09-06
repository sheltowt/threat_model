/**
 * OWASP Threat Dragon v2 importer.
 *
 * Threat Dragon stores an AntV X6 canvas and the security content in one file, with
 * the security properties nested inside `cell.data`. We split the two: semantics go
 * into the model, coordinates into the layout sidecar (ADR 0003). Trust boundary
 * membership is only expressed geometrically in Threat Dragon, so it is recomputed
 * here from the cell rectangles.
 */

import type { ModelInput } from '@tmc/core';
import {
  asArray,
  asBool,
  asRecord,
  asString,
  coerceDocument,
  type ControlsIn,
  type ElementIn,
  type FlowIn,
  IdRegistry,
  type ImportResult,
  type ImportWarning,
  isRecord,
  type ManualThreatIn,
  mapLinddun,
  mapProtocol,
  mapSeverity,
  mapStride,
  pushWarning,
} from './util.js';

interface Rect {
  x: number;
  y: number;
  width: number;
  height: number;
}

interface Cell {
  raw: Record<string, unknown>;
  id: string;
  shape: string;
  type: string;
  data: Record<string, unknown>;
  rect?: Rect;
  source?: string;
  target?: string;
}

const NODE_TYPES = new Set(['tm.Actor', 'tm.Process', 'tm.Store']);

function num(value: unknown): number | undefined {
  return typeof value === 'number' && Number.isFinite(value) ? value : undefined;
}

function rectOf(raw: Record<string, unknown>): Rect | undefined {
  const position = asRecord(raw['position']);
  const size = asRecord(raw['size']);
  const x = num(position['x']);
  const y = num(position['y']);
  if (x === undefined || y === undefined) return undefined;
  return { x, y, width: num(size['width']) ?? 0, height: num(size['height']) ?? 0 };
}

function endpoint(value: unknown): string | undefined {
  if (typeof value === 'string') return value;
  if (isRecord(value)) return asString(value['cell']);
  return undefined;
}

/** True when the centre of `inner` lies within `outer`. */
function contains(outer: Rect, inner: Rect): boolean {
  const cx = inner.x + inner.width / 2;
  const cy = inner.y + inner.height / 2;
  return (
    cx >= outer.x && cx <= outer.x + outer.width && cy >= outer.y && cy <= outer.y + outer.height
  );
}

function area(rect: Rect): number {
  return Math.max(rect.width, 0) * Math.max(rect.height, 0);
}

/** Threat Dragon does not record what a boundary separates, so the name has to say. */
const UNTRUSTED_NAME = /internet|public|untrusted|external|wan\b|dmz/i;

function collectCells(detail: Record<string, unknown>): Cell[] {
  const cells: Cell[] = [];
  for (const diagram of asArray(detail['diagrams'])) {
    const d = asRecord(diagram);
    for (const rawCell of asArray(d['cells'])) {
      if (!isRecord(rawCell)) continue;
      const data = asRecord(rawCell['data']);
      const id = asString(rawCell['id']) ?? '';
      if (id === '') continue;
      cells.push({
        raw: rawCell,
        id,
        shape: asString(rawCell['shape']) ?? '',
        type: asString(data['type']) ?? '',
        data,
        rect: rectOf(rawCell),
        source: endpoint(rawCell['source']),
        target: endpoint(rawCell['target']),
      });
    }
  }
  return cells;
}

function processTechnology(data: Record<string, unknown>): string {
  return asBool(data['isWebApplication']) === true ? 'web-application' : 'unknown-technology';
}

function tagIf(tags: string[], flag: unknown, tag: string): void {
  if (asBool(flag) === true) tags.push(tag);
}

export function importThreatDragon(json: unknown): ImportResult {
  const warnings: ImportWarning[] = [];
  const doc = asRecord(coerceDocument(json));
  const summary = asRecord(doc['summary']);
  const detail = asRecord(doc['detail']);
  const cells = collectCells(detail);

  const registry = new IdRegistry();
  const elements: NonNullable<ModelInput['elements']> = {};
  const flows: FlowIn[] = [];
  const boundaries: NonNullable<ModelInput['trust_boundaries']> = {};
  const manualThreats: ManualThreatIn[] = [];
  const layoutElements: Record<string, Rect> = {};
  const layoutBoundaries: Record<string, Rect> = {};

  // --- nodes ---------------------------------------------------------------
  const nodeCells = cells.filter((c) => NODE_TYPES.has(c.type));
  for (const cell of nodeCells) {
    const name = asString(cell.data['name']) ?? asString(cell.raw['id']) ?? 'element';
    const id = registry.assign([cell.id, name], name, 'element');
    const tags: string[] = [];
    const controls: ControlsIn = {};
    let element: ElementIn;

    if (cell.type === 'tm.Actor') {
      // Threat Dragon actors are the humans and external systems at the edge.
      element = { name, kind: 'actor', technology: 'unknown-technology' };
      if (asBool(cell.data['providesAuthentication']) === true) {
        controls.authenticates_source = true;
      }
    } else if (cell.type === 'tm.Process') {
      element = { name, kind: 'process', technology: processTechnology(cell.data) };
      const privilege = asString(cell.data['privilegeLevel']);
      if (privilege !== undefined) tags.push(`privilege-level:${privilege}`);
      tagIf(tags, cell.data['handlesCardPayment'], 'handles-card-payment');
      tagIf(tags, cell.data['handlesGoodsOrServices'], 'handles-goods-or-services');
    } else {
      element = { name, kind: 'datastore', technology: 'database' };
      if (asBool(cell.data['isEncrypted']) === true) element.encryption = 'transparent';
      if (asBool(cell.data['isALog']) === true) {
        element.usage = 'devops';
        tags.push('log');
      }
      tagIf(tags, cell.data['storesCredentials'], 'stores-credentials');
      tagIf(tags, cell.data['isSigned'], 'signed');
      tagIf(tags, cell.data['storesInventory'], 'stores-inventory');
    }

    const description = asString(cell.data['description']);
    if (description !== undefined) element.description = description;
    if (asBool(cell.data['outOfScope']) === true) {
      element.out_of_scope = true;
      const reason = asString(cell.data['reasonOutOfScope']);
      if (reason !== undefined) element.justification_out_of_scope = reason;
    }
    if (tags.length > 0) element.tags = tags;
    if (Object.keys(controls).length > 0) element.controls = controls;

    elements[id] = element;
    if (cell.rect) layoutElements[id] = cell.rect;
  }

  // --- flows ---------------------------------------------------------------
  for (const cell of cells) {
    if (cell.type !== 'tm.Flow') continue;
    const name = asString(cell.data['name']) ?? 'flow';
    const from = registry.resolve(cell.source);
    const to = registry.resolve(cell.target);
    if (from === undefined || to === undefined) {
      pushWarning(
        warnings,
        'td-dangling-flow',
        `flow "${name}" is not attached to two shapes and was dropped`,
        'Reconnect the data flow in Threat Dragon and re-export.',
      );
      continue;
    }
    const flowId = registry.assign([cell.id], name, 'flow');
    const encrypted = asBool(cell.data['isEncrypted']) === true;
    const declared = cell.data['protocol'];
    let protocol = mapProtocol(declared);
    if (protocol === undefined) {
      protocol = encrypted ? 'https' : 'http';
      const spelled = asString(declared);
      if (spelled !== undefined) {
        pushWarning(
          warnings,
          'td-protocol-unmapped',
          `protocol "${spelled}" on flow "${name}" is not in the catalogue; used ${protocol}`,
          'Add the protocol to .tmc/protocols.yaml, or set it on the flow by hand.',
        );
      }
    }
    const flow: FlowIn = { id: flowId, from, to, name, protocol };
    const description = asString(cell.data['description']);
    if (description !== undefined) flow.description = description;
    const tags: string[] = [];
    tagIf(tags, cell.data['isPublicNetwork'], 'public-network');
    tagIf(tags, cell.data['isBidirectional'], 'bidirectional');
    if (tags.length > 0) flow.tags = tags;
    flows.push(flow);
  }

  // --- trust boundaries ----------------------------------------------------
  const drafts = new Map<string, BoundaryDraft>();
  const boxes = cells.filter((c) => c.type === 'tm.Boundary' && c.shape === 'trust-boundary-box');
  const boxRects = new Map<string, Rect>();
  for (const cell of boxes) {
    const name = asString(cell.data['name']) ?? 'boundary';
    const id = registry.assign([cell.id, name], name, 'boundary');
    const type = UNTRUSTED_NAME.test(name) ? 'network-untrusted' : 'network-on-prem';
    const boundary: BoundaryDraft = { id, name, type, contains: [], nested: [] };
    const description = asString(cell.data['description']);
    if (description !== undefined) boundary.description = description;
    drafts.set(cell.id, boundary);
    if (cell.rect) {
      boxRects.set(cell.id, cell.rect);
      layoutBoundaries[id] = cell.rect;
    }
  }

  // Membership: the smallest box whose rectangle covers the shape wins, so a nested
  // boundary claims its own members rather than the outer one claiming everything.
  for (const cell of nodeCells) {
    if (!cell.rect) continue;
    let best: { id: string; size: number } | undefined;
    for (const [boxId, rect] of boxRects) {
      if (!contains(rect, cell.rect)) continue;
      const size = area(rect);
      if (best === undefined || size < best.size) best = { id: boxId, size };
    }
    if (best === undefined) continue;
    const draft = drafts.get(best.id);
    const elementId = registry.resolve(cell.id);
    if (draft && elementId) draft.contains.push(elementId);
  }

  // Boundary nesting, by the same smallest-enclosing-rectangle rule.
  for (const [boxId, rect] of boxRects) {
    let best: { id: string; size: number } | undefined;
    for (const [otherId, other] of boxRects) {
      if (otherId === boxId) continue;
      if (!contains(other, rect) || area(other) <= area(rect)) continue;
      const size = area(other);
      if (best === undefined || size < best.size) best = { id: otherId, size };
    }
    const parent = best ? drafts.get(best.id) : undefined;
    const child = drafts.get(boxId);
    if (parent && child) parent.nested.push(child.id);
  }

  for (const cell of cells) {
    if (cell.type !== 'tm.Boundary' || cell.shape === 'trust-boundary-box') continue;
    const name = asString(cell.data['name']) ?? 'boundary';
    const id = registry.assign([cell.id, name], name, 'boundary');
    drafts.set(cell.id, {
      id,
      name,
      type: UNTRUSTED_NAME.test(name) ? 'network-untrusted' : 'network-on-prem',
      contains: [],
      nested: [],
    });
    pushWarning(
      warnings,
      'td-boundary-curve-membership',
      `boundary "${name}" is drawn as a curve, which carries no membership information`,
      'List the elements it separates under trust_boundaries.contains by hand.',
    );
  }

  for (const draft of drafts.values()) {
    const boundary: NonNullable<ModelInput['trust_boundaries']>[string] = {
      name: draft.name,
      type: draft.type,
    };
    if (draft.description !== undefined) boundary.description = draft.description;
    if (draft.contains.length > 0) boundary.contains = draft.contains;
    if (draft.nested.length > 0) boundary.nested = draft.nested;
    // Nested boundaries own their members; drop them from the outer list.
    boundaries[draft.id] = boundary;
  }
  for (const draft of drafts.values()) {
    if (draft.nested.length === 0) continue;
    const owned = new Set<string>();
    for (const childId of draft.nested) {
      const child = [...drafts.values()].find((d) => d.id === childId);
      for (const member of child?.contains ?? []) owned.add(member);
    }
    const boundary = boundaries[draft.id];
    if (boundary?.contains) {
      boundary.contains = boundary.contains.filter((m) => !owned.has(m));
      if (boundary.contains.length === 0) delete boundary.contains;
    }
  }

  // --- threats -------------------------------------------------------------
  const threatIds = new IdRegistry();
  for (const cell of cells) {
    const subject = registry.resolve(cell.id);
    if (subject === undefined) continue;
    const isFlow = cell.type === 'tm.Flow';
    for (const rawThreat of asArray(cell.data['threats'])) {
      if (!isRecord(rawThreat)) continue;
      const title = asString(rawThreat['title']) ?? 'Untitled threat';
      const id = threatIds.assign([asString(rawThreat['id'])], asString(rawThreat['id']) ?? title, 'threat');
      const threat: ManualThreatIn = { id, title };
      const description = asString(rawThreat['description']);
      if (description !== undefined) threat.description = description;
      const mitigation = asString(rawThreat['mitigation']);
      if (mitigation !== undefined) threat.mitigation = mitigation;
      if (isFlow) threat.flow = subject;
      else threat.element = subject;

      const category = asString(rawThreat['type']);
      const stride = mapStride(category);
      const linddun = mapLinddun(category);
      if (stride !== undefined) threat.stride = stride;
      if (linddun !== undefined) threat.linddun = linddun;
      if (stride === undefined && linddun === undefined) {
        pushWarning(
          warnings,
          'td-threat-category-unmapped',
          `threat "${title}" has category ${category === undefined ? '(none)' : `"${category}"`}, which does not map to STRIDE or LINDDUN`,
          'Set `stride:` on the imported manual threat rather than leaving it uncategorised.',
        );
      }

      const rawSeverity = asString(rawThreat['severity']);
      const severity = mapSeverity(rawSeverity);
      if (severity === 'low' || severity === 'medium' || severity === 'high') {
        threat.severity = severity;
      } else {
        threat.severity = 'medium';
        pushWarning(
          warnings,
          'td-severity-unmapped',
          `severity ${rawSeverity === undefined ? '(none)' : `"${rawSeverity}"`} on threat "${title}" is not High, Medium or Low; imported as medium`,
          'Threat Dragon writes TBD for an unrated threat; rate it and re-import, or edit the severity here.',
        );
      }

      const tags: string[] = [];
      const status = asString(rawThreat['status']);
      if (status !== undefined) tags.push(`td-status:${status.toLowerCase()}`);
      const modelType = asString(rawThreat['modelType']);
      if (modelType !== undefined) tags.push(`td-model:${modelType.toLowerCase()}`);
      if (tags.length > 0) threat.tags = tags;
      manualThreats.push(threat);
    }
  }

  // --- meta ----------------------------------------------------------------
  const contributors = asArray(detail['contributors'])
    .map((c) => (isRecord(c) ? asString(c['name']) : asString(c)))
    .filter((c): c is string => c !== undefined);

  const meta: ModelInput['meta'] = {
    title: asString(summary['title']) ?? 'Imported Threat Dragon model',
  };
  const description = asString(summary['description']);
  if (description !== undefined) meta.description = description;
  const owner = asString(summary['owner']);
  if (owner !== undefined) meta.owner = owner;
  if (contributors.length > 0) meta.author = contributors.join(', ');
  const version = asString(doc['version']);
  if (version !== undefined) meta.version = version;

  const model: ModelInput = { schema: 'tmc/1.0', meta };
  if (Object.keys(elements).length > 0) model.elements = elements;
  if (flows.length > 0) model.flows = flows;
  if (Object.keys(boundaries).length > 0) model.trust_boundaries = boundaries;
  if (manualThreats.length > 0) model.manual_threats = manualThreats;

  return {
    model,
    layout: { elements: layoutElements, boundaries: layoutBoundaries },
    warnings,
  };
}

interface BoundaryDraft {
  id: string;
  name: string;
  type: 'network-untrusted' | 'network-on-prem';
  description?: string;
  contains: string[];
  nested: string[];
}
