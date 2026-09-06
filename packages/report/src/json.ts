/**
 * Machine-readable output.
 *
 * Two properties matter more than anything else here. The structure is *stable*:
 * key order is fixed, every list is sorted by an explicit comparator rather than by
 * whatever order the engine happened to produce, and absent optional fields are
 * omitted rather than emitted as null. And it is *reproducible*: `generated_at` is
 * injectable, so two runs over an unchanged model produce byte-identical files and a
 * diff in CI means the model changed.
 */

import { SEVERITY, type ModelGraph, type ElementNode } from '@tmc/core/browser';
import type { Analysis, Risk } from '@tmc/rules/browser';

export interface JsonOptions {
  /** ISO timestamp. Injectable so golden files and CI diffs stay deterministic. */
  generatedAt?: string;
}

export const RISKS_SCHEMA = 'tmc/risks/1.0';
export const STATS_SCHEMA = 'tmc/stats/1.0';
export const ASSETS_SCHEMA = 'tmc/technical-assets/1.0';

function stamp(options: JsonOptions): string {
  return options.generatedAt ?? new Date().toISOString();
}

/** Worst first, then by id, so the file order never depends on rule evaluation order. */
export function compareRisks(a: Risk, b: Risk): number {
  const rank = SEVERITY.indexOf(b.severity) - SEVERITY.indexOf(a.severity);
  return rank !== 0 ? rank : a.id.localeCompare(b.id);
}

export interface ModelSummary {
  title: string;
  description?: string;
  owner?: string;
  author?: string;
  date?: string;
  version?: string;
  business_criticality: string;
}

export function modelSummary(graph: ModelGraph): ModelSummary {
  const meta = graph.meta;
  const out: ModelSummary = {
    title: meta.title,
    business_criticality: meta.business_criticality,
  };
  if (meta.description) out.description = meta.description;
  if (meta.owner) out.owner = meta.owner;
  if (meta.author) out.author = meta.author;
  if (meta.date) out.date = meta.date;
  if (meta.version !== undefined) out.version = String(meta.version);
  return out;
}

/** Counts sorted by the enum's own order, not alphabetically, so tables read right. */
function severityCounts(risks: readonly Risk[]): Record<string, number> {
  const out: Record<string, number> = {};
  for (const level of [...SEVERITY].reverse()) out[level] = 0;
  for (const r of risks) out[r.severity] = (out[r.severity] ?? 0) + 1;
  return out;
}

function tally<T extends string>(values: Iterable<T>): Record<string, number> {
  const out: Record<string, number> = {};
  for (const v of values) out[v] = (out[v] ?? 0) + 1;
  return Object.fromEntries(Object.entries(out).sort(([a], [b]) => a.localeCompare(b)));
}

function riskEntry(risk: Risk): Record<string, unknown> {
  const out: Record<string, unknown> = {
    id: risk.id,
    rule: risk.rule,
    title: risk.title,
    severity: risk.severity,
    likelihood: risk.likelihood,
    impact: risk.impact,
    confidence: risk.confidence,
    status: risk.status,
    stride: risk.stride,
    function: risk.function,
    subject: { kind: risk.subject.kind, id: risk.subject.id, name: risk.subject.name },
    data_breach_probability: risk.data_breach_probability,
    data_breach_elements: [...risk.data_breach_elements].sort(),
    detection_logic: risk.detection_logic,
    false_positives: risk.false_positives,
    mitigation: risk.mitigation,
    tags: [...risk.tags].sort(),
  };
  if (risk.description) out['description'] = risk.description;
  if (risk.linddun) out['linddun'] = risk.linddun;
  if (risk.cwe !== undefined) out['cwe'] = risk.cwe;
  if (risk.capec.length > 0) out['capec'] = [...risk.capec].sort();
  if (risk.asvs) out['asvs'] = risk.asvs;
  if (risk.cheat_sheet) out['cheat_sheet'] = risk.cheat_sheet;
  if (risk.action) out['action'] = risk.action;
  if (risk.check) out['check'] = risk.check;
  if (risk.unknowns.length > 0) out['unknowns'] = [...risk.unknowns].sort();
  if (risk.most_relevant_element) out['most_relevant_element'] = risk.most_relevant_element;
  if (risk.most_relevant_flow) out['most_relevant_flow'] = risk.most_relevant_flow;
  if (risk.most_relevant_data) out['most_relevant_data'] = [...risk.most_relevant_data].sort();
  if (risk.suppressed_by) out['suppressed_by'] = risk.suppressed_by;
  if (risk.tracking) {
    const t: Record<string, unknown> = { key: risk.tracking.key, status: risk.tracking.status };
    if (risk.tracking.justification) t['justification'] = risk.tracking.justification;
    if (risk.tracking.ticket) t['ticket'] = risk.tracking.ticket;
    if (risk.tracking.date) t['date'] = risk.tracking.date;
    if (risk.tracking.checked_by) t['checked_by'] = risk.tracking.checked_by;
    out['tracking'] = t;
  }
  return out;
}

export interface RisksDocument {
  schema: string;
  generated_at: string;
  model: ModelSummary;
  stats: Record<string, unknown>;
  risks: Record<string, unknown>[];
  warnings: { code: string; message: string; rule?: string; hint?: string }[];
}

/** The full risk register: every risk, including suppressed and resolved ones. */
export function risksJson(
  analysis: Analysis,
  graph: ModelGraph,
  options: JsonOptions = {},
): RisksDocument {
  const risks = [...analysis.risks].sort(compareRisks);
  return {
    schema: RISKS_SCHEMA,
    generated_at: stamp(options),
    model: modelSummary(graph),
    stats: statsBlock(analysis, graph),
    risks: risks.map(riskEntry),
    warnings: [...analysis.warnings]
      .map((w) => {
        const out: { code: string; message: string; rule?: string; hint?: string } = {
          code: w.code,
          message: w.message,
        };
        if (w.rule) out.rule = w.rule;
        if (w.hint) out.hint = w.hint;
        return out;
      })
      .sort((a, b) => a.code.localeCompare(b.code) || a.message.localeCompare(b.message)),
  };
}

function statsBlock(analysis: Analysis, graph: ModelGraph): Record<string, unknown> {
  const open = analysis.risks.filter(isOpenRisk);
  return {
    rules_run: analysis.stats.rulesRun,
    rules_skipped: analysis.stats.rulesSkipped,
    candidates_evaluated: analysis.stats.candidatesEvaluated,
    elements: graph.elements.length,
    elements_in_scope: graph.inScope.length,
    elements_out_of_scope: graph.elements.length - graph.inScope.length,
    internet_facing: graph.elements.filter((e) => e.internet_facing).length,
    flows: graph.flows.length,
    trust_boundaries: graph.boundaries.length,
    shared_runtimes: graph.shared_runtimes.length,
    data_assets: graph.data.length,
    orphaned_data_assets: graph.data.filter((d) => d.orphaned).length,
    risks: analysis.risks.length,
    open_risks: analysis.stats.openRisks,
    low_confidence_risks: analysis.stats.lowConfidenceRisks,
    suppressed_risks: analysis.risks.filter((r) => Boolean(r.suppressed_by)).length,
    risks_by_severity: severityCounts(analysis.risks),
    open_risks_by_severity: severityCounts(open),
    risks_by_status: tally(analysis.risks.map((r) => r.status)),
    risks_by_stride: tally(analysis.risks.map((r) => r.stride)),
    risks_by_function: tally(analysis.risks.map((r) => r.function)),
    risks_by_rule: tally(analysis.risks.map((r) => r.rule)),
    warnings: analysis.warnings.length,
  };
}

/**
 * A risk is open when nobody has decided about it yet. Mirrors `isOpen` in the rules
 * package; duplicated rather than imported so the reporters have no opinion baked in
 * that the engine could later change under them.
 */
export function isOpenRisk(risk: Risk): boolean {
  if (risk.suppressed_by) return false;
  return (
    risk.status === 'unchecked' ||
    risk.status === 'in-discussion' ||
    risk.status === 'in-progress'
  );
}

export interface StatsDocument {
  schema: string;
  generated_at: string;
  model: ModelSummary;
  stats: Record<string, unknown>;
}

/** Just the counts, for a CI job that wants a trend line without parsing the risks. */
export function statsJson(
  analysis: Analysis,
  graph: ModelGraph,
  options: JsonOptions = {},
): StatsDocument {
  return {
    schema: STATS_SCHEMA,
    generated_at: stamp(options),
    model: modelSummary(graph),
    stats: statsBlock(analysis, graph),
  };
}

function assetEntry(el: ElementNode): Record<string, unknown> {
  const out: Record<string, unknown> = {
    id: el.id,
    name: el.name,
    kind: el.kind,
    technology: el.technology.id,
    size: el.size,
    usage: el.usage,
    raa: el.raa,
    confidentiality: el.confidentiality,
    integrity: el.integrity,
    availability: el.availability,
    internet_facing: el.internet_facing,
    internet_reachable: el.internet_reachable,
    human: el.human,
    custom_code: el.custom_code,
    multi_tenant: el.multi_tenant,
    out_of_scope: el.out_of_scope,
    encryption: el.encryption,
    processes: el.processes.map((d) => d.id).sort(),
    stores: el.stores.map((d) => d.id).sort(),
    incoming: el.incoming.map((f) => f.id).sort(),
    outgoing: el.outgoing.map((f) => f.id).sort(),
    boundaries: el.boundaries.map((b) => b.id),
    shared_runtimes: el.shared_runtimes.map((r) => r.id).sort(),
    tags: [...el.tags].sort(),
  };
  if (el.description) out['description'] = el.description;
  if (el.machine) out['machine'] = el.machine;
  if (el.owner) out['owner'] = el.owner;
  // Controls are tri-state; only the keys the author actually recorded are emitted,
  // because "absent" is a distinct answer from "false" everywhere else in tmc.
  const controls = Object.entries(el.controls)
    .filter(([, v]) => v !== undefined)
    .sort(([a], [b]) => a.localeCompare(b));
  if (controls.length > 0) out['controls'] = Object.fromEntries(controls);
  return out;
}

export interface TechnicalAssetsDocument {
  schema: string;
  generated_at: string;
  model: ModelSummary;
  assets: Record<string, unknown>[];
  data_assets: Record<string, unknown>[];
}

/** The element and data-asset inventory, sorted by id. */
export function technicalAssetsJson(
  graph: ModelGraph,
  options: JsonOptions = {},
): TechnicalAssetsDocument {
  return {
    schema: ASSETS_SCHEMA,
    generated_at: stamp(options),
    model: modelSummary(graph),
    assets: [...graph.elements].sort((a, b) => a.id.localeCompare(b.id)).map(assetEntry),
    data_assets: [...graph.data]
      .sort((a, b) => a.id.localeCompare(b.id))
      .map((d) => {
        const out: Record<string, unknown> = {
          id: d.id,
          classification: d.classification,
          integrity: d.integrity,
          availability: d.availability,
          quantity: d.quantity,
          usage: d.usage,
          pii: d.pii,
          credentials: d.credentials,
          orphaned: d.orphaned,
          regulations: [...d.regulations].sort(),
          processed_by: d.processed_by.map((e) => e.id).sort(),
          stored_by: d.stored_by.map((e) => e.id).sort(),
          sent_via: d.sent_via.map((f) => f.id).sort(),
          received_via: d.received_via.map((f) => f.id).sort(),
          tags: [...d.tags].sort(),
        };
        if (d.description) out['description'] = d.description;
        if (d.owner) out['owner'] = d.owner;
        if (d.origin) out['origin'] = d.origin;
        if (d.justification) out['justification'] = d.justification;
        return out;
      }),
  };
}
