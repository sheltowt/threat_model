/**
 * Shared vocabulary for the human-readable reporters.
 *
 * The Markdown and HTML reports must agree about what counts as an open risk, which
 * risks are hidden by default and how a severity is ordered, or a team reading the
 * HTML and a team reading the Markdown end up arguing about two different numbers.
 * All of that lives here once.
 */

import { isResolved, SEVERITY, type ModelGraph, type Severity } from '@tmc/core';
import type { Analysis, Risk } from '@tmc/rules';
import { isOpenRisk } from './json.js';

export interface DiagramSet {
  dataFlow?: string;
  dataAssets?: string;
}

export interface ReportOptions {
  /** ISO timestamp, injectable so golden files stay deterministic. */
  generatedAt?: string;
  /** Include risks whose status is mitigated, accepted, transferred or a false positive. */
  showMitigated?: boolean;
  /** Include risks whose subject is entirely out of scope. */
  showOutOfScope?: boolean;
  /** Include risks an assumption suppresses, marked as suppressed. Default true. */
  showSuppressed?: boolean;
  /** Render sections with nothing in them, saying so, rather than omitting them. */
  showEmpty?: boolean;
  /** Default true; the diagram sections still need paths or inline SVG to show. */
  includeDiagrams?: boolean;
  /** Paths or URLs, used by the Markdown reporter's image links. */
  diagramPaths?: DiagramSet;
  /** SVG source, embedded inline by the HTML reporter. */
  diagrams?: DiagramSet;
  /** Path shown in the metadata block. */
  modelPath?: string;
}

export interface ResolvedOptions {
  generatedAt: string;
  showMitigated: boolean;
  showOutOfScope: boolean;
  showSuppressed: boolean;
  showEmpty: boolean;
  includeDiagrams: boolean;
  diagramPaths: DiagramSet;
  diagrams: DiagramSet;
  modelPath: string | undefined;
}

export function resolveOptions(options: ReportOptions = {}): ResolvedOptions {
  return {
    generatedAt: options.generatedAt ?? new Date().toISOString(),
    showMitigated: options.showMitigated ?? false,
    showOutOfScope: options.showOutOfScope ?? false,
    // Suppressed risks stay visible by default: an assumption that quietly hides a
    // finding is the failure mode this whole design exists to avoid.
    showSuppressed: options.showSuppressed ?? true,
    showEmpty: options.showEmpty ?? false,
    includeDiagrams: options.includeDiagrams ?? true,
    diagramPaths: options.diagramPaths ?? {},
    diagrams: options.diagrams ?? {},
    modelPath: options.modelPath,
  };
}

/** Worst first. */
export const SEVERITY_DESC: readonly Severity[] = [...SEVERITY].reverse();

export function severityRank(severity: string): number {
  return SEVERITY.indexOf(severity as Severity);
}

export { isOpenRisk };

export function isSuppressed(risk: Risk): boolean {
  return Boolean(risk.suppressed_by);
}

/** True when everything the risk points at sits outside the reviewed scope. */
export function isOutOfScope(risk: Risk, graph: ModelGraph): boolean {
  if (risk.subject.kind === 'element') {
    return graph.elementById.get(risk.subject.id)?.out_of_scope === true;
  }
  if (risk.subject.kind === 'flow') {
    const flow = graph.flowById.get(risk.subject.id);
    return flow ? flow.from.out_of_scope && flow.to.out_of_scope : false;
  }
  return false;
}

/** Apply the display filters, keeping the engine's worst-first ordering. */
export function visibleRisks(
  analysis: Analysis,
  graph: ModelGraph,
  options: ResolvedOptions,
): Risk[] {
  return analysis.risks.filter((risk) => {
    if (!options.showSuppressed && isSuppressed(risk)) return false;
    if (!options.showMitigated && isResolved(risk.status) && !isSuppressed(risk)) return false;
    if (!options.showOutOfScope && isOutOfScope(risk, graph)) return false;
    return true;
  });
}

export function groupBySeverity(risks: readonly Risk[]): Map<Severity, Risk[]> {
  const out = new Map<Severity, Risk[]>();
  for (const level of SEVERITY_DESC) out.set(level, []);
  for (const risk of risks) out.get(risk.severity)?.push(risk);
  return out;
}

/** The risks a reader should look at before anything else. */
export function attentionFirst(risks: readonly Risk[]): Risk[] {
  return risks.filter(
    (r) => isOpenRisk(r) && (r.severity === 'critical' || r.severity === 'high'),
  );
}

export interface SeverityRow {
  severity: Severity;
  total: number;
  open: number;
  resolved: number;
  suppressed: number;
  lowConfidence: number;
}

/**
 * The severity summary table, computed over *all* risks rather than the visible
 * subset. A summary that changed when a display flag flipped would be worthless as a
 * management number.
 */
export function severityRows(analysis: Analysis): SeverityRow[] {
  return SEVERITY_DESC.map((severity) => {
    const of = analysis.risks.filter((r) => r.severity === severity);
    return {
      severity,
      total: of.length,
      open: of.filter(isOpenRisk).length,
      resolved: of.filter((r) => isResolved(r.status) && !isSuppressed(r)).length,
      suppressed: of.filter(isSuppressed).length,
      lowConfidence: of.filter((r) => r.confidence === 'low').length,
    };
  });
}

export function totalRow(rows: readonly SeverityRow[]): Omit<SeverityRow, 'severity'> {
  return rows.reduce(
    (acc, r) => ({
      total: acc.total + r.total,
      open: acc.open + r.open,
      resolved: acc.resolved + r.resolved,
      suppressed: acc.suppressed + r.suppressed,
      lowConfidence: acc.lowConfidence + r.lowConfidence,
    }),
    { total: 0, open: 0, resolved: 0, suppressed: 0, lowConfidence: 0 },
  );
}

/** How a risk's disposition reads in a status column. */
export function statusLabel(risk: Risk): string {
  if (risk.suppressed_by) return `suppressed (${risk.suppressed_by})`;
  return risk.status;
}

export function subjectLabel(risk: Risk): string {
  return `${risk.subject.name} (${risk.subject.kind})`;
}

/** Collapse YAML folded scalars into one paragraph for a table cell. */
export function oneLine(text: string | undefined | null): string {
  return (text ?? '').replace(/\s*\n\s*/g, ' ').trim();
}

/** Trim trailing whitespace on a block of prose, keeping paragraph breaks. */
export function prose(text: string | undefined | null): string {
  return (text ?? '')
    .split(/\n{2,}/)
    .map((p) => p.replace(/\s*\n\s*/g, ' ').trim())
    .filter(Boolean)
    .join('\n\n');
}

/**
 * Every unrecorded control across the low-confidence risks, with how many findings
 * each one is holding up. This is the model-gap worklist: filling in the top entry
 * settles the most findings for the least effort.
 */
export function unknownFields(risks: readonly Risk[]): { field: string; count: number }[] {
  const counts = new Map<string, number>();
  for (const risk of risks) {
    if (risk.confidence !== 'low') continue;
    for (const field of risk.unknowns) counts.set(field, (counts.get(field) ?? 0) + 1);
  }
  return [...counts.entries()]
    .map(([field, count]) => ({ field, count }))
    .sort((a, b) => b.count - a.count || a.field.localeCompare(b.field));
}

export function cweLabel(risk: Risk): string {
  return risk.cwe === undefined ? '—' : `CWE-${risk.cwe}`;
}

export function cweUrl(cwe: number): string {
  return `https://cwe.mitre.org/data/definitions/${cwe}.html`;
}
