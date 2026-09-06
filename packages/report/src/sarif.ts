/**
 * SARIF 2.1.0 output, aimed squarely at GitHub code scanning.
 *
 * Two decisions are worth stating. First, suppressed and resolved risks are emitted
 * with a `suppressions` entry rather than dropped: GitHub then shows them as
 * dismissed with the justification attached, which is auditable, whereas dropping
 * them makes a risk that someone consciously accepted indistinguishable from one the
 * rules stopped finding. Second, `security-severity` is a number, because that is the
 * property GitHub's severity filter and sort actually read; the string severity in
 * `tags` is for humans reading the raw file.
 */

import { readFileSync } from 'node:fs';
import { isResolved, SEVERITY, type ModelGraph, type Severity } from '@tmc/core';
import type { Analysis, Risk } from '@tmc/rules';
import { compareRisks } from './json.js';

export interface SarifOptions {
  /** Path recorded in `artifactLocation.uri`. Relative to the repo root reads best. */
  modelPath?: string;
  /** Model source text. When omitted it is read from `modelPath`, if that resolves. */
  modelText?: string;
  /** Rule definitions, for richer `reportingDescriptor`s than a risk alone carries. */
  rules?: readonly RuleMeta[];
  toolVersion?: string;
  informationUri?: string;
}

/** The subset of a `LoadedRule` this reporter uses; structural so any shape fits. */
export interface RuleMeta {
  id: string;
  title?: string;
  description?: string;
  detection_logic?: string;
  mitigation?: string;
  false_positives?: string;
  cwe?: number;
  stride?: string;
  function?: string;
  tags?: readonly string[];
  cheat_sheet?: string;
  asvs?: string;
}

export const SARIF_SCHEMA =
  'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json';

const INFORMATION_URI = 'https://github.com/tmc-dev/tmc';

export type SarifLevel = 'error' | 'warning' | 'note' | 'none';

/**
 * SARIF has three usable levels and tmc has five severities, so the mapping is lossy
 * by construction. `security-severity` carries the full resolution; `level` decides
 * whether a pull request check goes red.
 */
export function sarifLevel(severity: Severity | string): SarifLevel {
  switch (severity) {
    case 'critical':
    case 'high':
      return 'error';
    case 'elevated':
      return 'warning';
    case 'medium':
    case 'low':
      return 'note';
    default:
      return 'note';
  }
}

/** GitHub sorts and filters on this number, so it is the load-bearing severity. */
export function securitySeverity(severity: Severity | string): number {
  switch (severity) {
    case 'critical':
      return 9.5;
    case 'high':
      return 8.0;
    case 'elevated':
      return 6.0;
    case 'medium':
      return 4.0;
    case 'low':
      return 2.0;
    default:
      return 0.0;
  }
}

function worstOf(risks: readonly Risk[]): Severity {
  let best: Severity = 'low';
  for (const r of risks) {
    if (SEVERITY.indexOf(r.severity) > SEVERITY.indexOf(best)) best = r.severity;
  }
  return best;
}

/**
 * Find the line a model id is declared on.
 *
 * Deliberately textual rather than a YAML CST walk: the id may live in an included
 * file, the model may have been assembled in memory, and a wrong line number is worse
 * than none. Two shapes are recognised — a mapping key (`  payment_api:`) for
 * elements, data assets and boundaries, and an `id:` scalar for flows. Anything else
 * returns undefined and the result gets no `region`, which SARIF allows.
 */
export function findModelLine(text: string, id: string): number | undefined {
  const quoted = id.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const key = new RegExp(`^\\s*(?:["']?)${quoted}(?:["']?)\\s*:`);
  const scalar = new RegExp(`^\\s*-?\\s*id\\s*:\\s*(?:["']?)${quoted}(?:["']?)\\s*(?:#.*)?$`);
  const lines = text.split(/\r\n|\r|\n/);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;
    if (key.test(line) || scalar.test(line)) return i + 1;
  }
  return undefined;
}

function loadModelText(options: SarifOptions): string | undefined {
  if (options.modelText !== undefined) return options.modelText;
  if (!options.modelPath) return undefined;
  try {
    return readFileSync(options.modelPath, 'utf8');
  } catch {
    // A path recorded for the report but absent on this machine is normal, for
    // instance when the SARIF is regenerated from a stored analysis.
    return undefined;
  }
}

/**
 * Which model id best identifies where this risk lives. The subject is the honest
 * answer; the most relevant element is a useful fallback for model-scoped rules.
 */
function anchorId(risk: Risk): string | undefined {
  if (risk.subject.kind !== 'model') return risk.subject.id;
  return risk.most_relevant_element ?? risk.most_relevant_flow;
}

function ruleTags(risk: Risk, meta: RuleMeta | undefined): string[] {
  const tags = new Set<string>(['security']);
  const stride = meta?.stride ?? risk.stride;
  if (stride) tags.add(`stride/${stride}`);
  const fn = meta?.function ?? risk.function;
  if (fn) tags.add(`function/${fn}`);
  const cwe = meta?.cwe ?? risk.cwe;
  if (cwe !== undefined) {
    tags.add(`CWE-${cwe}`);
    // GitHub's own taxonomy prefix; it renders these as linked CWE chips.
    tags.add(`external/cwe/cwe-${cwe}`);
  }
  for (const t of meta?.tags ?? risk.tags) tags.add(t);
  return [...tags].sort();
}

function descriptorFor(ruleId: string, risks: readonly Risk[], meta: RuleMeta | undefined) {
  const sample = risks[0]!;
  const worst = worstOf(risks);
  const shortText = meta?.title ?? (ruleId === 'manual' ? 'Manually recorded threat' : sample.title);
  const fullText =
    meta?.description ??
    sample.description ??
    meta?.detection_logic ??
    sample.detection_logic;

  const mitigation = (meta?.mitigation ?? sample.mitigation).trim();
  const falsePositives = (meta?.false_positives ?? sample.false_positives).trim();
  const cheatSheet = meta?.cheat_sheet ?? sample.cheat_sheet;

  const helpMarkdown = [
    `**Mitigation.** ${mitigation}`,
    sample.action ? `\n**Action.** ${sample.action.trim()}` : '',
    sample.check ? `\n**How to check.** ${sample.check.trim()}` : '',
    `\n**When this is a false positive.** ${falsePositives}`,
    cheatSheet ? `\n[OWASP cheat sheet](${cheatSheet})` : '',
  ]
    .filter(Boolean)
    .join('\n');

  const properties: Record<string, unknown> = {
    tags: ruleTags(sample, meta),
    'security-severity': securitySeverity(worst).toFixed(1),
    precision: risks.every((r) => r.confidence === 'low') ? 'medium' : 'high',
    'problem.severity': sarifLevel(worst) === 'error' ? 'error' : 'warning',
  };
  const cwe = meta?.cwe ?? sample.cwe;
  if (cwe !== undefined) properties['cwe'] = `CWE-${cwe}`;
  const asvs = meta?.asvs ?? sample.asvs;
  if (asvs) properties['asvs'] = asvs;

  const descriptor: Record<string, unknown> = {
    id: ruleId,
    name: ruleId,
    shortDescription: { text: oneLine(shortText) },
    fullDescription: { text: oneLine(fullText) },
    help: { text: `${mitigation}\n\nFalse positives: ${falsePositives}`, markdown: helpMarkdown },
    defaultConfiguration: { level: sarifLevel(worst) },
    properties,
  };
  if (cheatSheet) descriptor['helpUri'] = cheatSheet;
  return descriptor;
}

/** SARIF `text` fields are single-paragraph by convention; collapse the YAML folding. */
function oneLine(text: string | undefined): string {
  return (text ?? '').replace(/\s*\n\s*/g, ' ').trim();
}

function suppressionFor(risk: Risk): Record<string, unknown>[] | undefined {
  if (risk.suppressed_by) {
    return [
      {
        kind: 'external',
        status: 'accepted',
        justification: `Suppressed by assumption "${risk.suppressed_by}".`,
      },
    ];
  }
  if (isResolved(risk.status)) {
    const parts = [`Risk tracked as "${risk.status}".`];
    if (risk.tracking?.justification) parts.push(risk.tracking.justification.trim());
    if (risk.tracking?.ticket) parts.push(`Ticket: ${risk.tracking.ticket}.`);
    if (risk.tracking?.checked_by) parts.push(`Checked by ${risk.tracking.checked_by}.`);
    return [{ kind: 'external', status: 'accepted', justification: oneLine(parts.join(' ')) }];
  }
  return undefined;
}

function messageFor(risk: Risk): string {
  const parts = [oneLine(risk.title)];
  if (risk.confidence === 'low' && risk.unknowns.length > 0) {
    parts.push(
      `Reported at low confidence because the model does not record ${[...risk.unknowns]
        .sort()
        .join(', ')}.`,
    );
  }
  parts.push(oneLine(risk.mitigation));
  return parts.join(' ');
}

export interface SarifLog {
  $schema: string;
  version: '2.1.0';
  runs: Record<string, unknown>[];
}

export function toSarif(
  analysis: Analysis,
  graph: ModelGraph,
  options: SarifOptions = {},
): SarifLog {
  const uri = options.modelPath ?? 'threatmodel.yaml';
  const text = loadModelText(options);
  const metaById = new Map<string, RuleMeta>((options.rules ?? []).map((r) => [r.id, r]));

  const risks = [...analysis.risks].sort(compareRisks);

  // Rules appear in the driver in id order, and only if they actually fired: a
  // reportingDescriptor for a rule with no results is noise in the GitHub UI.
  const byRule = new Map<string, Risk[]>();
  for (const risk of risks) {
    const bucket = byRule.get(risk.rule);
    if (bucket) bucket.push(risk);
    else byRule.set(risk.rule, [risk]);
  }
  const ruleIds = [...byRule.keys()].sort();
  const rules = ruleIds.map((id) => descriptorFor(id, byRule.get(id)!, metaById.get(id)));
  const ruleIndex = new Map(ruleIds.map((id, i) => [id, i]));

  const results = risks.map((risk) => {
    const region = (() => {
      const id = anchorId(risk);
      if (!text || !id) return undefined;
      const line = findModelLine(text, id);
      return line === undefined ? undefined : { startLine: line };
    })();

    const physicalLocation: Record<string, unknown> = { artifactLocation: { uri } };
    if (region) physicalLocation['region'] = region;

    const result: Record<string, unknown> = {
      ruleId: risk.rule,
      ruleIndex: ruleIndex.get(risk.rule) ?? 0,
      level: sarifLevel(risk.severity),
      message: { text: messageFor(risk) },
      locations: [
        {
          physicalLocation,
          logicalLocations: [
            {
              name: risk.subject.name,
              fullyQualifiedName: `${risk.subject.kind}/${risk.subject.id}`,
              kind: risk.subject.kind,
            },
          ],
        },
      ],
      // The synthetic id is stable across regeneration and re-layout, which is
      // exactly what a fingerprint has to be for GitHub to track one alert over time.
      partialFingerprints: { tmcRiskId: risk.id },
      properties: {
        'security-severity': securitySeverity(risk.severity).toFixed(1),
        severity: risk.severity,
        likelihood: risk.likelihood,
        impact: risk.impact,
        confidence: risk.confidence,
        status: risk.status,
        stride: risk.stride,
        function: risk.function,
        subject: `${risk.subject.kind}/${risk.subject.id}`,
        tmcRiskId: risk.id,
        ...(risk.unknowns.length > 0 ? { unknowns: [...risk.unknowns].sort() } : {}),
        ...(risk.suppressed_by ? { suppressedBy: risk.suppressed_by } : {}),
      },
    };
    const suppressions = suppressionFor(risk);
    if (suppressions) result['suppressions'] = suppressions;
    return result;
  });

  return {
    $schema: SARIF_SCHEMA,
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'tmc',
            informationUri: options.informationUri ?? INFORMATION_URI,
            ...(options.toolVersion ? { version: options.toolVersion } : {}),
            rules,
          },
        },
        results,
        properties: {
          model: graph.meta.title,
          businessCriticality: graph.meta.business_criticality,
          openRisks: analysis.stats.openRisks,
          lowConfidenceRisks: analysis.stats.lowConfidenceRisks,
        },
      },
    ],
  };
}
