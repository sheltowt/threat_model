import {
  IMPACT,
  LIKELIHOOD,
  isResolved,
  matchesTrackingKey,
  resolveTrackingKey,
  syntheticId,
  type BoundaryNode,
  type DataAssetNode,
  type ElementNode,
  type FlowNode,
  type Impact,
  type Likelihood,
  type ModelGraph,
  type RiskStatus,
} from 'tmac-core/browser';
import {
  evaluate,
  parseExpression,
  triState,
  isUnknown,
  type Value,
} from './expr/index.js';
import { interpolationParts, type LoadedRule } from './builtin.js';
import { calculateSeverity, compareSeverity } from './severity.js';
import type { Risk, RiskSubject } from './risk.js';

export interface AnalyzeOptions {
  /** Rule ids to skip beyond those the model disables. */
  exclude?: readonly string[];
  /** Fail rather than warn when a tracking key matches nothing. */
  strictTracking?: boolean;
}

export interface AnalysisWarning {
  code: string;
  message: string;
  rule?: string;
  hint?: string;
}

export interface Analysis {
  risks: Risk[];
  warnings: AnalysisWarning[];
  stats: {
    rulesRun: number;
    rulesSkipped: number;
    candidatesEvaluated: number;
    risksBySeverity: Record<string, number>;
    risksByStatus: Record<string, number>;
    openRisks: number;
    lowConfidenceRisks: number;
  };
}

type Candidate =
  | { kind: 'element'; node: ElementNode }
  | { kind: 'flow'; node: FlowNode }
  | { kind: 'boundary'; node: BoundaryNode }
  | { kind: 'data'; node: DataAssetNode }
  | { kind: 'model'; node: undefined };

/**
 * The scope a rule expression sees.
 *
 * Only plain data goes in. There are no functions on these objects, so an
 * expression has nothing to call even if the evaluator let it, and the graph the
 * engine holds is never handed to a rule for mutation.
 */
function scopeFor(candidate: Candidate, graph: ModelGraph): Record<string, unknown> {
  const model = {
    title: graph.meta.title,
    business_criticality: graph.meta.business_criticality,
    elements: graph.inScope,
    all_elements: graph.elements,
    flows: graph.flows,
    boundaries: graph.boundaries,
    data: graph.data,
    shared_runtimes: graph.shared_runtimes,
    element_count: graph.elements.length,
    flow_count: graph.flows.length,
  };
  switch (candidate.kind) {
    case 'element':
      return { element: candidate.node, el: candidate.node, model };
    case 'flow':
      return { flow: candidate.node, model };
    case 'boundary':
      return { boundary: candidate.node, model };
    case 'data':
      return { data: candidate.node, model };
    case 'model':
      return { model };
  }
}

function candidatesFor(scope: LoadedRule['scope'], graph: ModelGraph): Candidate[] {
  switch (scope) {
    case 'element':
      // Out-of-scope elements are excluded here, once, rather than in every rule.
      return graph.inScope.map((node) => ({ kind: 'element' as const, node }));
    case 'flow':
      return graph.flows
        .filter((f) => !f.from.out_of_scope || !f.to.out_of_scope)
        .map((node) => ({ kind: 'flow' as const, node }));
    case 'boundary':
      return graph.boundaries.map((node) => ({ kind: 'boundary' as const, node }));
    case 'data':
      return graph.data.map((node) => ({ kind: 'data' as const, node }));
    case 'model':
      return [{ kind: 'model', node: undefined }];
  }
}

function subjectOf(candidate: Candidate, graph: ModelGraph): RiskSubject {
  switch (candidate.kind) {
    case 'element':
      return { kind: 'element', id: candidate.node.id, name: candidate.node.name };
    case 'flow':
      return { kind: 'flow', id: candidate.node.id, name: candidate.node.name };
    case 'boundary':
      return { kind: 'boundary', id: candidate.node.id, name: candidate.node.name };
    case 'data':
      return { kind: 'data', id: candidate.node.id, name: candidate.node.id };
    case 'model':
      return { kind: 'model', id: 'model', name: graph.meta.title };
  }
}

function asString(value: Value): string {
  if (isUnknown(value)) return '';
  if (value === null) return '';
  if (Array.isArray(value)) return value.map((v) => asString(v as Value)).join(', ');
  if (typeof value === 'object') return '';
  return String(value);
}

function renderTitle(
  rule: LoadedRule,
  scope: Record<string, unknown>,
  subject: RiskSubject,
): string {
  if (!rule.risk_title) return `${rule.title} at ${subject.name}`;
  let out = '';
  for (const part of interpolationParts(rule.risk_title)) {
    out += part.expression ? asString(evaluate(parseExpression(part.text), scope)) : part.text;
  }
  return out.trim() || rule.title;
}

/**
 * Resolve a likelihood or impact field, which may be a literal enum member or an
 * expression producing one. An expression that cannot decide falls back to the
 * neutral middle rather than silently dropping the finding.
 */
function resolveRating<T extends string>(
  field: string,
  allowed: readonly T[],
  fallback: T,
  scope: Record<string, unknown>,
  rule: LoadedRule,
  warnings: AnalysisWarning[],
): T {
  if ((allowed as readonly string[]).includes(field)) return field as T;
  const value = evaluate(parseExpression(field), scope);
  const text = asString(value);
  if ((allowed as readonly string[]).includes(text)) return text as T;
  if (!isUnknown(value)) {
    warnings.push({
      code: 'rating',
      rule: rule.id,
      message: `rule "${rule.id}" produced "${text || 'nothing'}" where one of ${allowed.join(', ')} was expected`,
      hint: `falling back to "${fallback}"`,
    });
  }
  return fallback;
}

function dataBreachElements(candidate: Candidate): string[] {
  switch (candidate.kind) {
    case 'element':
      return [candidate.node.id];
    case 'flow':
      return [...new Set([candidate.node.from.id, candidate.node.to.id])];
    case 'boundary':
      return candidate.node.all_members.map((e) => e.id);
    case 'data':
      return [
        ...new Set([
          ...candidate.node.stored_by.map((e) => e.id),
          ...candidate.node.processed_by.map((e) => e.id),
        ]),
      ];
    case 'model':
      return [];
  }
}

function relevantData(candidate: Candidate): string[] {
  switch (candidate.kind) {
    case 'element':
      return candidate.node.handles.map((d) => d.id);
    case 'flow':
      return candidate.node.carries.map((d) => d.id);
    case 'data':
      return [candidate.node.id];
    default:
      return [];
  }
}

/** Run every enabled rule over the graph and return the risks, worst first. */
export function analyze(
  graph: ModelGraph,
  rules: readonly LoadedRule[],
  options: AnalyzeOptions = {},
): Analysis {
  const warnings: AnalysisWarning[] = [];
  const risks: Risk[] = [];
  const excluded = new Set(options.exclude ?? []);
  let rulesRun = 0;
  let rulesSkipped = 0;
  let candidatesEvaluated = 0;

  for (const rule of rules) {
    if (!rule.enabled || excluded.has(rule.id) || rule.id in graph.disabled_rules) {
      rulesSkipped++;
      continue;
    }
    rulesRun++;

    const matchAst = parseExpression(rule.match);

    for (const candidate of candidatesFor(rule.scope, graph)) {
      candidatesEvaluated++;
      const scope = scopeFor(candidate, graph);
      const unknowns = new Set<string>();

      let state: ReturnType<typeof triState>;
      try {
        state = triState(evaluate(matchAst, scope, { unknowns }));
      } catch (err) {
        warnings.push({
          code: 'rule-error',
          rule: rule.id,
          message: `rule "${rule.id}" failed on ${candidate.kind} "${
            subjectOf(candidate, graph).id
          }": ${(err as Error).message}`,
          hint: `defined in ${rule.source}`,
        });
        continue;
      }
      if (state === 'false') continue;

      const subject = subjectOf(candidate, graph);
      const likelihood = resolveRating<Likelihood>(
        rule.likelihood,
        LIKELIHOOD,
        'likely',
        scope,
        rule,
        warnings,
      );
      const impact = resolveRating<Impact>(rule.impact, IMPACT, 'medium', scope, rule, warnings);

      const suffix = rule.id_suffix
        .map((expr) => asString(evaluate(parseExpression(expr), scope)))
        .filter((s) => s.length > 0);
      const id = syntheticId({ rule: rule.id, subject: subject.id, secondary: suffix });

      const risk: Risk = {
        id,
        rule: rule.id,
        title: renderTitle(rule, scope, subject),
        severity: calculateSeverity(likelihood, impact),
        likelihood,
        impact,
        // An unsettled condition is reported, but never as a confirmed problem.
        confidence: state === 'unknown' ? 'low' : 'high',
        unknowns: state === 'unknown' ? [...unknowns].sort() : [],
        stride: rule.stride,
        capec: rule.capec,
        function: rule.function,
        subject,
        data_breach_probability: rule.data_breach_probability,
        data_breach_elements: dataBreachElements(candidate),
        detection_logic: rule.detection_logic,
        false_positives: rule.false_positives,
        mitigation: rule.mitigation,
        status: 'unchecked',
        tags: rule.tags,
      };
      if (rule.linddun) risk.linddun = rule.linddun;
      if (rule.cwe !== undefined) risk.cwe = rule.cwe;
      if (rule.asvs) risk.asvs = rule.asvs;
      if (rule.cheat_sheet) risk.cheat_sheet = rule.cheat_sheet;
      if (rule.action) risk.action = rule.action;
      if (rule.check) risk.check = rule.check;
      if (rule.description) risk.description = rule.description;

      const relevant = relevantData(candidate);
      if (relevant.length > 0) risk.most_relevant_data = relevant;
      if (candidate.kind === 'flow') {
        risk.most_relevant_flow = candidate.node.id;
        risk.most_relevant_element = candidate.node.to.id;
      } else if (candidate.kind === 'element') {
        risk.most_relevant_element = candidate.node.id;
      }

      risks.push(risk);
    }
  }

  // Manual threats join the same list so one report covers both.
  for (const threat of graph.manual_threats) {
    const subjectId = threat.element ?? threat.flow ?? 'model';
    const node = threat.element
      ? graph.elementById.get(threat.element)
      : threat.flow
        ? graph.flowById.get(threat.flow)
        : undefined;
    const risk: Risk = {
      id: syntheticId({ rule: `manual`, subject: threat.id }),
      rule: 'manual',
      title: threat.title,
      severity: threat.severity,
      likelihood: 'likely',
      impact: 'medium',
      confidence: 'high',
      unknowns: [],
      stride: threat.stride ?? 'tampering',
      capec: [],
      function: 'architecture',
      subject: {
        kind: threat.element ? 'element' : threat.flow ? 'flow' : 'model',
        id: subjectId,
        name: node?.name ?? subjectId,
      },
      data_breach_probability: 'improbable',
      data_breach_elements: threat.element ? [threat.element] : [],
      detection_logic: 'Recorded by hand in the model file.',
      false_positives: 'Reviewed by a person, so judge it on its own terms.',
      mitigation: threat.mitigation ?? 'No mitigation recorded.',
      status: 'unchecked',
      tags: threat.tags,
    };
    if (threat.linddun) risk.linddun = threat.linddun;
    if (threat.cwe !== undefined) risk.cwe = threat.cwe;
    if (threat.description) risk.description = threat.description;
    risks.push(risk);
  }

  applyTracking(risks, graph, warnings, options);
  applySuppressions(risks, graph, warnings);

  risks.sort(
    (a, b) => compareSeverity(a.severity, b.severity) || a.id.localeCompare(b.id),
  );

  const risksBySeverity: Record<string, number> = {};
  const risksByStatus: Record<string, number> = {};
  for (const r of risks) {
    risksBySeverity[r.severity] = (risksBySeverity[r.severity] ?? 0) + 1;
    risksByStatus[r.status] = (risksByStatus[r.status] ?? 0) + 1;
  }

  return {
    risks,
    warnings,
    stats: {
      rulesRun,
      rulesSkipped,
      candidatesEvaluated,
      risksBySeverity,
      risksByStatus,
      openRisks: risks.filter((r) => !isResolved(r.status) && !r.suppressed_by).length,
      lowConfidenceRisks: risks.filter((r) => r.confidence === 'low').length,
    },
  };
}

/**
 * Attach `risk_tracking` entries and report keys that match nothing.
 *
 * An orphaned key almost always means a risk was silently fixed or silently renamed,
 * and either way the accept-and-forget note attached to it is now lying. Threagile
 * fails the run on these by default and it is right to.
 */
function applyTracking(
  risks: Risk[],
  graph: ModelGraph,
  warnings: AnalysisWarning[],
  options: AnalyzeOptions,
): void {
  const keys = Object.keys(graph.risk_tracking);
  const used = new Set<string>();

  for (const risk of risks) {
    const key = resolveTrackingKey(risk.id, keys);
    if (!key) continue;
    used.add(key);
    const entry = graph.risk_tracking[key]!;
    risk.status = entry.status as RiskStatus;
    risk.tracking = { ...entry, key };
  }

  for (const key of keys) {
    if (used.has(key)) continue;
    warnings.push({
      code: options.strictTracking ? 'orphaned-tracking' : 'orphaned-tracking-warning',
      message: `risk_tracking key "${key}" does not match any risk in this model`,
      hint: 'the risk may have been fixed, or an id may have been renamed; remove the entry or correct it',
    });
  }
}

/** Apply assumption suppressions, keeping the risk visible but off the open list. */
function applySuppressions(
  risks: Risk[],
  graph: ModelGraph,
  warnings: AnalysisWarning[],
): void {
  for (const assumption of graph.assumptions) {
    for (const pattern of assumption.suppresses) {
      const hits = risks.filter((r) => matchesTrackingKey(pattern, r.id));
      if (hits.length === 0) {
        warnings.push({
          code: 'unused-suppression',
          message: `assumption "${assumption.id}" suppresses "${pattern}", which matches no risk`,
          hint: 'an assumption that hides nothing is either stale or misspelled',
        });
        continue;
      }
      for (const risk of hits) risk.suppressed_by = assumption.id;
    }
  }
}
