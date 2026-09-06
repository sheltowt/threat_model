import type { ModelGraph } from 'tmac-core/browser';
import { compareSeverity, severityRank } from './severity.js';
import { isOpen, type Risk } from './risk.js';
import type { Analysis } from './engine.js';

/**
 * The model gaps, ranked by what answering each one would settle.
 *
 * Every unsettled finding already names the field the rule could not read. That is
 * the honest answer to "why is this uncertain", but as a per-finding note it scales
 * badly: a young model produces dozens of them and the reader sees a wall rather
 * than a worklist.
 *
 * Turning it around, one entry per unrecorded field with the findings it is holding
 * up, gives the same information as a queue with an obvious first item. The data was
 * already computed and thrown away.
 *
 * Ranking is by worst severity then by count, which is a heuristic and not a
 * guarantee: a finding can wait on several fields, so answering the top question
 * moves every finding under it forward without necessarily resolving any of them.
 */

export interface Question {
  /** The unrecorded field, as a rule would write it: `api.controls.hardened`. */
  field: string;
  /** The element or flow the field belongs to, when it belongs to one. */
  subject?: string;
  /** The bare control name, for a reader who wants to go and record it. */
  control?: string;
  /**
   * Findings waiting on this field. A finding can wait on several fields at once,
   * so answering this one removes this gap from it rather than necessarily settling
   * it outright. Counting them is still the right way to rank the questions.
   */
  blocking: Risk[];
  /** The worst severity among them, which is what makes one question urgent. */
  worstSeverity: Risk['severity'];
  /** Rules waiting on this field, so the reader can see why it is asked. */
  rules: string[];
}

export interface QuestionsOptions {
  /** Include gaps behind findings that are resolved or suppressed. Default false. */
  includeSettled?: boolean;
}

/**
 * A field reads as `element.controls.hardened` or `flow.from.controls.x` inside a
 * rule, which is precise but written from the rule's point of view. The reader wants
 * to know which asset to go and edit, so resolve it against the finding's subject.
 */
function attribute(risk: Risk, field: string, graph: ModelGraph): {
  subject?: string;
  control?: string;
} {
  const control = /\.controls\.([a-z_]+)$/.exec(field)?.[1];
  const out: { subject?: string; control?: string } = {};
  if (control) out.control = control;

  const flow = risk.most_relevant_flow ? graph.flowById.get(risk.most_relevant_flow) : undefined;

  // `flow.from.x` and `flow.to.x` name the endpoints; anything else is the subject.
  if (field.startsWith('flow.from.') && flow) out.subject = flow.from.id;
  else if (field.startsWith('flow.to.') && flow) out.subject = flow.to.id;
  else if (field.startsWith('flow.') && flow) out.subject = flow.id;
  else if (risk.subject.kind !== 'model') out.subject = risk.subject.id;

  return out;
}

/**
 * One entry per unrecorded field, worst first, then by how many findings it holds
 * up. Answering the top entry settles the most serious uncertainty for the least
 * work, which is the whole point of the ordering.
 */
export function questions(
  analysis: Analysis,
  graph: ModelGraph,
  options: QuestionsOptions = {},
): Question[] {
  const byKey = new Map<string, Question>();

  for (const risk of analysis.risks) {
    if (risk.confidence !== 'low') continue;
    if (!options.includeSettled && !isOpen(risk)) continue;

    for (const field of risk.unknowns) {
      const { subject, control } = attribute(risk, field, graph);
      // Key on the asset and the control, not on the rule's spelling of the field:
      // two rules asking about the same control on the same asset are one question.
      const key = `${subject ?? 'model'}::${control ?? field}`;

      let entry = byKey.get(key);
      if (!entry) {
        entry = {
          field: subject && control ? `${subject}.controls.${control}` : field,
          blocking: [],
          worstSeverity: 'low',
          rules: [],
        };
        if (subject) entry.subject = subject;
        if (control) entry.control = control;
        byKey.set(key, entry);
      }
      entry.blocking.push(risk);
      if (severityRank(risk.severity) > severityRank(entry.worstSeverity)) {
        entry.worstSeverity = risk.severity;
      }
      if (!entry.rules.includes(risk.rule)) entry.rules.push(risk.rule);
    }
  }

  const all = [...byKey.values()];
  for (const q of all) q.rules.sort();
  return all.sort(
    (a, b) =>
      compareSeverity(a.worstSeverity, b.worstSeverity) ||
      b.blocking.length - a.blocking.length ||
      a.field.localeCompare(b.field),
  );
}

export interface QuestionStats {
  /** Distinct fields nobody has recorded. */
  open: number;
  /** Findings waiting on at least one of them. */
  unsettledFindings: number;
  /** Findings waiting on the top question, some of which also wait on others. */
  topQuestionUnblocks: number;
}

export function questionStats(list: readonly Question[]): QuestionStats {
  const findings = new Set<string>();
  for (const q of list) for (const r of q.blocking) findings.add(r.id);
  return {
    open: list.length,
    unsettledFindings: findings.size,
    topQuestionUnblocks: list[0]?.blocking.length ?? 0,
  };
}
