/**
 * The Markdown report: the artefact that gets committed, diffed and read in a pull
 * request.
 *
 * It is written to be read top to bottom by someone who was not in the modelling
 * session: what this is, how bad it is overall, what to do first, then the detail.
 * The low-confidence section is given its own place rather than being folded into the
 * risk tables, because those findings are a statement about the *model* — fields
 * nobody filled in — and treating them as ordinary findings is what makes pytm's
 * output noisy enough to ignore.
 */

import { isResolved, type ModelGraph, type Severity } from 'tmac-core/browser';
import type { Analysis, Risk } from 'tmac-rules/browser';
import {
  attentionFirst,
  cweLabel,
  groupBySeverity,
  isOpenRisk,
  oneLine,
  prose,
  resolveOptions,
  severityRows,
  statusLabel,
  subjectLabel,
  totalRow,
  unknownFields,
  visibleRisks,
  type ReportOptions,
} from './common.js';

/**
 * Pipes and newlines would break out of a table cell, so they are neutralised.
 *
 * Backslashes go first. Escaping only the pipe turns an input of `\|` into `\\|`,
 * which Markdown reads as a literal backslash followed by an unescaped pipe, and the
 * cell ends there. Escaping the escape character before what it escapes is the same
 * ordering `escapeLabel` gets right for Graphviz.
 */
function cell(text: unknown): string {
  const raw = oneLine(text === undefined || text === null ? '' : String(text));
  return raw.replace(/\\/g, '\\\\').replace(/\|/g, '\\|') || '—';
}

function table(headers: readonly string[], rows: readonly (readonly unknown[])[]): string {
  const out: string[] = [];
  out.push(`| ${headers.join(' | ')} |`);
  out.push(`| ${headers.map(() => '---').join(' | ')} |`);
  for (const row of rows) out.push(`| ${row.map(cell).join(' | ')} |`);
  return out.join('\n');
}

const SEVERITY_MARK: Record<Severity, string> = {
  critical: '🟥 critical',
  high: '🟧 high',
  elevated: '🟨 elevated',
  medium: '🟦 medium',
  low: '⬜ low',
};

function anchor(id: string): string {
  return id.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
}

export function toMarkdown(
  analysis: Analysis,
  graph: ModelGraph,
  options: ReportOptions = {},
): string {
  const opts = resolveOptions(options);
  const visible = visibleRisks(analysis, graph, opts);
  const out: string[] = [];
  const section = (heading: string) => {
    out.push('', heading, '');
  };

  // --- Title and metadata ---------------------------------------------------
  const meta = graph.meta;
  out.push(`# Threat model: ${meta.title}`);
  out.push('');
  if (meta.description) out.push(prose(meta.description), '');

  const metaRows: [string, unknown][] = [
    ['Business criticality', meta.business_criticality],
    ['Owner', meta.owner],
    ['Author', meta.author],
    ['Model date', meta.date],
    ['Model version', meta.version],
    ['Model file', opts.modelPath],
    ['Generated', opts.generatedAt],
    ['Rules run', `${analysis.stats.rulesRun} (${analysis.stats.rulesSkipped} skipped)`],
    [
      'Scope',
      `${graph.inScope.length} of ${graph.elements.length} elements, ${graph.flows.length} flows, ` +
        `${graph.boundaries.length} trust boundaries, ${graph.data.length} data assets`,
    ],
  ];
  out.push(table(['Field', 'Value'], metaRows.filter(([, v]) => v !== undefined && v !== '')));

  // --- Management summary ---------------------------------------------------
  const rows = severityRows(analysis);
  const totals = totalRow(rows);
  section('## Management summary');
  if (meta.management_summary) {
    out.push(prose(meta.management_summary), '');
  }
  const worst = rows.find((r) => r.open > 0);
  out.push(
    `The analysis found **${totals.total} risk${totals.total === 1 ? '' : 's'}** across ` +
      `${graph.elements.length} elements and ${graph.flows.length} flows, of which ` +
      `**${totals.open} remain open**` +
      (worst ? `, the worst at **${worst.severity}** severity` : '') +
      `. ${totals.resolved} have been dealt with and ${totals.suppressed} are suppressed by ` +
      `a recorded assumption.`,
  );
  if (totals.lowConfidence > 0) {
    out.push(
      '',
      `${totals.lowConfidence} of these are low-confidence findings, meaning the rule could ` +
        `not settle its condition because the model does not record the control it asks ` +
        `about. They are model gaps first and risks second — see ` +
        `[Low-confidence findings](#${anchor('Low-confidence findings')}).`,
    );
  }

  // --- Severity summary -----------------------------------------------------
  section('## Severity summary');
  out.push(
    table(
      ['Severity', 'Total', 'Open', 'Resolved', 'Suppressed', 'Low confidence'],
      [
        ...rows.map((r) => [
          SEVERITY_MARK[r.severity],
          r.total,
          r.open,
          r.resolved,
          r.suppressed,
          r.lowConfidence,
        ]),
        [
          '**Total**',
          totals.total,
          totals.open,
          totals.resolved,
          totals.suppressed,
          totals.lowConfidence,
        ],
      ],
    ),
  );

  // --- Attention first ------------------------------------------------------
  const urgent = attentionFirst(visible);
  section('## Attention first');
  if (urgent.length === 0) {
    out.push('No open critical or high risks. Work the rest of the register in severity order.');
  } else {
    out.push(
      `${urgent.length} open risk${urgent.length === 1 ? '' : 's'} at critical or high ` +
        `severity. Deal with these before anything else in this report.`,
      '',
    );
    for (const risk of urgent) {
      out.push(`### ${risk.title}`);
      out.push('');
      out.push(
        `\`${risk.id}\` · **${risk.severity}** · ${subjectLabel(risk)} · ` +
          `${risk.stride} · ${cweLabel(risk)} · confidence ${risk.confidence}`,
      );
      out.push('');
      if (risk.description) out.push(prose(risk.description), '');
      out.push(`**Do this.** ${oneLine(risk.action ?? risk.mitigation)}`);
      if (risk.check) out.push('', `**Confirm it worked.** ${oneLine(risk.check)}`);
      out.push('');
    }
  }

  // --- Diagrams -------------------------------------------------------------
  if (opts.includeDiagrams && (opts.diagramPaths.dataFlow || opts.diagramPaths.dataAssets)) {
    section('## Diagrams');
    if (opts.diagramPaths.dataFlow) {
      out.push('### Data flow diagram', '', `![Data flow diagram](${opts.diagramPaths.dataFlow})`, '');
    }
    if (opts.diagramPaths.dataAssets) {
      out.push('### Data assets', '', `![Data asset diagram](${opts.diagramPaths.dataAssets})`, '');
    }
  }

  // --- Risks by severity ----------------------------------------------------
  section('## Risks by severity');
  const grouped = groupBySeverity(visible);
  let anyGroup = false;
  for (const [severity, group] of grouped) {
    if (group.length === 0 && !opts.showEmpty) continue;
    anyGroup = true;
    out.push(`### ${SEVERITY_MARK[severity]} (${group.length})`, '');
    if (group.length === 0) {
      out.push('None.', '');
      continue;
    }
    out.push(
      table(
        ['ID', 'Title', 'Subject', 'STRIDE', 'CWE', 'Status', 'Confidence'],
        group.map((r) => [
          `\`${r.id}\``,
          r.title,
          subjectLabel(r),
          r.stride,
          cweLabel(r),
          statusLabel(r),
          r.confidence,
        ]),
      ),
      '',
    );
    for (const risk of group) {
      out.push(...riskDetail(risk));
    }
  }
  if (!anyGroup) out.push('No risks to show under the current display options.', '');

  // --- Low confidence -------------------------------------------------------
  const lowConfidence = visible.filter((r) => r.confidence === 'low');
  const gaps = unknownFields(analysis.risks);
  section('## Low-confidence findings');
  out.push(
    'A low-confidence finding is not a weaker risk. It is a rule that could not settle its',
    'condition because the model does not record the control it asks about, so tmac reports',
    'the possibility rather than inventing a `false`. Filling in the fields below either',
    'removes the finding or promotes it to a confirmed one; leaving them blank keeps the',
    'question open forever.',
    '',
  );
  if (gaps.length === 0) {
    out.push('Every control these rules asked about is recorded. Nothing to fill in.', '');
  } else {
    out.push('**Unrecorded fields, most consequential first.**', '');
    out.push(
      table(
        ['Field', 'Findings it would settle'],
        gaps.map((g) => [`\`${g.field}\``, g.count]),
      ),
      '',
    );
    if (lowConfidence.length > 0) {
      out.push('**The findings themselves.**', '');
      out.push(
        table(
          ['ID', 'Title', 'Severity', 'Unrecorded'],
          lowConfidence.map((r) => [
            `\`${r.id}\``,
            r.title,
            r.severity,
            r.unknowns.map((u) => `\`${u}\``).join(', '),
          ]),
        ),
        '',
      );
    }
  }

  // --- Risk tracking --------------------------------------------------------
  const tracked = analysis.risks.filter((r) => r.tracking || r.suppressed_by);
  const untracked = analysis.risks.filter(
    (r) => !r.tracking && !r.suppressed_by && !isResolved(r.status),
  );
  section('## Risk tracking');
  if (tracked.length === 0 && !opts.showEmpty) {
    out.push(
      `Nothing in this model has been triaged yet: all ${untracked.length} risks are ` +
        'unchecked. Record a decision in `risk_tracking` as each one is dealt with.',
      '',
    );
  } else {
    out.push(
      table(
        ['ID', 'Status', 'Justification', 'Ticket', 'Checked by', 'Date'],
        tracked.map((r) => [
          `\`${r.id}\``,
          statusLabel(r),
          r.tracking?.justification ?? (r.suppressed_by ? 'Suppressed by an assumption.' : ''),
          r.tracking?.ticket,
          r.tracking?.checked_by,
          r.tracking?.date,
        ]),
      ),
      '',
      `${untracked.length} risk${untracked.length === 1 ? ' has' : 's have'} no tracking entry.`,
      '',
    );
  }

  const orphaned = analysis.warnings.filter((w) => w.code.startsWith('orphaned-tracking'));
  if (orphaned.length > 0) {
    out.push(
      '**Stale tracking entries.** These keys match no risk in the current model, so the',
      'decision recorded against them no longer applies to anything.',
      '',
    );
    for (const w of orphaned) out.push(`- ${w.message}`);
    out.push('');
  }

  // --- Data asset matrix ----------------------------------------------------
  section('## Data asset matrix');
  if (graph.data.length === 0) {
    out.push('The model records no data assets.', '');
  } else {
    out.push(
      table(
        [
          'Asset',
          'Classification',
          'Integrity',
          'Availability',
          'Quantity',
          'Flags',
          'Processed by',
          'Stored by',
          'In transit',
        ],
        graph.data.map((d) => [
          `**${d.id}**`,
          d.classification,
          d.integrity,
          d.availability,
          d.quantity,
          [d.pii ? 'PII' : '', d.credentials ? 'credentials' : '', ...d.regulations]
            .filter(Boolean)
            .join(', '),
          d.processed_by.map((e) => e.name).join(', '),
          d.stored_by.map((e) => e.name).join(', '),
          [...new Set([...d.sent_via, ...d.received_via].map((f) => f.name))].join(', '),
        ]),
      ),
      '',
    );
    const orphans = graph.data.filter((d) => d.orphaned);
    if (orphans.length > 0) {
      out.push(
        `**Orphaned assets.** ${orphans.map((d) => `\`${d.id}\``).join(', ')} — declared but ` +
          'never processed, stored or carried. Either something is missing from the model or ' +
          'the asset is dead weight.',
        '',
      );
    }
  }

  // --- Assumptions ----------------------------------------------------------
  section('## Assumptions');
  if (graph.assumptions.length === 0) {
    out.push('No assumptions recorded.', '');
  } else {
    out.push(
      'Every finding below rests on these. If one turns out to be false, re-run the analysis.',
      '',
    );
    for (const a of graph.assumptions) {
      out.push(`- **${a.id}.** ${prose(a.text)}`);
      if (a.suppresses.length > 0) {
        out.push(
          `  Suppresses: ${a.suppresses.map((s) => `\`${s}\``).join(', ')}. Risks matching ` +
            'these patterns stay in the report, marked as suppressed.',
        );
      }
    }
    out.push('');
  }

  // --- Open questions -------------------------------------------------------
  const questions = Object.entries(meta.questions);
  const unanswered = questions.filter(([, a]) => !a);
  section('## Open questions');
  if (questions.length === 0) {
    out.push('No questions recorded.', '');
  } else {
    out.push(
      table(
        ['Question', 'Answer'],
        questions.map(([q, a]) => [q, a ?? '**Unanswered**']),
      ),
      '',
      `${unanswered.length} of ${questions.length} still unanswered.`,
      '',
    );
  }

  if (Object.keys(meta.abuse_cases).length > 0) {
    section('## Abuse cases');
    out.push(
      table(
        ['Case', 'Description'],
        Object.entries(meta.abuse_cases).map(([k, v]) => [k, v]),
      ),
      '',
    );
  }

  if (Object.keys(meta.security_requirements).length > 0) {
    section('## Security requirements');
    out.push(
      table(
        ['Requirement', 'Statement'],
        Object.entries(meta.security_requirements).map(([k, v]) => [k, v]),
      ),
      '',
    );
  }

  // --- Elements -------------------------------------------------------------
  section('## Elements');
  out.push(
    'RAA is Relative Attacker Attractiveness: where an attacker would spend a foothold if',
    'they had one. It is normalised across this model, so the numbers rank elements against',
    'each other and mean nothing against another model.',
    '',
  );
  const riskCount = new Map<string, number>();
  for (const risk of visible) {
    const ids = new Set<string>();
    if (risk.subject.kind === 'element') ids.add(risk.subject.id);
    if (risk.most_relevant_element) ids.add(risk.most_relevant_element);
    for (const id of ids) riskCount.set(id, (riskCount.get(id) ?? 0) + 1);
  }
  out.push(
    table(
      [
        'Element',
        'Kind',
        'Technology',
        'RAA',
        'Confidentiality',
        'Integrity',
        'Availability',
        'Trust boundary',
        'Internet',
        'Risks',
      ],
      [...graph.elements]
        .sort((a, b) => b.raa - a.raa || a.id.localeCompare(b.id))
        .map((el) => [
          el.out_of_scope ? `${el.name} _(out of scope)_` : `**${el.name}**`,
          el.kind,
          el.technology.id,
          el.raa,
          el.confidentiality,
          el.integrity,
          el.availability,
          el.boundary?.name ?? '',
          el.internet_facing ? 'facing' : el.internet_reachable ? 'reachable' : 'no',
          riskCount.get(el.id) ?? 0,
        ]),
    ),
    '',
  );

  // --- Shared runtimes ------------------------------------------------------
  if (graph.shared_runtimes.length > 0) {
    section('## Shared runtimes');
    out.push(
      'Elements sharing a runtime share its blast radius: a compromise of one is a foothold',
      'in all of them.',
      '',
    );
    out.push(
      table(
        ['Runtime', 'Runs'],
        graph.shared_runtimes.map((r) => [r.name, r.runs.map((e) => e.name).join(', ')]),
      ),
      '',
    );
  }

  // --- Warnings -------------------------------------------------------------
  const otherWarnings = analysis.warnings.filter((w) => !w.code.startsWith('orphaned-tracking'));
  if (otherWarnings.length > 0) {
    section('## Analysis warnings');
    for (const w of otherWarnings) {
      out.push(`- \`${w.code}\` ${w.message}${w.hint ? ` — ${w.hint}` : ''}`);
    }
    out.push('');
  }

  out.push('---', '');
  out.push(
    `Generated by tmac from \`${opts.modelPath ?? 'the model'}\` at ${opts.generatedAt}. ` +
      'Risk ids are derived from the rule and the model ids it concerns, so they survive ' +
      'a regeneration and can be tracked in `risk_tracking`.',
  );

  return out.join('\n').replace(/\n{3,}/g, '\n\n').trimStart() + '\n';
}

function riskDetail(risk: Risk): string[] {
  const out: string[] = [];
  out.push(`<details><summary><code>${risk.id}</code> — ${escapeHtmlish(risk.title)}</summary>`, '');
  if (risk.description) out.push(prose(risk.description), '');
  out.push(`**Why it fired.** ${oneLine(risk.detection_logic)}`, '');
  out.push(`**Mitigation.** ${oneLine(risk.mitigation)}`, '');
  if (risk.action) out.push(`**Action.** ${oneLine(risk.action)}`, '');
  if (risk.check) out.push(`**Check.** ${oneLine(risk.check)}`, '');
  out.push(`**When this is wrong.** ${oneLine(risk.false_positives)}`, '');
  const refs: string[] = [];
  if (risk.cwe !== undefined) refs.push(`CWE-${risk.cwe}`);
  if (risk.capec.length > 0) refs.push(risk.capec.join(', '));
  if (risk.asvs) refs.push(`ASVS ${risk.asvs}`);
  if (risk.cheat_sheet) refs.push(risk.cheat_sheet);
  if (refs.length > 0) out.push(`**References.** ${refs.join(' · ')}`, '');
  out.push(
    `**Rating.** likelihood ${risk.likelihood} × impact ${risk.impact} = ${risk.severity}; ` +
      `data breach ${risk.data_breach_probability}` +
      (risk.data_breach_elements.length > 0
        ? ` via ${risk.data_breach_elements.join(', ')}`
        : ''),
    '',
  );
  out.push('</details>', '');
  return out;
}

/** The summary line is rendered as HTML by every Markdown engine, so escape it. */
function escapeHtmlish(text: string): string {
  return oneLine(text)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}
