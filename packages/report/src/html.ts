/**
 * A single self-contained HTML report.
 *
 * No CDN, no external stylesheet, no web font, no image URL: everything, including
 * the diagrams, is inlined. That is not a stylistic preference. A threat model is
 * routinely read on an air-gapped review machine, attached to a ticket, mailed to an
 * auditor and printed to PDF, and a report that renders as unstyled text in any of
 * those places does not get read.
 *
 * Severity is encoded as a coloured pill *and* as the word, never as colour alone,
 * so the document survives greyscale printing and colour-blind readers.
 */

import { isResolved, type ModelGraph, type Severity } from 'tmac-core/browser';
import type { Analysis, Risk } from 'tmac-rules/browser';
import { svgBody } from 'tmac-render/svg-text';
import {
  attentionFirst,
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
  cweUrl,
  type ReportOptions,
  type ResolvedOptions,
} from './common.js';

/** The only way user text becomes markup. Everything else in this file goes through it. */
export function esc(value: unknown): string {
  if (value === undefined || value === null) return '';
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/** Escape then re-introduce paragraph breaks, so folded YAML prose reads properly. */
function paragraphs(text: string | undefined | null): string {
  const body = prose(text);
  if (!body) return '';
  return body
    .split('\n\n')
    .map((p) => `<p>${esc(p)}</p>`)
    .join('\n');
}

/**
 * A URL that is safe to put in an `href`. Only http(s) and mailto survive, so a
 * `javascript:` or `data:` scheme smuggled into a model's `cheat_sheet` field cannot
 * become a live link in a document a reviewer is about to click through.
 */
function safeHref(url: string | undefined): string | undefined {
  if (!url) return undefined;
  try {
    const parsed = new URL(url);
    if (!['http:', 'https:', 'mailto:'].includes(parsed.protocol)) return undefined;
    return parsed.toString();
  } catch {
    return undefined;
  }
}

function link(url: string | undefined, label: string): string {
  const href = safeHref(url);
  if (!href) return esc(label);
  return `<a href="${esc(href)}" rel="noopener noreferrer">${esc(label)}</a>`;
}

function slug(text: string): string {
  return text
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-|-$/g, '');
}

interface Section {
  id: string;
  title: string;
  html: string;
}

function pill(severity: Severity | string): string {
  return `<span class="pill pill--${esc(severity)}"><span class="pill__dot" aria-hidden="true"></span>${esc(severity)}</span>`;
}

function statusPill(risk: Risk): string {
  const label = statusLabel(risk);
  const kind = risk.suppressed_by
    ? 'suppressed'
    : isResolved(risk.status)
      ? 'resolved'
      : 'open';
  return `<span class="tag tag--${kind}">${esc(label)}</span>`;
}

function confidencePill(risk: Risk): string {
  return `<span class="tag tag--conf-${esc(risk.confidence)}">${esc(risk.confidence)}</span>`;
}

/** Wide tables get their own scroll container so the page body never scrolls sideways. */
function tableBlock(
  headers: readonly string[],
  rows: readonly (readonly string[])[],
  className = '',
): string {
  const head = headers.map((h) => `<th scope="col">${esc(h)}</th>`).join('');
  const body = rows
    .map((r) => `<tr>${r.map((c) => `<td>${c}</td>`).join('')}</tr>`)
    .join('\n');
  return `<div class="scroller"><table class="${esc(className)}">
<thead><tr>${head}</tr></thead>
<tbody>
${body}
</tbody>
</table></div>`;
}

function riskCard(risk: Risk): string {
  const refs: string[] = [];
  if (risk.cwe !== undefined) refs.push(link(cweUrl(risk.cwe), `CWE-${risk.cwe}`));
  for (const c of risk.capec) refs.push(esc(c));
  if (risk.asvs) refs.push(`ASVS ${esc(risk.asvs)}`);
  if (risk.cheat_sheet) refs.push(link(risk.cheat_sheet, 'OWASP cheat sheet'));

  const facts: [string, string][] = [
    ['Subject', esc(subjectLabel(risk))],
    ['STRIDE', esc(risk.stride)],
    ['Rating', `${esc(risk.likelihood)} × ${esc(risk.impact)} = ${pill(risk.severity)}`],
    ['Status', statusPill(risk)],
    ['Confidence', confidencePill(risk)],
    ['Data breach', esc(risk.data_breach_probability)],
  ];
  if (risk.linddun) facts.push(['LINDDUN', esc(risk.linddun)]);

  return `<details class="risk" id="risk-${esc(slug(risk.id))}">
<summary>
  <span class="risk__id">${esc(risk.id)}</span>
  <span class="risk__title">${esc(risk.title)}</span>
  ${pill(risk.severity)}
</summary>
<div class="risk__body">
  ${risk.description ? paragraphs(risk.description) : ''}
  <dl class="facts">
    ${facts.map(([k, v]) => `<div><dt>${esc(k)}</dt><dd>${v}</dd></div>`).join('\n    ')}
  </dl>
  ${
    risk.confidence === 'low' && risk.unknowns.length > 0
      ? `<p class="callout callout--gap"><strong>Model gap.</strong> This fired at low confidence because the model does not record ${risk.unknowns
          .map((u) => `<code>${esc(u)}</code>`)
          .join(', ')}. Record it to settle the finding either way.</p>`
      : ''
  }
  ${
    risk.suppressed_by
      ? `<p class="callout callout--suppressed"><strong>Suppressed.</strong> Assumption <code>${esc(risk.suppressed_by)}</code> hides this from the open list. It is shown here so the suppression can be audited.</p>`
      : ''
  }
  <h4>Why it fired</h4>${paragraphs(risk.detection_logic)}
  <h4>Mitigation</h4>${paragraphs(risk.mitigation)}
  ${risk.action ? `<h4>Action</h4>${paragraphs(risk.action)}` : ''}
  ${risk.check ? `<h4>How to check</h4>${paragraphs(risk.check)}` : ''}
  <h4>When this is wrong</h4>${paragraphs(risk.false_positives)}
  ${refs.length > 0 ? `<h4>References</h4><p class="refs">${refs.join(' · ')}</p>` : ''}
</div>
</details>`;
}

function diagramSection(opts: ResolvedOptions): Section | undefined {
  if (!opts.includeDiagrams) return undefined;
  const parts: string[] = [];
  if (opts.diagrams.dataFlow) {
    parts.push(
      `<h3>Data flow</h3><figure class="diagram">${svgBody(opts.diagrams.dataFlow)}<figcaption>Elements, flows and trust boundaries. Red links are unencrypted across a network boundary; heavy links carry credentials or strictly confidential data.</figcaption></figure>`,
    );
  } else if (opts.diagramPaths.dataFlow) {
    const href = safeHref(opts.diagramPaths.dataFlow) ?? opts.diagramPaths.dataFlow;
    parts.push(`<p>Data flow diagram: <code>${esc(href)}</code></p>`);
  }
  if (opts.diagrams.dataAssets) {
    parts.push(
      `<h3>Data assets</h3><figure class="diagram">${svgBody(opts.diagrams.dataAssets)}<figcaption>Which element touches which asset, coloured by classification. Heavy links are storage rather than processing.</figcaption></figure>`,
    );
  } else if (opts.diagramPaths.dataAssets) {
    const href = safeHref(opts.diagramPaths.dataAssets) ?? opts.diagramPaths.dataAssets;
    parts.push(`<p>Data asset diagram: <code>${esc(href)}</code></p>`);
  }
  if (parts.length === 0) return undefined;
  return { id: 'diagrams', title: 'Diagrams', html: parts.join('\n') };
}

export function toHtml(
  analysis: Analysis,
  graph: ModelGraph,
  options: ReportOptions = {},
): string {
  const opts = resolveOptions(options);
  const meta = graph.meta;
  const visible = visibleRisks(analysis, graph, opts);
  const rows = severityRows(analysis);
  const totals = totalRow(rows);
  const sections: Section[] = [];

  // --- Management summary ---------------------------------------------------
  const worst = rows.find((r) => r.open > 0);
  sections.push({
    id: 'summary',
    title: 'Management summary',
    html: `
${meta.management_summary ? paragraphs(meta.management_summary) : ''}
<p>The analysis found <strong>${totals.total} risk${totals.total === 1 ? '' : 's'}</strong>
across ${graph.elements.length} elements and ${graph.flows.length} flows, of which
<strong>${totals.open} remain open</strong>${
      worst ? `, the worst at ${pill(worst.severity)} severity` : ''
    }. ${totals.resolved} have been dealt with and ${totals.suppressed} are suppressed by a
recorded assumption.</p>
${
  totals.lowConfidence > 0
    ? `<p class="callout callout--gap"><strong>${totals.lowConfidence} finding${totals.lowConfidence === 1 ? ' is' : 's are'} low confidence.</strong>
The rule could not settle its condition because the model does not record the control it
asks about. These are gaps in the model before they are risks in the system — see
<a href="#low-confidence">Low-confidence findings</a>.</p>`
    : ''
}
<div class="stat-row">
  ${statTile(String(totals.open), 'open risks')}
  ${statTile(String(totals.total), 'risks found')}
  ${statTile(`${graph.inScope.length}/${graph.elements.length}`, 'elements in scope')}
  ${statTile(String(graph.flows.length), 'flows')}
  ${statTile(String(graph.data.length), 'data assets')}
  ${statTile(String(analysis.stats.rulesRun), 'rules run')}
</div>`,
  });

  // --- Severity summary -----------------------------------------------------
  sections.push({
    id: 'severity',
    title: 'Severity summary',
    html: tableBlock(
      ['Severity', 'Total', 'Open', 'Resolved', 'Suppressed', 'Low confidence'],
      [
        ...rows.map((r) => [
          pill(r.severity),
          bar(r.total, totals.total, r.total),
          String(r.open),
          String(r.resolved),
          String(r.suppressed),
          String(r.lowConfidence),
        ]),
        [
          '<strong>Total</strong>',
          `<strong>${totals.total}</strong>`,
          `<strong>${totals.open}</strong>`,
          `<strong>${totals.resolved}</strong>`,
          `<strong>${totals.suppressed}</strong>`,
          `<strong>${totals.lowConfidence}</strong>`,
        ],
      ],
      'table--severity',
    ),
  });

  // --- Attention first ------------------------------------------------------
  const urgent = attentionFirst(visible);
  sections.push({
    id: 'attention',
    title: 'Attention first',
    html:
      urgent.length === 0
        ? '<p>No open critical or high risks. Work the rest of the register in severity order.</p>'
        : `<p>${urgent.length} open risk${urgent.length === 1 ? '' : 's'} at critical or high
severity. Deal with these before anything else in this report.</p>
${urgent
  .map(
    (r) => `<article class="urgent">
  <header><h3>${esc(r.title)}</h3>${pill(r.severity)}</header>
  <p class="urgent__meta"><code>${esc(r.id)}</code> · ${esc(subjectLabel(r))} · ${esc(r.stride)}${
    r.cwe !== undefined ? ` · ${link(cweUrl(r.cwe), `CWE-${r.cwe}`)}` : ''
  } · confidence ${esc(r.confidence)}</p>
  ${r.description ? paragraphs(r.description) : ''}
  <p><strong>Do this.</strong> ${esc(oneLine(r.action ?? r.mitigation))}</p>
  ${r.check ? `<p><strong>Confirm it worked.</strong> ${esc(oneLine(r.check))}</p>` : ''}
  <p class="urgent__link"><a href="#risk-${esc(slug(r.id))}">Full detail</a></p>
</article>`,
  )
  .join('\n')}`,
  });

  const diagrams = diagramSection(opts);
  if (diagrams) sections.push(diagrams);

  // --- Risks by severity ----------------------------------------------------
  const grouped = groupBySeverity(visible);
  const groupHtml: string[] = [];
  for (const [severity, group] of grouped) {
    if (group.length === 0 && !opts.showEmpty) continue;
    groupHtml.push(
      `<h3 id="severity-${esc(severity)}">${pill(severity)} <span class="count">${group.length}</span></h3>`,
    );
    if (group.length === 0) {
      groupHtml.push('<p>None.</p>');
      continue;
    }
    groupHtml.push(
      tableBlock(
        ['ID', 'Title', 'Subject', 'STRIDE', 'CWE', 'Status', 'Confidence'],
        group.map((r) => [
          `<a href="#risk-${esc(slug(r.id))}"><code>${esc(r.id)}</code></a>`,
          esc(r.title),
          esc(subjectLabel(r)),
          esc(r.stride),
          r.cwe === undefined ? '—' : link(cweUrl(r.cwe), `CWE-${r.cwe}`),
          statusPill(r),
          confidencePill(r),
        ]),
        'table--risks',
      ),
    );
    groupHtml.push(group.map(riskCard).join('\n'));
  }
  sections.push({
    id: 'risks',
    title: 'Risks by severity',
    html:
      groupHtml.length > 0
        ? groupHtml.join('\n')
        : '<p>No risks to show under the current display options.</p>',
  });

  // --- Low confidence -------------------------------------------------------
  const lowConfidence = visible.filter((r) => r.confidence === 'low');
  const gaps = unknownFields(analysis.risks);
  sections.push({
    id: 'low-confidence',
    title: 'Low-confidence findings',
    html: `<p>A low-confidence finding is not a weaker risk. It is a rule that could not settle
its condition, because the model does not record the control it asks about, so tmac reports
the possibility rather than inventing a <code>false</code>. Filling in the fields below
either removes the finding or promotes it to a confirmed one; leaving them blank keeps the
question open forever.</p>
${
  gaps.length === 0
    ? '<p>Every control these rules asked about is recorded. Nothing to fill in.</p>'
    : `<h3>Unrecorded fields, most consequential first</h3>
${tableBlock(
  ['Field', 'Findings it would settle'],
  gaps.map((g) => [`<code>${esc(g.field)}</code>`, String(g.count)]),
)}
${
  lowConfidence.length > 0
    ? `<h3>The findings themselves</h3>
${tableBlock(
  ['ID', 'Title', 'Severity', 'Unrecorded'],
  lowConfidence.map((r) => [
    `<a href="#risk-${esc(slug(r.id))}"><code>${esc(r.id)}</code></a>`,
    esc(r.title),
    pill(r.severity),
    r.unknowns.map((u) => `<code>${esc(u)}</code>`).join(', '),
  ]),
)}`
    : ''
}`
}`,
  });

  // --- Risk tracking --------------------------------------------------------
  const tracked = analysis.risks.filter((r) => r.tracking || r.suppressed_by);
  const untracked = analysis.risks.filter(
    (r) => !r.tracking && !r.suppressed_by && !isResolved(r.status),
  );
  const stale = analysis.warnings.filter((w) => w.code.startsWith('orphaned-tracking'));
  sections.push({
    id: 'tracking',
    title: 'Risk tracking',
    html: `${
      tracked.length === 0
        ? `<p>Nothing in this model has been triaged yet: all ${untracked.length} risks are
unchecked. Record a decision in <code>risk_tracking</code> as each one is dealt with.</p>`
        : `${tableBlock(
            ['ID', 'Status', 'Justification', 'Ticket', 'Checked by', 'Date'],
            tracked.map((r) => [
              `<a href="#risk-${esc(slug(r.id))}"><code>${esc(r.id)}</code></a>`,
              statusPill(r),
              esc(
                r.tracking?.justification ??
                  (r.suppressed_by ? 'Suppressed by an assumption.' : ''),
              ),
              esc(r.tracking?.ticket ?? '—'),
              esc(r.tracking?.checked_by ?? '—'),
              esc(r.tracking?.date ?? '—'),
            ]),
          )}
<p>${untracked.length} risk${untracked.length === 1 ? ' has' : 's have'} no tracking entry.</p>`
    }
${
  stale.length > 0
    ? `<div class="callout callout--gap"><p><strong>Stale tracking entries.</strong> These keys
match no risk in the current model, so the decision recorded against them no longer applies
to anything.</p><ul>${stale.map((w) => `<li>${esc(w.message)}</li>`).join('')}</ul></div>`
    : ''
}`,
  });

  // --- Data assets ----------------------------------------------------------
  const orphans = graph.data.filter((d) => d.orphaned);
  sections.push({
    id: 'data',
    title: 'Data asset matrix',
    html:
      graph.data.length === 0
        ? '<p>The model records no data assets.</p>'
        : `${tableBlock(
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
              `<strong>${esc(d.id)}</strong>${d.description ? `<br><span class="muted">${esc(oneLine(d.description))}</span>` : ''}`,
              `<span class="tag tag--class-${esc(d.classification)}">${esc(d.classification)}</span>`,
              esc(d.integrity),
              esc(d.availability),
              esc(d.quantity),
              [
                d.pii ? '<span class="tag">PII</span>' : '',
                d.credentials ? '<span class="tag">credentials</span>' : '',
                ...d.regulations.map((r) => `<span class="tag">${esc(r)}</span>`),
              ]
                .filter(Boolean)
                .join(' ') || '—',
              esc(d.processed_by.map((e) => e.name).join(', ')) || '—',
              esc(d.stored_by.map((e) => e.name).join(', ')) || '—',
              esc(
                [...new Set([...d.sent_via, ...d.received_via].map((f) => f.name))].join(', '),
              ) || '—',
            ]),
            'table--data',
          )}
${
  orphans.length > 0
    ? `<p class="callout callout--gap"><strong>Orphaned assets.</strong> ${orphans
        .map((d) => `<code>${esc(d.id)}</code>`)
        .join(
          ', ',
        )} — declared but never processed, stored or carried. Either something is missing
from the model or the asset is dead weight.</p>`
    : ''
}`,
  });

  // --- Assumptions ----------------------------------------------------------
  sections.push({
    id: 'assumptions',
    title: 'Assumptions',
    html:
      graph.assumptions.length === 0
        ? '<p>No assumptions recorded.</p>'
        : `<p>Every finding in this report rests on these. If one turns out to be false,
re-run the analysis.</p>
<ul class="assumptions">
${graph.assumptions
  .map(
    (a) => `<li><strong>${esc(a.id)}.</strong> ${esc(prose(a.text))}${
      a.suppresses.length > 0
        ? `<br><span class="muted">Suppresses ${a.suppresses
            .map((s) => `<code>${esc(s)}</code>`)
            .join(', ')}. Matching risks stay in the report, marked as suppressed.</span>`
        : ''
    }</li>`,
  )
  .join('\n')}
</ul>`,
  });

  // --- Open questions -------------------------------------------------------
  const questions = Object.entries(meta.questions);
  const unanswered = questions.filter(([, a]) => !a);
  sections.push({
    id: 'questions',
    title: 'Open questions',
    html:
      questions.length === 0
        ? '<p>No questions recorded.</p>'
        : `${tableBlock(
            ['Question', 'Answer'],
            questions.map(([q, a]) => [
              esc(q),
              a ? esc(a) : '<span class="tag tag--open">Unanswered</span>',
            ]),
          )}
<p>${unanswered.length} of ${questions.length} still unanswered.</p>`,
  });

  if (Object.keys(meta.abuse_cases).length > 0) {
    sections.push({
      id: 'abuse-cases',
      title: 'Abuse cases',
      html: tableBlock(
        ['Case', 'Description'],
        Object.entries(meta.abuse_cases).map(([k, v]) => [`<strong>${esc(k)}</strong>`, esc(v)]),
      ),
    });
  }

  if (Object.keys(meta.security_requirements).length > 0) {
    sections.push({
      id: 'requirements',
      title: 'Security requirements',
      html: tableBlock(
        ['Requirement', 'Statement'],
        Object.entries(meta.security_requirements).map(([k, v]) => [
          `<strong>${esc(k)}</strong>`,
          esc(v),
        ]),
      ),
    });
  }

  // --- Elements -------------------------------------------------------------
  const riskCount = new Map<string, number>();
  for (const risk of visible) {
    const ids = new Set<string>();
    if (risk.subject.kind === 'element') ids.add(risk.subject.id);
    if (risk.most_relevant_element) ids.add(risk.most_relevant_element);
    for (const id of ids) riskCount.set(id, (riskCount.get(id) ?? 0) + 1);
  }
  const maxRaa = Math.max(1, ...graph.elements.map((e) => e.raa));
  sections.push({
    id: 'elements',
    title: 'Elements',
    html: `<p>RAA is Relative Attacker Attractiveness: where an attacker would spend a foothold
if they had one. It is normalised across this model, so the numbers rank elements against
each other and mean nothing against another model.</p>
${tableBlock(
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
      `<strong>${esc(el.name)}</strong>${el.out_of_scope ? ' <span class="tag">out of scope</span>' : ''}<br><span class="muted">${esc(el.id)}</span>`,
      esc(el.kind),
      esc(el.technology.id),
      bar(el.raa, maxRaa, el.raa),
      esc(el.confidentiality),
      esc(el.integrity),
      esc(el.availability),
      esc(el.boundary?.name ?? '—'),
      el.internet_facing
        ? '<span class="tag tag--open">facing</span>'
        : el.internet_reachable
          ? '<span class="tag">reachable</span>'
          : '—',
      String(riskCount.get(el.id) ?? 0),
    ]),
  'table--elements',
)}`,
  });

  if (graph.shared_runtimes.length > 0) {
    sections.push({
      id: 'runtimes',
      title: 'Shared runtimes',
      html: `<p>Elements sharing a runtime share its blast radius: a compromise of one is a
foothold in all of them.</p>
${tableBlock(
  ['Runtime', 'Runs'],
  graph.shared_runtimes.map((r) => [
    `<strong>${esc(r.name)}</strong>`,
    esc(r.runs.map((e) => e.name).join(', ')),
  ]),
)}`,
    });
  }

  const otherWarnings = analysis.warnings.filter((w) => !w.code.startsWith('orphaned-tracking'));
  if (otherWarnings.length > 0) {
    sections.push({
      id: 'warnings',
      title: 'Analysis warnings',
      html: `<ul>${otherWarnings
        .map(
          (w) =>
            `<li><code>${esc(w.code)}</code> ${esc(w.message)}${w.hint ? ` — <span class="muted">${esc(w.hint)}</span>` : ''}</li>`,
        )
        .join('')}</ul>`,
    });
  }

  const metaPairs: [string, string][] = [
    ['Business criticality', meta.business_criticality],
    ['Owner', meta.owner ?? ''],
    ['Author', meta.author ?? ''],
    ['Model date', meta.date ?? ''],
    ['Version', meta.version === undefined ? '' : String(meta.version)],
    ['Model file', opts.modelPath ?? ''],
    ['Generated', opts.generatedAt],
  ].filter((pair): pair is [string, string] => Boolean(pair[1]));

  return page(meta.title, sections, metaPairs, meta.description, opts);
}

function statTile(value: string, label: string): string {
  return `<div class="stat"><span class="stat__value">${esc(value)}</span><span class="stat__label">${esc(label)}</span></div>`;
}

/**
 * A number with a proportional bar behind it. The number is always present and always
 * readable; the bar is a secondary cue, never the only one.
 */
function bar(value: number, max: number, label: number): string {
  const pct = max <= 0 ? 0 : Math.round((value / max) * 100);
  return `<span class="bar"><span class="bar__fill" style="width:${pct}%"></span><span class="bar__label">${esc(label)}</span></span>`;
}

function page(
  title: string,
  sections: readonly Section[],
  metaPairs: readonly [string, string][],
  description: string | undefined,
  opts: ResolvedOptions,
): string {
  const toc = sections
    .map((s) => `<li><a href="#${esc(s.id)}">${esc(s.title)}</a></li>`)
    .join('\n');

  const body = sections
    .map(
      (s) => `<section id="${esc(s.id)}" class="section">
<h2>${esc(s.title)}</h2>
${s.html}
</section>`,
    )
    .join('\n\n');

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="generator" content="tmac">
<meta name="color-scheme" content="light dark">
<title>Threat model: ${esc(title)}</title>
<style>
${STYLES}
</style>
</head>
<body>
<a class="skip" href="#summary">Skip to the summary</a>
<div class="layout">
<nav class="toc" aria-label="Contents">
  <p class="toc__eyebrow">Threat model</p>
  <p class="toc__title">${esc(title)}</p>
  <ol class="toc__list">
${toc}
  </ol>
  <p class="toc__foot">Generated by tmac</p>
</nav>
<main class="content">
<header class="masthead">
  <p class="eyebrow">Threat model</p>
  <h1>${esc(title)}</h1>
  ${description ? paragraphs(description) : ''}
  <dl class="meta">
${metaPairs.map(([k, v]) => `    <div><dt>${esc(k)}</dt><dd>${esc(v)}</dd></div>`).join('\n')}
  </dl>
</header>

${body}

<footer class="colophon">
<p>Generated by tmac${opts.modelPath ? ` from <code>${esc(opts.modelPath)}</code>` : ''} at
${esc(opts.generatedAt)}. Risk ids are derived from the rule and the model ids it concerns,
so they survive a regeneration and can be tracked in <code>risk_tracking</code>.</p>
</footer>
</main>
</div>
<script>
${SCRIPT}
</script>
</body>
</html>
`;
}

/**
 * All colour lives in custom properties on `:root` and is redefined wholesale in the
 * dark media query, so there is exactly one place to change a hue and no rule
 * anywhere hard-codes one.
 */
const STYLES = `
:root {
  color-scheme: light dark;

  --bg: #f7f5f2;
  --surface: #ffffff;
  --surface-2: #f1eee9;
  --border: #e2ddd4;
  --border-strong: #c9c2b6;
  --text: #1a1815;
  --text-dim: #6b6559;
  --accent: #0d6b66;
  --accent-soft: #e2f0ef;
  --shadow: 0 1px 2px rgba(26, 24, 21, .06), 0 4px 16px rgba(26, 24, 21, .05);

  --sev-critical-bg: #fbdfe2;
  --sev-critical-fg: #7a1120;
  --sev-critical-line: #d4808c;
  --sev-high-bg: #fde7d6;
  --sev-high-fg: #8a3a10;
  --sev-high-line: #e0a778;
  --sev-elevated-bg: #fdf2d5;
  --sev-elevated-fg: #75530a;
  --sev-elevated-line: #ddc283;
  --sev-medium-bg: #e3ecfa;
  --sev-medium-fg: #16437e;
  --sev-medium-line: #9dbde6;
  --sev-low-bg: #eceae5;
  --sev-low-fg: #514c45;
  --sev-low-line: #c6c0b6;

  --ok-bg: #e0f0e6;
  --ok-fg: #1d5c37;
  --warn-bg: #fdf2d5;
  --warn-fg: #75530a;

  --fs-xs: .75rem;
  --fs-sm: .8125rem;
  --fs-base: .9375rem;
  --fs-md: 1.0625rem;
  --fs-lg: 1.3125rem;
  --fs-xl: 1.625rem;
  --fs-2xl: 2.25rem;

  --sp-1: .25rem;
  --sp-2: .5rem;
  --sp-3: .75rem;
  --sp-4: 1rem;
  --sp-5: 1.5rem;
  --sp-6: 2rem;
  --sp-7: 3rem;
  --sp-8: 4.5rem;

  --radius: 8px;
  --radius-sm: 5px;
}

@media (prefers-color-scheme: dark) {
  :root {
    --bg: #131519;
    --surface: #1a1d22;
    --surface-2: #22262d;
    --border: #2e333b;
    --border-strong: #434a55;
    --text: #e7e4de;
    --text-dim: #a29b90;
    --accent: #4ec9c0;
    --accent-soft: #16302f;
    --shadow: 0 1px 2px rgba(0, 0, 0, .4), 0 4px 16px rgba(0, 0, 0, .3);

    --sev-critical-bg: #421920;
    --sev-critical-fg: #ffb3ba;
    --sev-critical-line: #82323d;
    --sev-high-bg: #3f2411;
    --sev-high-fg: #ffc79a;
    --sev-high-line: #7d4a20;
    --sev-elevated-bg: #38300f;
    --sev-elevated-fg: #f0d68d;
    --sev-elevated-line: #6d5c1c;
    --sev-medium-bg: #16283f;
    --sev-medium-fg: #a8ccf5;
    --sev-medium-line: #2f5580;
    --sev-low-bg: #24272c;
    --sev-low-fg: #c2bdb5;
    --sev-low-line: #3d434c;

    --ok-bg: #16301f;
    --ok-fg: #92dcae;
    --warn-bg: #38300f;
    --warn-fg: #f0d68d;
  }
}

* { box-sizing: border-box; }

html { -webkit-text-size-adjust: 100%; }

body {
  margin: 0;
  background: var(--bg);
  color: var(--text);
  font-family: ui-sans-serif, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto,
    "Helvetica Neue", Arial, sans-serif;
  font-size: var(--fs-base);
  line-height: 1.65;
  -webkit-font-smoothing: antialiased;
}

code, pre, .risk__id {
  font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas,
    "Liberation Mono", monospace;
  font-size: .92em;
}

code {
  background: var(--surface-2);
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  padding: .06em .35em;
  overflow-wrap: anywhere;
}

a { color: var(--accent); text-decoration-thickness: 1px; text-underline-offset: 2px; }
a:hover { text-decoration-thickness: 2px; }

.skip {
  position: absolute;
  left: -9999px;
}
.skip:focus {
  left: var(--sp-4);
  top: var(--sp-4);
  z-index: 10;
  background: var(--surface);
  border: 1px solid var(--border-strong);
  border-radius: var(--radius-sm);
  padding: var(--sp-2) var(--sp-3);
}

.layout {
  display: grid;
  grid-template-columns: minmax(0, 15.5rem) minmax(0, 1fr);
  gap: var(--sp-7);
  max-width: 84rem;
  margin: 0 auto;
  padding: var(--sp-6) var(--sp-5) var(--sp-8);
}

/* --- Table of contents --------------------------------------------------- */

.toc {
  position: sticky;
  top: var(--sp-5);
  align-self: start;
  max-height: calc(100vh - var(--sp-8));
  overflow-y: auto;
  font-size: var(--fs-sm);
  border-right: 1px solid var(--border);
  padding-right: var(--sp-4);
}

.toc__eyebrow {
  margin: 0;
  font-size: var(--fs-xs);
  letter-spacing: .09em;
  text-transform: uppercase;
  color: var(--text-dim);
}
.toc__title {
  margin: var(--sp-1) 0 var(--sp-4);
  font-size: var(--fs-md);
  font-weight: 650;
  line-height: 1.3;
}
.toc__list {
  list-style: none;
  margin: 0;
  padding: 0;
  counter-reset: toc;
}
.toc__list li { counter-increment: toc; }
.toc__list a {
  display: block;
  padding: var(--sp-1) var(--sp-2) var(--sp-1) 0;
  color: var(--text-dim);
  text-decoration: none;
  border-left: 2px solid transparent;
  padding-left: var(--sp-3);
  margin-left: -2px;
}
.toc__list a::before {
  content: counter(toc) ".";
  display: inline-block;
  min-width: 1.4em;
  color: var(--border-strong);
}
.toc__list a:hover { color: var(--text); }
.toc__list a[aria-current="true"] {
  color: var(--accent);
  border-left-color: var(--accent);
  font-weight: 600;
}
.toc__foot {
  margin-top: var(--sp-5);
  color: var(--text-dim);
  font-size: var(--fs-xs);
}

/* --- Masthead ------------------------------------------------------------ */

.content { min-width: 0; }

.masthead { margin-bottom: var(--sp-7); }
.eyebrow {
  margin: 0;
  font-size: var(--fs-xs);
  letter-spacing: .09em;
  text-transform: uppercase;
  color: var(--accent);
  font-weight: 650;
}
h1 {
  margin: var(--sp-2) 0 var(--sp-4);
  font-size: var(--fs-2xl);
  line-height: 1.15;
  letter-spacing: -.02em;
  font-weight: 700;
}
h2 {
  margin: 0 0 var(--sp-4);
  font-size: var(--fs-xl);
  line-height: 1.25;
  letter-spacing: -.015em;
  font-weight: 680;
}
h3 {
  margin: var(--sp-6) 0 var(--sp-3);
  font-size: var(--fs-lg);
  line-height: 1.3;
  font-weight: 650;
}
h4 {
  margin: var(--sp-4) 0 var(--sp-1);
  font-size: var(--fs-xs);
  letter-spacing: .07em;
  text-transform: uppercase;
  color: var(--text-dim);
  font-weight: 650;
}
p { margin: 0 0 var(--sp-3); max-width: 68ch; }

.meta {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(11rem, 1fr));
  gap: var(--sp-3) var(--sp-5);
  margin: var(--sp-5) 0 0;
  padding: var(--sp-4) 0 0;
  border-top: 1px solid var(--border);
}
.meta dt, .facts dt {
  margin: 0;
  font-size: var(--fs-xs);
  letter-spacing: .06em;
  text-transform: uppercase;
  color: var(--text-dim);
}
.meta dd, .facts dd { margin: var(--sp-1) 0 0; }

/* --- Sections ------------------------------------------------------------ */

.section {
  margin: 0 0 var(--sp-8);
  scroll-margin-top: var(--sp-5);
}

.stat-row {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(8.5rem, 1fr));
  gap: var(--sp-3);
  margin: var(--sp-5) 0;
}
.stat {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: var(--sp-3) var(--sp-4);
  display: flex;
  flex-direction: column;
  gap: var(--sp-1);
}
.stat__value {
  font-size: var(--fs-xl);
  font-weight: 700;
  line-height: 1.1;
  letter-spacing: -.02em;
  font-variant-numeric: tabular-nums;
}
.stat__label {
  font-size: var(--fs-xs);
  color: var(--text-dim);
  letter-spacing: .03em;
}

.callout {
  background: var(--surface);
  border: 1px solid var(--border);
  border-left: 3px solid var(--border-strong);
  border-radius: var(--radius-sm);
  padding: var(--sp-3) var(--sp-4);
  margin: var(--sp-4) 0;
  max-width: none;
}
.callout--gap { border-left-color: var(--sev-elevated-line); background: var(--warn-bg); color: var(--warn-fg); }
.callout--gap code { background: transparent; border-color: currentColor; color: inherit; }
.callout--suppressed { border-left-color: var(--border-strong); background: var(--surface-2); }
.callout ul { margin: var(--sp-2) 0 0; padding-left: var(--sp-5); }

/* --- Tables -------------------------------------------------------------- */

.scroller {
  overflow-x: auto;
  margin: var(--sp-4) 0;
  border: 1px solid var(--border);
  border-radius: var(--radius);
  background: var(--surface);
  box-shadow: var(--shadow);
}
table {
  border-collapse: collapse;
  width: 100%;
  font-size: var(--fs-sm);
}
th, td {
  text-align: left;
  vertical-align: top;
  padding: var(--sp-3) var(--sp-4);
  border-bottom: 1px solid var(--border);
}
thead th {
  position: relative;
  font-size: var(--fs-xs);
  letter-spacing: .06em;
  text-transform: uppercase;
  color: var(--text-dim);
  font-weight: 650;
  background: var(--surface-2);
  white-space: nowrap;
}
tbody tr:last-child td { border-bottom: none; }
tbody tr:hover { background: var(--surface-2); }
td { overflow-wrap: anywhere; }
.table--risks td:nth-child(2) { min-width: 20rem; }
.table--data td:first-child { min-width: 12rem; }
.table--elements td:first-child { min-width: 11rem; }

.muted { color: var(--text-dim); font-size: var(--fs-xs); }

.bar {
  position: relative;
  display: inline-flex;
  align-items: center;
  min-width: 4.5rem;
  height: 1.35rem;
  padding: 0 var(--sp-2);
  border-radius: var(--radius-sm);
  background: var(--surface-2);
  overflow: hidden;
}
.bar__fill {
  position: absolute;
  inset: 0 auto 0 0;
  background: var(--accent-soft);
  border-right: 2px solid var(--accent);
}
.bar__label {
  position: relative;
  font-variant-numeric: tabular-nums;
  font-weight: 600;
}

/* --- Pills and tags ------------------------------------------------------ */

.pill {
  display: inline-flex;
  align-items: center;
  gap: .4em;
  padding: .1em .6em .1em .5em;
  border-radius: 999px;
  font-size: var(--fs-xs);
  font-weight: 650;
  letter-spacing: .03em;
  white-space: nowrap;
  border: 1px solid;
}
.pill__dot {
  width: .5em;
  height: .5em;
  border-radius: 50%;
  background: currentColor;
  flex: none;
}
.pill--critical { background: var(--sev-critical-bg); color: var(--sev-critical-fg); border-color: var(--sev-critical-line); }
.pill--high { background: var(--sev-high-bg); color: var(--sev-high-fg); border-color: var(--sev-high-line); }
.pill--elevated { background: var(--sev-elevated-bg); color: var(--sev-elevated-fg); border-color: var(--sev-elevated-line); }
.pill--medium { background: var(--sev-medium-bg); color: var(--sev-medium-fg); border-color: var(--sev-medium-line); }
.pill--low { background: var(--sev-low-bg); color: var(--sev-low-fg); border-color: var(--sev-low-line); }

.tag {
  display: inline-block;
  padding: .05em .5em;
  border-radius: var(--radius-sm);
  border: 1px solid var(--border);
  background: var(--surface-2);
  color: var(--text-dim);
  font-size: var(--fs-xs);
  white-space: nowrap;
}
.tag--open { background: var(--warn-bg); color: var(--warn-fg); border-color: var(--sev-elevated-line); }
.tag--resolved { background: var(--ok-bg); color: var(--ok-fg); border-color: var(--ok-fg); }
.tag--suppressed { background: var(--surface-2); color: var(--text-dim); border-style: dashed; }
.tag--conf-low { background: var(--warn-bg); color: var(--warn-fg); border-color: var(--sev-elevated-line); }
.tag--conf-high { background: var(--surface-2); color: var(--text-dim); }
.tag--class-strictly-confidential { background: var(--sev-critical-bg); color: var(--sev-critical-fg); border-color: var(--sev-critical-line); }
.tag--class-confidential { background: var(--sev-high-bg); color: var(--sev-high-fg); border-color: var(--sev-high-line); }
.tag--class-restricted { background: var(--sev-elevated-bg); color: var(--sev-elevated-fg); border-color: var(--sev-elevated-line); }
.tag--class-internal { background: var(--sev-medium-bg); color: var(--sev-medium-fg); border-color: var(--sev-medium-line); }
.tag--class-public { background: var(--sev-low-bg); color: var(--sev-low-fg); border-color: var(--sev-low-line); }

.count {
  font-size: var(--fs-sm);
  color: var(--text-dim);
  font-weight: 500;
}

/* --- Urgent cards -------------------------------------------------------- */

.urgent {
  background: var(--surface);
  border: 1px solid var(--border);
  border-left: 3px solid var(--sev-high-line);
  border-radius: var(--radius);
  padding: var(--sp-4) var(--sp-5);
  margin: var(--sp-4) 0;
  box-shadow: var(--shadow);
}
.urgent header {
  display: flex;
  align-items: baseline;
  gap: var(--sp-3);
  flex-wrap: wrap;
}
.urgent h3 { margin: 0; font-size: var(--fs-md); }
.urgent__meta { color: var(--text-dim); font-size: var(--fs-sm); margin-top: var(--sp-1); }
.urgent__link { margin-bottom: 0; font-size: var(--fs-sm); }

/* --- Risk detail --------------------------------------------------------- */

.risk {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  margin: var(--sp-2) 0;
  scroll-margin-top: var(--sp-5);
}
.risk > summary {
  display: flex;
  align-items: center;
  gap: var(--sp-3);
  flex-wrap: wrap;
  padding: var(--sp-3) var(--sp-4);
  cursor: pointer;
  list-style: none;
}
.risk > summary::-webkit-details-marker { display: none; }
.risk > summary::before {
  content: "▸";
  color: var(--text-dim);
  flex: none;
}
.risk[open] > summary::before { content: "▾"; }
.risk[open] > summary { border-bottom: 1px solid var(--border); }
.risk__id { font-size: var(--fs-xs); color: var(--text-dim); }
.risk__title { font-weight: 600; flex: 1 1 18rem; }
.risk__body { padding: var(--sp-4) var(--sp-5) var(--sp-5); }
.risk__body > h4:first-child { margin-top: 0; }
.refs { font-size: var(--fs-sm); }

.facts {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(9rem, 1fr));
  gap: var(--sp-3);
  margin: var(--sp-4) 0;
  padding: var(--sp-3) var(--sp-4);
  background: var(--surface-2);
  border-radius: var(--radius-sm);
}

.assumptions { padding-left: var(--sp-5); max-width: 68ch; }
.assumptions li { margin-bottom: var(--sp-3); }

/* --- Diagrams ------------------------------------------------------------ */

.diagram {
  margin: var(--sp-4) 0;
  padding: var(--sp-4);
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  overflow-x: auto;
}
.diagram svg { max-width: 100%; height: auto; display: block; margin: 0 auto; }
.diagram figcaption {
  margin-top: var(--sp-3);
  color: var(--text-dim);
  font-size: var(--fs-sm);
  max-width: 68ch;
}

.colophon {
  border-top: 1px solid var(--border);
  padding-top: var(--sp-4);
  color: var(--text-dim);
  font-size: var(--fs-sm);
}

/* --- Narrow screens ------------------------------------------------------ */

@media (max-width: 60rem) {
  .layout {
    grid-template-columns: minmax(0, 1fr);
    gap: var(--sp-5);
    padding: var(--sp-4);
  }
  .toc {
    position: static;
    max-height: none;
    border-right: none;
    border-bottom: 1px solid var(--border);
    padding: 0 0 var(--sp-4);
  }
  .toc__list { columns: 2; column-gap: var(--sp-5); }
}

/* --- Print --------------------------------------------------------------- */

@media print {
  :root {
    --bg: #ffffff;
    --surface: #ffffff;
    --surface-2: #f4f4f4;
    --border: #cccccc;
    --text: #000000;
    --text-dim: #444444;
    --shadow: none;
  }
  .toc, .skip, .urgent__link { display: none !important; }
  .layout {
    display: block;
    max-width: none;
    padding: 0;
  }
  body { font-size: 10pt; line-height: 1.45; }
  .section { margin-bottom: var(--sp-6); break-inside: auto; }
  h1, h2, h3, h4 { break-after: avoid; break-inside: avoid; }
  h2 { border-bottom: 1px solid var(--border); padding-bottom: var(--sp-2); }
  tr, .stat, .urgent, .callout, .facts, figure { break-inside: avoid; }
  thead { display: table-header-group; }
  tfoot { display: table-footer-group; }
  .scroller { overflow: visible; box-shadow: none; }
  /* Every disclosure is expanded on paper: a PDF nobody can click is a PDF that
     silently omits half the report. */
  .risk { break-inside: avoid; }
  .risk > summary::before { content: ""; }
  .risk__body { display: block !important; }
  a { color: inherit; text-decoration: underline; }
  .diagram { overflow: visible; }
  @page { margin: 16mm 14mm; }
}
`;

/**
 * Two small conveniences, deliberately optional: the document is fully readable with
 * scripting off, which is how it will be read in a PDF and in most mail clients.
 */
const SCRIPT = `
(function () {
  // Open every disclosure before printing so nothing is silently missing from the PDF.
  var reopen = [];
  function expand() {
    reopen = [];
    document.querySelectorAll('details:not([open])').forEach(function (d) {
      reopen.push(d);
      d.open = true;
    });
  }
  function restore() {
    reopen.forEach(function (d) { d.open = false; });
    reopen = [];
  }
  window.addEventListener('beforeprint', expand);
  window.addEventListener('afterprint', restore);

  // Highlight the section currently in view in the table of contents.
  var links = {};
  document.querySelectorAll('.toc__list a').forEach(function (a) {
    links[a.getAttribute('href').slice(1)] = a;
  });
  if (!('IntersectionObserver' in window)) return;
  var seen = {};
  var observer = new IntersectionObserver(function (entries) {
    entries.forEach(function (e) { seen[e.target.id] = e.isIntersecting; });
    var current = null;
    document.querySelectorAll('.section').forEach(function (s) {
      if (!current && seen[s.id]) current = s.id;
    });
    Object.keys(links).forEach(function (id) {
      if (id === current) links[id].setAttribute('aria-current', 'true');
      else links[id].removeAttribute('aria-current');
    });
  }, { rootMargin: '-10% 0px -70% 0px' });
  document.querySelectorAll('.section').forEach(function (s) { observer.observe(s); });

  // A fragment link into a collapsed risk must open it, or the link goes nowhere.
  function openTarget() {
    if (!location.hash) return;
    var el = document.querySelector(location.hash);
    while (el) {
      if (el.tagName === 'DETAILS') el.open = true;
      el = el.parentElement;
    }
  }
  window.addEventListener('hashchange', openTarget);
  openTarget();
})();
`;
