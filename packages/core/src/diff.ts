import type { Model } from './schema.js';

/**
 * Semantic diff of two models.
 *
 * Layout lives in a sidecar (ADR 0003), so nothing here reports a moved box. What
 * comes out is the set of changes a reviewer has to think about: an element gained
 * internet exposure, a flow lost authentication, a data asset was reclassified.
 */

export type ChangeKind = 'added' | 'removed' | 'changed';

export interface Change {
  kind: ChangeKind;
  /** `element`, `flow`, `data_asset`, `trust_boundary`, `meta`, `risk_tracking`. */
  category: string;
  id: string;
  field?: string;
  before?: unknown;
  after?: unknown;
  /** True when the change plausibly widens exposure and deserves review. */
  securityRelevant: boolean;
}

export interface ModelDiff {
  changes: Change[];
  summary: { added: number; removed: number; changed: number; securityRelevant: number };
}

/**
 * Fields where a change alters the attack surface. Everything else (descriptions,
 * owners, tags) still shows in the diff but does not raise the flag.
 */
const SECURITY_FIELDS: ReadonlySet<string> = new Set([
  'internet_facing',
  'out_of_scope',
  'encryption',
  'authentication',
  'authorization',
  'protocol',
  'classification',
  'integrity',
  'availability',
  'pii',
  'credentials',
  'custom_code',
  'multi_tenant',
  'vpn',
  'ip_filtered',
  'type',
  'technology',
  'kind',
  'from',
  'to',
  'processes',
  'stores',
  'sends',
  'receives',
  'contains',
  'nested',
]);

function isSecurityField(field: string): boolean {
  if (field.startsWith('controls.')) return true;
  return SECURITY_FIELDS.has(field);
}

function stable(value: unknown): string {
  if (Array.isArray(value)) return JSON.stringify([...value].map(stable).sort());
  if (value && typeof value === 'object') {
    const entries = Object.entries(value as Record<string, unknown>).sort(([a], [b]) =>
      a.localeCompare(b),
    );
    return JSON.stringify(entries.map(([k, v]) => [k, stable(v)]));
  }
  return JSON.stringify(value ?? null);
}

function compareRecords(
  category: string,
  before: Record<string, Record<string, unknown>>,
  after: Record<string, Record<string, unknown>>,
  changes: Change[],
): void {
  for (const id of Object.keys(before)) {
    if (!(id in after)) {
      changes.push({ kind: 'removed', category, id, before: before[id], securityRelevant: true });
    }
  }
  for (const id of Object.keys(after)) {
    if (!(id in before)) {
      changes.push({ kind: 'added', category, id, after: after[id], securityRelevant: true });
      continue;
    }
    diffFields(category, id, before[id]!, after[id]!, changes);
  }
}

function diffFields(
  category: string,
  id: string,
  before: Record<string, unknown>,
  after: Record<string, unknown>,
  changes: Change[],
  prefix = '',
): void {
  const keys = new Set([...Object.keys(before), ...Object.keys(after)]);
  for (const key of keys) {
    const field = prefix ? `${prefix}.${key}` : key;
    const b = before[key];
    const a = after[key];
    const bothObjects =
      b !== null &&
      a !== null &&
      typeof b === 'object' &&
      typeof a === 'object' &&
      !Array.isArray(b) &&
      !Array.isArray(a);
    if (bothObjects) {
      diffFields(
        category,
        id,
        b as Record<string, unknown>,
        a as Record<string, unknown>,
        changes,
        field,
      );
      continue;
    }
    if (stable(b) === stable(a)) continue;
    changes.push({
      kind: 'changed',
      category,
      id,
      field,
      before: b,
      after: a,
      securityRelevant: isSecurityField(field),
    });
  }
}

export function diffModels(before: Model, after: Model): ModelDiff {
  const changes: Change[] = [];

  diffFields('meta', 'meta', before.meta, after.meta, changes);
  compareRecords('data_asset', before.data_assets, after.data_assets, changes);
  compareRecords('element', before.elements, after.elements, changes);
  compareRecords('trust_boundary', before.trust_boundaries, after.trust_boundaries, changes);
  compareRecords('shared_runtime', before.shared_runtimes, after.shared_runtimes, changes);

  const byId = (flows: Model['flows']) =>
    Object.fromEntries(flows.map((f) => [f.id, f as unknown as Record<string, unknown>]));
  compareRecords('flow', byId(before.flows), byId(after.flows), changes);

  compareRecords(
    'risk_tracking',
    before.risk_tracking as Record<string, Record<string, unknown>>,
    after.risk_tracking as Record<string, Record<string, unknown>>,
    changes,
  );

  const summary = {
    added: changes.filter((c) => c.kind === 'added').length,
    removed: changes.filter((c) => c.kind === 'removed').length,
    changed: changes.filter((c) => c.kind === 'changed').length,
    securityRelevant: changes.filter((c) => c.securityRelevant).length,
  };
  return { changes, summary };
}

export function formatDiff(diff: ModelDiff): string {
  if (diff.changes.length === 0) return 'No semantic changes.';
  const lines: string[] = [];
  const mark = (c: Change) => (c.securityRelevant ? '!' : ' ');
  const sign = { added: '+', removed: '-', changed: '~' } as const;
  for (const c of diff.changes) {
    const head = `${mark(c)} ${sign[c.kind]} ${c.category} ${c.id}`;
    if (c.kind === 'changed') {
      lines.push(`${head}.${c.field}: ${JSON.stringify(c.before)} -> ${JSON.stringify(c.after)}`);
    } else {
      lines.push(head);
    }
  }
  lines.push(
    '',
    `${diff.summary.added} added, ${diff.summary.removed} removed, ${diff.summary.changed} changed; ${diff.summary.securityRelevant} security relevant (marked !)`,
  );
  return lines.join('\n');
}
