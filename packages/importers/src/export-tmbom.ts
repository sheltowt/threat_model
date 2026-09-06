/**
 * Export a tmc model as a CycloneDX 1.6 Threat Model BOM.
 *
 * Elements become `components`, flows become `dependencies`, and each risk becomes
 * both a `vulnerability` (so existing CycloneDX tooling sees it) and an `annotation`
 * (so the reasoning survives, which the vulnerability record has no field for).
 *
 * The risk parameter is loosely typed on purpose: this package must not depend on
 * `@tmc/rules`, and callers pass either engine risks or hand-written entries.
 */

import { createHash } from 'node:crypto';
import type { Model } from '@tmc/core';

export interface RiskLike {
  id?: string;
  title?: string;
  severity?: string;
  cwe?: number | string;
  description?: string;
  mitigation?: string;
  /** Optional subject references, used to fill `affects`. */
  element?: string;
  flow?: string;
  [key: string]: unknown;
}

export interface TmbomExportOptions {
  /** Overrides the generated timestamp, for reproducible output. */
  timestamp?: string;
  toolVersion?: string;
}

/** CycloneDX severities. `elevated` is ours alone and folds into `high`. */
const SEVERITY_MAP: Record<string, string> = {
  low: 'low',
  medium: 'medium',
  elevated: 'high',
  high: 'high',
  critical: 'critical',
};

/** CycloneDX component types are a fixed vocabulary; pick the closest. */
function componentType(kind: string | undefined, technology: string, machine?: string): string {
  if (technology === 'ai-model' || technology === 'ai-agent') return 'machine-learning-model';
  if (machine === 'container') return 'container';
  if (kind === 'datastore') return 'data';
  if (kind === 'actor' || kind === 'external') return 'device';
  return 'application';
}

function property(name: string, value: unknown): { name: string; value: string } | undefined {
  if (value === undefined || value === null || value === '') return undefined;
  if (Array.isArray(value)) {
    return value.length > 0 ? { name, value: value.join(',') } : undefined;
  }
  return { name, value: String(value) };
}

function properties(entries: [string, unknown][]): { name: string; value: string }[] {
  return entries
    .map(([name, value]) => property(name, value))
    .filter((p): p is { name: string; value: string } => p !== undefined);
}

/**
 * A stable urn:uuid derived from the model title, so re-exporting an unchanged model
 * produces an identical BOM and a diff shows only real change.
 */
function serialNumber(seed: string): string {
  const hex = createHash('sha256').update(seed).digest('hex');
  const v = `${hex.slice(0, 8)}-${hex.slice(8, 12)}-4${hex.slice(13, 16)}-${
    ((parseInt(hex.slice(16, 17), 16) & 0x3) | 0x8).toString(16)
  }${hex.slice(17, 20)}-${hex.slice(20, 32)}`;
  return `urn:uuid:${v}`;
}

export function exportTmbom(
  model: Model,
  risks: readonly RiskLike[] = [],
  options: TmbomExportOptions = {},
): Record<string, unknown> {
  const timestamp = options.timestamp ?? new Date().toISOString();
  const elements = Object.entries(model.elements ?? {});
  const flows = model.flows ?? [];

  const boundaryOf = new Map<string, string>();
  for (const [boundaryId, boundary] of Object.entries(model.trust_boundaries ?? {})) {
    for (const member of boundary.contains) {
      if (!boundaryOf.has(member)) boundaryOf.set(member, boundaryId);
    }
  }

  const components = elements.map(([id, element]) => ({
    type: componentType(element.kind, element.technology, element.machine),
    'bom-ref': id,
    name: element.name ?? id,
    ...(element.description === undefined ? {} : { description: element.description }),
    scope: element.out_of_scope ? 'excluded' : 'required',
    properties: properties([
      ['tmc:kind', element.kind],
      ['tmc:technology', element.technology],
      ['tmc:size', element.size],
      ['tmc:machine', element.machine],
      ['tmc:usage', element.usage],
      ['tmc:internet_facing', element.internet_facing],
      ['tmc:human', element.human],
      ['tmc:custom_code', element.custom_code],
      ['tmc:multi_tenant', element.multi_tenant],
      ['tmc:encryption', element.encryption],
      ['tmc:owner', element.owner],
      ['tmc:confidentiality', element.confidentiality],
      ['tmc:integrity', element.integrity],
      ['tmc:availability', element.availability],
      ['tmc:trust_boundary', boundaryOf.get(id)],
      ['tmc:processes', element.processes],
      ['tmc:stores', element.stores],
      ['tmc:tags', element.tags],
      ...Object.entries(element.controls ?? {}).map(
        ([control, value]) => [`tmc:control:${control}`, value] as [string, unknown],
      ),
    ]),
  }));

  // Data assets are components too: CycloneDX 1.6 has a `data` type for exactly this.
  for (const [id, asset] of Object.entries(model.data_assets ?? {})) {
    components.push({
      type: 'data',
      'bom-ref': `data:${id}`,
      name: id,
      ...(asset.description === undefined ? {} : { description: asset.description }),
      scope: 'required',
      properties: properties([
        ['tmc:classification', asset.classification],
        ['tmc:integrity', asset.integrity],
        ['tmc:availability', asset.availability],
        ['tmc:quantity', asset.quantity],
        ['tmc:pii', asset.pii],
        ['tmc:credentials', asset.credentials],
        ['tmc:regulations', asset.regulations],
        ['tmc:owner', asset.owner],
        ['tmc:tags', asset.tags],
      ]),
    });
  }

  // One dependency edge per flow, which is how CycloneDX expresses a call graph.
  const dependsOn = new Map<string, Set<string>>();
  for (const flow of flows) {
    const set = dependsOn.get(flow.from) ?? new Set<string>();
    set.add(flow.to);
    dependsOn.set(flow.from, set);
  }
  const dependencies = elements.map(([id]) => ({
    ref: id,
    dependsOn: [...(dependsOn.get(id) ?? [])],
  }));

  const allRisks: RiskLike[] = [
    ...(model.manual_threats ?? []).map((threat) => ({
      id: threat.id,
      title: threat.title,
      severity: threat.severity,
      cwe: threat.cwe,
      description: threat.description,
      mitigation: threat.mitigation,
      element: threat.element,
      flow: threat.flow,
      source: 'manual',
    })),
    ...risks,
  ];

  const vulnerabilities = allRisks.map((risk, index) => {
    const id = String(risk.id ?? `tmc-risk-${index + 1}`);
    const severity = SEVERITY_MAP[String(risk.severity ?? 'medium').toLowerCase()] ?? 'unknown';
    const cwe = Number(risk.cwe);
    const subject = risk.element ?? risk.flow;
    return {
      'bom-ref': `vuln:${id}`,
      id,
      source: { name: 'tmc' },
      ratings: [{ severity, method: 'other' }],
      ...(Number.isInteger(cwe) && cwe > 0 ? { cwes: [cwe] } : {}),
      ...(risk.title === undefined ? {} : { description: risk.title }),
      ...(risk.description === undefined ? {} : { detail: risk.description }),
      ...(risk.mitigation === undefined ? {} : { recommendation: risk.mitigation }),
      ...(subject === undefined ? {} : { affects: [{ ref: subject }] }),
      properties: properties([
        ['tmc:severity', risk.severity],
        ['tmc:flow', risk.flow],
        ['tmc:element', risk.element],
        ['tmc:source', risk['source']],
      ]),
    };
  });

  // The tracking decision is the part a reviewer cares about and the vulnerability
  // record has nowhere to put it, so it goes in an annotation.
  const annotations = Object.entries(model.risk_tracking ?? {}).map(([riskId, tracking]) => ({
    'bom-ref': `annotation:${riskId}`,
    subjects: [`vuln:${riskId}`],
    annotator: { organization: { name: 'tmc' } },
    timestamp: tracking.date ?? timestamp,
    text: [
      `status: ${tracking.status}`,
      tracking.justification === undefined ? undefined : `justification: ${tracking.justification}`,
      tracking.ticket === undefined ? undefined : `ticket: ${tracking.ticket}`,
      tracking.checked_by === undefined ? undefined : `checked by: ${tracking.checked_by}`,
    ]
      .filter((line): line is string => line !== undefined)
      .join('\n'),
  }));

  return {
    bomFormat: 'CycloneDX',
    specVersion: '1.6',
    serialNumber: serialNumber(model.meta.title),
    version: 1,
    metadata: {
      timestamp,
      tools: {
        components: [
          {
            type: 'application',
            name: 'tmc',
            ...(options.toolVersion === undefined ? {} : { version: options.toolVersion }),
          },
        ],
      },
      component: {
        type: 'application',
        'bom-ref': 'tmc:model',
        name: model.meta.title,
        ...(model.meta.description === undefined ? {} : { description: model.meta.description }),
        ...(model.meta.version === undefined ? {} : { version: String(model.meta.version) }),
      },
      ...(model.meta.author === undefined
        ? {}
        : { authors: [{ name: model.meta.author }] }),
      properties: properties([
        ['tmc:business_criticality', model.meta.business_criticality],
        ['tmc:owner', model.meta.owner],
        ['tmc:date', model.meta.date],
      ]),
    },
    components,
    dependencies,
    ...(vulnerabilities.length > 0 ? { vulnerabilities } : {}),
    ...(annotations.length > 0 ? { annotations } : {}),
  };
}
