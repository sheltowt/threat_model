/**
 * Export a tmc model to Open Threat Model (OTM) JSON.
 *
 * OTM has no vocabulary for data assets, controls or CIA ratings, so those are
 * carried in `attributes` rather than silently dropped: `attributes.technology` and
 * `attributes.kind` on a component are what make an OTM export re-importable
 * without losing the technology catalogue entry.
 */

import type { Model } from '@tmc/core';
import { slugify } from './util.js';

export interface OtmExportOptions {
  /** Overrides `project.id`, which otherwise derives from the title. */
  projectId?: string;
  otmVersion?: string;
}

/** Higher is more trusted, matching OTM's convention. */
const TRUST_RATING: Record<string, number> = {
  'network-untrusted': 10,
  'network-on-prem': 80,
  'network-dedicated-hoster': 60,
  'network-virtual-lan': 70,
  'network-cloud-provider': 60,
  'network-cloud-security-group': 75,
  'network-policy-namespace-isolation': 85,
  'execution-environment': 90,
};

const UNASSIGNED_ZONE = 'tmc-unassigned';

function pruneUndefined<T extends Record<string, unknown>>(value: T): T {
  for (const key of Object.keys(value)) {
    if (value[key] === undefined) delete value[key];
  }
  return value;
}

export function exportOtm(model: Model, options: OtmExportOptions = {}): Record<string, unknown> {
  const boundaries = model.trust_boundaries ?? {};
  const elements = model.elements ?? {};

  // An element belongs to the innermost boundary that lists it.
  const zoneOf = new Map<string, string>();
  for (const [boundaryId, boundary] of Object.entries(boundaries)) {
    for (const member of boundary.contains ?? []) {
      if (!zoneOf.has(member)) zoneOf.set(member, boundaryId);
    }
  }

  const trustZones: Record<string, unknown>[] = Object.entries(boundaries).map(([id, boundary]) =>
    pruneUndefined({
      id,
      name: boundary.name ?? id,
      description: boundary.description,
      risk: { trustRating: TRUST_RATING[boundary.type] ?? 50 },
      attributes: pruneUndefined({
        type: boundary.type,
        nested: (boundary.nested ?? []).length > 0 ? boundary.nested : undefined,
        tags: (boundary.tags ?? []).length > 0 ? boundary.tags : undefined,
      }),
    }),
  );

  const needsFallback = Object.keys(elements).some((id) => !zoneOf.has(id));
  if (needsFallback) {
    // OTM requires every component to name a parent, so unbounded elements get one.
    trustZones.push({
      id: UNASSIGNED_ZONE,
      name: 'Unassigned',
      description: 'Elements the tmc model does not place in a trust boundary.',
      risk: { trustRating: 50 },
      attributes: { type: 'network-on-prem' },
    });
  }

  const threatsByElement = new Map<string, string[]>();
  const threatsByFlow = new Map<string, string[]>();
  for (const threat of model.manual_threats ?? []) {
    if (threat.element !== undefined) {
      threatsByElement.set(threat.element, [
        ...(threatsByElement.get(threat.element) ?? []),
        threat.id,
      ]);
    } else if (threat.flow !== undefined) {
      threatsByFlow.set(threat.flow, [...(threatsByFlow.get(threat.flow) ?? []), threat.id]);
    }
  }

  const components = Object.entries(elements).map(([id, element]) =>
    pruneUndefined({
      id,
      name: element.name ?? id,
      description: element.description,
      type: element.technology,
      parent: { trustZone: zoneOf.get(id) ?? UNASSIGNED_ZONE },
      tags: element.tags.length > 0 ? element.tags : undefined,
      threats:
        threatsByElement.get(id)?.map((threatId) => ({ threat: threatId })) ?? undefined,
      attributes: pruneUndefined({
        technology: element.technology,
        kind: element.kind,
        size: element.size,
        machine: element.machine,
        usage: element.usage,
        internetFacing: element.internet_facing,
        human: element.human,
        customCode: element.custom_code,
        multiTenant: element.multi_tenant,
        outOfScope: element.out_of_scope,
        justificationOutOfScope: element.justification_out_of_scope,
        encryption: element.encryption,
        owner: element.owner,
        confidentiality: element.confidentiality,
        integrity: element.integrity,
        availability: element.availability,
        processes: element.processes.length > 0 ? element.processes : undefined,
        stores: element.stores.length > 0 ? element.stores : undefined,
        acceptsFormats: element.accepts_formats.length > 0 ? element.accepts_formats : undefined,
        controls: Object.keys(element.controls).length > 0 ? element.controls : undefined,
      }),
    }),
  );

  const dataflows = (model.flows ?? []).map((flow) =>
    pruneUndefined({
      id: flow.id,
      name: flow.name ?? flow.id,
      description: flow.description,
      source: flow.from,
      destination: flow.to,
      tags: flow.tags.length > 0 ? flow.tags : undefined,
      threats: threatsByFlow.get(flow.id)?.map((threatId) => ({ threat: threatId })) ?? undefined,
      attributes: pruneUndefined({
        protocol: flow.protocol,
        authentication: flow.authentication,
        authorization: flow.authorization,
        usage: flow.usage,
        vpn: flow.vpn,
        ipFiltered: flow.ip_filtered,
        readonly: flow.readonly,
        isResponse: flow.is_response,
        sends: flow.sends.length > 0 ? flow.sends : undefined,
        receives: flow.receives.length > 0 ? flow.receives : undefined,
        controls: Object.keys(flow.controls).length > 0 ? flow.controls : undefined,
      }),
    }),
  );

  const threats = (model.manual_threats ?? []).map((threat) =>
    pruneUndefined({
      id: threat.id,
      name: threat.title,
      description: threat.description,
      categories: threat.stride === undefined ? undefined : [threat.stride],
      risk: { likelihood: 50, impact: 50 },
      tags: threat.tags.length > 0 ? threat.tags : undefined,
      attributes: pruneUndefined({
        severity: threat.severity,
        stride: threat.stride,
        linddun: threat.linddun,
        cwe: threat.cwe,
        mitigation: threat.mitigation,
      }),
    }),
  );

  return pruneUndefined({
    otmVersion: options.otmVersion ?? '0.2.0',
    project: pruneUndefined({
      name: model.meta.title,
      id: options.projectId ?? slugify(model.meta.title, 'tmc-model'),
      description: model.meta.description,
      owner: model.meta.owner,
      attributes: pruneUndefined({
        author: model.meta.author,
        date: model.meta.date,
        version: model.meta.version,
        businessCriticality: model.meta.business_criticality,
        managementSummary: model.meta.management_summary,
        businessOverview: model.meta.business_overview,
        technicalOverview: model.meta.technical_overview,
        questions: Object.keys(model.meta.questions ?? {}).length > 0 ? model.meta.questions : undefined,
        abuseCases:
          Object.keys(model.meta.abuse_cases ?? {}).length > 0 ? model.meta.abuse_cases : undefined,
        securityRequirements:
          Object.keys(model.meta.security_requirements ?? {}).length > 0
            ? model.meta.security_requirements
            : undefined,
        // OTM has no concept of either of these, so park them here rather than drop
        // them. Another tool ignores an attribute it does not know; ours reads it
        // back, which is what makes a tmc -> OTM -> tmc round trip keep its meaning.
        dataAssets:
          Object.keys(model.data_assets ?? {}).length > 0 ? model.data_assets : undefined,
        sharedRuntimes:
          Object.keys(model.shared_runtimes ?? {}).length > 0 ? model.shared_runtimes : undefined,
      }),
    }),
    representations: [
      { name: 'tmc', id: 'tmc', type: 'threat-model', description: 'Exported by tmc' },
    ],
    trustZones,
    components,
    dataflows,
    threats: threats.length > 0 ? threats : undefined,
  });
}
