/**
 * Open Threat Model (OTM) importer.
 *
 * OTM is an interchange format rather than an analysis format: its component `type`
 * is a free-text vendor string, so the mapping table below is the whole game. A type
 * we cannot place becomes `unknown-technology` and a warning, never a guess.
 */

import type { ModelInput } from '@tmc/core';
import {
  asArray,
  asBool,
  asRecord,
  asString,
  coerceDocument,
  type DataAssetIn,
  type ElementIn,
  type FlowIn,
  IdRegistry,
  type ImportResult,
  type ImportWarning,
  isRecord,
  knownTechnology,
  type ManualThreatIn,
  mapProtocol,
  mapSeverity,
  mapStride,
  pick,
  pushWarning,
  stringList,
} from './util.js';

/** OTM component type -> tmc technology. Keys are normalised (lower, dashed). */
const TYPE_MAP: Record<string, string> = {
  'empty-component': 'unknown-technology',
  'generic-component': 'unknown-technology',
  'web-application': 'web-application',
  'web-application-server': 'application-server',
  'application-server': 'application-server',
  'web-server': 'web-server',
  webserver: 'web-server',
  'web-service': 'web-service-rest',
  'rest-api': 'web-service-rest',
  api: 'web-service-rest',
  'api-gateway': 'gateway',
  gateway: 'gateway',
  microservice: 'web-service-rest',
  'soap-service': 'web-service-soap',
  cms: 'cms',
  erp: 'erp',
  database: 'database',
  'sql-database': 'database',
  'nosql-database': 'database',
  'relational-database': 'database',
  datastore: 'database',
  'data-store': 'database',
  cache: 'database',
  'file-system': 'local-file-system',
  filesystem: 'local-file-system',
  'file-server': 'file-server',
  'object-storage': 'block-storage',
  storage: 'block-storage',
  s3: 'block-storage',
  'data-lake': 'data-lake',
  'search-index': 'search-index',
  'message-queue': 'message-queue',
  queue: 'message-queue',
  'stream-processing': 'stream-processing',
  kafka: 'stream-processing',
  'load-balancer': 'load-balancer',
  proxy: 'reverse-proxy',
  'reverse-proxy': 'reverse-proxy',
  waf: 'waf',
  'service-mesh': 'service-mesh',
  'identity-provider': 'identity-provider',
  ldap: 'ldap-server',
  'ldap-server': 'ldap-server',
  vault: 'vault',
  'secrets-manager': 'vault',
  hsm: 'hsm',
  'ci-cd': 'build-pipeline',
  'build-pipeline': 'build-pipeline',
  'source-code-repository': 'sourcecode-repository',
  'artifact-registry': 'artifact-registry',
  monitoring: 'monitoring',
  logging: 'monitoring',
  scheduler: 'scheduler',
  'service-registry': 'service-registry',
  'container-platform': 'container-platform',
  container: 'container-platform',
  kubernetes: 'container-platform',
  'docker-container': 'container-platform',
  function: 'function',
  'serverless-function': 'function',
  lambda: 'function',
  'batch-processing': 'batch-processing',
  'mail-server': 'mail-server',
  mainframe: 'mainframe',
  browser: 'browser',
  'web-browser': 'browser',
  desktop: 'desktop',
  'desktop-application': 'desktop-application',
  'mobile-app': 'mobile-app',
  'mobile-application': 'mobile-app',
  cli: 'cli',
  'iot-device': 'iot-device',
  'external-system': 'client-system',
  'generic-external-system': 'client-system',
  'client-system': 'client-system',
  'ai-model': 'ai-model',
  llm: 'ai-model',
  'machine-learning-model': 'ai-model',
  'ai-agent': 'ai-agent',
  agent: 'ai-agent',
  'vector-database': 'vector-database',
};

/** Types that describe a person rather than a machine. */
const ACTOR_TYPES = new Set([
  'actor',
  'user',
  'human',
  'person',
  'customer',
  'employee',
  'administrator',
]);

function normaliseType(raw: unknown): string | undefined {
  const text = asString(raw);
  if (text === undefined) return undefined;
  return text
    .trim()
    .toLowerCase()
    .replace(/^(cd|ir)-/, '')
    .replace(/[\s_]+/g, '-');
}

interface TechResolution {
  technology: string;
  kind?: ElementIn['kind'];
  human?: boolean;
}

function resolveType(raw: unknown, where: string, warnings: ImportWarning[]): TechResolution {
  const key = normaliseType(raw);
  if (key === undefined) return { technology: 'unknown-technology' };
  if (ACTOR_TYPES.has(key)) return { technology: 'unknown-technology', kind: 'actor', human: true };
  const mapped = TYPE_MAP[key];
  if (mapped !== undefined) return { technology: mapped };
  if (knownTechnology(key)) return { technology: key };
  // Cloud vendors prefix everything; try the tail before giving up.
  const tail = key.replace(/^(cloud|aws|azure|gcp|google|amazon)-/, '');
  const tailMapped = TYPE_MAP[tail] ?? (knownTechnology(tail) ? tail : undefined);
  if (tailMapped !== undefined) return { technology: tailMapped };
  pushWarning(
    warnings,
    'otm-type-unmapped',
    `${where}: component type "${asString(raw)}" has no tmc technology; used unknown-technology`,
    'Add a matching entry to .tmc/technologies.yaml, or set `technology:` on the element.',
  );
  return { technology: 'unknown-technology' };
}

const KINDS = new Set(['actor', 'process', 'datastore', 'external']);
const SIZES = new Set(['component', 'application', 'service', 'system']);
const MACHINES = new Set(['physical', 'virtual', 'container', 'serverless']);
const USAGES = new Set(['business', 'devops']);
const ENCRYPTIONS = new Set([
  'none',
  'transparent',
  'symmetric-shared-key',
  'asymmetric-shared-key',
  'end-user-key',
]);
const AUTHENTICATIONS = new Set([
  'none',
  'credentials',
  'session-id',
  'token',
  'client-certificate',
  'two-factor',
]);
const AUTHORIZATIONS = new Set(['none', 'technical-user', 'end-user-identity']);
const BOUNDARY_TYPES = new Set([
  'network-untrusted',
  'network-on-prem',
  'network-dedicated-hoster',
  'network-virtual-lan',
  'network-cloud-provider',
  'network-cloud-security-group',
  'network-policy-namespace-isolation',
  'execution-environment',
]);

/** Read an attribute only when it names a member of the tmc enum it belongs to. */
function enumAttr<T extends string>(
  attributes: Record<string, unknown>,
  key: string,
  allowed: ReadonlySet<string>,
): T | undefined {
  const text = asString(attributes[key]);
  return text !== undefined && allowed.has(text) ? (text as T) : undefined;
}

/** Controls written by `exportOtm`; anything unrecognised is ignored, not guessed. */
function controlsAttr(attributes: Record<string, unknown>): Record<string, boolean> | undefined {
  const raw = asRecord(attributes['controls']);
  const out: Record<string, boolean> = {};
  for (const [key, value] of Object.entries(raw)) {
    const bool = asBool(value);
    if (bool !== undefined && /^[a-z][a-z0-9_]*$/.test(key)) out[key] = bool;
  }
  return Object.keys(out).length > 0 ? out : undefined;
}

type BoundaryType = NonNullable<NonNullable<ModelInput['trust_boundaries']>[string]['type']>;

/** OTM trust ratings run 1..100, higher meaning more trusted. */
function boundaryType(zone: Record<string, unknown>): BoundaryType {
  const name = asString(zone['name']) ?? '';
  const rating = asRecord(zone['risk'])['trustRating'];
  if (/internet|public|untrusted|external|wan\b|dmz/i.test(name)) return 'network-untrusted';
  if (typeof rating === 'number' && rating <= 20) return 'network-untrusted';
  if (/cloud|aws|azure|gcp/i.test(name)) return 'network-cloud-provider';
  return 'network-on-prem';
}

export function importOtm(json: unknown): ImportResult {
  const warnings: ImportWarning[] = [];
  const doc = asRecord(coerceDocument(json));
  const project = asRecord(doc['project']);

  const registry = new IdRegistry();
  const zoneRegistry = new IdRegistry();
  const threatRegistry = new IdRegistry();
  const dataRegistry = new IdRegistry();

  /**
   * OTM has no data asset of its own, so a tmc export parks them under
   * `project.attributes.dataAssets`. Reading them back is what makes the round trip
   * keep classifications, and with them every reference on an element or a flow.
   * A file from another tool simply has no such attribute and loses nothing.
   */
  const dataAssets: NonNullable<ModelInput['data_assets']> = {};
  for (const [rawId, rawAsset] of Object.entries(
    asRecord(pick(asRecord(project['attributes']), 'dataAssets', 'data_assets')) ?? {},
  )) {
    if (!isRecord(rawAsset)) continue;
    const id = dataRegistry.assign([rawId], rawId, 'data');
    dataAssets[id] = rawAsset as DataAssetIn;
  }

  /** Keep only the references that resolve, so the model stays self-consistent. */
  const dataRefs = (value: unknown): string[] => {
    const out: string[] = [];
    for (const name of stringList(value)) {
      const resolved = dataRegistry.resolve(name);
      if (resolved !== undefined) out.push(resolved);
    }
    return out;
  };

  const elements: NonNullable<ModelInput['elements']> = {};
  const flows: FlowIn[] = [];
  const trustBoundaries: NonNullable<ModelInput['trust_boundaries']> = {};
  const manualThreats: ManualThreatIn[] = [];

  const nestedZones = new Map<string, string[]>();

  // --- trust zones ---------------------------------------------------------
  for (const rawZone of asArray(doc['trustZones'])) {
    if (!isRecord(rawZone)) continue;
    const name = asString(rawZone['name']) ?? asString(rawZone['id']) ?? 'zone';
    const id = zoneRegistry.assign(
      [asString(rawZone['id']), name],
      asString(rawZone['id']) ?? name,
      'boundary',
    );
    const zoneAttributes = asRecord(rawZone['attributes']);
    const boundary: NonNullable<ModelInput['trust_boundaries']>[string] = {
      name,
      type: enumAttr<BoundaryType>(zoneAttributes, 'type', BOUNDARY_TYPES) ?? boundaryType(rawZone),
    };
    const description = asString(rawZone['description']);
    if (description !== undefined) boundary.description = description;
    const zoneTags = stringList(pick(zoneAttributes, 'tags') ?? rawZone['tags']);
    if (zoneTags.length > 0) boundary.tags = zoneTags;
    const nested = stringList(zoneAttributes['nested']);
    if (nested.length > 0) nestedZones.set(id, nested);
    trustBoundaries[id] = boundary;
  }

  // --- components ----------------------------------------------------------
  const components = asArray(doc['components']).filter(isRecord);
  const parentOf = new Map<string, { zone?: string; component?: string }>();
  for (const component of components) {
    const otmId = asString(component['id']);
    const name = asString(component['name']) ?? otmId ?? 'component';
    const id = registry.assign([otmId, name], otmId ?? name, 'element');
    const where = `component "${name}"`;
    const attributes = asRecord(component['attributes']);
    // `attributes.technology` is what a tmc export writes; trust it over `type`.
    const declaredTech = asString(pick(attributes, 'technology'));
    const resolved =
      declaredTech !== undefined && knownTechnology(declaredTech)
        ? { technology: declaredTech }
        : resolveType(component['type'], where, warnings);
    const element: ElementIn = { name, technology: resolved.technology };
    const kind = enumAttr<NonNullable<ElementIn['kind']>>(attributes, 'kind', KINDS) ?? resolved.kind;
    if (kind !== undefined) element.kind = kind;
    if (resolved.human === true || asBool(pick(attributes, 'human')) === true) element.human = true;
    const size = enumAttr<NonNullable<ElementIn['size']>>(attributes, 'size', SIZES);
    if (size !== undefined) element.size = size;
    const machine = enumAttr<NonNullable<ElementIn['machine']>>(attributes, 'machine', MACHINES);
    if (machine !== undefined) element.machine = machine;
    const usage = enumAttr<NonNullable<ElementIn['usage']>>(attributes, 'usage', USAGES);
    if (usage !== undefined) element.usage = usage;
    if (asBool(pick(attributes, 'customCode', 'custom_code')) === true) element.custom_code = true;
    if (asBool(pick(attributes, 'multiTenant', 'multi_tenant')) === true) element.multi_tenant = true;
    const justification = asString(pick(attributes, 'justificationOutOfScope'));
    if (justification !== undefined) element.justification_out_of_scope = justification;
    const componentControls = controlsAttr(attributes);
    if (componentControls !== undefined) {
      element.controls = componentControls as NonNullable<ElementIn['controls']>;
    }
    const description = asString(component['description']);
    if (description !== undefined) element.description = description;
    if (asBool(pick(attributes, 'internetFacing', 'internet_facing', 'internet')) === true) {
      element.internet_facing = true;
    }
    if (asBool(pick(attributes, 'outOfScope', 'out_of_scope')) === true) element.out_of_scope = true;
    const encryption = enumAttr<NonNullable<ElementIn['encryption']>>(
      attributes,
      'encryption',
      ENCRYPTIONS,
    );
    if (encryption !== undefined) element.encryption = encryption;
    else if (asBool(pick(attributes, 'isEncrypted', 'encrypted')) === true) {
      element.encryption = 'transparent';
    }
    const owner = asString(pick(attributes, 'owner'));
    if (owner !== undefined) element.owner = owner;
    const processes = dataRefs(pick(attributes, 'processes'));
    if (processes.length > 0) element.processes = processes;
    const stores = dataRefs(pick(attributes, 'stores'));
    if (stores.length > 0) element.stores = stores;
    const formats = stringList(pick(attributes, 'acceptsFormats', 'accepts_formats'));
    if (formats.length > 0) {
      element.accepts_formats = formats as NonNullable<ElementIn['accepts_formats']>;
    }
    const tags = stringList(component['tags']);
    if (tags.length > 0) element.tags = tags;
    elements[id] = element;

    parentOf.set(id, {
      zone: asString(pick(asRecord(component['parent']), 'trustZone', 'trust_zone')),
      component: asString(pick(asRecord(component['parent']), 'component')),
    });
  }

  // Walk component parents until a trust zone is reached, so a component nested in
  // another component still lands in the right boundary.
  const members = new Map<string, string[]>();
  for (const [id] of parentOf) {
    let cursor: string | undefined = id;
    const seen = new Set<string>();
    let zoneKey: string | undefined;
    while (cursor !== undefined && !seen.has(cursor)) {
      seen.add(cursor);
      const parent: { zone?: string; component?: string } | undefined = parentOf.get(cursor);
      if (parent === undefined) break;
      if (parent.zone !== undefined) {
        zoneKey = parent.zone;
        break;
      }
      cursor = parent.component === undefined ? undefined : registry.resolve(parent.component);
    }
    if (zoneKey === undefined) continue;
    const boundaryId = zoneRegistry.resolve(zoneKey);
    if (boundaryId === undefined) {
      pushWarning(
        warnings,
        'otm-unknown-trust-zone',
        `component "${id}" refers to trust zone "${zoneKey}", which the file does not define`,
      );
      continue;
    }
    const list = members.get(boundaryId) ?? [];
    list.push(id);
    members.set(boundaryId, list);
  }
  for (const [boundaryId, list] of members) {
    const boundary = trustBoundaries[boundaryId];
    if (boundary) boundary.contains = list;
  }
  for (const [boundaryId, children] of nestedZones) {
    const boundary = trustBoundaries[boundaryId];
    const resolvedChildren = children
      .map((child) => zoneRegistry.resolve(child))
      .filter((child): child is string => child !== undefined);
    if (boundary && resolvedChildren.length > 0) boundary.nested = resolvedChildren;
  }

  // --- dataflows -----------------------------------------------------------
  for (const rawFlow of asArray(doc['dataflows'])) {
    if (!isRecord(rawFlow)) continue;
    const name = asString(rawFlow['name']) ?? 'flow';
    const from = registry.resolve(asString(pick(rawFlow, 'source', 'from')));
    const to = registry.resolve(asString(pick(rawFlow, 'destination', 'target', 'to')));
    if (from === undefined || to === undefined) {
      pushWarning(
        warnings,
        'otm-dangling-dataflow',
        `dataflow "${name}" references a component that is not defined and was dropped`,
      );
      continue;
    }
    const otmId = asString(rawFlow['id']);
    const id = registry.assign([otmId], otmId ?? name, 'flow');
    const attributes = asRecord(rawFlow['attributes']);
    let protocol = mapProtocol(pick(attributes, 'protocol')) ?? mapProtocol(rawFlow['protocol']);
    if (protocol === undefined) {
      const declared = asString(pick(attributes, 'protocol')) ?? asString(rawFlow['protocol']);
      protocol =
        asBool(pick(attributes, 'isEncrypted', 'encrypted')) === true ? 'https' : 'unknown-protocol';
      if (declared !== undefined) {
        pushWarning(
          warnings,
          'otm-protocol-unmapped',
          `dataflow "${name}": protocol "${declared}" is not in the catalogue; used ${protocol}`,
        );
      }
    }
    const flow: FlowIn = { id, from, to, name, protocol };
    const sends = dataRefs(pick(attributes, 'sends'));
    if (sends.length > 0) flow.sends = sends;
    const receives = dataRefs(pick(attributes, 'receives'));
    if (receives.length > 0) flow.receives = receives;
    const description = asString(rawFlow['description']);
    if (description !== undefined) flow.description = description;
    const authentication = enumAttr<NonNullable<FlowIn['authentication']>>(
      attributes,
      'authentication',
      AUTHENTICATIONS,
    );
    if (authentication !== undefined) flow.authentication = authentication;
    const authorization = enumAttr<NonNullable<FlowIn['authorization']>>(
      attributes,
      'authorization',
      AUTHORIZATIONS,
    );
    if (authorization !== undefined) flow.authorization = authorization;
    const flowUsage = enumAttr<NonNullable<FlowIn['usage']>>(attributes, 'usage', USAGES);
    if (flowUsage !== undefined) flow.usage = flowUsage;
    if (asBool(pick(attributes, 'vpn')) === true) flow.vpn = true;
    if (asBool(pick(attributes, 'ipFiltered', 'ip_filtered')) === true) flow.ip_filtered = true;
    if (asBool(pick(attributes, 'readonly')) === true) flow.readonly = true;
    if (asBool(pick(attributes, 'isResponse', 'is_response')) === true) flow.is_response = true;
    const flowControls = controlsAttr(attributes);
    if (flowControls !== undefined) flow.controls = flowControls as NonNullable<FlowIn['controls']>;
    const tags = stringList(rawFlow['tags']);
    if (asBool(pick(attributes, 'bidirectional', 'isBidirectional')) === true) {
      tags.push('bidirectional');
    }
    if (tags.length > 0) flow.tags = tags;
    flows.push(flow);
  }

  // --- threats -------------------------------------------------------------
  const threatSubjects = new Map<string, { element?: string; flow?: string }>();
  for (const component of components) {
    const subject = registry.resolve(asString(component['id']));
    if (subject === undefined) continue;
    for (const rawRef of asArray(component['threats'])) {
      const ref = asString(isRecord(rawRef) ? pick(rawRef, 'threat', 'id') : rawRef);
      if (ref !== undefined && !threatSubjects.has(ref)) {
        threatSubjects.set(ref, { element: subject });
      }
    }
  }
  for (const rawFlow of asArray(doc['dataflows'])) {
    if (!isRecord(rawFlow)) continue;
    const subject = registry.resolve(asString(rawFlow['id']));
    if (subject === undefined) continue;
    for (const rawRef of asArray(rawFlow['threats'])) {
      const ref = asString(isRecord(rawRef) ? pick(rawRef, 'threat', 'id') : rawRef);
      if (ref !== undefined && !threatSubjects.has(ref)) threatSubjects.set(ref, { flow: subject });
    }
  }

  for (const rawThreat of asArray(doc['threats'])) {
    if (!isRecord(rawThreat)) continue;
    const otmId = asString(rawThreat['id']);
    const title = asString(pick(rawThreat, 'name', 'title')) ?? 'Untitled threat';
    const id = threatRegistry.assign([otmId], otmId ?? title, 'threat');
    const threat: ManualThreatIn = { id, title };
    const description = asString(rawThreat['description']);
    if (description !== undefined) threat.description = description;
    const attributes = asRecord(rawThreat['attributes']);
    const mitigation =
      asString(pick(rawThreat, 'mitigation', 'remediation')) ??
      asString(pick(attributes, 'mitigation'));
    if (mitigation !== undefined) threat.mitigation = mitigation;
    const subject = otmId === undefined ? undefined : threatSubjects.get(otmId);
    if (subject?.element !== undefined) threat.element = subject.element;
    else if (subject?.flow !== undefined) threat.flow = subject.flow;

    const categories = stringList(pick(rawThreat, 'categories', 'category'));
    let stride: ReturnType<typeof mapStride>;
    for (const category of categories) {
      stride ??= mapStride(category);
    }
    if (stride !== undefined) threat.stride = stride;
    else if (categories.length > 0) {
      pushWarning(
        warnings,
        'otm-threat-category-unmapped',
        `threat "${title}" has categories [${categories.join(', ')}], none of which map to STRIDE`,
        'Set `stride:` on the imported manual threat.',
      );
    }
    const risk = asRecord(rawThreat['risk']);
    const severity = mapSeverity(pick(rawThreat, 'severity')) ?? mapSeverity(pick(risk, 'severity'));
    if (severity !== undefined) threat.severity = severity;
    const cwe = Number(asString(pick(attributes, 'cwe', 'cweId')) ?? NaN);
    if (Number.isInteger(cwe) && cwe > 0) threat.cwe = cwe;
    const tags = stringList(rawThreat['tags']);
    if (tags.length > 0) threat.tags = tags;
    manualThreats.push(threat);
  }

  const meta: ModelInput['meta'] = { title: asString(project['name']) ?? 'Imported OTM model' };
  const description = asString(pick(project, 'description'));
  if (description !== undefined) meta.description = description;
  const owner = asString(pick(project, 'owner'));
  if (owner !== undefined) meta.owner = owner;
  const projectAttributes = asRecord(project['attributes']) ?? {};
  const author = asString(pick(projectAttributes, 'author'));
  if (author !== undefined) meta.author = author;
  const date = asString(pick(projectAttributes, 'date'));
  if (date !== undefined) meta.date = date;
  const version = asString(pick(projectAttributes, 'version'));
  if (version !== undefined) meta.version = version;
  const criticality = asString(pick(projectAttributes, 'businessCriticality', 'business_criticality'));
  if (criticality !== undefined) {
    meta.business_criticality = criticality as NonNullable<ModelInput['meta']>['business_criticality'];
  }
  const summary = asString(pick(projectAttributes, 'managementSummary', 'management_summary'));
  if (summary !== undefined) meta.management_summary = summary;
  const businessOverview = asString(pick(projectAttributes, 'businessOverview', 'business_overview'));
  if (businessOverview !== undefined) meta.business_overview = businessOverview;
  const technicalOverview = asString(
    pick(projectAttributes, 'technicalOverview', 'technical_overview'),
  );
  if (technicalOverview !== undefined) meta.technical_overview = technicalOverview;
  // An unanswered question is carried as null, which is how the model marks it open.
  const questions = asRecord(pick(projectAttributes, 'questions'));
  if (questions && Object.keys(questions).length > 0) {
    meta.questions = questions as NonNullable<ModelInput['meta']>['questions'];
  }
  const abuseCases = asRecord(pick(projectAttributes, 'abuseCases', 'abuse_cases'));
  if (abuseCases && Object.keys(abuseCases).length > 0) {
    meta.abuse_cases = abuseCases as NonNullable<ModelInput['meta']>['abuse_cases'];
  }
  const requirements = asRecord(
    pick(projectAttributes, 'securityRequirements', 'security_requirements'),
  );
  if (requirements && Object.keys(requirements).length > 0) {
    meta.security_requirements = requirements as NonNullable<ModelInput['meta']>['security_requirements'];
  }

  const model: ModelInput = { schema: 'tmc/1.0', meta };
  if (Object.keys(dataAssets).length > 0) model.data_assets = dataAssets;
  const sharedRuntimes = asRecord(
    pick(projectAttributes, 'sharedRuntimes', 'shared_runtimes'),
  );
  if (sharedRuntimes && Object.keys(sharedRuntimes).length > 0) {
    model.shared_runtimes = sharedRuntimes as NonNullable<ModelInput['shared_runtimes']>;
  }
  if (Object.keys(elements).length > 0) model.elements = elements;
  if (flows.length > 0) model.flows = flows;
  if (Object.keys(trustBoundaries).length > 0) model.trust_boundaries = trustBoundaries;
  if (manualThreats.length > 0) model.manual_threats = manualThreats;

  return { model, warnings };
}
