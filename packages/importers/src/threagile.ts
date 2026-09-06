/**
 * Threagile YAML importer.
 *
 * tmac's model is a deliberate descendant of Threagile's, so most of this file is
 * renames. The places that are not renames are called out in comments: Threagile's
 * `technology` is a single string where ours is a catalogue entry, and its
 * `encryption` values carry a `data-with-` prefix we drop.
 */

import { parse as parseYaml } from 'yaml';
import type { ModelInput } from 'tmac-core';
import {
  asBool,
  asRecord,
  asString,
  coerceDocument,
  type ControlsIn,
  type DataAssetIn,
  type ElementIn,
  type FlowIn,
  IdRegistry,
  type ImportResult,
  type ImportWarning,
  isRecord,
  knownTechnology,
  mapProtocol,
  pick,
  pushWarning,
  stringList,
} from './util.js';

const ENCRYPTION_MAP: Record<string, ElementIn['encryption']> = {
  none: 'none',
  transparent: 'transparent',
  'data-with-symmetric-shared-key': 'symmetric-shared-key',
  'data-with-asymmetric-shared-key': 'asymmetric-shared-key',
  'data-with-enduser-individual-key': 'end-user-key',
  'data-with-end-user-individual-key': 'end-user-key',
};

const KIND_MAP: Record<string, ElementIn['kind']> = {
  'external-entity': 'external',
  external: 'external',
  process: 'process',
  datastore: 'datastore',
  'data-store': 'datastore',
};

/** Threagile technology names our catalogue spells differently. */
const TECHNOLOGY_ALIASES: Record<string, string> = {
  ai: 'ai-model',
  'ai-model': 'ai-model',
  'client-system': 'client-system',
  'identity-provider': 'identity-provider',
  'search-engine': 'search-engine',
  'big-data-platform': 'big-data-platform',
  'reverse-proxy': 'reverse-proxy',
  'unknown-technology': 'unknown-technology',
};

const DATA_FORMATS = new Set(['json', 'xml', 'yaml', 'csv', 'file', 'serialization', 'protobuf', 'html']);
const MACHINES = new Set(['physical', 'virtual', 'container', 'serverless']);
const SIZES = new Set(['component', 'application', 'service', 'system']);
const USAGES = new Set(['business', 'devops']);
const CONFIDENTIALITY = new Set(['public', 'internal', 'restricted', 'confidential', 'strictly-confidential']);
const CRITICALITY = new Set(['archive', 'operational', 'important', 'critical', 'mission-critical']);
const QUANTITY = new Set(['very-few', 'few', 'many', 'very-many']);
const AUTHENTICATION = new Set(['none', 'credentials', 'session-id', 'token', 'client-certificate', 'two-factor']);
const AUTHORIZATION = new Set(['none', 'technical-user', 'end-user-identity']);
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
const RISK_STATUSES = new Set([
  'unchecked',
  'in-discussion',
  'accepted',
  'in-progress',
  'mitigated',
  'false-positive',
  'transferred',
]);

function enumOr<T extends string>(
  raw: unknown,
  allowed: ReadonlySet<string>,
  where: string,
  field: string,
  warnings: ImportWarning[],
): T | undefined {
  const text = asString(raw)?.toLowerCase();
  if (text === undefined) return undefined;
  if (allowed.has(text)) return text as T;
  pushWarning(
    warnings,
    'threagile-enum-unmapped',
    `${where}: "${text}" is not a valid ${field} for tmac and was left at the default`,
    `Valid values: ${[...allowed].join(', ')}.`,
  );
  return undefined;
}

/** Threagile writes overviews as either a string or `{description, images}`. */
function overview(raw: unknown): string | undefined {
  if (isRecord(raw)) return asString(raw['description']);
  return asString(raw);
}

function technologyOf(
  asset: Record<string, unknown>,
  where: string,
  warnings: ImportWarning[],
): string {
  const names = stringList(pick(asset, 'technologies', 'technology'));
  for (const raw of names) {
    const key = raw.toLowerCase().trim();
    const alias = TECHNOLOGY_ALIASES[key];
    if (alias !== undefined && knownTechnology(alias)) return alias;
    if (knownTechnology(key)) return key;
  }
  if (names.length > 0) {
    pushWarning(
      warnings,
      'threagile-technology-unmapped',
      `${where}: technology "${names.join(', ')}" is not in the tmac catalogue; used unknown-technology`,
      'Add the technology to .tmac/technologies.yaml with the attributes the rules should see.',
    );
  }
  return 'unknown-technology';
}

/**
 * Threagile states a control's value explicitly in YAML or leaves the key out, so
 * unlike pytm a `false` here is a real assertion and is carried across.
 */
function controlIfPresent(
  source: Record<string, unknown>,
  key: string,
  control: string,
  controls: ControlsIn,
): void {
  if (!Object.prototype.hasOwnProperty.call(source, key)) return;
  const value = asBool(source[key]);
  if (value !== undefined) (controls as Record<string, boolean>)[control] = value;
}

export function importThreagile(input: unknown): ImportResult {
  const warnings: ImportWarning[] = [];
  const doc = asRecord(coerceDocument(input, (text) => parseYaml(text)));

  const elementIds = new IdRegistry();
  const dataIds = new IdRegistry();
  const boundaryIds = new IdRegistry();
  const runtimeIds = new IdRegistry();
  const flowIds = new IdRegistry();

  const dataAssets: NonNullable<ModelInput['data_assets']> = {};
  const elements: NonNullable<ModelInput['elements']> = {};
  const flows: FlowIn[] = [];
  const trustBoundaries: NonNullable<ModelInput['trust_boundaries']> = {};
  const sharedRuntimes: NonNullable<ModelInput['shared_runtimes']> = {};
  const riskTracking: NonNullable<ModelInput['risk_tracking']> = {};

  // --- data assets ---------------------------------------------------------
  const rawDataAssets = asRecord(doc['data_assets']);
  for (const [key, value] of Object.entries(rawDataAssets)) {
    const raw = asRecord(value);
    const name = asString(raw['id']) ?? key;
    const id = dataIds.assign([key, name, asString(raw['id'])], name, 'data');
    const asset: DataAssetIn = {};
    const description = asString(raw['description']);
    if (description !== undefined) asset.description = description;
    const where = `data asset "${key}"`;
    const classification = enumOr<NonNullable<DataAssetIn['classification']>>(
      raw['confidentiality'], CONFIDENTIALITY, where, 'confidentiality', warnings);
    if (classification !== undefined) asset.classification = classification;
    const integrity = enumOr<NonNullable<DataAssetIn['integrity']>>(
      raw['integrity'], CRITICALITY, where, 'integrity', warnings);
    if (integrity !== undefined) asset.integrity = integrity;
    const availability = enumOr<NonNullable<DataAssetIn['availability']>>(
      raw['availability'], CRITICALITY, where, 'availability', warnings);
    if (availability !== undefined) asset.availability = availability;
    const quantity = enumOr<NonNullable<DataAssetIn['quantity']>>(
      raw['quantity'], QUANTITY, where, 'quantity', warnings);
    if (quantity !== undefined) asset.quantity = quantity;
    const usage = enumOr<NonNullable<DataAssetIn['usage']>>(
      raw['usage'], USAGES, where, 'usage', warnings);
    if (usage !== undefined) asset.usage = usage;
    const justification = asString(pick(raw, 'justification_cia_rating', 'justification'));
    if (justification !== undefined) asset.justification = justification;
    const origin = asString(raw['origin']);
    if (origin !== undefined) asset.origin = origin;
    const owner = asString(raw['owner']);
    if (owner !== undefined) asset.owner = owner;
    const tags = stringList(pick(raw, 'tags', 'tags_available'));
    if (tags.length > 0) asset.tags = tags;
    dataAssets[id] = asset;
  }

  // --- technical assets ----------------------------------------------------
  const rawAssets = asRecord(doc['technical_assets']);
  for (const [key, value] of Object.entries(rawAssets)) {
    const raw = asRecord(value);
    const name = asString(raw['id']) ?? key;
    const id = elementIds.assign([key, name, asString(raw['id'])], name, 'element');
    const where = `technical asset "${key}"`;
    const element: ElementIn = { name: key, technology: technologyOf(raw, where, warnings) };
    const description = asString(raw['description']);
    if (description !== undefined) element.description = description;
    const kind = KIND_MAP[asString(raw['type'])?.toLowerCase() ?? ''];
    if (kind !== undefined) element.kind = kind;
    else if (raw['type'] !== undefined) {
      pushWarning(warnings, 'threagile-enum-unmapped', `${where}: unknown type "${asString(raw['type'])}"`);
    }
    const usage = enumOr<NonNullable<ElementIn['usage']>>(raw['usage'], USAGES, where, 'usage', warnings);
    if (usage !== undefined) element.usage = usage;
    const size = enumOr<NonNullable<ElementIn['size']>>(raw['size'], SIZES, where, 'size', warnings);
    if (size !== undefined) element.size = size;
    const machine = enumOr<NonNullable<ElementIn['machine']>>(raw['machine'], MACHINES, where, 'machine', warnings);
    if (machine !== undefined) element.machine = machine;
    if (asBool(pick(raw, 'used_as_client_by_human')) === true) element.human = true;
    if (asBool(raw['internet']) === true) element.internet_facing = true;
    if (asBool(raw['out_of_scope']) === true) element.out_of_scope = true;
    const justification = asString(raw['justification_out_of_scope']);
    if (justification !== undefined) element.justification_out_of_scope = justification;
    const encryptionRaw = asString(raw['encryption'])?.toLowerCase();
    if (encryptionRaw !== undefined) {
      const encryption = ENCRYPTION_MAP[encryptionRaw];
      if (encryption !== undefined) element.encryption = encryption;
      else {
        pushWarning(warnings, 'threagile-enum-unmapped', `${where}: unknown encryption "${encryptionRaw}"`);
      }
    }
    const owner = asString(raw['owner']);
    if (owner !== undefined) element.owner = owner;
    const confidentiality = enumOr<NonNullable<ElementIn['confidentiality']>>(
      raw['confidentiality'], CONFIDENTIALITY, where, 'confidentiality', warnings);
    if (confidentiality !== undefined) element.confidentiality = confidentiality;
    const integrity = enumOr<NonNullable<ElementIn['integrity']>>(
      raw['integrity'], CRITICALITY, where, 'integrity', warnings);
    if (integrity !== undefined) element.integrity = integrity;
    const availability = enumOr<NonNullable<ElementIn['availability']>>(
      raw['availability'], CRITICALITY, where, 'availability', warnings);
    if (availability !== undefined) element.availability = availability;
    if (asBool(raw['multi_tenant']) === true) element.multi_tenant = true;
    if (asBool(pick(raw, 'custom_developed_parts')) === true) element.custom_code = true;

    const controls: ControlsIn = {};
    controlIfPresent(raw, 'redundant', 'redundant', controls);
    if (Object.keys(controls).length > 0) element.controls = controls;

    const formats: NonNullable<ElementIn['accepts_formats']> = [];
    for (const format of stringList(raw['data_formats_accepted'])) {
      const f = format.toLowerCase();
      if (DATA_FORMATS.has(f)) formats.push(f as NonNullable<ElementIn['accepts_formats']>[number]);
      else pushWarning(warnings, 'threagile-enum-unmapped', `${where}: unknown data format "${format}"`);
    }
    if (formats.length > 0) element.accepts_formats = formats;
    const tags = stringList(raw['tags']);
    if (tags.length > 0) element.tags = tags;
    elements[id] = element;
  }

  // Data references and communication links resolve after every id is allocated.
  for (const [key, value] of Object.entries(rawAssets)) {
    const raw = asRecord(value);
    const id = elementIds.resolve(key);
    const element = id === undefined ? undefined : elements[id];
    if (element === undefined || id === undefined) continue;
    const where = `technical asset "${key}"`;

    const processes = stringList(raw['data_assets_processed'])
      .map((d) => dataIds.resolve(d))
      .filter((d): d is string => d !== undefined);
    if (processes.length > 0) element.processes = processes;
    const stores = stringList(raw['data_assets_stored'])
      .map((d) => dataIds.resolve(d))
      .filter((d): d is string => d !== undefined);
    if (stores.length > 0) element.stores = stores;

    for (const [linkName, linkValue] of Object.entries(asRecord(raw['communication_links']))) {
      const link = asRecord(linkValue);
      const targetKey = asString(link['target']);
      const target = elementIds.resolve(targetKey);
      if (target === undefined) {
        pushWarning(
          warnings,
          'threagile-unknown-target',
          `${where}: communication link "${linkName}" targets "${targetKey ?? '(none)'}", which is not a technical asset`,
        );
        continue;
      }
      const flowId = flowIds.reserve(`${key}-${linkName}`, 'flow');
      const linkWhere = `${where} link "${linkName}"`;
      let protocol = mapProtocol(link['protocol']);
      if (protocol === undefined) {
        const spelled = asString(link['protocol']);
        protocol = 'unknown-protocol';
        if (spelled !== undefined) {
          pushWarning(
            warnings,
            'threagile-protocol-unmapped',
            `${linkWhere}: protocol "${spelled}" is not in the tmac catalogue`,
            'Add it to .tmac/protocols.yaml with the attributes the rules should see.',
          );
        }
      }
      const flow: FlowIn = { id: flowId, from: id, to: target, name: linkName, protocol };
      const description = asString(link['description']);
      if (description !== undefined) flow.description = description;
      const authentication = enumOr<NonNullable<FlowIn['authentication']>>(
        link['authentication'], AUTHENTICATION, linkWhere, 'authentication', warnings);
      if (authentication !== undefined) flow.authentication = authentication;
      const authorization = enumOr<NonNullable<FlowIn['authorization']>>(
        link['authorization'], AUTHORIZATION, linkWhere, 'authorization', warnings);
      if (authorization !== undefined) flow.authorization = authorization;
      const linkUsage = enumOr<NonNullable<FlowIn['usage']>>(link['usage'], USAGES, linkWhere, 'usage', warnings);
      if (linkUsage !== undefined) flow.usage = linkUsage;
      if (asBool(link['vpn']) === true) flow.vpn = true;
      if (asBool(link['ip_filtered']) === true) flow.ip_filtered = true;
      if (asBool(link['readonly']) === true) flow.readonly = true;
      const sends = stringList(link['data_assets_sent'])
        .map((d) => dataIds.resolve(d))
        .filter((d): d is string => d !== undefined);
      if (sends.length > 0) flow.sends = sends;
      const receives = stringList(link['data_assets_received'])
        .map((d) => dataIds.resolve(d))
        .filter((d): d is string => d !== undefined);
      if (receives.length > 0) flow.receives = receives;
      const linkTags = stringList(link['tags']);
      if (linkTags.length > 0) flow.tags = linkTags;
      flows.push(flow);
    }
  }

  // --- trust boundaries ----------------------------------------------------
  const rawBoundaries = asRecord(doc['trust_boundaries']);
  for (const [key, value] of Object.entries(rawBoundaries)) {
    const raw = asRecord(value);
    boundaryIds.assign([key, asString(raw['id'])], asString(raw['id']) ?? key, 'boundary');
  }
  for (const [key, value] of Object.entries(rawBoundaries)) {
    const raw = asRecord(value);
    const id = boundaryIds.resolve(key);
    if (id === undefined) continue;
    const boundary: NonNullable<ModelInput['trust_boundaries']>[string] = { name: key };
    const description = asString(raw['description']);
    if (description !== undefined) boundary.description = description;
    const type = enumOr<NonNullable<typeof boundary.type>>(
      raw['type'], BOUNDARY_TYPES, `trust boundary "${key}"`, 'type', warnings);
    if (type !== undefined) boundary.type = type;
    const contains = stringList(raw['technical_assets_inside'])
      .map((a) => elementIds.resolve(a))
      .filter((a): a is string => a !== undefined);
    if (contains.length > 0) boundary.contains = contains;
    const nested = stringList(raw['trust_boundaries_nested'])
      .map((b) => boundaryIds.resolve(b))
      .filter((b): b is string => b !== undefined);
    if (nested.length > 0) boundary.nested = nested;
    trustBoundaries[id] = boundary;
  }

  // --- shared runtimes -----------------------------------------------------
  for (const [key, value] of Object.entries(asRecord(doc['shared_runtimes']))) {
    const raw = asRecord(value);
    const id = runtimeIds.assign([key, asString(raw['id'])], asString(raw['id']) ?? key, 'runtime');
    const runtime: NonNullable<ModelInput['shared_runtimes']>[string] = { name: key };
    const description = asString(raw['description']);
    if (description !== undefined) runtime.description = description;
    const runs = stringList(pick(raw, 'technical_assets_running', 'technical_assets'))
      .map((a) => elementIds.resolve(a))
      .filter((a): a is string => a !== undefined);
    if (runs.length > 0) runtime.runs = runs;
    const tags = stringList(raw['tags']);
    if (tags.length > 0) runtime.tags = tags;
    sharedRuntimes[id] = runtime;
  }

  // --- risk tracking -------------------------------------------------------
  for (const [key, value] of Object.entries(asRecord(doc['risk_tracking']))) {
    const raw = asRecord(value);
    const status = asString(raw['status'])?.toLowerCase();
    if (status === undefined || !RISK_STATUSES.has(status)) {
      pushWarning(
        warnings,
        'threagile-risk-status-unmapped',
        `risk tracking "${key}" has status "${status ?? '(none)'}", which tmac does not recognise; entry dropped`,
      );
      continue;
    }
    const entry: NonNullable<ModelInput['risk_tracking']>[string] = {
      status: status as NonNullable<ModelInput['risk_tracking']>[string]['status'],
    };
    const justification = asString(raw['justification']);
    if (justification !== undefined) entry.justification = justification;
    const ticket = asString(raw['ticket']);
    if (ticket !== undefined) entry.ticket = ticket;
    const date = asString(raw['date']);
    if (date !== undefined) entry.date = date;
    const checkedBy = asString(pick(raw, 'checked_by', 'checkedBy'));
    if (checkedBy !== undefined) entry.checked_by = checkedBy;
    riskTracking[key] = entry;
  }

  // --- meta ----------------------------------------------------------------
  const meta: ModelInput['meta'] = { title: asString(doc['title']) ?? 'Imported Threagile model' };
  const author = asRecord(doc['author']);
  const authorName = asString(author['name']) ?? asString(doc['author']);
  if (authorName !== undefined) meta.author = authorName;
  const date = asString(doc['date']);
  if (date !== undefined) meta.date = date;
  const criticality = enumOr<NonNullable<ModelInput['meta']['business_criticality']>>(
    doc['business_criticality'], CRITICALITY, 'model', 'business_criticality', warnings);
  if (criticality !== undefined) meta.business_criticality = criticality;
  const summary = asString(pick(doc, 'management_summary_comment', 'management_summary'));
  if (summary !== undefined) meta.management_summary = summary;
  const business = overview(doc['business_overview']);
  if (business !== undefined) meta.business_overview = business;
  const technical = overview(doc['technical_overview']);
  if (technical !== undefined) meta.technical_overview = technical;

  const questions: Record<string, string | null> = {};
  for (const [q, a] of Object.entries(asRecord(doc['questions']))) {
    questions[q] = asString(a) ?? null;
  }
  if (Object.keys(questions).length > 0) meta.questions = questions;
  const abuseCases: Record<string, string> = {};
  for (const [name, text] of Object.entries(asRecord(doc['abuse_cases']))) {
    const value = asString(text);
    if (value !== undefined) abuseCases[name] = value;
  }
  if (Object.keys(abuseCases).length > 0) meta.abuse_cases = abuseCases;
  const requirements: Record<string, string> = {};
  for (const [name, text] of Object.entries(asRecord(doc['security_requirements']))) {
    const value = asString(text);
    if (value !== undefined) requirements[name] = value;
  }
  if (Object.keys(requirements).length > 0) meta.security_requirements = requirements;

  const model: ModelInput = { schema: 'tmac/1.0', meta };
  if (Object.keys(dataAssets).length > 0) model.data_assets = dataAssets;
  if (Object.keys(elements).length > 0) model.elements = elements;
  if (flows.length > 0) model.flows = flows;
  if (Object.keys(trustBoundaries).length > 0) model.trust_boundaries = trustBoundaries;
  if (Object.keys(sharedRuntimes).length > 0) model.shared_runtimes = sharedRuntimes;
  if (Object.keys(riskTracking).length > 0) model.risk_tracking = riskTracking;

  return { model, warnings };
}
