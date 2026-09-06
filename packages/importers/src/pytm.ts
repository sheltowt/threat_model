/**
 * pytm importer (`pytm.py --json`).
 *
 * The important part of this file is not the class mapping, it is the control
 * handling. pytm's element attributes are plain Python booleans that default to
 * `False`, so its JSON dump cannot distinguish "we checked, there is no input
 * validation" from "nobody has said". tmc treats those as different states
 * (ADR 0002), and a `false` we invent here would fabricate an assertion the pytm
 * author never made. So only `true` is carried across, and every dropped `false`
 * is counted into one summary warning.
 */

import type { ModelInput } from '@tmc/core';
import {
  asArray,
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
  mapProtocol,
  pick,
  pushWarning,
  stringList,
} from './util.js';

export interface PytmImportOptions {
  /**
   * Treat a `false` in the input as a deliberate assertion that the control is
   * absent. Off by default, because pytm cannot tell you which of its `false`
   * values were typed by a human.
   */
  trustFalseControls?: boolean;
}

/** pytm class name -> element kind and default technology. */
const CLASS_MAP: Record<string, { kind: ElementIn['kind']; technology: string; machine?: ElementIn['machine']; human?: boolean }> = {
  actor: { kind: 'actor', technology: 'unknown-technology', human: true },
  server: { kind: 'process', technology: 'web-server' },
  datastore: { kind: 'datastore', technology: 'database' },
  database: { kind: 'datastore', technology: 'database' },
  process: { kind: 'process', technology: 'unknown-technology' },
  setofprocesses: { kind: 'process', technology: 'unknown-technology' },
  lambda: { kind: 'process', technology: 'function', machine: 'serverless' },
  externalentity: { kind: 'external', technology: 'client-system' },
  llm: { kind: 'process', technology: 'ai-model' },
  agent: { kind: 'process', technology: 'ai-agent' },
};

/** pytm control attribute -> tmc control name. */
const CONTROL_MAP: Record<string, string> = {
  authenticatesSource: 'authenticates_source',
  authenticatesDestination: 'authenticates_destination',
  authorizesSource: 'authorizes_source',
  checksDestinationRevocation: 'checks_certificate_revocation',
  checksInputBounds: 'checks_input_bounds',
  encodesOutput: 'encodes_output',
  hasAccessControl: 'has_access_control',
  isHardened: 'hardened',
  implementsCSRFToken: 'implements_csrf_token',
  implementsPOLP: 'implements_least_privilege',
  implementsAuthenticationScheme: 'authenticates_source',
  isResilient: 'redundant',
  isMonitored: 'monitored',
  handlesResourceConsumption: 'rate_limited',
  sanitizesInput: 'sanitizes_input',
  usesCodeSigning: 'uses_code_signing',
  usesContentSecurityPolicy: 'uses_content_security_policy',
  usesMFA: 'uses_mfa',
  usesParameterizedInput: 'uses_parameterized_queries',
  usesSecureFunctions: 'uses_secure_defaults',
  usesStrongSessionIdentifiers: 'uses_strong_session_ids',
  usesVPN: 'uses_vpn',
  validatesContentType: 'validates_content_type',
  validatesInput: 'validates_input',
  validatesHeaders: 'validates_schema',
  checksInputContentType: 'validates_content_type',
  hasAccessControlOnFiles: 'validates_file_uploads',
  verifySessionIdentifiers: 'uses_strong_session_ids',
  contentFiltered: 'content_filtered',
  humanInTheLoop: 'human_in_the_loop',
  logsSecurityEvents: 'logs_security_events',
  isLogIntegrityProtected: 'log_integrity_protected',
};

/** pytm Classification -> tmc confidentiality. */
const CLASSIFICATION_MAP: Record<string, DataAssetIn['classification']> = {
  UNKNOWN: 'internal',
  PUBLIC: 'public',
  RESTRICTED: 'internal',
  SENSITIVE: 'restricted',
  SECRET: 'confidential',
  TOP_SECRET: 'strictly-confidential',
};

function classOf(entry: Record<string, unknown>): string {
  const raw = pick(entry, '__class__', '_class', 'class', 'type', 'kind', 'element_type');
  const text = asString(raw) ?? '';
  return text.replace(/^pytm\./, '').replace(/[^A-Za-z]/g, '').toLowerCase();
}

/** Flatten pytm's nested `controls` object next to the element's own attributes. */
function controlSource(entry: Record<string, unknown>): Record<string, unknown> {
  return { ...entry, ...asRecord(entry['controls']) };
}

interface ControlHarvest {
  controls: ControlsIn;
  dropped: number;
}

function harvestControls(
  entry: Record<string, unknown>,
  options: PytmImportOptions,
): ControlHarvest {
  const source = controlSource(entry);
  const controls: ControlsIn = {};
  let dropped = 0;
  for (const [pytmName, tmcName] of Object.entries(CONTROL_MAP)) {
    if (!Object.prototype.hasOwnProperty.call(source, pytmName)) continue;
    const value = asBool(source[pytmName]);
    if (value === undefined) continue;
    if (value) {
      (controls as Record<string, boolean>)[tmcName] = true;
    } else if (options.trustFalseControls === true) {
      (controls as Record<string, boolean>)[tmcName] = false;
    } else {
      dropped += 1;
    }
  }
  return { controls, dropped };
}

export function importPytm(json: unknown, options: PytmImportOptions = {}): ImportResult {
  const warnings: ImportWarning[] = [];
  const doc = coerceDocument(json);
  const root = Array.isArray(doc) ? { elements: doc } : asRecord(doc);

  // pytm's dump is one flat `elements` list; some builds split dataflows out.
  const entries = [...asArray(root['elements']), ...asArray(root['dataflows'])]
    .filter(isRecord)
    .map((entry) => ({ entry, cls: classOf(entry) }));

  const registry = new IdRegistry();
  const dataRegistry = new IdRegistry();
  const boundaryRegistry = new IdRegistry();

  const elements: NonNullable<ModelInput['elements']> = {};
  const flows: FlowIn[] = [];
  const dataAssets: NonNullable<ModelInput['data_assets']> = {};
  const boundaries: NonNullable<ModelInput['trust_boundaries']> = {};
  const boundaryMembers = new Map<string, string[]>();
  const boundaryNesting = new Map<string, string[]>();
  let droppedControls = 0;

  // --- data assets first, so elements and flows can reference them ---------
  for (const { entry, cls } of entries) {
    if (cls !== 'data') continue;
    const name = asString(entry['name']) ?? 'data';
    const id = dataRegistry.assign([asString(entry['id']), name], name, 'data');
    const asset: DataAssetIn = {};
    const description = asString(entry['description']);
    if (description !== undefined) asset.description = description;
    const classification = asString(pick(entry, 'classification', 'Classification'));
    if (classification !== undefined) {
      const mapped = CLASSIFICATION_MAP[classification.toUpperCase().replace(/^CLASSIFICATION\./, '')];
      if (mapped !== undefined) {
        asset.classification = mapped;
      } else {
        pushWarning(
          warnings,
          'pytm-classification-unmapped',
          `data "${name}" has classification "${classification}", which is not a pytm Classification member`,
          'Set `classification:` on the imported data asset by hand.',
        );
      }
    }
    if (asBool(entry['isPII']) === true) asset.pii = true;
    if (asBool(entry['isCredentials']) === true) asset.credentials = true;
    const carrier = asString(pick(entry, 'carriedBy', 'origin'));
    if (carrier !== undefined) asset.origin = carrier;
    dataAssets[id] = asset;
  }

  // --- boundaries ----------------------------------------------------------
  for (const { entry, cls } of entries) {
    if (cls !== 'boundary') continue;
    const name = asString(entry['name']) ?? 'boundary';
    const id = boundaryRegistry.assign([asString(entry['id']), name], name, 'boundary');
    const boundary: NonNullable<ModelInput['trust_boundaries']>[string] = { name };
    const description = asString(entry['description']);
    if (description !== undefined) boundary.description = description;
    boundary.type = /internet|public|untrusted|external/i.test(name)
      ? 'network-untrusted'
      : 'network-on-prem';
    boundaries[id] = boundary;
    const parent = asString(pick(entry, 'inBoundary', 'inboundary'));
    if (parent !== undefined) {
      const existing = boundaryNesting.get(parent.toLowerCase()) ?? [];
      existing.push(id);
      boundaryNesting.set(parent.toLowerCase(), existing);
    }
  }

  // --- elements ------------------------------------------------------------
  for (const { entry, cls } of entries) {
    const spec = CLASS_MAP[cls];
    if (spec === undefined) continue;
    const name = asString(entry['name']) ?? cls;
    const id = registry.assign([asString(entry['id']), name], name, 'element');
    const element: ElementIn = { name, kind: spec.kind, technology: spec.technology };
    if (spec.machine !== undefined) element.machine = spec.machine;
    if (spec.human === true) element.human = true;
    const description = asString(entry['description']);
    if (description !== undefined) element.description = description;
    if (asBool(entry['inScope']) === false) {
      element.out_of_scope = true;
      const reason = asString(pick(entry, 'outOfScopeReason', 'reason'));
      if (reason !== undefined) element.justification_out_of_scope = reason;
    }
    if (asBool(pick(entry, 'onAWS', 'isInternetFacing', 'internetFacing')) === true) {
      element.internet_facing = true;
    }
    if (asBool(entry['isEncryptedAtRest']) === true || asBool(entry['isEncrypted']) === true) {
      element.encryption = 'transparent';
    }
    const stores = stringList(pick(entry, 'stores', 'data'))
      .map((d) => dataRegistry.resolve(d))
      .filter((d): d is string => d !== undefined);
    if (stores.length > 0) {
      if (spec.kind === 'datastore') element.stores = stores;
      else element.processes = stores;
    }
    const { controls, dropped } = harvestControls(entry, options);
    droppedControls += dropped;
    if (Object.keys(controls).length > 0) element.controls = controls;

    elements[id] = element;

    const inBoundary = asString(pick(entry, 'inBoundary', 'inboundary'));
    if (inBoundary !== undefined) {
      const key = inBoundary.toLowerCase();
      const members = boundaryMembers.get(key) ?? [];
      members.push(id);
      boundaryMembers.set(key, members);
    }
  }

  // --- dataflows -----------------------------------------------------------
  for (const { entry, cls } of entries) {
    if (cls !== 'dataflow' && cls !== 'flow') continue;
    const name = asString(entry['name']) ?? 'flow';
    const from = registry.resolve(asString(pick(entry, 'source', 'src', 'from')));
    const to = registry.resolve(asString(pick(entry, 'sink', 'destination', 'dst', 'to')));
    if (from === undefined || to === undefined) {
      pushWarning(
        warnings,
        'pytm-dangling-dataflow',
        `dataflow "${name}" references an element that is not in the export and was dropped`,
      );
      continue;
    }
    const id = registry.assign([asString(entry['id'])], name, 'flow');
    const declared = pick(entry, 'protocol');
    let protocol = mapProtocol(declared);
    if (protocol === undefined) {
      protocol = asBool(entry['isEncrypted']) === true ? 'https' : 'unknown-protocol';
      const spelled = asString(declared);
      if (spelled !== undefined) {
        pushWarning(
          warnings,
          'pytm-protocol-unmapped',
          `protocol "${spelled}" on dataflow "${name}" is not in the catalogue; used ${protocol}`,
          'Add it to .tmc/protocols.yaml if your organisation uses it.',
        );
      }
    }
    const flow: FlowIn = { id, from, to, name, protocol };
    const description = asString(entry['description']);
    if (description !== undefined) flow.description = description;
    if (asBool(entry['isResponse']) === true) flow.is_response = true;
    const sends = stringList(pick(entry, 'data', 'sends'))
      .map((d) => dataRegistry.resolve(d))
      .filter((d): d is string => d !== undefined);
    if (sends.length > 0) flow.sends = sends;
    const receives = stringList(entry['responseTo'])
      .map((d) => dataRegistry.resolve(d))
      .filter((d): d is string => d !== undefined);
    if (receives.length > 0) flow.receives = receives;
    const port = pick(entry, 'dstPort', 'dstport');
    const tags: string[] = [];
    if (typeof port === 'number' && port >= 0) tags.push(`port:${port}`);
    if (tags.length > 0) flow.tags = tags;
    const { controls, dropped } = harvestControls(entry, options);
    droppedControls += dropped;
    if (Object.keys(controls).length > 0) flow.controls = controls;
    if (controls.authenticates_source === true) flow.authentication = 'credentials';
    flows.push(flow);
  }

  // --- boundary membership -------------------------------------------------
  for (const [key, members] of boundaryMembers) {
    const boundaryId = boundaryRegistry.resolve(key);
    if (boundaryId === undefined) {
      pushWarning(
        warnings,
        'pytm-unknown-boundary',
        `elements reference boundary "${key}", which is not in the export`,
      );
      continue;
    }
    const boundary = boundaries[boundaryId];
    if (boundary) boundary.contains = members;
  }
  for (const [key, children] of boundaryNesting) {
    const boundaryId = boundaryRegistry.resolve(key);
    if (boundaryId === undefined) continue;
    const boundary = boundaries[boundaryId];
    if (boundary) boundary.nested = children;
  }

  if (droppedControls > 0) {
    pushWarning(
      warnings,
      'pytm-controls-indeterminate',
      `${droppedControls} control flag(s) were false in the pytm export and have been imported as unknown rather than as "absent"`,
      'pytm defaults every control to False, so a false there cannot be distinguished from "nobody has said". tmc keeps the two apart (ADR 0002): set the controls you have actually verified, or re-run the import with trustFalseControls if every false in your pytm model was deliberate.',
    );
  }

  const meta: ModelInput['meta'] = {
    title: asString(pick(root, 'name', 'title')) ?? 'Imported pytm model',
  };
  const description = asString(pick(root, 'description'));
  if (description !== undefined) meta.description = description;

  const model: ModelInput = { schema: 'tmc/1.0', meta };
  if (Object.keys(dataAssets).length > 0) model.data_assets = dataAssets;
  if (Object.keys(elements).length > 0) model.elements = elements;
  if (flows.length > 0) model.flows = flows;
  if (Object.keys(boundaries).length > 0) model.trust_boundaries = boundaries;

  return { model, warnings };
}
