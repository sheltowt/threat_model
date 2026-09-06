/**
 * `@tmc/importers` — read foreign threat model formats into a tmc model, and write
 * a tmc model back out as OTM or a CycloneDX threat model BOM.
 *
 * Every importer returns the same shape: a model that passes `modelSchema`, an
 * optional layout sidecar (ADR 0003), and a list of warnings. Nothing is guessed
 * silently — anything the importer could not map with confidence comes back as a
 * warning with a hint about how to finish the job by hand.
 */

import { parse as parseYaml } from 'yaml';
import { importOtm } from './otm.js';
import { importPytm } from './pytm.js';
import { importThreagile } from './threagile.js';
import { importThreatDragon } from './threat-dragon.js';
import { asArray, coerceDocument, isRecord, type ImportResult } from './util.js';

export type {
  ImportResult,
  ImportWarning,
  ElementIn,
  FlowIn,
  BoundaryIn,
  DataAssetIn,
  ManualThreatIn,
  ControlsIn,
} from './util.js';
export { IdRegistry, isValidId, mapLinddun, mapProtocol, mapSeverity, mapStride, slugify } from './util.js';

export { importThreatDragon } from './threat-dragon.js';
export { importPytm, type PytmImportOptions } from './pytm.js';
export { importThreagile } from './threagile.js';
export { importOtm } from './otm.js';
export { exportOtm, type OtmExportOptions } from './export-otm.js';
export { exportTmbom, type RiskLike, type TmbomExportOptions } from './export-tmbom.js';

export const IMPORT_FORMATS = ['threat-dragon', 'pytm', 'threagile', 'otm'] as const;
export type ImportFormat = (typeof IMPORT_FORMATS)[number];

/**
 * Identify a document by the keys only that format has. Returns undefined rather
 * than a best guess, because importing a file as the wrong format produces a model
 * that looks plausible and is wrong.
 */
export function detectFormat(data: unknown): ImportFormat | undefined {
  let doc: unknown;
  try {
    doc = coerceDocument(data, (text) => parseYaml(text));
  } catch {
    return undefined;
  }
  if (!isRecord(doc)) return undefined;

  // OTM is the only format with a version key of this name.
  if (typeof doc['otmVersion'] === 'string') return 'otm';

  // Threat Dragon v2: summary + detail.diagrams full of X6 cells.
  if (isRecord(doc['summary']) && isRecord(doc['detail'])) return 'threat-dragon';

  // Threagile: technical assets keyed by title, or the data-asset/title pairing.
  if (isRecord(doc['technical_assets'])) return 'threagile';
  if (isRecord(doc['data_assets']) && typeof doc['title'] === 'string') return 'threagile';

  // pytm: a flat elements list whose entries carry a class discriminator.
  const elements = asArray(doc['elements']);
  if (elements.length > 0 && elements.every(isRecord)) return 'pytm';
  if (Array.isArray(doc['dataflows']) && Array.isArray(doc['elements'])) return 'pytm';

  return undefined;
}

/** Run the importer for `format`. */
export function importAny(format: ImportFormat, data: unknown): ImportResult {
  switch (format) {
    case 'threat-dragon':
      return importThreatDragon(data);
    case 'pytm':
      return importPytm(data);
    case 'threagile':
      return importThreagile(data);
    case 'otm':
      return importOtm(data);
    default: {
      const exhaustive: never = format;
      throw new Error(`tmc: unknown import format "${String(exhaustive)}"`);
    }
  }
}
