/**
 * Shared helpers for every importer and exporter.
 *
 * The one job that matters here is identifier hygiene. Foreign formats use UUIDs
 * (Threat Dragon), free-text names (pytm) or dotted vendor ids (OTM), none of which
 * satisfy the tmac id grammar. Every importer routes its ids through the one
 * `IdRegistry` below so that cross-references still resolve after renaming.
 */

import {
  builtinCatalog,
  type ControlName,
  type Linddun,
  type ModelInput,
  type Stride,
} from 'tmac-core';

export interface ImportWarning {
  code: string;
  message: string;
  hint?: string;
}

export interface ImportResult {
  /** Must pass `modelSchema.safeParse`. */
  model: ModelInput;
  /** Coordinates and other presentation-only data, kept out of the model (ADR 0003). */
  layout?: Record<string, unknown>;
  warnings: ImportWarning[];
}

export type Elements = NonNullable<ModelInput['elements']>;
export type ElementIn = Elements[string];
export type FlowIn = NonNullable<ModelInput['flows']>[number];
export type BoundaryIn = NonNullable<ModelInput['trust_boundaries']>[string];
export type DataAssetIn = NonNullable<ModelInput['data_assets']>[string];
export type ManualThreatIn = NonNullable<ModelInput['manual_threats']>[number];
export type ControlsIn = Partial<Record<ControlName, boolean>>;

const ID_RE = /^[a-zA-Z0-9][a-zA-Z0-9_.-]*$/;

export function isValidId(value: string): boolean {
  return value.length > 0 && value.length <= 120 && ID_RE.test(value);
}

/**
 * Turn arbitrary text into a legal tmac id. An input that is already legal is passed
 * through untouched, which keeps `model -> export -> import` round trips stable.
 */
export function slugify(input: unknown, fallback = 'item'): string {
  const raw = typeof input === 'string' ? input.trim() : String(input ?? '').trim();
  if (isValidId(raw)) return raw;
  let s = raw
    .normalize('NFKD')
    .replace(/[\u0300-\u036f]/g, '')
    .toLowerCase()
    .replace(/[^a-z0-9_.-]+/g, '-')
    .replace(/-{2,}/g, '-')
    .replace(/^[^a-z0-9]+/, '')
    .replace(/[-_.]+$/, '');
  if (s.length > 120) s = s.slice(0, 120).replace(/[-_.]+$/, '');
  return s.length > 0 ? s : fallback;
}

/**
 * Allocates unique tmac ids and remembers where each came from, so a later reference
 * to the foreign id (or to the element's name, which is how pytm cross-references)
 * still resolves.
 */
export class IdRegistry {
  private readonly used = new Set<string>();
  private readonly byKey = new Map<string, string>();

  /** Allocate a unique id derived from `preferred`. */
  reserve(preferred: unknown, fallback = 'item'): string {
    const base = slugify(preferred, fallback);
    if (!this.used.has(base)) {
      this.used.add(base);
      return base;
    }
    for (let n = 2; ; n += 1) {
      const candidate = `${base}-${n}`;
      if (!this.used.has(candidate)) {
        this.used.add(candidate);
        return candidate;
      }
    }
  }

  /**
   * Allocate an id and index it under every supplied key (foreign id, name, ...).
   * Keys are matched case-insensitively; the first claimant of a key keeps it.
   */
  assign(keys: readonly (string | undefined)[], preferred: unknown, fallback = 'item'): string {
    const id = this.reserve(preferred, fallback);
    this.alias(keys, id);
    return id;
  }

  alias(keys: readonly (string | undefined)[], id: string): void {
    for (const key of keys) {
      if (typeof key !== 'string' || key.length === 0) continue;
      const k = key.toLowerCase();
      if (!this.byKey.has(k)) this.byKey.set(k, id);
    }
  }

  resolve(key: unknown): string | undefined {
    if (typeof key !== 'string' || key.length === 0) return undefined;
    return this.byKey.get(key.toLowerCase());
  }

  has(key: unknown): boolean {
    return this.resolve(key) !== undefined;
  }
}

// --- shapeless input helpers ------------------------------------------------

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

export function asRecord(value: unknown): Record<string, unknown> {
  return isRecord(value) ? value : {};
}

export function asArray(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

export function asString(value: unknown): string | undefined {
  if (typeof value === 'string') {
    const t = value.trim();
    return t.length > 0 ? t : undefined;
  }
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  if (value instanceof Date) return value.toISOString().slice(0, 10);
  return undefined;
}

export function asBool(value: unknown): boolean | undefined {
  if (typeof value === 'boolean') return value;
  if (value === 'true') return true;
  if (value === 'false') return false;
  return undefined;
}

/** Read a key under any of several spellings, tolerating snake/camel drift. */
export function pick(source: Record<string, unknown>, ...keys: string[]): unknown {
  for (const key of keys) {
    if (Object.prototype.hasOwnProperty.call(source, key) && source[key] !== undefined) {
      return source[key];
    }
  }
  return undefined;
}

/** Every string in a value that may be a string, a list, or absent. */
export function stringList(value: unknown): string[] {
  if (typeof value === 'string') return value.trim() ? [value.trim()] : [];
  return asArray(value)
    .map((v) => (isRecord(v) ? asString(pick(v, 'name', 'id')) : asString(v)))
    .filter((v): v is string => v !== undefined);
}

// --- catalogue lookups ------------------------------------------------------

let techIds: Set<string> | undefined;
let protoIds: Set<string> | undefined;

export function knownTechnology(id: string): boolean {
  techIds ??= new Set(builtinCatalog().technologies.keys());
  return techIds.has(id);
}

export function knownProtocol(id: string): boolean {
  protoIds ??= new Set(builtinCatalog().protocols.keys());
  return protoIds.has(id);
}

/** Aliases seen in foreign files that name a protocol our catalogue spells differently. */
const PROTOCOL_ALIASES: Record<string, string> = {
  tls: 'https',
  ssl: 'https',
  'http/2': 'http',
  'http/1.1': 'http',
  http2: 'http',
  websocket: 'ws',
  websockets: 'ws',
  'websocket-secure': 'wss',
  sql: 'sql-access-protocol',
  mysql: 'sql-access-protocol',
  postgres: 'sql-access-protocol',
  postgresql: 'sql-access-protocol',
  oracle: 'sql-access-protocol',
  mssql: 'sql-access-protocol',
  mongodb: 'nosql-access-protocol',
  mongo: 'nosql-access-protocol',
  redis: 'nosql-access-protocol',
  dynamodb: 'nosql-access-protocol',
  cassandra: 'nosql-access-protocol',
  amqp: 'jms',
  kafka: 'jms',
  sqs: 'jms',
  'grpc/protobuf': 'grpc',
  rest: 'https',
  soap: 'https',
  'file-access': 'local-file-access',
  file: 'local-file-access',
  ipc: 'inter-process-communication',
};

/**
 * Best-effort protocol resolution. Returns undefined when nothing in the catalogue
 * matches, so the caller can decide between a fallback and a warning.
 */
export function mapProtocol(raw: unknown): string | undefined {
  const text = asString(raw);
  if (text === undefined) return undefined;
  const key = text.toLowerCase().replace(/\s+/g, '-');
  if (knownProtocol(key)) return key;
  const alias = PROTOCOL_ALIASES[key];
  if (alias !== undefined) return alias;
  return undefined;
}

/** Coerce whatever the caller handed us into a parsed document. */
export function coerceDocument(data: unknown, parseYaml?: (text: string) => unknown): unknown {
  if (typeof data !== 'string') return data;
  const text = data.trim();
  if (text.length === 0) return {};
  try {
    return JSON.parse(text);
  } catch {
    if (parseYaml) return parseYaml(text);
    throw new Error('tmac: input is not valid JSON');
  }
}

/** Collapse a list to unique members, preserving order. */
export function unique<T>(items: Iterable<T>): T[] {
  return [...new Set(items)];
}

export function pushWarning(
  warnings: ImportWarning[],
  code: string,
  message: string,
  hint?: string,
): void {
  warnings.push(hint === undefined ? { code, message } : { code, message, hint });
}

// --- threat categorisation --------------------------------------------------

const STRIDE_PATTERNS: [RegExp, Stride][] = [
  [/spoof/i, 'spoofing'],
  [/tamper|integrity/i, 'tampering'],
  [/repudiat/i, 'repudiation'],
  [/information\s*disclosure|disclosure|confidentiality|leak/i, 'information-disclosure'],
  [/denial\s*of\s*service|\bdos\b|availability/i, 'denial-of-service'],
  [/elevation|privilege|escalation/i, 'elevation-of-privilege'],
];

const LINDDUN_PATTERNS: [RegExp, Linddun][] = [
  [/linkab|linking/i, 'linking'],
  [/identifiab|identifying/i, 'identifying'],
  [/non[-\s]?repudiation/i, 'non-repudiation'],
  [/detectab|detecting/i, 'detecting'],
  [/data\s*disclosure/i, 'data-disclosure'],
  [/unaware/i, 'unawareness'],
  [/non[-\s]?compliance/i, 'non-compliance'],
];

/**
 * Best-effort STRIDE classification of a free-text category. Deliberately returns
 * undefined rather than guessing: the caller records a warning so a reviewer knows
 * the threat arrived uncategorised.
 */
export function mapStride(category: unknown): Stride | undefined {
  const text = asString(category);
  if (text === undefined) return undefined;
  // LINDDUN's "non-repudiation" would otherwise be caught by the repudiation rule.
  if (/non[-\s]?repudiation/i.test(text)) return undefined;
  for (const [pattern, value] of STRIDE_PATTERNS) {
    if (pattern.test(text)) return value;
  }
  return undefined;
}

export function mapLinddun(category: unknown): Linddun | undefined {
  const text = asString(category);
  if (text === undefined) return undefined;
  for (const [pattern, value] of LINDDUN_PATTERNS) {
    if (pattern.test(text)) return value;
  }
  return undefined;
}

export type ModelSeverity = 'low' | 'medium' | 'elevated' | 'high' | 'critical';

const SEVERITY_WORDS: Record<string, ModelSeverity> = {
  low: 'low',
  medium: 'medium',
  moderate: 'medium',
  elevated: 'elevated',
  high: 'high',
  critical: 'critical',
};

/** Map a free-text severity, or undefined when the word is not one we recognise. */
export function mapSeverity(raw: unknown): ModelSeverity | undefined {
  const text = asString(raw);
  if (text === undefined) return undefined;
  return SEVERITY_WORDS[text.trim().toLowerCase()];
}
