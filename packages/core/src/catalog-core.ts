import type { ElementKind } from './enums.js';
import { BUILTIN_CATALOG_DATA } from './generated/catalog-data.js';

/**
 * The technology and protocol catalogue, with no filesystem in sight.
 *
 * Rules never name a technology; they ask about the boolean attributes declared
 * here (ADR 0004). Keeping this half pure is what lets the same catalogue back the
 * CLI and the browser editor without either one reimplementing it.
 */

export interface TechnologyEntry {
  id: string;
  kind: ElementKind;
  attrs: Record<string, boolean>;
}

export interface ProtocolEntry {
  id: string;
  attrs: Record<string, boolean>;
}

export interface Catalog {
  technologies: Map<string, TechnologyEntry>;
  protocols: Map<string, ProtocolEntry>;
  /** Every attribute name seen, so the JSON Schema and docs can enumerate them. */
  technologyAttributes: string[];
  protocolAttributes: string[];
}

/** The shape of a `technologies.yaml` or `protocols.yaml` document, once parsed. */
export interface RawCatalogData {
  technologies?: Record<string, Record<string, unknown> | null>;
  protocols?: Record<string, Record<string, unknown> | null>;
}

const KIND_KEY: ReadonlySet<string> = new Set(['kind']);
const NO_KEYS: ReadonlySet<string> = new Set();

function readSection(
  raw: RawCatalogData,
  section: 'technologies' | 'protocols',
  where: string,
  required: boolean,
): Map<string, Record<string, unknown>> {
  const body = raw[section];
  if (body === undefined || body === null) {
    if (required) throw new Error(`tmc: ${where} has no top-level "${section}:" key`);
    return new Map();
  }
  if (typeof body !== 'object' || Array.isArray(body)) {
    throw new Error(`tmc: "${section}:" in ${where} must be a mapping`);
  }
  const out = new Map<string, Record<string, unknown>>();
  for (const [id, value] of Object.entries(body)) {
    if (value !== null && (typeof value !== 'object' || Array.isArray(value))) {
      throw new Error(`tmc: ${section}.${id} in ${where} must be a mapping`);
    }
    out.set(id, (value ?? {}) as Record<string, unknown>);
  }
  return out;
}

function toBooleanAttrs(
  entry: Record<string, unknown>,
  where: string,
  skip: ReadonlySet<string>,
): Record<string, boolean> {
  const attrs: Record<string, boolean> = {};
  for (const [key, value] of Object.entries(entry)) {
    if (skip.has(key)) continue;
    if (typeof value !== 'boolean') {
      throw new Error(`tmc: attribute ${where}.${key} must be true or false, got ${typeof value}`);
    }
    attrs[key] = value;
  }
  return attrs;
}

function collectAttrNames(entries: Iterable<{ attrs: Record<string, boolean> }>): string[] {
  const names = new Set<string>();
  for (const e of entries) for (const k of Object.keys(e.attrs)) names.add(k);
  return [...names].sort();
}

export function emptyCatalog(): Catalog {
  return {
    technologies: new Map(),
    protocols: new Map(),
    technologyAttributes: [],
    protocolAttributes: [],
  };
}

/**
 * Merge one parsed catalogue document into a catalogue.
 *
 * An overriding document adds entries and adds or flips attributes on entries that
 * already exist; it never has to restate the whole catalogue. `kind` is replaced
 * wholesale because an entry has exactly one.
 */
export function mergeCatalogData(
  into: Catalog,
  raw: RawCatalogData,
  where: string,
  options: { requireSections?: boolean } = {},
): Catalog {
  const required = options.requireSections ?? false;

  for (const [id, entry] of readSection(raw, 'technologies', where, required)) {
    const attrs = toBooleanAttrs(entry, `technologies.${id}`, KIND_KEY);
    const base = into.technologies.get(id);
    const kind = (entry['kind'] ?? base?.kind ?? 'process') as ElementKind;
    into.technologies.set(id, { id, kind, attrs: { ...base?.attrs, ...attrs } });
  }

  for (const [id, entry] of readSection(raw, 'protocols', where, required)) {
    const attrs = toBooleanAttrs(entry, `protocols.${id}`, NO_KEYS);
    const base = into.protocols.get(id);
    into.protocols.set(id, { id, attrs: { ...base?.attrs, ...attrs } });
  }

  into.technologyAttributes = collectAttrNames(into.technologies.values());
  into.protocolAttributes = collectAttrNames(into.protocols.values());
  return into;
}

/** Build a catalogue from one or more parsed documents, in order of precedence. */
export function createCatalog(
  documents: readonly { data: RawCatalogData; where: string; requireSections?: boolean }[],
): Catalog {
  const catalog = emptyCatalog();
  for (const doc of documents) {
    mergeCatalogData(catalog, doc.data, doc.where, {
      requireSections: doc.requireSections ?? false,
    });
  }
  return catalog;
}

let cached: Catalog | undefined;

/**
 * The built-in catalogue, with no project overrides.
 *
 * The data is compiled in by `scripts/generate-data.mjs` rather than read from disk,
 * so this works identically in Node, in a bundle and in the browser, and cannot
 * break because a consumer moved the package's `data/` directory.
 */
export function builtinCatalog(): Catalog {
  cached ??= createCatalog([
    { data: BUILTIN_CATALOG_DATA, where: 'the built-in catalogue', requireSections: true },
  ]);
  return cached;
}
