import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join, resolve } from 'node:path';
import { parse as parseYaml } from 'yaml';
import type { ElementKind } from './enums.js';

/** Boolean facts a rule may ask about a technology. Unlisted names read as false. */
export interface TechnologyAttrs {
  readonly [attr: string]: boolean;
}

export interface Technology extends TechnologyAttrs {
  /** Present as a marker so `technology.name` is readable inside rules. */
  readonly [k: string]: boolean;
}

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

const HERE = dirname(fileURLToPath(import.meta.url));

/**
 * Built-in data files sit next to the compiled output in `dist/`, or one level up
 * from `src/` when running from source. Try both so tests and the shipped package
 * behave identically.
 */
function builtinDataDir(): string {
  for (const candidate of [join(HERE, '..', 'data'), join(HERE, '..', '..', 'data')]) {
    if (existsSync(join(candidate, 'technologies.yaml'))) return candidate;
  }
  throw new Error('tmc: built-in catalogue data not found next to the core package');
}

function readAttrMap(
  raw: unknown,
  file: string,
  section: string,
): Map<string, Record<string, unknown>> {
  const doc = raw as Record<string, unknown> | null;
  const body = doc?.[section];
  if (body === undefined || body === null) {
    throw new Error(`tmc: ${file} has no top-level "${section}:" key`);
  }
  if (typeof body !== 'object' || Array.isArray(body)) {
    throw new Error(`tmc: "${section}:" in ${file} must be a mapping`);
  }
  const out = new Map<string, Record<string, unknown>>();
  for (const [id, value] of Object.entries(body as Record<string, unknown>)) {
    if (value !== null && (typeof value !== 'object' || Array.isArray(value))) {
      throw new Error(`tmc: ${section}.${id} in ${file} must be a mapping`);
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

const KIND_KEY: ReadonlySet<string> = new Set(['kind']);
const NO_KEYS: ReadonlySet<string> = new Set();

function parseTechnologies(
  raw: unknown,
  file: string,
  into: Map<string, TechnologyEntry>,
): void {
  for (const [id, entry] of readAttrMap(raw, file, 'technologies')) {
    const kind = (entry['kind'] ?? 'process') as ElementKind;
    into.set(id, { id, kind, attrs: toBooleanAttrs(entry, `technologies.${id}`, KIND_KEY) });
  }
}

function parseProtocols(raw: unknown, file: string, into: Map<string, ProtocolEntry>): void {
  for (const [id, entry] of readAttrMap(raw, file, 'protocols')) {
    into.set(id, { id, attrs: toBooleanAttrs(entry, `protocols.${id}`, NO_KEYS) });
  }
}

function collectAttrNames(entries: Iterable<{ attrs: Record<string, boolean> }>): string[] {
  const names = new Set<string>();
  for (const e of entries) for (const k of Object.keys(e.attrs)) names.add(k);
  return [...names].sort();
}

/**
 * Load the built-in catalogue, then merge any project overrides. A project file may
 * add new entries and may add or flip attributes on a built-in entry; it never has
 * to restate the whole catalogue.
 */
export function loadCatalog(projectDirs: readonly string[] = []): Catalog {
  const dataDir = builtinDataDir();
  const technologies = new Map<string, TechnologyEntry>();
  const protocols = new Map<string, ProtocolEntry>();

  const techFile = join(dataDir, 'technologies.yaml');
  const protoFile = join(dataDir, 'protocols.yaml');
  parseTechnologies(parseYaml(readFileSync(techFile, 'utf8')), techFile, technologies);
  parseProtocols(parseYaml(readFileSync(protoFile, 'utf8')), protoFile, protocols);

  for (const dir of projectDirs) {
    const overrideTech = resolve(dir, 'technologies.yaml');
    if (existsSync(overrideTech)) {
      const added = new Map<string, TechnologyEntry>();
      parseTechnologies(parseYaml(readFileSync(overrideTech, 'utf8')), overrideTech, added);
      for (const [id, entry] of added) {
        const base = technologies.get(id);
        technologies.set(
          id,
          base ? { id, kind: entry.kind, attrs: { ...base.attrs, ...entry.attrs } } : entry,
        );
      }
    }
    const overrideProto = resolve(dir, 'protocols.yaml');
    if (existsSync(overrideProto)) {
      const added = new Map<string, ProtocolEntry>();
      parseProtocols(parseYaml(readFileSync(overrideProto, 'utf8')), overrideProto, added);
      for (const [id, entry] of added) {
        const base = protocols.get(id);
        protocols.set(id, base ? { id, attrs: { ...base.attrs, ...entry.attrs } } : entry);
      }
    }
  }

  return {
    technologies,
    protocols,
    technologyAttributes: collectAttrNames(technologies.values()),
    protocolAttributes: collectAttrNames(protocols.values()),
  };
}

let cached: Catalog | undefined;
/** The built-in catalogue with no project overrides, loaded once. */
export function builtinCatalog(): Catalog {
  cached ??= loadCatalog();
  return cached;
}
