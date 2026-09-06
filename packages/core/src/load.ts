import { readFileSync, existsSync } from 'node:fs';
import { dirname, isAbsolute, resolve } from 'node:path';
import { parse as parseYaml } from 'yaml';
import type { Model } from './schema.js';
import { type Diagnostic, ModelError } from './diagnostics.js';
import { loadCatalog, type Catalog } from './catalog.js';
import { isPlainObject, parseModelDocument } from './parse.js';

/**
 * File reading and include resolution. Validation lives in `parse.ts`, which has no
 * filesystem dependency, so the browser editor validates a model exactly as the CLI
 * does rather than reimplementing the rules.
 */

export interface LoadOptions {
  /** Extra directories searched for `technologies.yaml` / `protocols.yaml`. */
  catalogDirs?: string[];
  /** Cap on include depth, guarding against a cycle the visited-set misses. */
  maxIncludeDepth?: number;
}

export interface LoadResult {
  model: Model;
  catalog: Catalog;
  /** Absolute paths of every file that contributed, for stale-model checks. */
  sources: string[];
  diagnostics: Diagnostic[];
}

type Raw = Record<string, unknown>;

/**
 * Merge an included document into the accumulator. Maps merge key-wise and arrays
 * concatenate; a scalar in the including file wins, so a parent can pin a title.
 */
function mergeInto(base: Raw, extra: Raw, path: string, diagnostics: Diagnostic[]): void {
  for (const [key, value] of Object.entries(extra)) {
    const here = path ? `${path}.${key}` : key;
    const existing = base[key];
    if (existing === undefined) {
      base[key] = value;
    } else if (Array.isArray(existing) && Array.isArray(value)) {
      base[key] = [...existing, ...value];
    } else if (isPlainObject(existing) && isPlainObject(value)) {
      mergeInto(existing, value, here, diagnostics);
    } else if (key !== 'schema' && key !== 'includes') {
      diagnostics.push({
        severity: 'warning',
        code: 'include-conflict',
        message: `included file redefines "${here}"; the including file's value is kept`,
        path: here,
      });
    }
  }
}

function readDocument(file: string): Raw {
  let text: string;
  try {
    text = readFileSync(file, 'utf8');
  } catch (err) {
    throw new ModelError([
      {
        severity: 'error',
        code: 'unreadable',
        message: `cannot read ${file}: ${(err as Error).message}`,
        file,
      },
    ]);
  }
  let doc: unknown;
  try {
    doc = parseYaml(text, { merge: true });
  } catch (err) {
    throw new ModelError([
      { severity: 'error', code: 'yaml', message: (err as Error).message, file },
    ]);
  }
  if (doc === null || doc === undefined) return {};
  if (!isPlainObject(doc)) {
    throw new ModelError([
      {
        severity: 'error',
        code: 'yaml',
        message: 'a threat model file must contain a YAML mapping at the top level',
        file,
      },
    ]);
  }
  return doc;
}

function resolveIncludes(
  entry: string,
  diagnostics: Diagnostic[],
  maxDepth: number,
): { raw: Raw; sources: string[] } {
  const sources: string[] = [];
  const visited = new Set<string>();

  const walk = (file: string, depth: number): Raw => {
    const abs = resolve(file);
    if (visited.has(abs)) {
      diagnostics.push({
        severity: 'warning',
        code: 'include-cycle',
        message: `${abs} is included more than once; the repeat is ignored`,
        file: abs,
      });
      return {};
    }
    if (depth > maxDepth) {
      throw new ModelError([
        {
          severity: 'error',
          code: 'include-depth',
          message: `includes nested more than ${maxDepth} deep starting at ${abs}`,
          file: abs,
        },
      ]);
    }
    visited.add(abs);
    sources.push(abs);
    const doc = readDocument(abs);
    const includes = Array.isArray(doc['includes']) ? (doc['includes'] as unknown[]) : [];
    for (const inc of includes) {
      if (typeof inc !== 'string') {
        diagnostics.push({
          severity: 'error',
          code: 'include',
          message: 'every entry of "includes" must be a path string',
          file: abs,
        });
        continue;
      }
      const target = isAbsolute(inc) ? inc : resolve(dirname(abs), inc);
      if (!existsSync(target)) {
        diagnostics.push({
          severity: 'error',
          code: 'include',
          message: `included file not found: ${inc}`,
          file: abs,
          hint: `resolved to ${target}`,
        });
        continue;
      }
      mergeInto(doc, walk(target, depth + 1), '', diagnostics);
    }
    return doc;
  };

  return { raw: walk(entry, 0), sources };
}

/** Read, merge, validate and cross-check a model file. Throws on any error. */
export function loadModel(file: string, options: LoadOptions = {}): LoadResult {
  const diagnostics: Diagnostic[] = [];
  const abs = resolve(file);
  const { raw, sources } = resolveIncludes(abs, diagnostics, options.maxIncludeDepth ?? 10);

  const catalogDirs = options.catalogDirs ?? [resolve(dirname(abs), '.tmc')];
  const catalog = loadCatalog(catalogDirs);

  let parsed;
  try {
    parsed = parseModelDocument(raw, catalog, { source: abs });
  } catch (err) {
    if (err instanceof ModelError) throw new ModelError([...diagnostics, ...err.diagnostics]);
    throw err;
  }

  diagnostics.push(...parsed.diagnostics);
  if (diagnostics.some((d) => d.severity === 'error')) throw new ModelError(diagnostics);

  return { model: parsed.model, catalog, sources, diagnostics };
}

/** Validate without throwing; returns every diagnostic found. */
export function validateModel(
  file: string,
  options: LoadOptions = {},
): { ok: boolean; diagnostics: Diagnostic[]; result?: LoadResult } {
  try {
    const result = loadModel(file, options);
    return { ok: true, diagnostics: result.diagnostics, result };
  } catch (err) {
    if (err instanceof ModelError) return { ok: false, diagnostics: err.diagnostics };
    throw err;
  }
}
