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
 * Keys that reach the prototype chain rather than the object.
 *
 * An included file is untrusted: it arrives in a repository, and `includes` is the
 * one place this tool copies keys from a YAML document into an object it already
 * holds. Assigning `__proto__` there would let a model file change the behaviour of
 * every object in the process, so those keys are dropped and reported rather than
 * merged. Reported, because a model that contains one is either broken or hostile
 * and the reader should know which.
 */
function isUnsafeKey(key: string): boolean {
  return key === '__proto__' || key === 'constructor' || key === 'prototype';
}

/**
 * Create an own data property, rather than assigning to one.
 *
 * A plain `base[key] = value` runs a setter inherited from the prototype chain if
 * one exists, which is the second half of a pollution attack and survives any
 * key-based filter that misses a case. `defineProperty` cannot reach the prototype
 * at all, so the write is safe on its own terms and not only because the guard above
 * held. The descriptor matches what assignment would have produced.
 */
function define(base: Raw, key: string, value: unknown): void {
  Object.defineProperty(base, key, {
    value,
    writable: true,
    enumerable: true,
    configurable: true,
  });
}

/**
 * Merge an included document into the accumulator. Maps merge key-wise and arrays
 * concatenate; a scalar in the including file wins, so a parent can pin a title.
 */
function mergeInto(base: Raw, extra: Raw, path: string, diagnostics: Diagnostic[]): void {
  for (const [key, value] of Object.entries(extra)) {
    const here = path ? `${path}.${key}` : key;
    if (isUnsafeKey(key)) {
      diagnostics.push({
        severity: 'error',
        code: 'unsafe-key',
        message: `an included file sets "${key}", which is not a model field`,
        path: here,
        hint: 'that key reaches the JavaScript prototype chain and is never merged',
      });
      continue;
    }
    // Own properties only: an inherited one is not this document's to merge with.
    const existing = Object.prototype.hasOwnProperty.call(base, key)
      ? base[key]
      : undefined;
    if (existing === undefined) {
      define(base, key, value);
    } else if (Array.isArray(existing) && Array.isArray(value)) {
      define(base, key, [...existing, ...value]);
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
