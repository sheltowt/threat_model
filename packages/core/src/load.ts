import { readFileSync, existsSync } from 'node:fs';
import { dirname, isAbsolute, resolve } from 'node:path';
import { parse as parseYaml } from 'yaml';
import { modelSchema, type Model } from './schema.js';
import { type Diagnostic, ModelError, suggest } from './diagnostics.js';
import { BOUNDARY_TYPE, type BoundaryType } from './enums.js';
import { builtinCatalog, loadCatalog, type Catalog } from './catalog.js';

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

function isPlainObject(v: unknown): v is Raw {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

/**
 * Merge an included document into the accumulator. Maps merge key-wise and arrays
 * concatenate; a scalar in the including file wins, so a parent can pin a title.
 * Threagile supports includes but leaves the merge semantics undocumented, which
 * makes multi-file models hard to reason about.
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

/** Turn Zod issues into diagnostics that name the offending path in model terms. */
function zodDiagnostics(error: unknown, file: string): Diagnostic[] {
  const issues = (error as { issues?: unknown[] }).issues;
  if (!Array.isArray(issues)) {
    return [
      { severity: 'error', code: 'schema', message: String((error as Error).message), file },
    ];
  }
  return issues.map((raw) => {
    const issue = raw as { path?: (string | number)[]; message?: string; code?: string };
    const path = (issue.path ?? [])
      .map((p) => (typeof p === 'number' ? `[${p}]` : p))
      .join('.')
      .replace(/\.\[/g, '[');
    const d: Diagnostic = {
      severity: 'error',
      code: 'schema',
      message: issue.message ?? 'invalid value',
      file,
    };
    if (path) d.path = path;
    if (issue.code === 'unrecognized_keys') {
      d.hint = 'unknown keys are rejected so a typo cannot silently disable a control';
    }
    return d;
  });
}

/**
 * Cross-reference checks the schema cannot express: every id a model mentions must
 * exist, boundaries must not overlap or loop, and every element must be reachable
 * from at least one flow or explicitly stand alone.
 */
function checkReferences(model: Model, catalog: Catalog, diagnostics: Diagnostic[]): void {
  const elementIds = new Set(Object.keys(model.elements));
  const dataIds = new Set(Object.keys(model.data_assets));
  const boundaryIds = new Set(Object.keys(model.trust_boundaries));
  const flowIds = new Set<string>();

  const ref = (
    value: string,
    pool: Set<string>,
    path: string,
    what: string,
  ): void => {
    if (pool.has(value)) return;
    const near = suggest(value, pool);
    const d: Diagnostic = {
      severity: 'error',
      code: 'unknown-reference',
      message: `${what} "${value}" is not defined`,
      path,
    };
    if (near) d.hint = `did you mean "${near}"?`;
    diagnostics.push(d);
  };

  for (const [id, el] of Object.entries(model.elements)) {
    if (!catalog.technologies.has(el.technology)) {
      const near = suggest(el.technology, catalog.technologies.keys());
      diagnostics.push({
        severity: 'error',
        code: 'unknown-technology',
        message: `technology "${el.technology}" is not in the catalogue`,
        path: `elements.${id}.technology`,
        hint: near
          ? `did you mean "${near}"? Otherwise add it to .tmc/technologies.yaml`
          : 'add it to .tmc/technologies.yaml to extend the catalogue',
      });
    }
    el.processes.forEach((d, i) =>
      ref(d, dataIds, `elements.${id}.processes[${i}]`, 'data asset'),
    );
    el.stores.forEach((d, i) => ref(d, dataIds, `elements.${id}.stores[${i}]`, 'data asset'));
    if (el.out_of_scope && !el.justification_out_of_scope) {
      diagnostics.push({
        severity: 'warning',
        code: 'unjustified-scope',
        message: `element "${id}" is out of scope with no justification`,
        path: `elements.${id}.justification_out_of_scope`,
        hint: 'an unexplained exclusion is the most common way a real risk disappears',
      });
    }
  }

  for (const [i, flow] of model.flows.entries()) {
    if (flowIds.has(flow.id)) {
      diagnostics.push({
        severity: 'error',
        code: 'duplicate-id',
        message: `flow id "${flow.id}" is used more than once`,
        path: `flows[${i}].id`,
      });
    }
    flowIds.add(flow.id);
    ref(flow.from, elementIds, `flows[${i}].from`, 'element');
    ref(flow.to, elementIds, `flows[${i}].to`, 'element');
    if (!catalog.protocols.has(flow.protocol)) {
      const near = suggest(flow.protocol, catalog.protocols.keys());
      diagnostics.push({
        severity: 'error',
        code: 'unknown-protocol',
        message: `protocol "${flow.protocol}" is not in the catalogue`,
        path: `flows[${i}].protocol`,
        hint: near ? `did you mean "${near}"?` : 'add it to .tmc/protocols.yaml',
      });
    }
    flow.sends.forEach((d, j) => ref(d, dataIds, `flows[${i}].sends[${j}]`, 'data asset'));
    flow.receives.forEach((d, j) => ref(d, dataIds, `flows[${i}].receives[${j}]`, 'data asset'));
    if (flow.from === flow.to) {
      diagnostics.push({
        severity: 'warning',
        code: 'self-flow',
        message: `flow "${flow.id}" connects "${flow.from}" to itself`,
        path: `flows[${i}]`,
      });
    }
  }

  // Boundary membership must be a forest: one parent per element and per boundary.
  const elementOwner = new Map<string, string>();
  const boundaryParent = new Map<string, string>();
  for (const [id, b] of Object.entries(model.trust_boundaries)) {
    if (!BOUNDARY_TYPE.includes(b.type as BoundaryType)) continue;
    b.contains.forEach((e, i) => {
      ref(e, elementIds, `trust_boundaries.${id}.contains[${i}]`, 'element');
      const owner = elementOwner.get(e);
      if (owner !== undefined) {
        diagnostics.push({
          severity: 'error',
          code: 'boundary-overlap',
          message: `element "${e}" is inside both "${owner}" and "${id}"`,
          path: `trust_boundaries.${id}.contains[${i}]`,
          hint: 'nest one boundary inside the other instead of listing the element twice',
        });
      } else {
        elementOwner.set(e, id);
      }
    });
    b.nested.forEach((n, i) => {
      ref(n, boundaryIds, `trust_boundaries.${id}.nested[${i}]`, 'trust boundary');
      const parent = boundaryParent.get(n);
      if (parent !== undefined) {
        diagnostics.push({
          severity: 'error',
          code: 'boundary-overlap',
          message: `trust boundary "${n}" is nested inside both "${parent}" and "${id}"`,
          path: `trust_boundaries.${id}.nested[${i}]`,
        });
      } else {
        boundaryParent.set(n, id);
      }
    });
  }
  // Reject nesting cycles.
  for (const start of boundaryIds) {
    const seen = new Set<string>();
    let cur: string | undefined = start;
    while (cur !== undefined) {
      if (seen.has(cur)) {
        diagnostics.push({
          severity: 'error',
          code: 'boundary-cycle',
          message: `trust boundary nesting forms a cycle through "${cur}"`,
          path: `trust_boundaries.${cur}.nested`,
        });
        break;
      }
      seen.add(cur);
      cur = boundaryParent.get(cur);
    }
  }

  for (const [id, rt] of Object.entries(model.shared_runtimes)) {
    rt.runs.forEach((e, i) => ref(e, elementIds, `shared_runtimes.${id}.runs[${i}]`, 'element'));
  }
  for (const [i, a] of model.assumptions.entries()) {
    if (a.suppresses.length === 0) continue;
    for (const [j, s] of a.suppresses.entries()) {
      if (!/^[a-z0-9-]+@/.test(s) && s !== '*') {
        diagnostics.push({
          severity: 'warning',
          code: 'suppression-shape',
          message: `"${s}" does not look like a synthetic risk id`,
          path: `assumptions[${i}].suppresses[${j}]`,
          hint: 'the form is rule-id@subject-id, for example unencrypted-communication@api_to_db',
        });
      }
    }
  }
  for (const [i, t] of model.manual_threats.entries()) {
    if (t.element) ref(t.element, elementIds, `manual_threats[${i}].element`, 'element');
    if (t.flow) ref(t.flow, flowIds, `manual_threats[${i}].flow`, 'flow');
  }
}

/** Read, merge, validate and cross-check a model file. Throws on any error. */
export function loadModel(file: string, options: LoadOptions = {}): LoadResult {
  const diagnostics: Diagnostic[] = [];
  const abs = resolve(file);
  const { raw, sources } = resolveIncludes(abs, diagnostics, options.maxIncludeDepth ?? 10);

  const parsed = modelSchema.safeParse(raw);
  if (!parsed.success) {
    throw new ModelError([...diagnostics, ...zodDiagnostics(parsed.error, abs)]);
  }

  const catalogDirs = options.catalogDirs ?? [resolve(dirname(abs), '.tmc')];
  const catalog = catalogDirs.length > 0 ? loadCatalog(catalogDirs) : builtinCatalog();

  checkReferences(parsed.data, catalog, diagnostics);
  if (diagnostics.some((d) => d.severity === 'error')) throw new ModelError(diagnostics);

  return { model: parsed.data, catalog, sources, diagnostics };
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
