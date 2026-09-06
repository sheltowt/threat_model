import { parse as parseYaml } from 'yaml';
import { modelSchema, type Model } from './schema.js';
import { type Diagnostic, ModelError, suggest } from './diagnostics.js';
import { BOUNDARY_TYPE, type BoundaryType } from './enums.js';
import type { Catalog } from './catalog-core.js';

/**
 * Parsing and validation with no filesystem.
 *
 * `load.ts` adds file reading and include resolution on top. Everything the browser
 * editor needs lives here, so the CLI and the editor cannot disagree about whether a
 * model is valid.
 */

export interface ParseOptions {
  /** Shown in diagnostics. Any label will do; it is never opened. */
  source?: string;
}

export interface ParseResult {
  model: Model;
  diagnostics: Diagnostic[];
}

export function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

/** Turn Zod issues into diagnostics that name the offending path in model terms. */
export function zodDiagnostics(error: unknown, file: string): Diagnostic[] {
  const issues = (error as { issues?: unknown[] }).issues;
  if (!Array.isArray(issues)) {
    return [{ severity: 'error', code: 'schema', message: String((error as Error).message), file }];
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
 * exist, boundaries must not overlap or loop, and an exclusion must be explained.
 */
export function checkReferences(
  model: Model,
  catalog: Catalog,
  diagnostics: Diagnostic[],
): void {
  const elementIds = new Set(Object.keys(model.elements));
  const dataIds = new Set(Object.keys(model.data_assets));
  const boundaryIds = new Set(Object.keys(model.trust_boundaries));
  const flowIds = new Set<string>();

  const ref = (value: string, pool: Set<string>, path: string, what: string): void => {
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
          ? `did you mean "${near}"? Otherwise add it to .tmac/technologies.yaml`
          : 'add it to .tmac/technologies.yaml to extend the catalogue',
      });
    }
    el.processes.forEach((d, i) => ref(d, dataIds, `elements.${id}.processes[${i}]`, 'data asset'));
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
        hint: near ? `did you mean "${near}"?` : 'add it to .tmac/protocols.yaml',
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

/** Validate an already-parsed document. Throws `ModelError` on any error. */
export function parseModelDocument(
  raw: unknown,
  catalog: Catalog,
  options: ParseOptions = {},
): ParseResult {
  const source = options.source ?? 'model';
  const diagnostics: Diagnostic[] = [];

  const parsed = modelSchema.safeParse(raw);
  if (!parsed.success) throw new ModelError(zodDiagnostics(parsed.error, source));

  checkReferences(parsed.data, catalog, diagnostics);
  if (diagnostics.some((d) => d.severity === 'error')) throw new ModelError(diagnostics);

  return { model: parsed.data, diagnostics };
}

/** Parse YAML or JSON text into a validated model. Throws `ModelError`. */
export function parseModelText(
  text: string,
  catalog: Catalog,
  options: ParseOptions = {},
): ParseResult {
  const source = options.source ?? 'model';
  let doc: unknown;
  try {
    doc = parseYaml(text, { merge: true });
  } catch (err) {
    throw new ModelError([
      { severity: 'error', code: 'yaml', message: (err as Error).message, file: source },
    ]);
  }
  if (doc === null || doc === undefined) doc = {};
  if (!isPlainObject(doc)) {
    throw new ModelError([
      {
        severity: 'error',
        code: 'yaml',
        message: 'a threat model file must contain a YAML mapping at the top level',
        file: source,
      },
    ]);
  }
  return parseModelDocument(doc, catalog, options);
}

/** Parse without throwing; returns every diagnostic found. */
export function tryParseModelText(
  text: string,
  catalog: Catalog,
  options: ParseOptions = {},
): { ok: boolean; diagnostics: Diagnostic[]; model?: Model } {
  try {
    const result = parseModelText(text, catalog, options);
    return { ok: true, diagnostics: result.diagnostics, model: result.model };
  } catch (err) {
    if (err instanceof ModelError) return { ok: false, diagnostics: err.diagnostics };
    throw err;
  }
}
