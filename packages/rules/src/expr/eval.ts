import { comparableEnum, rankOf } from 'tmac-core/browser';
import type { MacroName, Node } from './ast.js';

/**
 * The third truth value.
 *
 * A security control that nobody has recorded is not the same as a control that is
 * absent. pytm conflates them, treating an unset boolean as false, which is why a
 * skeleton model there produces a wall of findings. Here an unrecorded control reads
 * as UNKNOWN, propagates through Kleene logic, and surfaces as a low-confidence
 * finding that names the gap instead of asserting the flaw. See ADR 0002.
 */
export const UNKNOWN = Symbol.for('tmac.unknown');
export type Unknown = typeof UNKNOWN;

export type Value =
  | string
  | number
  | boolean
  | null
  | Unknown
  | readonly Value[]
  | { readonly [key: string]: unknown };

export type TriState = 'true' | 'false' | 'unknown';

export class ExpressionRuntimeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ExpressionRuntimeError';
  }
}

export interface EvalOptions {
  /** Ceiling on evaluated nodes, so a pathological macro cannot stall a run. */
  maxSteps?: number;
  /** Hint naming the ordered enum for bare string comparisons. */
  enumHint?: Parameters<typeof rankOf>[1];
  /**
   * Collects the source text of every field selection that read as UNKNOWN. This is
   * what lets a low-confidence finding say "you have not recorded api.controls.hardened"
   * rather than leaving the reader to guess which gap produced it.
   */
  unknowns?: Set<string>;
}

/** Render a node back to source, used to name the field behind an UNKNOWN. */
export function renderNode(node: Node): string {
  switch (node.kind) {
    case 'literal':
      return typeof node.value === 'string' ? JSON.stringify(node.value) : String(node.value);
    case 'ident':
      return node.name;
    case 'member':
      return `${renderNode(node.object)}.${node.name}`;
    case 'index':
      return `${renderNode(node.object)}[${renderNode(node.index)}]`;
    case 'unary':
      return `${node.op}${renderNode(node.operand)}`;
    case 'binary':
      return `${renderNode(node.left)} ${node.op} ${renderNode(node.right)}`;
    case 'ternary':
      return `${renderNode(node.cond)} ? ${renderNode(node.then)} : ${renderNode(node.other)}`;
    case 'call':
      return `${node.name}(${node.args.map(renderNode).join(', ')})`;
    case 'macro':
      return `${renderNode(node.target)}.${node.name}(${node.variable}, ${renderNode(node.body)})`;
    case 'list':
      return `[${node.items.map(renderNode).join(', ')}]`;
    default:
      return '?';
  }
}

/** Property names that would reach the prototype chain and are never readable. */
const FORBIDDEN: ReadonlySet<string> = new Set([
  '__proto__',
  'constructor',
  'prototype',
  '__defineGetter__',
  '__defineSetter__',
  '__lookupGetter__',
  '__lookupSetter__',
]);

export function isUnknown(v: unknown): v is Unknown {
  return v === UNKNOWN;
}

export function triState(v: Value): TriState {
  if (isUnknown(v)) return 'unknown';
  return truthy(v) ? 'true' : 'false';
}

function truthy(v: Value): boolean {
  if (typeof v === 'boolean') return v;
  if (v === null) return false;
  if (typeof v === 'number') return v !== 0;
  if (typeof v === 'string') return v.length > 0;
  if (Array.isArray(v)) return v.length > 0;
  return true;
}

function typeName(v: Value): string {
  if (isUnknown(v)) return 'unknown';
  if (v === null) return 'null';
  if (Array.isArray(v)) return 'list';
  return typeof v;
}

/**
 * Compare two values, returning undefined when they are not ordered relative to one
 * another. Two members of the same ordered enum compare by ordinal, so
 * `'internal' < 'confidential'` is true where plain string comparison says the
 * opposite. This is the defect that ruled out cel-js.
 */
function compare(a: Value, b: Value, hint: EvalOptions['enumHint']): number | undefined {
  if (typeof a === 'number' && typeof b === 'number') return a - b;
  if (typeof a === 'string' && typeof b === 'string') {
    const shared = comparableEnum(a, b);
    if (shared) {
      const ra = rankOf(a, shared);
      const rb = rankOf(b, shared);
      if (ra !== undefined && rb !== undefined) return ra - rb;
    }
    if (hint) {
      const ra = rankOf(a, hint);
      const rb = rankOf(b, hint);
      if (ra !== undefined && rb !== undefined) return ra - rb;
    }
    return a < b ? -1 : a > b ? 1 : 0;
  }
  return undefined;
}

function deepEqual(a: Value, b: Value): boolean {
  if (a === b) return true;
  if (Array.isArray(a) && Array.isArray(b)) {
    return a.length === b.length && a.every((x, i) => deepEqual(x as Value, b[i] as Value));
  }
  return false;
}

type Fn = (args: Value[], ctx: Ctx) => Value;

interface Ctx {
  steps: { count: number };
  max: number;
  hint: EvalOptions['enumHint'];
  scope: ReadonlyMap<string, Value>;
  unknowns: Set<string> | undefined;
}

function requireString(v: Value, fn: string, position: number): string | Unknown {
  if (isUnknown(v)) return UNKNOWN;
  if (typeof v !== 'string') {
    throw new ExpressionRuntimeError(
      `${fn}() expects a string as argument ${position}, got ${typeName(v)}`,
    );
  }
  return v;
}

/**
 * The complete function table. Resolution never consults the scope or any host
 * object, so an expression cannot reach a function that is not listed here.
 */
const FUNCTIONS: Readonly<Record<string, Fn>> = Object.freeze({
  size: (args) => {
    const v = args[0];
    if (v === undefined || isUnknown(v)) return UNKNOWN;
    if (typeof v === 'string' || Array.isArray(v)) return v.length;
    if (v && typeof v === 'object') return Object.keys(v).length;
    return 0;
  },
  count: (args, ctx) => FUNCTIONS['size']!(args, ctx),
  /** True when the value was recorded at all, whatever it says. */
  known: (args) => !isUnknown(args[0] ?? UNKNOWN),
  /** The value, or the fallback when it was never recorded. */
  default: (args) => {
    const v = args[0] ?? UNKNOWN;
    return isUnknown(v) ? (args[1] ?? null) : v;
  },
  /** CEL's `has`: true when the selection produced a recorded, non-null value. */
  has: (args) => {
    const v = args[0] ?? UNKNOWN;
    return !isUnknown(v) && v !== null;
  },
  lower: (args) => {
    const s = requireString(args[0] ?? UNKNOWN, 'lower', 1);
    return isUnknown(s) ? UNKNOWN : s.toLowerCase();
  },
  upper: (args) => {
    const s = requireString(args[0] ?? UNKNOWN, 'upper', 1);
    return isUnknown(s) ? UNKNOWN : s.toUpperCase();
  },
  contains: (args) => {
    const s = requireString(args[0] ?? UNKNOWN, 'contains', 1);
    const needle = requireString(args[1] ?? UNKNOWN, 'contains', 2);
    if (isUnknown(s) || isUnknown(needle)) return UNKNOWN;
    return s.includes(needle);
  },
  startsWith: (args) => {
    const s = requireString(args[0] ?? UNKNOWN, 'startsWith', 1);
    const p = requireString(args[1] ?? UNKNOWN, 'startsWith', 2);
    if (isUnknown(s) || isUnknown(p)) return UNKNOWN;
    return s.startsWith(p);
  },
  endsWith: (args) => {
    const s = requireString(args[0] ?? UNKNOWN, 'endsWith', 1);
    const p = requireString(args[1] ?? UNKNOWN, 'endsWith', 2);
    if (isUnknown(s) || isUnknown(p)) return UNKNOWN;
    return s.endsWith(p);
  },
  matches: (args) => {
    const s = requireString(args[0] ?? UNKNOWN, 'matches', 1);
    const pattern = requireString(args[1] ?? UNKNOWN, 'matches', 2);
    if (isUnknown(s) || isUnknown(pattern)) return UNKNOWN;
    if (pattern.length > 200) {
      throw new ExpressionRuntimeError('matches() pattern is longer than 200 characters');
    }
    try {
      return new RegExp(pattern).test(s);
    } catch (err) {
      throw new ExpressionRuntimeError(`matches() pattern is not valid: ${(err as Error).message}`);
    }
  },
  int: (args) => {
    const v = args[0] ?? UNKNOWN;
    if (isUnknown(v)) return UNKNOWN;
    const n = Number(v as never);
    return Number.isFinite(n) ? Math.trunc(n) : UNKNOWN;
  },
  string: (args) => {
    const v = args[0] ?? UNKNOWN;
    if (isUnknown(v)) return UNKNOWN;
    if (v === null) return '';
    if (Array.isArray(v) || typeof v === 'object') {
      throw new ExpressionRuntimeError('string() expects a scalar');
    }
    return String(v);
  },
  min: (args) => numericFold(args, (a, b) => Math.min(a, b), 'min'),
  max: (args) => numericFold(args, (a, b) => Math.max(a, b), 'max'),
});

function numericFold(args: Value[], fold: (a: number, b: number) => number, name: string): Value {
  const flat = args.length === 1 && Array.isArray(args[0]) ? [...(args[0] as Value[])] : args;
  if (flat.length === 0) return UNKNOWN;
  let acc: number | undefined;
  for (const v of flat) {
    if (isUnknown(v)) return UNKNOWN;
    if (typeof v !== 'number') {
      throw new ExpressionRuntimeError(`${name}() expects numbers, got ${typeName(v)}`);
    }
    acc = acc === undefined ? v : fold(acc, v);
  }
  return acc ?? UNKNOWN;
}

export const FUNCTION_NAMES: readonly string[] = Object.keys(FUNCTIONS).sort();

function member(object: Value, name: string): Value {
  if (isUnknown(object) || object === null || object === undefined) return UNKNOWN;
  if (FORBIDDEN.has(name)) {
    throw new ExpressionRuntimeError(`property "${name}" is not readable`);
  }
  if (Array.isArray(object)) {
    // Lists expose only their length; everything else goes through size() or a macro.
    return name === 'length' ? object.length : UNKNOWN;
  }
  if (typeof object === 'string') {
    return name === 'length' ? object.length : UNKNOWN;
  }
  if (typeof object !== 'object') return UNKNOWN;
  if (!Object.prototype.hasOwnProperty.call(object, name)) return UNKNOWN;
  const value = (object as Record<string, unknown>)[name];
  if (value === undefined) return UNKNOWN;
  if (typeof value === 'function') {
    throw new ExpressionRuntimeError(`property "${name}" is not readable`);
  }
  return value as Value;
}

function evalMacro(name: MacroName, items: Value, run: (item: Value) => Value): Value {
  if (isUnknown(items)) return UNKNOWN;
  if (!Array.isArray(items)) {
    throw new ExpressionRuntimeError(`.${name}() applies to a list, got ${typeName(items)}`);
  }
  const list = items as readonly Value[];

  if (name === 'filter' || name === 'map') {
    const out: Value[] = [];
    for (const item of list) {
      const r = run(item);
      if (name === 'map') out.push(r);
      else if (triState(r) === 'true') out.push(item);
    }
    return out;
  }

  let sawUnknown = false;
  let trueCount = 0;
  for (const item of list) {
    const state = triState(run(item));
    if (state === 'unknown') sawUnknown = true;
    else if (state === 'true') trueCount++;
  }

  switch (name) {
    case 'exists':
      // One definite hit settles it; otherwise an unknown leaves the answer open.
      if (trueCount > 0) return true;
      return sawUnknown ? UNKNOWN : false;
    case 'exists_one':
      if (trueCount > 1) return false;
      if (sawUnknown) return UNKNOWN;
      return trueCount === 1;
    case 'all': {
      const definiteFalse = list.length - trueCount - (sawUnknown ? 1 : 0);
      if (definiteFalse > 0 && !sawUnknown) return trueCount === list.length;
      if (trueCount === list.length) return true;
      return sawUnknown ? UNKNOWN : false;
    }
    case 'none':
      if (trueCount > 0) return false;
      return sawUnknown ? UNKNOWN : true;
    default:
      return UNKNOWN;
  }
}

function evalNode(node: Node, ctx: Ctx): Value {
  if (++ctx.steps.count > ctx.max) {
    throw new ExpressionRuntimeError(`expression exceeded ${ctx.max} evaluation steps`);
  }

  switch (node.kind) {
    case 'literal':
      return node.value;

    case 'ident': {
      if (!ctx.scope.has(node.name)) return UNKNOWN;
      return ctx.scope.get(node.name)!;
    }

    case 'member': {
      const object = evalNode(node.object, ctx);
      const value = member(object, node.name);
      if (isUnknown(value) && !isUnknown(object) && ctx.unknowns) {
        ctx.unknowns.add(renderNode(node));
      }
      return value;
    }

    case 'index': {
      const object = evalNode(node.object, ctx);
      const index = evalNode(node.index, ctx);
      if (isUnknown(object) || isUnknown(index)) return UNKNOWN;
      if (Array.isArray(object)) {
        if (typeof index !== 'number') {
          throw new ExpressionRuntimeError('a list index must be a number');
        }
        const at = object[index];
        return at === undefined ? UNKNOWN : (at as Value);
      }
      if (typeof index !== 'string') {
        throw new ExpressionRuntimeError('a map key must be a string');
      }
      return member(object, index);
    }

    case 'unary': {
      const v = evalNode(node.operand, ctx);
      if (isUnknown(v)) return UNKNOWN;
      if (node.op === '!') return !truthy(v);
      if (typeof v !== 'number') {
        throw new ExpressionRuntimeError(`unary "-" expects a number, got ${typeName(v)}`);
      }
      return -v;
    }

    case 'ternary': {
      const state = triState(evalNode(node.cond, ctx));
      if (state === 'true') return evalNode(node.then, ctx);
      if (state === 'false') return evalNode(node.other, ctx);
      // With the condition unrecorded, an answer only exists if both arms agree.
      const a = evalNode(node.then, ctx);
      const b = evalNode(node.other, ctx);
      return deepEqual(a, b) ? a : UNKNOWN;
    }

    case 'list':
      return node.items.map((item) => evalNode(item, ctx));

    case 'call': {
      const fn = FUNCTIONS[node.name];
      if (!fn) {
        throw new ExpressionRuntimeError(
          `unknown function "${node.name}"; available: ${FUNCTION_NAMES.join(', ')}`,
        );
      }
      return fn(
        node.args.map((a) => evalNode(a, ctx)),
        ctx,
      );
    }

    case 'macro': {
      const target = evalNode(node.target, ctx);
      return evalMacro(node.name, target, (item) => {
        const scope = new Map(ctx.scope);
        scope.set(node.variable, item);
        return evalNode(node.body, { ...ctx, scope });
      });
    }

    case 'binary':
      return evalBinary(node, ctx);

    default:
      return UNKNOWN;
  }
}

function evalBinary(
  node: Extract<Node, { kind: 'binary' }>,
  ctx: Ctx,
): Value {
  // Kleene logic: short-circuit on the value that settles the answer alone.
  if (node.op === '&&') {
    const left = triState(evalNode(node.left, ctx));
    if (left === 'false') return false;
    const right = triState(evalNode(node.right, ctx));
    if (right === 'false') return false;
    return left === 'true' && right === 'true' ? true : UNKNOWN;
  }
  if (node.op === '||') {
    const left = triState(evalNode(node.left, ctx));
    if (left === 'true') return true;
    const right = triState(evalNode(node.right, ctx));
    if (right === 'true') return true;
    return left === 'false' && right === 'false' ? false : UNKNOWN;
  }

  const a = evalNode(node.left, ctx);
  const b = evalNode(node.right, ctx);

  if (node.op === 'in') {
    if (isUnknown(b)) return UNKNOWN;
    if (!Array.isArray(b)) {
      if (b && typeof b === 'object') {
        if (isUnknown(a) || typeof a !== 'string') return UNKNOWN;
        return Object.prototype.hasOwnProperty.call(b, a);
      }
      throw new ExpressionRuntimeError(`"in" expects a list on the right, got ${typeName(b)}`);
    }
    if (isUnknown(a)) return UNKNOWN;
    const items = b as readonly Value[];
    if (items.some((x) => deepEqual(x, a))) return true;
    return items.some(isUnknown) ? UNKNOWN : false;
  }

  if (isUnknown(a) || isUnknown(b)) return UNKNOWN;

  switch (node.op) {
    case '==':
      return deepEqual(a, b);
    case '!=':
      return !deepEqual(a, b);
    case '<':
    case '<=':
    case '>':
    case '>=': {
      const c = compare(a, b, ctx.hint);
      if (c === undefined) {
        throw new ExpressionRuntimeError(
          `cannot order ${typeName(a)} against ${typeName(b)} with "${node.op}"`,
        );
      }
      if (node.op === '<') return c < 0;
      if (node.op === '<=') return c <= 0;
      if (node.op === '>') return c > 0;
      return c >= 0;
    }
    case '+':
      if (typeof a === 'string' && typeof b === 'string') return a + b;
      if (Array.isArray(a) && Array.isArray(b)) return [...a, ...b];
      if (typeof a === 'number' && typeof b === 'number') return a + b;
      throw new ExpressionRuntimeError(`cannot add ${typeName(a)} and ${typeName(b)}`);
    case '-':
    case '*':
    case '/':
    case '%': {
      if (typeof a !== 'number' || typeof b !== 'number') {
        throw new ExpressionRuntimeError(
          `"${node.op}" expects numbers, got ${typeName(a)} and ${typeName(b)}`,
        );
      }
      if ((node.op === '/' || node.op === '%') && b === 0) {
        throw new ExpressionRuntimeError('division by zero');
      }
      if (node.op === '-') return a - b;
      if (node.op === '*') return a * b;
      if (node.op === '/') return a / b;
      return a % b;
    }
    default:
      return UNKNOWN;
  }
}

/** Evaluate a parsed expression against a scope. Never mutates the scope. */
export function evaluate(
  node: Node,
  scope: Record<string, unknown>,
  options: EvalOptions = {},
): Value {
  const ctx: Ctx = {
    steps: { count: 0 },
    max: options.maxSteps ?? 200_000,
    hint: options.enumHint,
    scope: new Map(Object.entries(scope)) as ReadonlyMap<string, Value>,
    unknowns: options.unknowns,
  };
  return evalNode(node, ctx);
}
