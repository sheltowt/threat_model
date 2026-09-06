import { parseExpression, rootIdentifiers } from './expr/index.js';
import { ruleSchema, type Rule } from './rule.js';
import { BUILTIN_RULE_DATA } from './generated/rule-data.js';
import { IMPACT, LIKELIHOOD } from '@tmc/core/browser';

/**
 * Rule parsing and the built-in library, with no filesystem.
 *
 * The rule YAML is compiled in by `scripts/generate-data.mjs`, so the browser editor
 * evaluates the same rules as the CLI rather than shipping a second copy or asking a
 * server for them.
 */

export interface LoadedRule extends Rule {
  /** Where the rule came from, so `explain` can cite it. */
  source: string;
  builtin: boolean;
}

export interface RuleError {
  file: string;
  message: string;
}

export interface TemplatePart {
  text: string;
  expression: boolean;
}

/** Split `Unencrypted link {{ flow.id }}` into literal and expression parts. */
export function interpolationParts(template: string): TemplatePart[] {
  const parts: TemplatePart[] = [];
  let index = 0;
  for (;;) {
    const open = template.indexOf('{{', index);
    if (open === -1) break;
    const close = template.indexOf('}}', open + 2);
    if (close === -1) break;
    if (open > index) parts.push({ text: template.slice(index, open), expression: false });
    parts.push({ text: template.slice(open + 2, close).trim(), expression: true });
    index = close + 2;
  }
  if (index < template.length) parts.push({ text: template.slice(index), expression: false });
  return parts;
}

/**
 * The variables the engine binds for each scope. A rule may reference nothing else
 * at the root of an expression.
 */
const SCOPE_BINDINGS: Readonly<Record<Rule['scope'], readonly string[]>> = {
  element: ['element', 'el', 'model'],
  flow: ['flow', 'model'],
  boundary: ['boundary', 'model'],
  data: ['data', 'model'],
  model: ['model'],
};

/** A bare enum member such as `likely` is a value, not an expression to resolve. */
function isLiteralRating(source: string): boolean {
  const text = source.trim();
  return (
    (LIKELIHOOD as readonly string[]).includes(text) ||
    (IMPACT as readonly string[]).includes(text)
  );
}

/**
 * Parse every expression in a rule up front, so a typo fails immediately and names
 * the file rather than surfacing halfway through one particular analysis.
 *
 * The scope check matters more than it looks. An expression that reads an undefined
 * name yields UNKNOWN rather than raising, which is right for a field nobody
 * recorded but wrong for `element.internet_facing` written in a flow-scoped rule:
 * that rule would load, run, match nothing and report nothing, for ever. A rule that
 * is quietly inert is worse than one that fails loudly.
 */
export function checkExpressions(rule: Rule): void {
  const allowed = new Set(SCOPE_BINDINGS[rule.scope]);

  const check = (source: string, field: string): void => {
    const ast = parseExpression(source);
    for (const name of rootIdentifiers(ast)) {
      if (allowed.has(name)) continue;
      const others = Object.entries(SCOPE_BINDINGS)
        .filter(([, names]) => names.includes(name))
        .map(([scope]) => scope);
      const hint =
        others.length > 0
          ? ` "${name}" is bound in ${others.join(' and ')} scope, not ${rule.scope} scope.`
          : '';
      throw new Error(
        `${field} references "${name}", which is not available to a ${rule.scope} rule. ` +
          `Available: ${[...allowed].join(', ')}.${hint}`,
      );
    }
  };

  check(rule.match, 'match');
  for (const [field, source] of [
    ['likelihood', rule.likelihood],
    ['impact', rule.impact],
  ] as const) {
    if (source.trim() && !isLiteralRating(source)) check(source, field);
  }
  for (const part of interpolationParts(rule.risk_title ?? '')) {
    if (part.expression) check(part.text, 'risk_title');
  }
  for (const [i, source] of rule.id_suffix.entries()) {
    if (source.trim()) check(source, `id_suffix[${i}]`);
  }
}

/**
 * Validate one rule document. Every problem is collected against `source` rather
 * than thrown, so one bad rule does not hide the rest.
 */
export function parseRuleDocument(
  doc: unknown,
  source: string,
  builtin: boolean,
  errors: RuleError[],
): LoadedRule | undefined {
  const parsed = ruleSchema.safeParse(doc);
  if (!parsed.success) {
    for (const issue of parsed.error.issues) {
      const path = issue.path.join('.');
      errors.push({ file: source, message: `${path ? `${path}: ` : ''}${issue.message}` });
    }
    return undefined;
  }
  try {
    checkExpressions(parsed.data);
  } catch (err) {
    errors.push({ file: source, message: (err as Error).message });
    return undefined;
  }
  return { ...parsed.data, source, builtin };
}

/**
 * Collapse rules to one per id, later entries winning, and report a collision
 * between two rules of the same origin.
 */
export function dedupeRules(rules: readonly LoadedRule[], errors: RuleError[]): LoadedRule[] {
  const byId = new Map<string, LoadedRule>();
  for (const rule of rules) {
    const existing = byId.get(rule.id);
    if (existing && existing.builtin === rule.builtin) {
      errors.push({
        file: rule.source,
        message: `duplicate rule id "${rule.id}", also defined in ${existing.source}`,
      });
      continue;
    }
    byId.set(rule.id, rule);
  }
  return [...byId.values()].sort((a, b) => a.id.localeCompare(b.id));
}

let cached: LoadedRule[] | undefined;

/** The built-in rule library. Compiled in, so it works anywhere the code runs. */
export function builtinRules(): LoadedRule[] {
  if (cached) return cached;
  const errors: RuleError[] = [];
  const rules: LoadedRule[] = [];
  for (const entry of BUILTIN_RULE_DATA) {
    const rule = parseRuleDocument(entry.doc, entry.file, true, errors);
    if (rule) rules.push(rule);
  }
  if (errors.length > 0) {
    // A built-in that fails to parse is a build error, not a user error.
    throw new Error(
      `tmc: the built-in rule library is invalid:\n${errors
        .map((e) => `  ${e.file}: ${e.message}`)
        .join('\n')}`,
    );
  }
  cached = dedupeRules(rules, errors);
  return cached;
}
