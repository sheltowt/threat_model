import { readFileSync, readdirSync, existsSync, statSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, extname, join } from 'node:path';
import { parse as parseYaml } from 'yaml';
import { parseExpression, rootIdentifiers } from './expr/index.js';
import { ruleSchema, type Rule } from './rule.js';
import { IMPACT, LIKELIHOOD } from '@tmc/core';

export interface LoadedRule extends Rule {
  /** Absolute path the rule came from, so `explain` can point at it. */
  source: string;
  builtin: boolean;
}

export interface RuleLoadResult {
  rules: LoadedRule[];
  errors: { file: string; message: string }[];
}

const HERE = dirname(fileURLToPath(import.meta.url));

function builtinRuleDir(): string {
  for (const candidate of [join(HERE, '..', 'rules'), join(HERE, '..', '..', 'rules')]) {
    if (existsSync(candidate)) return candidate;
  }
  throw new Error('tmc: built-in rule directory not found next to the rules package');
}

function ruleFilesIn(dir: string): string[] {
  if (!existsSync(dir) || !statSync(dir).isDirectory()) return [];
  const out: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true }).sort((a, b) =>
    a.name.localeCompare(b.name),
  )) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      out.push(...ruleFilesIn(full));
    } else if (entry.name.endsWith('.rule.yaml') || entry.name.endsWith('.rule.yml')) {
      out.push(full);
    } else if (extname(entry.name) === '.yaml' && dir.endsWith('rules')) {
      out.push(full);
    }
  }
  return out;
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

/**
 * Parse every expression in a rule at load time rather than at first use, so a typo
 * in a rule shipped by a team fails the run immediately and names the file, instead
 * of surfacing halfway through an analysis of one particular model.
 *
 * The scope check matters more than it looks. An expression that reads an undefined
 * name yields UNKNOWN rather than raising, which is the right behaviour for a field
 * nobody recorded but the wrong behaviour for `element.internet_facing` written in a
 * flow-scoped rule: that rule would load, run, match nothing, and report nothing,
 * for ever. A rule that is quietly inert is worse than one that fails loudly.
 */
function checkExpressions(rule: Rule): void {
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

/** A bare enum member such as `likely` is a value, not an expression to resolve. */
function isLiteralRating(source: string): boolean {
  const text = source.trim();
  return (
    (LIKELIHOOD as readonly string[]).includes(text) ||
    (IMPACT as readonly string[]).includes(text)
  );
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

function loadFile(file: string, builtin: boolean, result: RuleLoadResult): void {
  let raw: unknown;
  try {
    raw = parseYaml(readFileSync(file, 'utf8'));
  } catch (err) {
    result.errors.push({ file, message: `not valid YAML: ${(err as Error).message}` });
    return;
  }
  // A file may hold one rule or a `rules:` list.
  const docs = Array.isArray((raw as { rules?: unknown[] })?.rules)
    ? ((raw as { rules: unknown[] }).rules)
    : [raw];

  for (const doc of docs) {
    const parsed = ruleSchema.safeParse(doc);
    if (!parsed.success) {
      for (const issue of parsed.error.issues) {
        const path = issue.path.join('.');
        result.errors.push({
          file,
          message: `${path ? `${path}: ` : ''}${issue.message}`,
        });
      }
      continue;
    }
    try {
      checkExpressions(parsed.data);
    } catch (err) {
      result.errors.push({ file, message: (err as Error).message });
      continue;
    }
    result.rules.push({ ...parsed.data, source: file, builtin });
  }
}

/**
 * Load the built-in library, then any project rules. A project rule that reuses a
 * built-in id replaces it, which is how a team retunes a noisy rule without
 * forking the tool.
 */
export function loadRules(projectDirs: readonly string[] = []): RuleLoadResult {
  const result: RuleLoadResult = { rules: [], errors: [] };

  for (const file of ruleFilesIn(builtinRuleDir())) loadFile(file, true, result);
  for (const dir of projectDirs) {
    for (const file of ruleFilesIn(dir)) loadFile(file, false, result);
  }

  const byId = new Map<string, LoadedRule>();
  for (const rule of result.rules) {
    const existing = byId.get(rule.id);
    if (existing && existing.builtin === rule.builtin) {
      result.errors.push({
        file: rule.source,
        message: `duplicate rule id "${rule.id}", also defined in ${existing.source}`,
      });
      continue;
    }
    byId.set(rule.id, rule);
  }

  result.rules = [...byId.values()].sort((a, b) => a.id.localeCompare(b.id));
  return result;
}
