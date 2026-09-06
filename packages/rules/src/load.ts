import { readFileSync, readdirSync, existsSync, statSync } from 'node:fs';
import { extname, join } from 'node:path';
import { parse as parseYaml } from 'yaml';
import {
  builtinRules,
  dedupeRules,
  parseRuleDocument,
  type LoadedRule,
  type RuleError,
} from './builtin.js';

export * from './builtin.js';

export interface RuleLoadResult {
  rules: LoadedRule[];
  errors: RuleError[];
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

function loadFile(file: string, result: RuleLoadResult): void {
  let raw: unknown;
  try {
    raw = parseYaml(readFileSync(file, 'utf8'));
  } catch (err) {
    result.errors.push({ file, message: `not valid YAML: ${(err as Error).message}` });
    return;
  }
  // A file may hold one rule or a `rules:` list.
  const docs = Array.isArray((raw as { rules?: unknown[] })?.rules)
    ? (raw as { rules: unknown[] }).rules
    : [raw];

  for (const doc of docs) {
    const rule = parseRuleDocument(doc, file, false, result.errors);
    if (rule) result.rules.push(rule);
  }
}

/**
 * The built-in library plus any project rules found in the given directories.
 *
 * A project rule that reuses a built-in id replaces it, which is how a team retunes
 * a noisy rule without forking the tool.
 */
export function loadRules(projectDirs: readonly string[] = []): RuleLoadResult {
  const result: RuleLoadResult = { rules: [...builtinRules()], errors: [] };
  for (const dir of projectDirs) {
    for (const file of ruleFilesIn(dir)) loadFile(file, result);
  }
  result.rules = dedupeRules(result.rules, result.errors);
  return result;
}
