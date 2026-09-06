import { ModelError, formatDiagnostic, validateModel, type Diagnostic } from '@tmc/core';
import { loadRules } from '@tmc/rules';
import { resolve } from 'node:path';
import { findModel, projectDir } from '../context.js';
import { bold, dim, green, plural, red, yellow } from '../ui.js';

export interface ValidateOptions {
  json?: boolean;
  /** Treat warnings as failures, for a strict CI gate. */
  strict?: boolean;
}

function print(diagnostics: Diagnostic[]): void {
  for (const d of diagnostics) {
    const colour = d.severity === 'error' ? red : yellow;
    process.stderr.write(`${colour(formatDiagnostic(d))}\n`);
  }
}

/** Schema and cross-reference check. Exit code 1 on any error. */
export function validate(file: string | undefined, options: ValidateOptions): number {
  const target = findModel(file);
  const result = validateModel(target);

  // Rules are validated too, since a broken project rule breaks every later command.
  const { errors: ruleErrors } = loadRules([resolve(projectDir(target), 'rules')]);
  const ruleDiagnostics: Diagnostic[] = ruleErrors.map((e) => ({
    severity: 'error' as const,
    code: 'rule',
    message: e.message,
    file: e.file,
  }));

  const diagnostics = [...result.diagnostics, ...ruleDiagnostics];
  const errors = diagnostics.filter((d) => d.severity === 'error');
  const warnings = diagnostics.filter((d) => d.severity === 'warning');

  if (options.json) {
    process.stdout.write(
      `${JSON.stringify({ file: target, ok: errors.length === 0, diagnostics }, null, 2)}\n`,
    );
    return errors.length > 0 || (options.strict && warnings.length > 0) ? 1 : 0;
  }

  print(diagnostics);

  if (errors.length > 0) {
    process.stderr.write(`\n${red(bold(`${plural(errors.length, 'error')}`))} in ${target}\n`);
    return 1;
  }
  if (warnings.length > 0) {
    process.stdout.write(
      `${green('Valid')} ${dim(target)} with ${yellow(plural(warnings.length, 'warning'))}\n`,
    );
    return options.strict ? 1 : 0;
  }
  process.stdout.write(`${green('Valid')} ${dim(target)}\n`);
  return 0;
}

export function reportModelError(err: unknown): number {
  if (err instanceof ModelError) {
    print(err.diagnostics);
    return 1;
  }
  throw err;
}
