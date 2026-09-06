import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { expect } from 'vitest';
import { buildGraph, loadModel, type ModelGraph } from '@tmc/core';
import { analyze, loadRules, type Analysis, type LoadedRule } from '@tmc/rules';

export const EXAMPLE = fileURLToPath(
  new URL('../../../examples/payment-service/threatmodel.yaml', import.meta.url),
);

/** A fixed timestamp, so every golden file is reproducible. */
export const FIXED_NOW = '2026-09-06T12:00:00Z';

export interface Fixture {
  graph: ModelGraph;
  rules: LoadedRule[];
  analysis: Analysis;
}

let cached: Fixture | undefined;

export function fixture(): Fixture {
  if (cached) return cached;
  const { model, catalog } = loadModel(EXAMPLE);
  const graph = buildGraph(model, catalog);
  const { rules } = loadRules();
  cached = { graph, rules, analysis: analyze(graph, rules) };
  return cached;
}

export function goldenPath(name: string): string {
  return fileURLToPath(new URL(`./golden/${name}`, import.meta.url));
}

/**
 * Compare against a committed expected file. Run with `UPDATE_GOLDEN=1` to rewrite
 * them after a deliberate change, then read the diff before committing.
 */
export function expectGolden(path: string, actual: string): void {
  if (process.env['UPDATE_GOLDEN'] === '1' || !existsSync(path)) {
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, actual, 'utf8');
    if (process.env['UPDATE_GOLDEN'] !== '1') {
      throw new Error(`golden file ${path} did not exist; it has been written, review it`);
    }
    return;
  }
  expect(actual).toBe(readFileSync(path, 'utf8'));
}
