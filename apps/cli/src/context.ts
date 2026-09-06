import { existsSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { buildGraph, loadModel, type LoadResult, type ModelGraph } from 'tmac-core';
import { loadRules, type LoadedRule } from 'tmac-rules';

export const DEFAULT_MODEL = 'threatmodel.yaml';

/** Walk up from the working directory looking for a model file. */
export function findModel(explicit?: string): string {
  if (explicit) return resolve(explicit);
  let dir = process.cwd();
  for (;;) {
    const candidate = resolve(dir, DEFAULT_MODEL);
    if (existsSync(candidate)) return candidate;
    const parent = dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return resolve(DEFAULT_MODEL);
}

export interface Context {
  file: string;
  load: LoadResult;
  graph: ModelGraph;
  rules: LoadedRule[];
  ruleErrors: { file: string; message: string }[];
}

export function projectDir(file: string): string {
  return resolve(dirname(file), '.tmac');
}

export function open(file: string): Context {
  const load = loadModel(file);
  const graph = buildGraph(load.model, load.catalog);
  const { rules, errors } = loadRules([resolve(projectDir(file), 'rules')]);
  return { file, load, graph, rules, ruleErrors: errors };
}
