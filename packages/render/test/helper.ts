import { fileURLToPath } from 'node:url';
import { buildGraph, loadModel, type ModelGraph } from 'tmac-core';

export const EXAMPLE = fileURLToPath(
  new URL('../../../examples/payment-service/threatmodel.yaml', import.meta.url),
);

export const HOSTILE = fileURLToPath(new URL('./fixtures/hostile.yaml', import.meta.url));

export function graphOf(file: string): ModelGraph {
  const { model, catalog } = loadModel(file);
  return buildGraph(model, catalog);
}
