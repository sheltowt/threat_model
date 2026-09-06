import type { ModelGraph } from '@tmc/core/browser';

/**
 * Graphviz is a megabyte of compiled WASM, and most of it is only needed once
 * somebody actually looks at a diagram. Loading it on demand keeps the first paint
 * to the app itself; the module caches after the first call.
 */
type RenderModule = typeof import('@tmc/render/browser');

let pending: Promise<RenderModule> | undefined;

export function renderModule(): Promise<RenderModule> {
  pending ??= import('@tmc/render/browser');
  return pending;
}

export async function dataFlowSvg(
  graph: ModelGraph,
  options: { risks?: unknown[]; leftToRight?: boolean } = {},
): Promise<string> {
  const { dataFlowDot, renderSvg } = await renderModule();
  const dot = dataFlowDot(graph, {
    ...(options.risks ? { risks: options.risks as never } : {}),
    ...(options.leftToRight ? { layout: 'left-to-right' as const } : {}),
  });
  return renderSvg(dot);
}

export async function dataAssetSvg(graph: ModelGraph): Promise<string> {
  const { dataAssetDot, renderSvg } = await renderModule();
  return renderSvg(dataAssetDot(graph));
}
