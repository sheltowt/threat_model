/**
 * DOT to SVG, using the WebAssembly build of Graphviz.
 *
 * There is deliberately no `child_process` here. Threagile and pytm both require a
 * system `dot` on PATH, which is the single most common reason their diagram step
 * fails in CI and on a developer laptop. `@viz-js/viz` ships Graphviz compiled to
 * WASM, so the only requirement is Node itself.
 */

import { instance } from '@viz-js/viz';
import { themeSvg } from './svg-text.js';

export interface SvgOptions {
  /** Graphviz layout engine. `dot` is the only one these diagrams are tuned for. */
  engine?: 'dot' | 'neato' | 'fdp' | 'circo' | 'twopi' | 'osage' | 'patchwork';
  /** Inject the light/dark `<style>` block. Default true. */
  themeAware?: boolean;
}

export { svgBody, themeSvg } from './svg-text.js';

/** Cached because instantiating the WASM module costs far more than a render. */
let vizPromise: ReturnType<typeof instance> | undefined;

function viz(): ReturnType<typeof instance> {
  vizPromise ??= instance();
  return vizPromise;
}

/** Render DOT to an SVG string. Throws with Graphviz's own diagnostics on bad DOT. */
export async function renderSvg(dot: string, options: SvgOptions = {}): Promise<string> {
  const v = await viz();
  const result = v.render(dot, {
    format: 'svg',
    engine: options.engine ?? 'dot',
  });
  if (result.status !== 'success') {
    const detail = result.errors.map((e) => e.message).join('\n') || 'unknown error';
    throw new Error(`tmc: graphviz failed to render the diagram:\n${detail}`);
  }
  return options.themeAware === false ? result.output : themeSvg(result.output);
}

/** Render DOT and write the SVG, creating the parent directory if needed. */
