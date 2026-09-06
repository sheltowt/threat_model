/**
 * DOT to SVG, using the WebAssembly build of Graphviz.
 *
 * There is deliberately no `child_process` here. Threagile and pytm both require a
 * system `dot` on PATH, which is the single most common reason their diagram step
 * fails in CI and on a developer laptop. `@viz-js/viz` ships Graphviz compiled to
 * WASM, so the only requirement is Node itself.
 */

import { instance } from '@viz-js/viz';
import { mkdir, writeFile } from 'node:fs/promises';
import { dirname } from 'node:path';

export interface SvgOptions {
  /** Graphviz layout engine. `dot` is the only one these diagrams are tuned for. */
  engine?: 'dot' | 'neato' | 'fdp' | 'circo' | 'twopi' | 'osage' | 'patchwork';
  /** Inject the light/dark `<style>` block. Default true. */
  themeAware?: boolean;
}

/**
 * The one place SVG text colour is decided.
 *
 * Node fills are pale in both themes, so node text stays dark and is left alone.
 * Only the labels that sit directly on the page background — edge labels, cluster
 * labels and the graph title — need to flip, along with the cluster outlines. A CSS
 * rule beats a presentation attribute (`fill="#000000"`) on specificity, so this
 * overrides what Graphviz emitted without any string surgery on the shapes.
 */
const THEME_STYLE = `<style>
svg { color-scheme: light dark; }
@media (prefers-color-scheme: dark) {
  .edge text, .cluster text, .graph > text { fill: #e8eaed; }
  .cluster > polygon, .cluster > path { stroke: #5f6771; }
  .node > polygon[fill="none"], .node > ellipse[fill="none"] { stroke: #9aa0a6; }
}
</style>`;

/**
 * Insert the theme block immediately after the opening `<svg>` tag.
 *
 * Deliberately the simplest thing that works: one regex, one insertion, and an
 * untouched document if the input is not an SVG at all. Parsing the SVG to do this
 * would buy nothing and would give a malformed render a second way to fail.
 */
export function themeSvg(svg: string): string {
  const open = /<svg\b[^>]*>/.exec(svg);
  if (!open) return svg;
  const at = open.index + open[0].length;
  return `${svg.slice(0, at)}\n${THEME_STYLE}${svg.slice(at)}`;
}

/**
 * Strip the XML prologue and doctype so the result can be dropped straight into an
 * HTML document, where both are invalid.
 */
export function svgBody(svg: string): string {
  return svg
    .replace(/^﻿/, '')
    .replace(/<\?xml[\s\S]*?\?>/g, '')
    .replace(/<!DOCTYPE[\s\S]*?>/gi, '')
    .replace(/<!--[\s\S]*?-->/g, '')
    .trim();
}

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
export async function renderToFile(
  dot: string,
  path: string,
  options: SvgOptions = {},
): Promise<string> {
  const svg = await renderSvg(dot, options);
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, svg, 'utf8');
  return svg;
}
