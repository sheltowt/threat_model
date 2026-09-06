/**
 * SVG post-processing that is pure string work.
 *
 * Kept apart from `svg.ts` because that module pulls in a megabyte of Graphviz
 * compiled to WebAssembly. The HTML reporter only needs to strip a prolog before
 * embedding a diagram, and should not drag a compiler in to do it.
 */

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
