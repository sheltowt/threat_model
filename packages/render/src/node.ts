import { mkdir, writeFile } from 'node:fs/promises';
import { dirname } from 'node:path';
import { renderSvg, type SvgOptions } from './svg.js';

/** Render a diagram and write it, creating the directory if it is missing. */
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
