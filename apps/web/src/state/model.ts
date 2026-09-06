import {
  buildGraph,
  builtinCatalog,
  tryParseModelText,
  type Diagnostic,
  type Model,
  type ModelGraph,
} from 'tmac-core/browser';
import { analyze, builtinRules, type Analysis } from 'tmac-rules/browser';

/**
 * The model text is the single source of truth.
 *
 * Everything else here is derived from it. There is no separate in-memory object
 * graph that the editor mutates and later serialises, because that is exactly how a
 * GUI and its file format drift apart. An edit rewrites the text; the text is
 * reparsed; the graph, the findings and the diagram all fall out of that.
 */

export interface ModelState {
  /** Where this came from, shown in the header. */
  name: string;
  text: string;
  /** Present when the text parses. */
  model?: Model;
  graph?: ModelGraph;
  analysis?: Analysis;
  diagnostics: Diagnostic[];
  /** True when the text is valid enough to analyse. */
  ok: boolean;
  /** Milliseconds spent parsing and analysing, shown in the status bar. */
  elapsedMs: number;
}

export const EMPTY: ModelState = {
  name: 'no model',
  text: '',
  diagnostics: [],
  ok: false,
  elapsedMs: 0,
};

/**
 * Parse and analyse. Errors become diagnostics rather than exceptions, because a
 * half-typed model is the normal state of an editor and must not blank the screen.
 */
export function evaluateModel(name: string, text: string): ModelState {
  const started = performance.now();
  const catalog = builtinCatalog();
  const parsed = tryParseModelText(text, catalog, { source: name });

  if (!parsed.ok || !parsed.model) {
    return {
      name,
      text,
      diagnostics: parsed.diagnostics,
      ok: false,
      elapsedMs: performance.now() - started,
    };
  }

  const graph = buildGraph(parsed.model, catalog);
  let analysis: Analysis | undefined;
  const diagnostics = [...parsed.diagnostics];
  try {
    analysis = analyze(graph, builtinRules());
  } catch (err) {
    diagnostics.push({
      severity: 'error',
      code: 'analysis',
      message: `the rules could not run: ${(err as Error).message}`,
    });
  }

  return {
    name,
    text,
    model: parsed.model,
    graph,
    analysis,
    diagnostics,
    ok: true,
    elapsedMs: performance.now() - started,
  };
}

/** The example that ships with the app, so a first visit shows something real. */
export async function loadExample(): Promise<{ name: string; text: string }> {
  const response = await fetch(new URL('../example.yaml', import.meta.url));
  if (!response.ok) throw new Error(`could not load the example: ${response.status}`);
  return { name: 'payment-service (example)', text: await response.text() };
}

/**
 * Fetch a model named in the URL, so a link can carry one.
 *
 * Cross-origin fetches are subject to the other site's CORS policy, which is the
 * browser's decision and not ours to work around. A raw file URL from a git host
 * usually works; a repository page does not.
 */
export async function loadFromUrl(url: string): Promise<{ name: string; text: string }> {
  const response = await fetch(url, { redirect: 'follow' });
  if (!response.ok) {
    throw new Error(`${response.status} ${response.statusText} fetching ${url}`);
  }
  const text = await response.text();
  const name = url.split('/').pop() || url;
  return { name, text };
}

export interface UrlTarget {
  kind: 'url' | 'gist' | 'none';
  value?: string;
}

/** Read `?model=<url>` from the address bar. */
export function urlTarget(search: string): UrlTarget {
  const params = new URLSearchParams(search);
  const model = params.get('model');
  if (model) return { kind: 'url', value: model };
  return { kind: 'none' };
}
