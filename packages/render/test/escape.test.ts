import { describe, expect, it } from 'vitest';
import { dataAssetDot, dataFlowDot, escapeLabel, renderSvg } from '@tmc/render';
import { graphOf, HOSTILE } from './helper.js';

/**
 * Label injection is the one bug in this package that would matter. A model file is
 * untrusted input — it arrives by pull request — and a name that closes the quoted
 * string can append arbitrary DOT attributes, including `image=` pointing at a local
 * file that Graphviz would then read and embed.
 */
describe('escapeLabel', () => {
  it('neutralises every DOT metacharacter', () => {
    expect(escapeLabel('a "quoted" name')).toBe('a \\"quoted\\" name');
    expect(escapeLabel('back\\slash')).toBe('back\\\\slash');
    expect(escapeLabel('line one\nline two')).toBe('line one\\nline two');
    expect(escapeLabel('windows\r\nnewline')).toBe('windows\\nnewline');
    expect(escapeLabel('bare\rreturn')).toBe('bare\\nreturn');
    expect(escapeLabel('tab\there')).toBe('tab here');
  });

  it('escapes the backslash before anything that introduces one', () => {
    // A naive implementation that escapes quotes first turns `\"` into `\\"`, which
    // is a literal backslash followed by an unescaped quote: the string ends there.
    expect(escapeLabel('\\"')).toBe('\\\\\\"');
  });

  it('leaves braces and angle brackets as inert text', () => {
    // Safe only because every emitted string is quoted; an HTML-like label is one
    // that begins with an *unquoted* `<`, and record fields need an unquoted `{`.
    expect(escapeLabel('{a|b}')).toBe('{a|b}');
    expect(escapeLabel('<b>bold</b>')).toBe('<b>bold</b>');
  });

  it('drops control characters rather than emitting them raw', () => {
    expect(escapeLabel('null\u0000and\u001bescape')).toBe('nullandescape');
  });

  it('handles the hostile kitchen sink in one go', () => {
    const hostile = '" ]; a -> b [label="x"] // {braces} <angles> \\ \n end';
    const escaped = escapeLabel(hostile);
    expect(escaped).not.toMatch(/(^|[^\\])"/);
    expect(escaped).not.toContain('\n');
  });

  it('is total: undefined and null become the empty string', () => {
    expect(escapeLabel(undefined)).toBe('');
    expect(escapeLabel(null)).toBe('');
    expect(escapeLabel(42)).toBe('42');
  });
});

describe('a model built to inject DOT', () => {
  const graph = graphOf(HOSTILE);

  for (const [name, dot] of [
    ['data flow', dataFlowDot(graph)],
    ['data asset', dataAssetDot(graph)],
    ['data flow with risks', dataFlowDot(graph, { risks: [] })],
  ] as const) {
    describe(name, () => {
      it('emits balanced quotes on every line', () => {
        for (const line of dot.split('\n')) {
          const quotes = (line.match(/(?<!\\)(?:\\\\)*"/g) ?? []).length;
          expect(quotes % 2, `unbalanced quotes in: ${line}`).toBe(0);
        }
      });

      it('never lets an injected attribute reach the graph', () => {
        // These names appear verbatim in the fixture. If any of them survives as a
        // real attribute rather than as label text, the escaping failed.
        const outsideStrings = dot.replace(/"(?:[^"\\]|\\.)*"/g, '""');
        expect(outsideStrings).not.toContain('image=');
        expect(outsideStrings).not.toContain('URL=');
        expect(outsideStrings).not.toContain('system(');
        expect(outsideStrings).not.toContain('digraph evil');
      });

      it('opens exactly one graph', () => {
        expect(dot.match(/^digraph /gm)?.length).toBe(1);
      });

      it('still renders', async () => {
        const svg = await renderSvg(dot);
        expect(svg).toContain('<svg');
        // Graphviz would have refused or mangled the layout on malformed DOT.
        expect(svg).toContain('</svg>');
      });
    });
  }
});
