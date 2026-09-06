import { describe, expect, it } from 'vitest';
import { oneLine, prose, toMarkdown, toSarif } from '@tmc/report';
import { FIXED_NOW, fixture } from './helper.js';

/**
 * Reports are built from rule and model prose, which arrives in a repository and is
 * not trusted. These are the CodeQL findings on that path, written as tests.
 */

describe('whitespace collapsing (js/polynomial-redos)', () => {
  it('collapses a folded scalar onto one line', () => {
    expect(oneLine('one\n  two\n  three')).toBe('one two three');
    expect(oneLine('  padded  ')).toBe('padded');
    expect(oneLine(undefined)).toBe('');
    expect(oneLine(null)).toBe('');
  });

  it('keeps paragraph breaks but folds within a paragraph', () => {
    expect(prose('one\ntwo\n\nthree\nfour')).toBe('one two\n\nthree four');
  });

  it('runs in linear time on a long run of spaces', () => {
    // `\s*\n\s*` backtracks quadratically here, because `\s` matches `\n` too, so
    // the engine retries every split of a run that never reaches a newline.
    const hostile = `${' '.repeat(200_000)}x`;
    const started = performance.now();
    expect(oneLine(hostile)).toBe('x');
    expect(performance.now() - started).toBeLessThan(400);
  });

  it('runs in linear time inside prose', () => {
    const started = performance.now();
    prose(`${' '.repeat(200_000)}x`);
    expect(performance.now() - started).toBeLessThan(400);
  });
});

describe('markdown table cells (js/incomplete-sanitization)', () => {
  const cellsOf = (markdown: string, needle: string) =>
    markdown.split('\n').find((line) => line.includes(needle)) ?? '';

  it('escapes a pipe so it cannot end the cell', () => {
    const { analysis, graph } = fixture();
    const hostile = {
      ...graph,
      meta: { ...graph.meta, title: 'Pipe | here' },
    };
    const md = toMarkdown(analysis, hostile, { generatedAt: FIXED_NOW });
    expect(md).toContain('Pipe | here');
  });

  it('escapes the escape character before what it escapes', () => {
    // Escaping only the pipe turns `\|` into `\\|`: a literal backslash followed by
    // an unescaped pipe, and the cell ends there. This is the same ordering bug the
    // Graphviz label escaper already has a test for.
    const { analysis, graph } = fixture();
    const hostile = {
      ...graph,
      elements: graph.elements.map((el) =>
        el.id === 'payment_api' ? { ...el, name: 'back\\|slash' } : el,
      ),
      meta: graph.meta,
    } as typeof graph;
    const md = toMarkdown(analysis, hostile, { generatedAt: FIXED_NOW });
    const row = cellsOf(md, 'slash');
    // Asserted, not guarded: a vacuous pass here would hide the very bug it covers.
    expect(row, 'the element table should contain the hostile name').not.toBe('');
    // The backslash arrives doubled, so the pipe after it stays escaped.
    expect(row).toContain('back\\\\\\|slash');
    // And the row still has the column count its header promises.
    expect(row.split(' | ').length).toBeGreaterThan(5);
  });
});

describe('SARIF text', () => {
  it('collapses folded prose without backtracking', () => {
    const { analysis, graph } = fixture();
    const started = performance.now();
    const sarif = toSarif(analysis, graph, { generatedAt: FIXED_NOW });
    expect(performance.now() - started).toBeLessThan(2000);
    const results = sarif.runs[0]!['results'] as { message: { text: string } }[];
    for (const r of results) {
      expect(r.message.text).not.toContain('\n');
    }
  });
});
