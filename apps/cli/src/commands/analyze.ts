import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';
import { SEVERITY, type Severity } from 'tmac-core';
import { analyze as runAnalysis, atLeastSeverity, isOpen, type Analysis } from 'tmac-rules';
import { dataAssetDot, dataFlowDot, renderSvg } from 'tmac-render';
import { risksJson, statsJson, technicalAssetsJson, toHtml, toMarkdown, toSarif } from 'tmac-report';
import { open, findModel } from '../context.js';
import { bold, dim, green, magenta, plural, red, severityColor, table, yellow } from '../ui.js';

export type Format = 'text' | 'json' | 'sarif' | 'md' | 'html' | 'all';

export interface AnalyzeOptions {
  format: Format;
  out: string;
  failOn?: string;
  exclude?: string[];
  allowOrphanedTracking?: boolean;
  showSuppressed?: boolean;
  quiet?: boolean;
  /** Fixed timestamp, so golden-file and CI comparisons stay stable. */
  now?: string;
}

function severityLine(analysis: Analysis): string {
  const counts = analysis.stats.risksBySeverity;
  const parts = [...SEVERITY]
    .reverse()
    .filter((s) => (counts[s] ?? 0) > 0)
    .map((s) => severityColor(s)(`${counts[s]} ${s}`));
  return parts.length > 0 ? parts.join(dim(' | ')) : dim('no risks');
}

function printSummary(analysis: Analysis, file: string): void {
  const open = analysis.risks.filter(isOpen);
  process.stdout.write(`\n${bold('Risks')}  ${severityLine(analysis)}\n`);

  if (open.length > 0) {
    const rows = open
      .slice(0, 25)
      .map((r) => [
        severityColor(r.severity)(r.severity),
        r.confidence === 'low' ? yellow('low') : dim('high'),
        r.id,
        r.title,
      ]);
    process.stdout.write(`\n${table(rows, ['SEVERITY', 'CONF', 'ID', 'TITLE'])}\n`);
    if (open.length > rows.length) {
      process.stdout.write(dim(`\n  and ${open.length - rows.length} more\n`));
    }
  }

  const lowConfidence = analysis.stats.lowConfidenceRisks;
  if (lowConfidence > 0) {
    process.stdout.write(
      `\n${yellow(bold(`${plural(lowConfidence, 'finding')} could not be settled`))}\n` +
        dim(
          '  These are model gaps, not confirmed flaws. Record the missing controls\n' +
            `  and they will either resolve or become confirmed. Run: tmac explain <id>\n`,
        ),
    );
  }

  for (const w of analysis.warnings) {
    const colour = w.code === 'rule-error' ? red : yellow;
    process.stdout.write(`\n${colour(w.message)}\n`);
    if (w.hint) process.stdout.write(dim(`  ${w.hint}\n`));
  }
  process.stdout.write(dim(`\n${file}\n`));
}

interface RenderedDiagrams {
  written: string[];
  svg: { dataFlow?: string; dataAssets?: string };
}

async function writeDiagrams(
  outDir: string,
  ctx: ReturnType<typeof open>,
  analysis: Analysis,
): Promise<RenderedDiagrams> {
  const written: string[] = [];
  const svg: RenderedDiagrams['svg'] = {};
  const diagrams: [keyof RenderedDiagrams['svg'], string, string][] = [
    ['dataFlow', 'data-flow-diagram.svg', dataFlowDot(ctx.graph, { risks: analysis.risks })],
    ['dataAssets', 'data-asset-diagram.svg', dataAssetDot(ctx.graph)],
  ];
  for (const [key, name, dot] of diagrams) {
    const dotPath = join(outDir, name.replace(/\.svg$/, '.dot'));
    writeFileSync(dotPath, dot, 'utf8');
    written.push(dotPath);
    try {
      const rendered = await renderSvg(dot);
      const svgPath = join(outDir, name);
      writeFileSync(svgPath, rendered, 'utf8');
      written.push(svgPath);
      svg[key] = rendered;
    } catch (err) {
      // A diagram failing must not lose the report; the DOT source is still there.
      process.stderr.write(
        yellow(`could not render ${name}: ${(err as Error).message}\n`) +
          dim(`  the DOT source was still written to ${dotPath}\n`),
      );
    }
  }
  return { written, svg };
}

/** Run the rules and write whatever the caller asked for. */
export async function analyze(file: string | undefined, options: AnalyzeOptions): Promise<number> {
  const target = findModel(file);
  const ctx = open(target);

  if (ctx.ruleErrors.length > 0) {
    for (const e of ctx.ruleErrors) {
      process.stderr.write(red(`rule error in ${e.file}: ${e.message}\n`));
    }
    return 1;
  }

  const analysis = runAnalysis(ctx.graph, ctx.rules, {
    exclude: options.exclude ?? [],
    strictTracking: !options.allowOrphanedTracking,
  });

  if (!options.allowOrphanedTracking) {
    const orphaned = analysis.warnings.filter((w) => w.code === 'orphaned-tracking');
    if (orphaned.length > 0) {
      for (const w of orphaned) process.stderr.write(red(`${w.message}\n`));
      process.stderr.write(
        dim('  pass --allow-orphaned-tracking to downgrade this to a warning\n'),
      );
      return 1;
    }
  }

  const wantsFile = options.format !== 'text';
  const outDir = resolve(options.out);
  const written: string[] = [];

  if (wantsFile) {
    mkdirSync(outDir, { recursive: true });
    const want = (f: Format) => options.format === 'all' || options.format === f;
    const reportOptions = {
      ...(options.now ? { generatedAt: options.now } : {}),
      ...(options.showSuppressed === undefined ? {} : { showSuppressed: options.showSuppressed }),
      modelPath: target,
    };

    if (want('json')) {
      const files: [string, unknown][] = [
        ['risks.json', risksJson(analysis, ctx.graph, reportOptions)],
        ['stats.json', statsJson(analysis, ctx.graph, reportOptions)],
        ['technical-assets.json', technicalAssetsJson(ctx.graph)],
      ];
      for (const [name, data] of files) {
        const path = join(outDir, name);
        writeFileSync(path, `${JSON.stringify(data, null, 2)}\n`, 'utf8');
        written.push(path);
      }
    }
    if (want('sarif')) {
      const path = join(outDir, 'risks.sarif');
      writeFileSync(
        path,
        `${JSON.stringify(
          toSarif(analysis, ctx.graph, {
            ...reportOptions,
            rules: ctx.rules,
            // SARIF locates each result by line, so the reporter needs the text.
            modelText: readFileSync(target, 'utf8'),
          }),
          null,
          2,
        )}\n`,
        'utf8',
      );
      written.push(path);
    }
    let rendered: RenderedDiagrams = { written: [], svg: {} };
    if (want('md') || want('html')) {
      rendered = await writeDiagrams(outDir, ctx, analysis);
      written.push(...rendered.written);
    }
    if (want('md')) {
      const path = join(outDir, 'report.md');
      writeFileSync(
        path,
        toMarkdown(analysis, ctx.graph, {
          ...reportOptions,
          includeDiagrams: true,
          diagramPaths: {
            dataFlow: 'data-flow-diagram.svg',
            dataAssets: 'data-asset-diagram.svg',
          },
        }),
        'utf8',
      );
      written.push(path);
    }
    if (want('html')) {
      const path = join(outDir, 'report.html');
      // The HTML report embeds the SVG rather than linking it, so one file travels.
      writeFileSync(
        path,
        toHtml(analysis, ctx.graph, {
          ...reportOptions,
          includeDiagrams: true,
          diagrams: rendered.svg,
        }),
        'utf8',
      );
      written.push(path);
    }
  }

  if (!options.quiet) {
    printSummary(analysis, target);
    if (written.length > 0) {
      const rel = written.map((p) => relative(process.cwd(), p));
      process.stdout.write(`${green('Wrote')} ${rel.join(', ')}\n`);
    }
  }

  if (options.failOn) {
    const threshold = options.failOn as Severity;
    if (!SEVERITY.includes(threshold)) {
      process.stderr.write(
        red(`--fail-on must be one of ${SEVERITY.join(', ')}, got "${options.failOn}"\n`),
      );
      return 2;
    }
    const breaches = analysis.risks.filter(
      (r) => isOpen(r) && atLeastSeverity(r.severity, threshold),
    );
    if (breaches.length > 0) {
      process.stderr.write(
        `\n${magenta(bold(`${plural(breaches.length, 'open risk')} at or above ${threshold}`))}\n`,
      );
      return 1;
    }
  }
  return 0;
}
