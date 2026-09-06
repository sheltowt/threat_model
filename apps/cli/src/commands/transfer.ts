import { readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { parse as parseYaml, stringify as stringifyYaml } from 'yaml';
import { modelSchema } from 'tmac-core';
import {
  detectFormat,
  exportOtm,
  exportTmbom,
  importAny,
  type ImportFormat,
} from 'tmac-importers';
import { analyze as runAnalysis } from 'tmac-rules';
import { findModel, open } from '../context.js';
import { dim, green, red, yellow } from '../ui.js';

const FORMATS: ImportFormat[] = ['threat-dragon', 'pytm', 'threagile', 'otm'];

function readData(path: string): unknown {
  const text = readFileSync(resolve(path), 'utf8');
  // YAML is a superset of JSON, so one parser covers both input shapes.
  return parseYaml(text);
}

export interface ImportOptions {
  from?: string;
  out?: string;
  layout?: string;
}

/** Convert a foreign threat model into a tmac model file. */
export function importModel(input: string, options: ImportOptions): number {
  const data = readData(input);

  const format = (options.from ?? detectFormat(data)) as ImportFormat | undefined;
  if (!format || !FORMATS.includes(format)) {
    process.stderr.write(
      red(`could not tell what format ${input} is\n`) +
        dim(`  pass --from with one of: ${FORMATS.join(', ')}\n`),
    );
    return 1;
  }

  const result = importAny(format, data);

  for (const w of result.warnings) {
    process.stderr.write(yellow(`${w.message}\n`));
    if (w.hint) process.stderr.write(dim(`  ${w.hint}\n`));
  }

  const parsed = modelSchema.safeParse(result.model);
  if (!parsed.success) {
    process.stderr.write(red(`the imported model is not valid:\n`));
    for (const issue of parsed.error.issues) {
      process.stderr.write(red(`  ${issue.path.join('.')}: ${issue.message}\n`));
    }
    return 1;
  }

  const yaml = stringifyYaml(result.model, { lineWidth: 100 });
  if (options.out) {
    writeFileSync(resolve(options.out), yaml, 'utf8');
    process.stdout.write(`${green('Wrote')} ${options.out} ${dim(`(from ${format})`)}\n`);
    if (result.layout && options.layout) {
      writeFileSync(resolve(options.layout), `${JSON.stringify(result.layout, null, 2)}\n`, 'utf8');
      process.stdout.write(`${green('Wrote')} ${options.layout} ${dim('(diagram layout)')}\n`);
    }
  } else {
    process.stdout.write(yaml);
  }
  return 0;
}

export interface ExportOptions {
  to: string;
  out?: string;
}

/** Convert a tmac model into an interchange format. */
export function exportModel(file: string | undefined, options: ExportOptions): number {
  const target = findModel(file);
  const ctx = open(target);

  let payload: unknown;
  if (options.to === 'otm') {
    payload = exportOtm(ctx.load.model);
  } else if (options.to === 'tm-bom') {
    const analysis = runAnalysis(ctx.graph, ctx.rules);
    // The exporter names its subject fields `element` and `flow`; map ours across
    // explicitly rather than casting, so a rename on either side fails the build.
    payload = exportTmbom(
      ctx.load.model,
      analysis.risks.map((r) => ({
        id: r.id,
        title: r.title,
        severity: r.severity,
        cwe: r.cwe,
        description: r.description ?? r.detection_logic,
        mitigation: r.mitigation,
        element: r.most_relevant_element,
        flow: r.most_relevant_flow,
        status: r.status,
        stride: r.stride,
        confidence: r.confidence,
      })),
    );
  } else {
    process.stderr.write(red(`--to must be otm or tm-bom, got "${options.to}"\n`));
    return 1;
  }

  const json = `${JSON.stringify(payload, null, 2)}\n`;
  if (options.out) {
    writeFileSync(resolve(options.out), json, 'utf8');
    process.stdout.write(`${green('Wrote')} ${options.out}\n`);
  } else {
    process.stdout.write(json);
  }
  return 0;
}
