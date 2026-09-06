import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join, resolve } from 'node:path';
import { stringify as stringifyYaml } from 'yaml';
import { diffModels, formatDiff, loadModel, modelJsonSchema } from '@tmc/core';
import { analyze as runAnalysis, isOpen, loadRules } from '@tmc/rules';
import { dataAssetDot, dataFlowDot, renderSvg } from '@tmc/render';
import { findModel, open, projectDir } from '../context.js';
import { bold, dim, green, plural, red, table, wrapText, yellow } from '../ui.js';

const HERE = dirname(fileURLToPath(import.meta.url));

function scaffoldDir(): string {
  for (const candidate of [join(HERE, '..', 'scaffold'), join(HERE, '..', '..', 'scaffold')]) {
    if (existsSync(candidate)) return candidate;
  }
  throw new Error('tmc: scaffold templates not found');
}

/** Create a starter model and project directory. */
export function init(dir: string, options: { force?: boolean }): number {
  const target = resolve(dir);
  const modelPath = join(target, 'threatmodel.yaml');
  if (existsSync(modelPath) && !options.force) {
    process.stderr.write(
      red(`${modelPath} already exists\n`) + dim('  pass --force to overwrite it\n'),
    );
    return 1;
  }
  mkdirSync(join(target, '.tmc', 'rules'), { recursive: true });
  const scaffold = scaffoldDir();
  writeFileSync(modelPath, readFileSync(join(scaffold, 'threatmodel.yaml'), 'utf8'), 'utf8');
  writeFileSync(
    join(target, '.tmc', 'README.md'),
    readFileSync(join(scaffold, 'tmc-readme.md'), 'utf8'),
    'utf8',
  );

  process.stdout.write(
    `${green('Created')} ${modelPath}\n` +
      dim('  .tmc/rules/    drop *.rule.yaml here to add or replace rules\n') +
      `\nNext: ${bold('tmc analyze')}\n`,
  );
  return 0;
}

/** Emit the JSON Schema, so an editor can complete and validate the model file. */
export function schema(options: { out?: string }): number {
  const json = `${JSON.stringify(modelJsonSchema(), null, 2)}\n`;
  if (options.out) {
    writeFileSync(resolve(options.out), json, 'utf8');
    process.stdout.write(`${green('Wrote')} ${options.out}\n`);
    process.stdout.write(
      dim('  point your editor at it, for example in .vscode/settings.json:\n') +
        dim('  "yaml.schemas": { "./tmc.schema.json": "threatmodel.yaml" }\n'),
    );
  } else {
    process.stdout.write(json);
  }
  return 0;
}

/** Semantic diff between two model files. */
export function diff(beforePath: string, afterPath: string, options: { json?: boolean }): number {
  const before = loadModel(resolve(beforePath)).model;
  const after = loadModel(resolve(afterPath)).model;
  const result = diffModels(before, after);
  if (options.json) {
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  } else {
    process.stdout.write(`${formatDiff(result)}\n`);
  }
  return 0;
}

/** List the rules that would run. */
export function rulesList(file: string | undefined, options: { json?: boolean }): number {
  const target = findModel(file);
  const { rules, errors } = loadRules([resolve(projectDir(target), 'rules')]);
  for (const e of errors) process.stderr.write(red(`${e.file}: ${e.message}\n`));

  if (options.json) {
    process.stdout.write(`${JSON.stringify(rules, null, 2)}\n`);
    return errors.length > 0 ? 1 : 0;
  }
  const rows = rules.map((r) => [
    r.id,
    r.stride,
    r.scope,
    r.builtin ? dim('built-in') : green('project'),
    r.title,
  ]);
  process.stdout.write(`${table(rows, ['ID', 'STRIDE', 'SCOPE', 'ORIGIN', 'TITLE'])}\n`);
  process.stdout.write(dim(`\n${plural(rules.length, 'rule')}\n`));
  return errors.length > 0 ? 1 : 0;
}

/** Explain a rule, or a specific finding including why it is low confidence. */
export function explain(id: string, file: string | undefined): number {
  const target = findModel(file);
  const ctx = open(target);
  const ruleId = id.includes('@') ? id.split('@')[0]! : id;
  const rule = ctx.rules.find((r) => r.id === ruleId);

  if (!rule) {
    process.stderr.write(red(`no rule with id "${ruleId}"\n`));
    process.stderr.write(dim('  run "tmc rules list" to see them all\n'));
    return 1;
  }

  const out: string[] = [];
  out.push(`${bold(rule.title)}  ${dim(rule.id)}`);
  out.push('');
  const meta: string[][] = [
    ['STRIDE', rule.stride],
    ['Scope', rule.scope],
    ['Function', rule.function],
  ];
  if (rule.linddun) meta.push(['LINDDUN', rule.linddun]);
  if (rule.cwe) meta.push(['CWE', `CWE-${rule.cwe}`]);
  if (rule.capec.length > 0) meta.push(['CAPEC', rule.capec.join(', ')]);
  if (rule.asvs) meta.push(['ASVS', rule.asvs]);
  if (rule.cheat_sheet) meta.push(['Guidance', rule.cheat_sheet]);
  meta.push(['Defined in', rule.source]);
  out.push(table(meta));

  const section = (heading: string, body: string | undefined) => {
    if (!body) return;
    out.push('', bold(heading), wrapText(body, 78, '  '));
  };
  section('What it detects', rule.detection_logic);
  section('How it is rated', rule.risk_assessment);
  section('When it is wrong', rule.false_positives);
  section('How to fix it', rule.mitigation);
  section('Action', rule.action);
  section('How to check the fix', rule.check);

  out.push('', bold('Condition'), ...rule.match.trim().split('\n').map((l) => `  ${dim(l)}`));

  if (id.includes('@')) {
    const analysis = runAnalysis(ctx.graph, ctx.rules);
    const risk = analysis.risks.find((r) => r.id === id);
    if (!risk) {
      out.push('', yellow(`No current finding with id ${id}.`));
    } else {
      out.push('', bold('This finding'), table([
        ['Title', risk.title],
        ['Severity', `${risk.severity} (${risk.likelihood} x ${risk.impact})`],
        ['Confidence', risk.confidence],
        ['Subject', `${risk.subject.kind} ${risk.subject.id}`],
        ['Status', risk.status],
      ]));
      if (risk.unknowns.length > 0) {
        out.push(
          '',
          yellow('Why the confidence is low'),
          wrapText(
            'The condition could not be settled because the model does not record these fields. This is a gap in the model, not a confirmed flaw.',
            78,
            '  ',
          ),
          ...risk.unknowns.map((u) => `    ${u}`),
        );
      }
    }
  }
  process.stdout.write(`${out.join('\n')}\n`);
  return 0;
}

/** Write an unchecked tracking entry for every open risk. */
export function trackSeed(file: string | undefined, options: { write?: boolean }): number {
  const target = findModel(file);
  const ctx = open(target);
  const analysis = runAnalysis(ctx.graph, ctx.rules);
  const existing = new Set(Object.keys(ctx.load.model.risk_tracking));

  const seeded: Record<string, unknown> = {};
  for (const risk of analysis.risks.filter(isOpen)) {
    if (existing.has(risk.id)) continue;
    seeded[risk.id] = {
      status: 'unchecked',
      justification: '',
      ticket: '',
      date: new Date().toISOString().slice(0, 10),
      checked_by: '',
    };
  }

  if (Object.keys(seeded).length === 0) {
    process.stdout.write(`${green('Nothing to seed')}, every open risk is already tracked.\n`);
    return 0;
  }

  const yaml = stringifyYaml({ risk_tracking: seeded }, { lineWidth: 100 });
  if (!options.write) {
    process.stdout.write(`${yaml}\n`);
    process.stdout.write(
      dim(`# ${plural(Object.keys(seeded).length, 'entry', 'entries')}. Append to ${target}, or rerun with --write.\n`),
    );
    return 0;
  }

  // Appending keeps the author's comments and ordering, which rewriting would lose.
  const text = readFileSync(target, 'utf8');
  const body = yaml.replace(/^risk_tracking:\n/, '');
  const updated = /^risk_tracking:\s*\{\s*\}\s*$/m.test(text)
    ? text.replace(/^risk_tracking:\s*\{\s*\}\s*$/m, `risk_tracking:\n${body}`)
    : `${text.trimEnd()}\n\n${/^risk_tracking:/m.test(text) ? body : yaml}`;
  writeFileSync(target, updated, 'utf8');
  process.stdout.write(
    `${green('Seeded')} ${plural(Object.keys(seeded).length, 'entry', 'entries')} into ${target}\n`,
  );
  return 0;
}

/** Render one diagram to a file. */
export async function diagram(
  file: string | undefined,
  options: { out: string; kind: string; layout?: string; dot?: boolean },
): Promise<number> {
  const target = findModel(file);
  const ctx = open(target);
  const analysis = runAnalysis(ctx.graph, ctx.rules);

  const renderOptions =
    options.layout === 'left-to-right' ? { layout: 'left-to-right' as const } : {};
  const source =
    options.kind === 'data-assets'
      ? dataAssetDot(ctx.graph)
      : dataFlowDot(ctx.graph, { risks: analysis.risks, ...renderOptions });

  const out = resolve(options.out);
  mkdirSync(dirname(out), { recursive: true });
  if (options.dot || out.endsWith('.dot')) {
    writeFileSync(out, source, 'utf8');
  } else {
    writeFileSync(out, await renderSvg(source), 'utf8');
  }
  process.stdout.write(`${green('Wrote')} ${options.out}\n`);
  return 0;
}
