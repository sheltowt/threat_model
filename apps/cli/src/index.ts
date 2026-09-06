#!/usr/bin/env node
import { Command } from 'commander';
import { ModelError } from 'tmac-core';
import { analyze, type Format } from './commands/analyze.js';
import { reportModelError, validate } from './commands/validate.js';
import { diagram, diff, explain, init, rulesList, schema, trackSeed } from './commands/misc.js';
import { exportModel, importModel } from './commands/transfer.js';
import { serve } from './commands/serve.js';
import { red } from './ui.js';

const VERSION = '0.1.0';

/**
 * Exit codes are part of the interface, because CI reads them:
 *   0  clean
 *   1  the model is invalid, or a --fail-on threshold was breached
 *   2  the command was used wrongly
 */
async function main(argv: string[]): Promise<number> {
  const program = new Command();

  program
    .name('tmac')
    .description('Threat models as code: one file, a rule library, and output CI can read.')
    .version(VERSION)
    .showHelpAfterError();

  program
    .command('init')
    .description('scaffold a threat model in a directory')
    .argument('[dir]', 'directory to create the model in', '.')
    .option('-f, --force', 'overwrite an existing threatmodel.yaml')
    .action((dir: string, opts: { force?: boolean }) => {
      process.exitCode = init(dir, opts);
    });

  program
    .command('validate')
    .description('check the model against the schema and its own cross-references')
    .argument('[file]', 'model file (default: the nearest threatmodel.yaml)')
    .option('--json', 'emit diagnostics as JSON')
    .option('--strict', 'treat warnings as failures')
    .action((file: string | undefined, opts: { json?: boolean; strict?: boolean }) => {
      process.exitCode = validate(file, opts);
    });

  program
    .command('analyze', { isDefault: false })
    .alias('run')
    .description('run the rules and report the risks')
    .argument('[file]', 'model file (default: the nearest threatmodel.yaml)')
    .option('-f, --format <format>', 'text, json, sarif, md, html or all', 'text')
    .option('-o, --out <dir>', 'directory for generated files', 'tm-out')
    .option('--fail-on <severity>', 'exit 1 when an open risk reaches this severity')
    .option('--exclude <ids>', 'comma-separated rule ids to skip', (v: string) => v.split(','))
    .option('--allow-orphaned-tracking', 'warn instead of failing on a stale tracking key')
    .option('--show-suppressed', 'include suppressed risks in reports')
    .option('-q, --quiet', 'write files but print nothing')
    .option('--now <iso>', 'fix the report timestamp, for reproducible output')
    .action(
      async (
        file: string | undefined,
        opts: {
          format: string;
          out: string;
          failOn?: string;
          exclude?: string[];
          allowOrphanedTracking?: boolean;
          showSuppressed?: boolean;
          quiet?: boolean;
          now?: string;
        },
      ) => {
        process.exitCode = await analyze(file, { ...opts, format: opts.format as Format });
      },
    );

  program
    .command('diff')
    .description('compare two models and show only what changed in security terms')
    .argument('<before>')
    .argument('<after>')
    .option('--json', 'emit the diff as JSON')
    .action((before: string, after: string, opts: { json?: boolean }) => {
      process.exitCode = diff(before, after, opts);
    });

  program
    .command('diagram')
    .description('render a data flow or data asset diagram')
    .argument('[file]')
    .option('-o, --out <path>', 'output file', 'dfd.svg')
    .option('-k, --kind <kind>', 'data-flow or data-assets', 'data-flow')
    .option('--layout <layout>', 'dot or left-to-right', 'dot')
    .option('--dot', 'write Graphviz source instead of SVG')
    .action(
      async (
        file: string | undefined,
        opts: { out: string; kind: string; layout?: string; dot?: boolean },
      ) => {
        process.exitCode = await diagram(file, opts);
      },
    );

  program
    .command('explain')
    .description('explain a rule, or a finding and why it is uncertain')
    .argument('<id>', 'a rule id, or a finding id like rule-id@subject')
    .argument('[file]')
    .action((id: string, file: string | undefined) => {
      process.exitCode = explain(id, file);
    });

  const rules = program.command('rules').description('inspect the rule library');
  rules
    .command('list', { isDefault: true })
    .description('list every rule that would run')
    .argument('[file]')
    .option('--json', 'emit the rules as JSON')
    .action((file: string | undefined, opts: { json?: boolean }) => {
      process.exitCode = rulesList(file, opts);
    });

  const track = program.command('track').description('manage risk tracking');
  track
    .command('seed')
    .description('write an unchecked tracking entry for every open risk')
    .argument('[file]')
    .option('-w, --write', 'append to the model file instead of printing')
    .action((file: string | undefined, opts: { write?: boolean }) => {
      process.exitCode = trackSeed(file, opts);
    });

  program
    .command('import')
    .description('convert a Threat Dragon, pytm, Threagile or OTM model into this format')
    .argument('<input>')
    .option('--from <format>', 'threat-dragon, pytm, threagile or otm (default: detect)')
    .option('-o, --out <path>', 'write the model here instead of stdout')
    .option('--layout <path>', 'write the diagram layout sidecar here')
    .action((input: string, opts: { from?: string; out?: string; layout?: string }) => {
      process.exitCode = importModel(input, opts);
    });

  program
    .command('export')
    .description('convert this model into an interchange format')
    .argument('[file]')
    .requiredOption('--to <format>', 'otm or tm-bom')
    .option('-o, --out <path>', 'write here instead of stdout')
    .action((file: string | undefined, opts: { to: string; out?: string }) => {
      process.exitCode = exportModel(file, opts);
    });

  program
    .command('serve')
    .description('open the editor in a browser against a local model')
    .argument('[file]')
    .option('-p, --port <port>', 'port to listen on', '7300')
    .option('--host <host>', 'interface to bind; loopback by default', '127.0.0.1')
    .option('-w, --write', 'let the editor save back to the model file')
    .action(
      async (
        file: string | undefined,
        opts: { port: string; host: string; write?: boolean },
      ) => {
        process.exitCode = await serve(file, opts);
      },
    );

  program
    .command('schema')
    .description('emit the JSON Schema for editor completion and validation')
    .option('-o, --out <path>', 'write here instead of stdout')
    .action((opts: { out?: string }) => {
      process.exitCode = schema(opts);
    });

  await program.parseAsync(argv);
  return process.exitCode === undefined ? 0 : Number(process.exitCode);
}

main(process.argv)
  .then((code) => {
    process.exitCode = code;
  })
  .catch((err: unknown) => {
    if (err instanceof ModelError) {
      process.exitCode = reportModelError(err);
      return;
    }
    process.stderr.write(red(`${(err as Error).message}\n`));
    if (process.env['TMC_DEBUG']) process.stderr.write(`${(err as Error).stack}\n`);
    process.exitCode = 2;
  });
