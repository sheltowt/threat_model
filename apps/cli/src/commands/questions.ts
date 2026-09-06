import { writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { analyze as runAnalysis, questionStats, questions } from 'tmac-rules';
import { findModel, open } from '../context.js';
import { bold, dim, green, plural, red, severityColor, table, wrapText, yellow } from '../ui.js';

export interface QuestionsOptions {
  json?: boolean;
  out?: string;
  limit?: string;
  includeSettled?: boolean;
}

/**
 * The model's own to-do list.
 *
 * `analyze` says which findings are unsettled; this says what to go and find out,
 * ordered so the top entry is the one worth answering first. It is the other half of
 * the tri-state design: the tool is allowed to say "I do not know" only if it also
 * says what would help.
 */
export function showQuestions(file: string | undefined, options: QuestionsOptions): number {
  const target = findModel(file);
  const ctx = open(target);

  if (ctx.ruleErrors.length > 0) {
    for (const e of ctx.ruleErrors) {
      process.stderr.write(red(`rule error in ${e.file}: ${e.message}\n`));
    }
    return 1;
  }

  const analysis = runAnalysis(ctx.graph, ctx.rules);
  const all = questions(analysis, ctx.graph, {
    includeSettled: options.includeSettled === true,
  });
  const stats = questionStats(all);

  if (options.json || options.out) {
    const payload = {
      schema: 'tmac/questions/1.0',
      model: { title: ctx.graph.meta.title, path: target },
      stats,
      questions: all.map((q) => ({
        field: q.field,
        subject: q.subject,
        control: q.control,
        worst_severity: q.worstSeverity,
        settles: q.blocking.length,
        rules: q.rules,
        findings: q.blocking.map((r) => ({ id: r.id, severity: r.severity, title: r.title })),
      })),
    };
    const json = `${JSON.stringify(payload, null, 2)}\n`;
    if (options.out) {
      writeFileSync(resolve(options.out), json, 'utf8');
      process.stdout.write(`${green('Wrote')} ${options.out}\n`);
    } else {
      process.stdout.write(json);
    }
    return 0;
  }

  if (all.length === 0) {
    process.stdout.write(
      `${green('Nothing unsettled.')} Every rule could decide from what the model records.\n`,
    );
    return 0;
  }

  const limit = Number(options.limit ?? '20');
  const shown = Number.isFinite(limit) && limit > 0 ? all.slice(0, limit) : all;

  process.stdout.write(
    `\n${bold('Unrecorded, in the order worth answering')}\n` +
      dim(
        `  ${plural(stats.open, 'question')} holding up ${plural(stats.unsettledFindings, 'finding')}.\n` +
          `  Answering the first settles ${plural(stats.topQuestionUnblocks, 'finding')}.\n\n`,
      ),
  );

  const rows = shown.map((q) => [
    severityColor(q.worstSeverity)(q.worstSeverity),
    String(q.blocking.length),
    q.field,
    q.rules.slice(0, 3).join(', ') + (q.rules.length > 3 ? ` +${q.rules.length - 3}` : ''),
  ]);
  process.stdout.write(`${table(rows, ['WORST', 'WAITING', 'RECORD THIS', 'FOR'])}\n`);

  if (all.length > shown.length) {
    process.stdout.write(dim(`\n  and ${all.length - shown.length} more, use --limit 0 for all\n`));
  }

  const top = shown[0]!;
  process.stdout.write(
    `\n${bold('Start here')}\n` +
      wrapText(
        `Record ${top.control ?? top.field}${top.subject ? ` on ${top.subject}` : ''}. ` +
          `It is what ${top.rules.length === 1 ? 'one rule' : `${top.rules.length} rules`} ` +
          `could not decide, and ${plural(top.blocking.length, 'finding')} ${top.blocking.length === 1 ? 'waits' : 'wait'} on it, ` +
          `the worst of them ${top.worstSeverity}.`,
        78,
        '  ',
      ) +
      '\n' +
      dim(`\n  Set it true if the control is there, false if it is not. Either answer\n`) +
      dim(`  is better than silence: false gives you a confirmed finding to act on.\n`),
  );

  process.stdout.write(dim(`\n${target}\n`));
  return 0;
}
