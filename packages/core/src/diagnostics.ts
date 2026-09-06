export type DiagnosticSeverity = 'error' | 'warning';

export interface Diagnostic {
  severity: DiagnosticSeverity;
  /** Machine-readable code, for example `unknown-reference` or `schema`. */
  code: string;
  message: string;
  /** Dotted path into the model, for example `elements.api.processes[0]`. */
  path?: string;
  file?: string;
  /** Practical next step, shown after the message. */
  hint?: string;
}

export class ModelError extends Error {
  readonly diagnostics: Diagnostic[];
  constructor(diagnostics: Diagnostic[]) {
    const first = diagnostics[0];
    super(first ? `${first.message}` : 'model error');
    this.name = 'ModelError';
    this.diagnostics = diagnostics;
  }
}

export function formatDiagnostic(d: Diagnostic): string {
  const where = [d.file, d.path].filter(Boolean).join(' ');
  const head = `${d.severity}: ${d.message}`;
  const loc = where ? `\n    at ${where}` : '';
  const hint = d.hint ? `\n    hint: ${d.hint}` : '';
  return `${head}${loc}${hint}`;
}

export function hasErrors(diagnostics: readonly Diagnostic[]): boolean {
  return diagnostics.some((d) => d.severity === 'error');
}

/** Levenshtein-based suggestion, so an unknown reference points at the likely typo. */
export function suggest(value: string, candidates: Iterable<string>): string | undefined {
  let best: string | undefined;
  let bestScore = Infinity;
  for (const candidate of candidates) {
    const score = editDistance(value.toLowerCase(), candidate.toLowerCase());
    if (score < bestScore) {
      bestScore = score;
      best = candidate;
    }
  }
  const limit = Math.max(2, Math.floor(value.length / 3));
  return best !== undefined && bestScore <= limit ? best : undefined;
}

function editDistance(a: string, b: string): number {
  if (a === b) return 0;
  const prev = new Array<number>(b.length + 1);
  const cur = new Array<number>(b.length + 1);
  for (let j = 0; j <= b.length; j++) prev[j] = j;
  for (let i = 1; i <= a.length; i++) {
    cur[0] = i;
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      cur[j] = Math.min(cur[j - 1]! + 1, prev[j]! + 1, prev[j - 1]! + cost);
    }
    for (let j = 0; j <= b.length; j++) prev[j] = cur[j]!;
  }
  return prev[b.length]!;
}
