/** Terminal helpers. Colour is dropped when stdout is not a TTY or NO_COLOR is set. */
const ESC = `${String.fromCharCode(27)}[`;
const enabled = process.stdout.isTTY === true && !process.env['NO_COLOR'];

const wrap = (code: string) => (s: string) => (enabled ? `${ESC}${code}m${s}${ESC}0m` : s);

export const bold = wrap('1');
export const dim = wrap('2');
export const red = wrap('31');
export const green = wrap('32');
export const yellow = wrap('33');
export const blue = wrap('34');
export const magenta = wrap('35');

export function severityColor(severity: string): (s: string) => string {
  switch (severity) {
    case 'critical':
      return magenta;
    case 'high':
      return red;
    case 'elevated':
      return yellow;
    case 'medium':
      return blue;
    default:
      return dim;
  }
}

/** Render aligned columns. The last column is never padded, so it can wrap. */
export function table(rows: string[][], head?: string[]): string {
  const all = head ? [head, ...rows] : rows;
  if (all.length === 0) return '';
  const widths: number[] = [];
  for (const row of all) {
    row.forEach((cell, i) => {
      widths[i] = Math.max(widths[i] ?? 0, cell.length);
    });
  }
  const line = (row: string[]) =>
    row.map((cell, i) => (i === row.length - 1 ? cell : cell.padEnd(widths[i] ?? 0))).join('  ');
  const out = all.map(line);
  if (head) out.splice(1, 0, widths.map((w) => '-'.repeat(w)).join('  '));
  return out.join('\n');
}

export function plural(n: number, one: string, many = `${one}s`): string {
  return `${n} ${n === 1 ? one : many}`;
}

/** Wrap prose to a width, for help and explanation output. */
export function wrapText(text: string, width = 78, indent = ''): string {
  const words = text.replace(/\s+/g, ' ').trim().split(' ');
  const lines: string[] = [];
  let current = indent;
  for (const word of words) {
    if (current.length + word.length + 1 > width && current !== indent) {
      lines.push(current);
      current = indent + word;
    } else {
      current = current === indent ? indent + word : `${current} ${word}`;
    }
  }
  if (current.trim()) lines.push(current);
  return lines.join('\n');
}
