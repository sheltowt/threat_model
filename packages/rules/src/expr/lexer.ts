export type TokenType = 'number' | 'string' | 'ident' | 'punct' | 'eof';

export interface Token {
  type: TokenType;
  value: string;
  pos: number;
}

export class ExpressionSyntaxError extends Error {
  readonly pos: number;
  constructor(message: string, pos: number, source: string) {
    const line = source.split('\n')[0] ?? source;
    super(`${message} at offset ${pos} in: ${line.slice(0, 120)}`);
    this.name = 'ExpressionSyntaxError';
    this.pos = pos;
  }
}

/** Longest first, so `>=` wins over `>` and `&&` is never two `&`. */
const PUNCT = [
  '&&', '||', '==', '!=', '<=', '>=',
  '(', ')', '[', ']', ',', '.', '?', ':',
  '<', '>', '!', '+', '-', '*', '/', '%',
];

const IDENT_START = /[A-Za-z_]/;
const IDENT_PART = /[A-Za-z0-9_]/;
const ESCAPES: Readonly<Record<string, string>> = {
  n: '\n', t: '\t', r: '\r', '\\': '\\', "'": "'", '"': '"',
};

export function tokenize(source: string): Token[] {
  const tokens: Token[] = [];
  let i = 0;

  while (i < source.length) {
    const ch = source[i]!;

    if (ch === ' ' || ch === '\t' || ch === '\n' || ch === '\r') {
      i++;
      continue;
    }
    // `#` or `//` starts a comment, so a long condition can carry its own notes.
    if (ch === '#' || (ch === '/' && source[i + 1] === '/')) {
      while (i < source.length && source[i] !== '\n') i++;
      continue;
    }

    if (ch === '"' || ch === "'") {
      const quote = ch;
      const start = i;
      i++;
      let value = '';
      while (i < source.length && source[i] !== quote) {
        if (source[i] === '\\') {
          const next = source[i + 1];
          const mapped = next === undefined ? undefined : ESCAPES[next];
          if (mapped === undefined) {
            throw new ExpressionSyntaxError(`unsupported escape sequence`, i, source);
          }
          value += mapped;
          i += 2;
          continue;
        }
        value += source[i];
        i++;
      }
      if (i >= source.length) {
        throw new ExpressionSyntaxError('unterminated string literal', start, source);
      }
      i++;
      tokens.push({ type: 'string', value, pos: start });
      continue;
    }

    if (ch >= '0' && ch <= '9') {
      const start = i;
      while (i < source.length && /[0-9]/.test(source[i]!)) i++;
      if (source[i] === '.' && /[0-9]/.test(source[i + 1] ?? '')) {
        i++;
        while (i < source.length && /[0-9]/.test(source[i]!)) i++;
      }
      tokens.push({ type: 'number', value: source.slice(start, i), pos: start });
      continue;
    }

    if (IDENT_START.test(ch)) {
      const start = i;
      while (i < source.length && IDENT_PART.test(source[i]!)) i++;
      tokens.push({ type: 'ident', value: source.slice(start, i), pos: start });
      continue;
    }

    const punct = PUNCT.find((p) => source.startsWith(p, i));
    if (punct) {
      tokens.push({ type: 'punct', value: punct, pos: i });
      i += punct.length;
      continue;
    }

    throw new ExpressionSyntaxError(`unexpected character "${ch}"`, i, source);
  }

  tokens.push({ type: 'eof', value: '', pos: source.length });
  return tokens;
}
