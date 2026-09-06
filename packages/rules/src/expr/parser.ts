import { tokenize, ExpressionSyntaxError, type Token } from './lexer.js';
import { isMacroName, type BinaryOp, type Node } from './ast.js';

/**
 * Recursive descent parser for the rule expression language.
 *
 * The grammar is a subset of CEL, chosen so that a rule written here would also
 * parse under a full CEL runtime if we ever adopt one (ADR 0002). There is no
 * assignment, no lambda except the macro forms, and no way to name a new function,
 * so a parsed expression cannot do anything but read the scope it is given.
 */

const KEYWORDS: Readonly<Record<string, string | number | boolean | null>> = {
  true: true,
  false: false,
  null: null,
};

class Parser {
  private pos = 0;
  constructor(
    private readonly tokens: Token[],
    private readonly source: string,
  ) {}

  private peek(): Token {
    return this.tokens[this.pos]!;
  }

  private at(value: string): boolean {
    const t = this.peek();
    return t.type === 'punct' && t.value === value;
  }

  private atIdent(value: string): boolean {
    const t = this.peek();
    return t.type === 'ident' && t.value === value;
  }

  private take(): Token {
    return this.tokens[this.pos++]!;
  }

  private expect(value: string): Token {
    if (!this.at(value)) {
      const t = this.peek();
      throw new ExpressionSyntaxError(
        `expected "${value}" but found ${t.type === 'eof' ? 'end of expression' : `"${t.value}"`}`,
        t.pos,
        this.source,
      );
    }
    return this.take();
  }

  parse(): Node {
    const node = this.ternary();
    const t = this.peek();
    if (t.type !== 'eof') {
      throw new ExpressionSyntaxError(`unexpected "${t.value}" after a complete expression`, t.pos, this.source);
    }
    return node;
  }

  private ternary(): Node {
    const cond = this.or();
    if (!this.at('?')) return cond;
    const pos = this.take().pos;
    const then = this.ternary();
    this.expect(':');
    const other = this.ternary();
    return { kind: 'ternary', cond, then, other, pos };
  }

  private or(): Node {
    let left = this.and();
    while (this.at('||')) {
      const pos = this.take().pos;
      left = { kind: 'binary', op: '||', left, right: this.and(), pos };
    }
    return left;
  }

  private and(): Node {
    let left = this.relational();
    while (this.at('&&')) {
      const pos = this.take().pos;
      left = { kind: 'binary', op: '&&', left, right: this.relational(), pos };
    }
    return left;
  }

  private relational(): Node {
    let left = this.additive();
    for (;;) {
      const t = this.peek();
      const isOp =
        (t.type === 'punct' && ['==', '!=', '<', '<=', '>', '>='].includes(t.value)) ||
        (t.type === 'ident' && t.value === 'in');
      if (!isOp) return left;
      this.take();
      left = { kind: 'binary', op: t.value as BinaryOp, left, right: this.additive(), pos: t.pos };
    }
  }

  private additive(): Node {
    let left = this.multiplicative();
    while (this.at('+') || this.at('-')) {
      const t = this.take();
      left = {
        kind: 'binary',
        op: t.value as BinaryOp,
        left,
        right: this.multiplicative(),
        pos: t.pos,
      };
    }
    return left;
  }

  private multiplicative(): Node {
    let left = this.unary();
    while (this.at('*') || this.at('/') || this.at('%')) {
      const t = this.take();
      left = { kind: 'binary', op: t.value as BinaryOp, left, right: this.unary(), pos: t.pos };
    }
    return left;
  }

  private unary(): Node {
    if (this.at('!') || this.at('-')) {
      const t = this.take();
      return { kind: 'unary', op: t.value as '!' | '-', operand: this.unary(), pos: t.pos };
    }
    return this.postfix();
  }

  private postfix(): Node {
    let node = this.primary();
    for (;;) {
      if (this.at('.')) {
        const dot = this.take();
        const name = this.take();
        if (name.type !== 'ident') {
          throw new ExpressionSyntaxError('expected a field name after "."', name.pos, this.source);
        }
        // A call after a dot is only ever one of the fixed macros.
        if (this.at('(')) {
          if (!isMacroName(name.value)) {
            throw new ExpressionSyntaxError(
              `"${name.value}" is not a macro; the available macros are exists, exists_one, all, none, filter and map`,
              name.pos,
              this.source,
            );
          }
          this.take();
          const variable = this.take();
          if (variable.type !== 'ident') {
            throw new ExpressionSyntaxError(
              `${name.value}() takes a variable name as its first argument, for example .${name.value}(d, d.pii)`,
              variable.pos,
              this.source,
            );
          }
          this.expect(',');
          const body = this.ternary();
          this.expect(')');
          node = {
            kind: 'macro',
            name: name.value,
            target: node,
            variable: variable.value,
            body,
            pos: dot.pos,
          };
          continue;
        }
        node = { kind: 'member', object: node, name: name.value, pos: dot.pos };
        continue;
      }
      if (this.at('[')) {
        const open = this.take();
        const index = this.ternary();
        this.expect(']');
        node = { kind: 'index', object: node, index, pos: open.pos };
        continue;
      }
      return node;
    }
  }

  private primary(): Node {
    const t = this.peek();

    if (t.type === 'number') {
      this.take();
      return { kind: 'literal', value: Number(t.value) };
    }
    if (t.type === 'string') {
      this.take();
      return { kind: 'literal', value: t.value };
    }
    if (this.at('(')) {
      this.take();
      const inner = this.ternary();
      this.expect(')');
      return inner;
    }
    if (this.at('[')) {
      const open = this.take();
      const items: Node[] = [];
      if (!this.at(']')) {
        items.push(this.ternary());
        while (this.at(',')) {
          this.take();
          if (this.at(']')) break;
          items.push(this.ternary());
        }
      }
      this.expect(']');
      return { kind: 'list', items, pos: open.pos };
    }
    if (t.type === 'ident') {
      this.take();
      if (t.value in KEYWORDS) {
        return { kind: 'literal', value: KEYWORDS[t.value]! };
      }
      if (this.at('(')) {
        this.take();
        const args: Node[] = [];
        if (!this.at(')')) {
          args.push(this.ternary());
          while (this.at(',')) {
            this.take();
            args.push(this.ternary());
          }
        }
        this.expect(')');
        return { kind: 'call', name: t.value, args, pos: t.pos };
      }
      return { kind: 'ident', name: t.value, pos: t.pos };
    }

    throw new ExpressionSyntaxError(
      t.type === 'eof' ? 'expression ended unexpectedly' : `unexpected "${t.value}"`,
      t.pos,
      this.source,
    );
  }
}

const cache = new Map<string, Node>();

export function parseExpression(source: string): Node {
  const hit = cache.get(source);
  if (hit) return hit;
  if (source.length > 8000) {
    throw new ExpressionSyntaxError('expression is longer than 8000 characters', 0, source);
  }
  const node = new Parser(tokenize(source), source).parse();
  cache.set(source, node);
  return node;
}

export { ExpressionSyntaxError };
