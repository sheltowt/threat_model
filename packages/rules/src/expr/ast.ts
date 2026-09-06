export type Node =
  | { kind: 'literal'; value: string | number | boolean | null }
  | { kind: 'ident'; name: string; pos: number }
  | { kind: 'member'; object: Node; name: string; pos: number }
  | { kind: 'index'; object: Node; index: Node; pos: number }
  | { kind: 'unary'; op: '!' | '-'; operand: Node; pos: number }
  | { kind: 'binary'; op: BinaryOp; left: Node; right: Node; pos: number }
  | { kind: 'ternary'; cond: Node; then: Node; other: Node; pos: number }
  | { kind: 'call'; name: string; args: Node[]; pos: number }
  | { kind: 'macro'; name: MacroName; target: Node; variable: string; body: Node; pos: number }
  | { kind: 'list'; items: Node[]; pos: number };

export type BinaryOp =
  | '&&' | '||'
  | '==' | '!=' | '<' | '<=' | '>' | '>='
  | '+' | '-' | '*' | '/' | '%'
  | 'in';

export const MACRO_NAMES = ['exists', 'all', 'none', 'filter', 'map', 'exists_one'] as const;
export type MacroName = (typeof MACRO_NAMES)[number];

export function isMacroName(name: string): name is MacroName {
  return (MACRO_NAMES as readonly string[]).includes(name);
}

/** Every identifier referenced at the root of the scope, for static checking. */
export function rootIdentifiers(node: Node, bound = new Set<string>()): Set<string> {
  const found = new Set<string>();
  const walk = (n: Node, scope: Set<string>): void => {
    switch (n.kind) {
      case 'ident':
        if (!scope.has(n.name)) found.add(n.name);
        return;
      case 'member':
        walk(n.object, scope);
        return;
      case 'index':
        walk(n.object, scope);
        walk(n.index, scope);
        return;
      case 'unary':
        walk(n.operand, scope);
        return;
      case 'binary':
        walk(n.left, scope);
        walk(n.right, scope);
        return;
      case 'ternary':
        walk(n.cond, scope);
        walk(n.then, scope);
        walk(n.other, scope);
        return;
      case 'call':
        for (const a of n.args) walk(a, scope);
        return;
      case 'macro': {
        walk(n.target, scope);
        const inner = new Set(scope);
        inner.add(n.variable);
        walk(n.body, inner);
        return;
      }
      case 'list':
        for (const item of n.items) walk(item, scope);
        return;
      default:
        return;
    }
  };
  walk(node, bound);
  return found;
}
