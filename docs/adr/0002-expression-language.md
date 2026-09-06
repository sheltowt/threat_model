# ADR 0002: A purpose-built sandboxed expression language for rules

Status: accepted (2026-09-06)

## Context

Rule conditions must be data, not code. pytm stores Python expressions in
`threats.json` and evaluates them; until 1.4.0 this was a bare `eval`, and the AST
allowlist added since is new and untested against user-supplied threat files.
Threagile requires custom rules to be compiled Go `.so` plugins, which are Linux and
CGO bound and version-locked to the host binary, and it is replacing them for exactly
that reason.

The plan proposed CEL, the Common Expression Language, with a JSON pattern matcher as
the fallback if the JavaScript implementation proved immature. We evaluated
`cel-js@0.8.2` against representative rule expressions.

## Evaluation result

| Requirement | cel-js 0.8.2 |
|---|---|
| Boolean logic, ternary, `in` | works |
| Reference to an absent field | throws, rather than yielding absent |
| Macros `exists` / `all` | not implemented |
| Ordering on ordered enums | compares strings lexicographically, so `internal >= confidential` is wrongly true |

The absent-field behaviour is disqualifying on its own. Most fields of a threat model
are optional, and a rule that references one the author omitted must not abort the
run. The lexicographic comparison is silently wrong, which is worse than an error.

## Decision

Write a small expression evaluator in `tmac-rules` implementing a CEL-shaped subset,
with no third-party dependency in the security-critical path:

- Grammar: literals, identifiers, member access, index, unary `!` and `-`, `*` `/`
  `%`, `+` `-`, comparisons, `in`, `&&`, `||`, ternary, and a fixed function set
  (`size`, `has`, `exists`, `all`, `count`, `lower`, `upper`, `matches`).
- No assignment, no user-defined functions, no property access that reaches a
  prototype, no host object escapes. Function names resolve from a frozen table.
- **Ordered enums compare by ordinal.** `flow.max_classification >= 'confidential'`
  compares rank, not text.
- **Absent fields yield `UNKNOWN`, not an error**, which feeds three-valued logic.

## Three-valued logic

This is the substantive improvement over all three source projects. pytm treats an
unset boolean as `false`, so a single unset flag fires many threats and drowns the
report in noise. Controls here are `true`, `false` or unknown, and expressions
evaluate under Kleene logic:

- `!unknown` is `unknown`
- `unknown && false` is `false`; `unknown && true` is `unknown`
- `unknown || true` is `true`; `unknown || false` is `unknown`

A rule whose `match` is `true` produces a confirmed risk. A rule whose `match` is
`unknown` produces a risk marked `confidence: low` together with the model gap that
caused it, so the reader can tell "you have this problem" from "you have not told me
whether you have this problem". A `false` match produces nothing.

## Consequences

- We own a parser, so it needs thorough tests. It is roughly 500 lines.
- Rule authors learn a small language rather than CEL proper. The syntax is a CEL
  subset, so migrating to a mature CEL runtime later is mechanical.
