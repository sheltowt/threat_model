# Contributing

```bash
npm ci
npm run build
npm test
```

The workspace is npm workspaces over TypeScript with NodeNext resolution, so
**relative imports need a `.js` extension** even in `.ts` files.

## Where things live

| | |
|---|---|
| `packages/core` | schema, loader, graph, diff. Everything else depends on it and it depends on nothing. |
| `packages/rules` | the expression evaluator, the engine, and the rule library in `rules/`. |
| `packages/render` | DOT and SVG. |
| `packages/report` | Markdown, HTML, SARIF, JSON. |
| `packages/importers` | foreign formats in, interchange formats out. |
| `apps/cli` | the `tmc` command. |
| `apps/web` | the browser editor. |

## Two entry points per package

`@tmc/core` and `@tmc/rules` each export a `/browser` entry carrying only the half
with no filesystem dependency, because the editor runs the real code rather than a
copy of it (ADR 0006). A test walks the import graph of each built browser entry and
fails on any reachable `node:` specifier.

So: put anything that reads a file in the default entry, and import
`@tmc/core/browser` from any package that the editor also loads.

The technology catalogue and the rule library are mirrored into generated
TypeScript by `scripts/generate-data.mjs`, which runs as part of `npm run build`.
After editing `packages/core/data/*.yaml` or `packages/rules/rules/*.rule.yaml`, run
`npm run generate`. CI fails if you forget.

## Working on the editor

```bash
npm run build          # the libraries and the editor
npm run dev            # vite, with the libraries aliased to source
tmc serve --write      # the built editor against a real file
```

UI tests mount the app under happy-dom in `apps/web/test`. The assertion that
matters most is in `state.test.ts`: the browser produces the same findings as the
CLI for the same file. If that ever fails, the editor has drifted and nothing else
about it matters.

## Adding a rule

Read [docs/rule-authoring.md](docs/rule-authoring.md). In short: a rule is a YAML
document in `packages/rules/rules/`, and it needs `detection_logic`,
`false_positives` and `mitigation` prose along with its condition.

**Every rule needs two fixtures**: one model it fires on, and one it stays quiet on.
The negative fixture is the important one, because it is what catches a rule that
fires on everything. A rule that fires on most elements of the example model is
wrong, not thorough.

## Touching the evaluator

`packages/rules/src/expr` is the sandbox boundary between the tool and rule files
that may come from a repository nobody vetted. Changes there need a test for the
behaviour and, if the change touches property access or the function table, a test
for the escape it prevents. See the `sandbox` block in
`packages/rules/test/expr.test.ts` for the shape of those.

Do not add a function that reaches the filesystem, the network, the clock, or the
host object graph. If a rule needs a derived fact, compute it in
`packages/core/src/graph.ts` and expose it as a plain field.

## Changing the model schema

The Zod schema in `packages/core/src/schema.ts` is the only definition. The JSON
Schema is generated from it, so the two cannot drift. Adding an optional field with a
default is backwards compatible; anything else needs a note in the changelog and a
thought about what happens to an existing `risk_tracking` block.

Never give a security control a default of `false`. The whole design rests on the
difference between recorded-absent and unrecorded (ADR 0002).

## Style

Deterministic output everywhere: reports take an injectable timestamp, collections
are sorted before they are written, and two runs over the same input must produce
identical bytes. There is a test for this.
