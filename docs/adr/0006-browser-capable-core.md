# ADR 0006: The core runs in the browser, and the data is compiled in

Status: accepted (2026-09-06)

## Context

The editor needs the schema, the model graph, the cross-reference checks and the rule
engine. There are two ways to give it those.

The first is to put the logic behind an HTTP API and have the editor call it. That is
what Threagile does, and its own documentation describes the resulting browser editor
as "a very first iteration" with risk-tracking editing "currently broken". An editor
that cannot validate without a round trip is slow, cannot work offline, and needs a
server to exist at all.

The second is to reimplement enough of the model in the front end to be responsive.
That is how a schema and its editor drift apart, which is the bug Threat Dragon has:
its published schema declares `threatId` and puts threats at cell level while every
real file uses `data.threats[].id`.

Neither is acceptable. The editor must run the real code.

## What blocked it

Three things read from disk at runtime: the technology and protocol catalogue, the
built-in rule library, and model loading. The first two located their data by walking
relative to the compiled output, which also breaks whenever a bundler moves the code.

## Decision

**Compile the data in.** `scripts/generate-data.mjs` mirrors `packages/core/data/*.yaml`
and `packages/rules/rules/*.rule.yaml` into generated TypeScript modules, and runs as
part of `npm run build`. The YAML stays the source of truth and stays reviewable in a
pull request. `npm run generate:check` fails CI if the two have diverged.

**Split each package into a pure entry and a filesystem entry.**

| entry | contains |
|---|---|
| `@tmc/core` | everything, including `loadModel` and `loadCatalog` |
| `@tmc/core/browser` | schema, enums, catalogue, graph, diff, ids, JSON Schema, and `parseModelText` |
| `@tmc/rules` | everything, including `loadRules` from a directory |
| `@tmc/rules/browser` | evaluator, engine, severity, and the compiled-in library |

Validation moved out of `load.ts` into `parse.ts`, which has no filesystem
dependency. `load.ts` is now only file reading and include resolution, and delegates.
`@tmc/rules` depends on `@tmc/core/browser` throughout, because an engine has no
business reading files.

## Enforcement

`packages/core/test/browser.test.ts` and the equivalent in `@tmc/rules` walk the
import graph of the built browser entry and fail on any `node:` specifier reachable
from it. This caught two real leaks while the split was being made: a value import of
`builtinCatalog` from the filesystem module, and every `@tmc/core` import inside the
rules package.

A second test asserts the compiled-in rule library is identical to what the
filesystem loader produces, and a third asserts that analysing a model in memory
yields the same findings as analysing it from disk. Two sources for one library is a
drift risk, so it is checked rather than assumed.

## Consequences

- The editor can be a static site. No server is required to open, validate or analyse
  a model, and it works offline.
- The editor cannot disagree with the CLI about whether a model is valid or what its
  findings are, because it is running the same code.
- Editing a rule or the catalogue now requires `npm run generate` before the change
  takes effect in a build. CI checks this rather than trusting it.
- Two entry points per package is a small ongoing cost, paid to keep `node:fs` out of
  a bundle.
