# ADR 0001: TypeScript monorepo with npm workspaces

Status: accepted (2026-09-06)

## Context

The tool needs a core model library, a CLI, an optional stateless server and a web
editor. Threagile is written in Go and, as a result, never shipped a usable editor;
its browser UI is described in its own docs as "a very first iteration". pytm is
Python and has no GUI at all. Threat Dragon is JavaScript and has a good editor but
no CLI, because its logic lives inside Vue components rather than a library.

## Decision

One TypeScript monorepo. `packages/core` holds the schema and model graph and is
consumed unchanged by the CLI, the reporters and, later, the editor. Zod is the
single source of schema truth and emits the JSON Schema that editors use for
completion, so the schema cannot drift from the code the way Threat Dragon's did.

The plan proposed pnpm workspaces. pnpm is not installed on the target machine and
installing a global package manager is a poor first act for a repository, so we use
npm workspaces, which ship with Node and give us the same layout. Nothing in the
codebase depends on the choice; a later switch is a lockfile change.

## Consequences

- One language for CLI and editor; no serialisation boundary between them.
- Node is a runtime prerequisite. We do not get Threagile's single static binary.
  A container image and `npx` cover distribution.
- Rendering must avoid a system Graphviz dependency, hence `@viz-js/viz` (WASM).
