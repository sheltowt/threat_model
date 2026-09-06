# ADR 0003: Diagram layout lives outside the model

Status: accepted (2026-09-06)

## Context

Threat Dragon stores X6 canvas cells, with `position`, `size`, `attrs`, `zIndex` and
`vertices`, in the same file as the security content, and nests the security
properties inside `cell.data`. Moving a box therefore changes the threat model file,
so a diff cannot distinguish "we moved a node" from "we removed authentication".

## Decision

`threatmodel.yaml` carries semantics only. Coordinates and diagram tweaks live in an
optional `threatmodel.layout.json` sidecar. Deleting the sidecar is always safe: the
renderer falls back to automatic layout.

`tmc diff` compares the semantic model, so its output contains only security-relevant
change.

## Consequences

- The editor must write two files. This is the cost of a readable diff and it is
  worth paying.
- Round-tripping a Threat Dragon file preserves its coordinates in the sidecar.
