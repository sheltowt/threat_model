# Changelog

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project uses semantic versioning.

## [Unreleased]

### Added

- Declarative model format `tmc/1.0`: data assets with confidentiality, integrity and
  availability ratings, generic elements backed by a technology catalogue, flows with
  protocol and authentication attributes, nested trust boundaries, shared runtimes,
  assumptions, manual threats and risk tracking.
- Three-valued security controls. A control that is not recorded is unknown rather
  than absent, and findings that depend on one come back marked `confidence: low`
  naming the gap.
- A rule engine over YAML rule documents, with a purpose-built sandboxed expression
  evaluator: no `eval`, no plugins, no host access, ordinal comparison of ordered
  enums, and Kleene three-valued logic.
- 53 built-in rules covering transport, authentication, injection, web, supply chain,
  data hygiene, LINDDUN privacy and AI risks.
- Scope binding is checked when a rule loads, so a rule that references the wrong
  scope variable fails loudly rather than loading, running and silently matching
  nothing for ever.
- Severity derived as likelihood times impact, so rules cannot disagree about how bad
  equivalent problems are.
- Synthetic finding ids of the form `rule-id@subject-id`, stable across regeneration,
  rewording and re-layout, with wildcard risk tracking and failure on orphaned keys.
- Relative Attacker Attractiveness scoring, adapted from Threagile.
- `tmc` command: `init`, `validate`, `analyze`, `diff`, `diagram`, `explain`,
  `rules list`, `track seed`, `import`, `export`, `schema`.
- Outputs: JSON, SARIF, Markdown, self-contained HTML, and Graphviz diagrams rendered
  through WASM so there is no system Graphviz dependency.
- Importers for OWASP Threat Dragon v2, pytm, Threagile and Open Threat Model.
  Exporters for Open Threat Model and CycloneDX Threat Model BOM.
- JSON Schema generated from the Zod schema, so the published schema cannot drift
  from the validator.

### Notes on interoperating

#### pytm

pytm treats an unset security control as `false`. tmc distinguishes unrecorded from
recorded-absent, so the importer carries across only controls that are explicitly
present in the input and reports how many were dropped as indeterminate. Expect a
freshly imported pytm model to produce low-confidence findings where pytm produced
confident ones; that is the import being honest about what the source file knew.

#### Open Threat Model

OTM has no data asset concept and no shared runtime, so an export parks those, the
security controls and the analysis-relevant metadata under project attributes. Other
tools ignore attributes they do not recognise; this one reads them back. A round trip
is asserted to produce the same findings, not merely the same fields.

#### Threat Dragon

Diagram coordinates are written to a layout sidecar rather than into the model
(ADR 0003), and boundary membership is derived from the geometry of the original
diagram. Threat categories are free text whose meaning depends on the methodology, so
a category that cannot be mapped to STRIDE with confidence is imported and reported
as a warning rather than guessed at.
