# Threat Modeling Tool: Implementation Plan

Working name: **tmac** ("threat model as code"). This plan synthesises what works in
OWASP Threat Dragon, OWASP pytm and Threagile, and what each gets wrong, into a
single design and a phased build order.

Research basis (verified against source as of September 2026):

| Project | Version inspected | Core idea | Copy | Avoid |
|---|---|---|---|---|
| Threat Dragon 2.6.2 | Vue 3 (compat mode) + AntV X6, Express, Electron | GUI diagram editor, JSON file in the user's git repo | Diagramming UX, stateless git/Drive providers, threat status lifecycle, CI rigor (95% coverage, ZAP, SBOM, signed releases) | Hard-coded "suggestions" instead of a rule engine, no CLI/API, schema drift, free-text severity |
| pytm 1.4.0 | Python + Pydantic v2 | Model is a Python script; threats.json with `condition` expressions | Element security-control flags, data classification enum, CAPEC-linked threat library, golden-file tests, report templating | `eval` of strings from a data file, rigid class taxonomy, global registry, noisy findings from unset defaults |
| Threagile 0.9.x / 1.0-pre | Go CLI + REST, Docker | Rich YAML model, ~42 risk rules over a typed graph | Data assets with CIA ratings, technology catalogue as data, communication-link attributes, likelihood x impact severity, synthetic risk IDs + risk tracking, fail-on-orphan, JSON Schema + editor support | Go `.so` plugins, verbose YAML with no GUI, monolithic PDF, unreleased 1.0 |

## 1. Design principles

1. **The model file is the source of truth.** One declarative YAML (or JSON) document,
   validated by a published JSON Schema. Both the CLI and the GUI read and write the
   same file. No server-side database; files live in the user's repository.
2. **Threats come from rules, not hand-typing.** A rule library evaluated over the
   model graph generates risks. Manual threats are still allowed but are the
   exception. Rules are data, not compiled code, and are sandboxed.
3. **Stable identity.** Every element and generated risk has a deterministic ID so
   risk tracking, diffs and CI comments survive regeneration and re-layout.
4. **CI is a first-class consumer.** Exit codes, SARIF, JSON, and a `diff` command
   are designed before the GUI is.
5. **Semantics and layout are separate.** Diagram coordinates never pollute the
   security model; a semantic diff shows only security-relevant changes.
6. **Interoperable.** Import Threat Dragon v2, pytm JSON, Threagile YAML and Open
   Threat Model; export CycloneDX TM-BOM and OTM.

## 2. Recommended stack

**TypeScript monorepo (pnpm workspaces).** One language covers the core library, CLI,
web editor and optional stateless server, and Zod schemas emit the JSON Schema that
editors use for completion. Go would give a smaller CLI binary but forces a second
language for the editor, which is what left Threagile without a usable GUI.

| Package | Purpose | Key dependencies |
|---|---|---|
| `packages/core` | Zod schema, parser, model graph, ID generation, diff | `zod`, `yaml` |
| `packages/rules` | Rule engine and built-in rule library | `cel-js` (CEL expression evaluator), `js-yaml` |
| `packages/render` | DOT generation, ELK auto-layout, SVG | `elkjs`, `@viz-js/viz` |
| `packages/report` | Markdown, HTML, SARIF, JSON, PDF | Handlebars templates, Playwright or `pdf-lib` for PDF |
| `packages/importers` | Threat Dragon v2, pytm JSON, Threagile YAML, OTM | none beyond core |
| `apps/cli` | `tmac` command | `commander` |
| `apps/web` | Editor and viewer, deployable as static site | React, React Flow, TanStack Query |
| `apps/server` | Optional OAuth proxy for GitHub/GitLab (Threat Dragon pattern) | Hono |

Rule condition language: **CEL** (Common Expression Language). It is a widely used,
non-Turing-complete, sandboxed expression language with a JS implementation. This
directly replaces pytm's Python `eval` and Threagile's Go plugins.

## 3. Model schema (v1)

Draft of `threatmodel.yaml`. Field names borrow Threagile's vocabulary where it is
already precise, pytm's control flags where Threagile has none, and Threat Dragon's
element types for GUI familiarity.

```yaml
schema: tmac/1.0
meta:
  title: Payment Service
  owner: platform-security
  version: 3
  business_criticality: critical          # archive|operational|important|critical|mission-critical
  methodologies: [stride, linddun]

data_assets:
  card_data:
    description: Primary account numbers
    classification: strictly-confidential # public|internal|restricted|confidential|strictly-confidential
    integrity: critical
    availability: important
    quantity: many                        # very-few|few|many|very-many
    pii: true
    credentials: false
    regulations: [pci-dss]

elements:                                 # generic; role via `kind` + `technology`
  browser:
    kind: actor                           # actor|process|datastore|external
    technology: browser
    human: true
  api:
    kind: process
    technology: web-service-rest
    size: service                         # system|service|application|component
    machine: container                    # physical|virtual|container|serverless
    internet_facing: true
    custom_code: true
    processes: [card_data]
    controls:                             # pytm-style booleans, all default unknown (null)
      validates_input: true
      uses_parameterized_queries: true
      hardened: null
  db:
    kind: datastore
    technology: database
    stores: [card_data]
    encryption: transparent               # none|transparent|symmetric-shared-key|asymmetric|end-user-key

flows:
  - id: browser_to_api
    from: browser
    to: api
    protocol: https                       # catalogue-backed enum; is_encrypted derived
    authentication: token                 # none|credentials|session-id|token|client-certificate|two-factor
    authorization: end-user-identity
    sends: [card_data]
    receives: []
  - id: api_to_db
    from: api
    to: db
    protocol: jdbc
    authentication: credentials
    authorization: technical-user
    sends: [card_data]
    receives: [card_data]

trust_boundaries:
  internet:
    type: network-untrusted
  vpc:
    type: network-cloud-provider
    contains: [api, db]
    nested: [k8s_ns]
  k8s_ns:
    type: network-policy-namespace-isolation
    contains: [api]

assumptions:
  - id: A1
    text: TLS termination is at the load balancer, which is out of scope.
    suppresses: [unencrypted-communication@browser_to_api]

manual_threats:
  - id: T-001
    element: api
    stride: repudiation
    title: Payment events not logged
    severity: medium

risk_tracking:
  sql-injection@api:
    status: mitigated                     # unchecked|in-discussion|accepted|in-progress|mitigated|false-positive|transferred
    justification: ORM with bound parameters, verified in PR 412
    ticket: SEC-118
    date: 2026-09-01
    checked_by: bshelton
```

Design notes:

- **Generic elements with a technology catalogue.** A single `elements` map with
  `kind` and `technology` avoids pytm's rigid `Server`/`Lambda`/`LLM` class tree while
  keeping Threat Dragon's four familiar shapes. `technologies.yaml` (ported from
  Threagile) carries boolean attributes such as `web_application`, `identity_store`,
  `vulnerable_to_query_injection`, and `unprotected_communications_tolerated` that
  rules consume. Users can extend the catalogue in-repo.
- **Tri-state controls.** pytm treats an unset boolean as `false`, which is why one
  unset flag fires fifteen threats. Controls default to `null` ("unknown"), and rules
  distinguish "known bad" from "unknown". Unknown produces a lower-confidence finding
  and an `incomplete-model` risk, mirroring Threagile.
- **Protocol and technology enums live in YAML data files**, not code, and the
  JSON Schema is generated from them, so editor completion stays in sync.
- **Layout is a sidecar.** `threatmodel.layout.json` holds coordinates and diagram
  tweaks. Deleting it is safe; ELK regenerates a layout.
- **Includes** for large systems (Threagile's `includes`), merged before validation.
- **IDs are the map keys**, so renames are explicit and diffs are readable.

## 4. Rule engine

Each rule is a YAML document. Metadata fields are the union of Threagile's risk
category and pytm's CAPEC-linked threat entry.

```yaml
id: unencrypted-communication
title: Unencrypted communication
stride: information-disclosure
cwe: 319
capec: [CAPEC-117]
asvs: V9
cheat_sheet: https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html
function: operations                  # business-side|architecture|development|operations
detection_logic: >
  Flows over an unencrypted protocol that carry data rated above internal, or
  any authentication data, where the target does not tolerate plaintext.
false_positives: Links inside a single process or within a dedicated hardware boundary.
mitigation: Terminate TLS at the receiving asset or use a mutually authenticated tunnel.
scope: flow                            # element|flow|boundary|model
match: |
  !flow.protocol.encrypted
  && !flow.process_local
  && !flow.to.technology.unprotected_communications_tolerated
  && (flow.max_classification >= 'confidential' || flow.carries_credentials)
likelihood: |
  flow.crosses_network_boundary ? 'likely' : 'unlikely'
impact: |
  flow.max_classification >= 'strictly-confidential' || flow.carries_credentials ? 'high' : 'medium'
data_breach_probability: possible
```

Engine behaviour:

- The core builds a graph with derived properties (`crosses_network_boundary`,
  `max_classification`, `carries_credentials`, `internet_reachable`, boundary
  nesting) once, then evaluates every rule's `match` in CEL against each candidate in
  `scope`. Rules cannot mutate the model or call arbitrary functions.
- **Severity = likelihood x impact** using Threagile's 1-4 weights and the thresholds
  low / medium / elevated / high / critical.
- **Synthetic ID** = `rule@subject[@secondary]`, for example
  `unencrypted-communication@api_to_db`. IDs are stable across layout changes and
  renames of descriptions.
- `risk_tracking` keys must resolve to a generated or manual risk; orphans fail the
  run unless `--allow-orphaned-tracking` is passed. Wildcards such as
  `unnecessary-data-transfer@*` are supported.
- **Relative Attacker Attractiveness** (Threagile's RAA) is computed per element and
  shown in reports to prioritise.
- Custom rules: any `*.rule.yaml` under `.tmac/rules/` in the repo is loaded. No
  plugins, no code execution.

Initial library: port all 42 Threagile built-ins (they cover architecture-level
risks), then add pytm's high-value element-level threats whose conditions map cleanly
onto `controls` (input validation, CSRF, session handling, deserialisation, the LLM
set). Every rule ships with a positive and negative fixture model.

## 5. CLI

```
tmac init                      # scaffold threatmodel.yaml + example + .tmac/ dir
tmac validate [file]           # schema + referential integrity, exit 1 on error
tmac analyze [file]            # run rules; writes risks.json, report, diagrams
    --format json|sarif|md|html|pdf
    --fail-on high            # CI gate on unresolved severity
    --allow-orphaned-tracking
tmac diff <old> <new>          # semantic diff: elements, flows, boundaries, risks added/removed/changed
tmac diagram [file] --out dfd.svg --layout elk|dot
tmac explain <rule-id>         # print rule metadata and detection logic
tmac rules list
tmac import --from threat-dragon|pytm|threagile|otm <file>
tmac export --to tm-bom|otm
tmac track seed                # write unchecked entries for every open risk (Threagile macro)
tmac serve                     # local editor on http://localhost:7300 for this file
```

Output layout (`tmac analyze --out ./tm-out`): `risks.json`, `risks.sarif`,
`report.md`, `report.html`, `dfd.svg`, `data-assets.svg`, `stats.json`.

SARIF lets GitHub code scanning surface risks on PRs with zero extra integration.

## 6. Web editor

Built last, on top of a stable core, and shipped as a static site plus an embedded
`tmac serve` mode.

- React Flow canvas with the four Threat Dragon shapes plus boundary boxes. Edits
  write back to the YAML through the core (never to a private JSON), so GUI and CLI
  stay in lock-step.
- Property panels are generated from the JSON Schema (enum dropdowns, tri-state
  controls), the way Threagile's server generates its editor.
- Risks panel shows generated risks live as the user edits, with status editing that
  writes `risk_tracking`.
- Read-only mode renders a shared model from a URL or a git provider without login.
- Git providers copied from Threat Dragon: GitHub, GitLab, Bitbucket via a stateless
  OAuth proxy that never stores models. Scope requests to a single repo where the
  provider allows it, addressing the "full repo access" criticism.
- Desktop packaging (Tauri) is deferred; the CLI plus `tmac serve` covers offline use.

## 7. Reporting

- Markdown and HTML from Handlebars templates in `.tmac/templates/`, so teams can
  restyle (pytm's template idea, but with a mainstream engine).
- Toggles from Threat Dragon: show mitigated, show out of scope, show empty
  elements, include element properties.
- Sections: management summary, RAA ranking, risks by severity with STRIDE, CWE and
  mitigation, risk tracking table, data asset matrix, assumptions, diagrams.
- PDF rendered from the HTML with headless Chromium rather than a hand-built PDF
  writer.

## 8. Testing and release practices

- **Golden files** per feature: fixture model in, expected `risks.json`, `dfd.dot`,
  `report.md` out (pytm).
- **Table-driven enum and parser tests**, one fixture per rule with positive and
  negative cases (Threagile).
- **Round-trip tests**: import each foreign format, export, re-import, compare.
- Coverage gate at 90 percent on core and rules; Playwright e2e for the editor.
- CI: lint, typecheck, unit, e2e, CodeQL, SHA-pinned Actions, dependency cooldown,
  CycloneDX SBOM per release, Trivy on the container, signed tags, release
  candidates before every minor (Threat Dragon's contract).
- Docker image `tmac` with graphviz and Chromium pinned, usable as
  `docker run -v $PWD:/work tmac analyze /work/threatmodel.yaml`.
- `SECURITY.md`, `CODEOWNERS`, ADRs under `docs/adr/`.

## 9. Phased delivery

| Phase | Weeks | Deliverable | Exit criteria |
|---|---|---|---|
| 0 Foundations | 1 | Monorepo, CI, ADRs for stack, schema and CEL decisions | `pnpm test` green in CI, first ADRs merged |
| 1 Schema and core | 3 | Zod schema, YAML loader, includes, graph with derived properties, JSON Schema export, `validate`, `init` | Example model validates; JSON Schema gives completion in VS Code |
| 2 Rule engine | 3 | CEL evaluator, severity, synthetic IDs, risk tracking, 15 ported rules | Fixture models produce expected `risks.json` |
| 3 CLI outputs | 2 | `analyze` with JSON, SARIF, Markdown, HTML; DOT and ELK diagrams; `diff`; `--fail-on` | SARIF shows on a GitHub PR; diff readable in CI log |
| 4 Rule library | 3 | Remaining Threagile rules, pytm control-based rules, LINDDUN privacy rules driven by `pii`, technology catalogue complete | 60+ rules, each with fixtures and `explain` text |
| 5 Interop | 2 | Importers for Threat Dragon v2, pytm JSON, Threagile YAML, OTM; TM-BOM and OTM export | Round-trip tests pass on each project's own demo model |
| 6 Editor (viewer) | 3 | Static web app: load file, render diagram, risk list, report | Shared model viewable from a URL |
| 7 Editor (authoring) | 4 | React Flow editing, schema-driven property panels, YAML write-back, layout sidecar, `tmac serve` | Model edited in GUI round-trips through CLI unchanged |
| 8 Providers and release | 3 | OAuth proxy, GitHub/GitLab/Bitbucket save, PDF, Docker, 1.0 RC | RC cycle complete, SBOM and signed release published |

Roughly six months for one to two engineers. Phases 1 to 5 deliver a CI-usable
tool with no GUI, which is the fastest path to real value; the editor is where
Threat Dragon's lessons apply and where scope creep is likeliest.

## 10. Open decisions and risks

- **CEL versus a pure declarative matcher.** CEL is the recommendation. If the JS CEL
  implementation proves immature, fall back to a JSON-pattern matcher (field, op,
  value trees) that is less expressive but trivially safe. Decide in Phase 2 after
  porting the first ten rules.
- **Threat Dragon import fidelity.** Its files carry free-text severity and category
  names that vary by methodology. Import maps to manual threats with a best-effort
  STRIDE category and flags unmapped entries rather than guessing.
- **Rule quality over rule count.** pytm's library shows that many shallow rules
  create noise. Each rule needs `false_positives` text and a fixture that must not
  fire, reviewed before merge.
- **Methodology beyond STRIDE.** LINDDUN is included via `pii` data assets. CIA,
  DIE and PLOT4ai are deferred; the rule format has a `stride` field today and will
  need a generic `category` map before those are added.
- **AI assistance** is out of scope for 1.0. The clean JSON output and `explain`
  command make it easy for an external assistant to consume results, which is the
  boundary Threat Dragon chose as well.
