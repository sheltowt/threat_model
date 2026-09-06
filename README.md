# tmac

Threat models as code. One declarative file, a rule library that generates the
findings, and output a pipeline can act on.

```bash
npx tmac init
npx tmac analyze --format all --fail-on high
```

Or without installing anything:

```bash
docker run --rm -v "$PWD:/work" ghcr.io/sheltowt/tmac analyze
```

## Why another one

Three tools solve different halves of this problem, and each leaves the other half
open.

| | Threat Dragon | pytm | Threagile |
|---|---|---|---|
| Diagram editor | yes | no | no |
| CLI for CI | no | yes | yes |
| Rules generate findings | no, hard-coded suggestions | yes, Python `eval` | yes, compiled Go plugins |
| Rich typed model | no | partly | yes |
| Custom rules without forking | no | edit a JSON file of Python | Linux-only `.so` plugins |

`tmac` takes the model from Threagile, the element-level security controls from pytm,
the storage and diagramming approach from Threat Dragon, and makes rules data rather
than code.

## The one idea that is new

**A control you have not recorded is unknown, not absent.**

pytm treats an unset boolean as `false`, so a half-finished model produces a wall of
findings and everyone learns to ignore the report. Here, controls are three-valued
and conditions evaluate under Kleene logic. A rule that cannot settle its condition
produces a finding marked `confidence: low` that names the fields it could not
resolve:

```
[elevated/low] sql-nosql-injection@batch_to_token_store
    Nightly settlement batch may build injectable queries against Token store
    unknown: flow.from.controls.uses_parameterized_queries
```

That is a different sentence from "you have a SQL injection flaw", and it is the
sentence the model actually supports. Record the control and the finding either
resolves or becomes confirmed.

## The model

```yaml
schema: tmac/1.0
meta:
  title: Payment Service
  business_criticality: critical

data_assets:
  card_data:
    classification: strictly-confidential
    integrity: critical
    pii: true
    regulations: [pci-dss]

elements:
  payment_api:
    technology: web-service-rest
    machine: container
    custom_code: true
    processes: [card_data]
    controls:
      validates_input: true
      uses_parameterized_queries: true
      rate_limited: false          # recorded absent, so findings are confirmed
      # hardened:                  omitted, so findings are low confidence

flows:
  - id: api_to_db
    from: payment_api
    to: token_store
    protocol: sql-access-protocol
    authentication: credentials
    sends: [payment_token]

trust_boundaries:
  vpc:
    type: network-cloud-provider
    contains: [payment_api, token_store]
```

Elements are generic: a `kind` plus a `technology` from a catalogue, rather than a
class hierarchy of `Server`, `Lambda` and `LLM`. Rules never name a technology; they
ask about its attributes, so adding `our-event-bus` to `.tmac/technologies.yaml` makes
every existing rule apply to it.

Diagram coordinates live in a separate `threatmodel.layout.json`, so a `git diff`
shows security changes and not the fact that somebody moved a box.

## Rules are documents

```yaml
id: unencrypted-communication
title: Unencrypted communication
stride: information-disclosure
cwe: 319
function: operations

detection_logic: >
  A flow whose protocol is not encrypted, is not confined to one process, and
  carries either credentials or data classified confidential or above.
false_positives: >
  Links inside a single host, or already wrapped by a service mesh that terminates
  mutual TLS transparently.
mitigation: >
  Use the encrypted variant of the protocol with TLS 1.2 or better.

scope: flow
match: |
  !flow.protocol.encrypted
  && !flow.process_local
  && (flow.carries_credentials || flow.max_classification >= 'confidential')
likelihood: |
  flow.crosses_network_boundary ? 'likely' : 'unlikely'
impact: |
  flow.carries_credentials ? 'high' : 'medium'
```

`detection_logic`, `false_positives` and `mitigation` are required. A rule whose
author cannot say when it is wrong is not ready to fire at anyone.

Conditions run in a purpose-built evaluator: no `eval`, no plugins, no filesystem, no
network, no way to name a function that is not on a fixed list. Ordered values
compare by rank, so `'internal' < 'confidential'` is true. See
[ADR 0002](docs/adr/0002-expression-language.md).

Drop a `*.rule.yaml` in `.tmac/rules/` to add one. Reuse a built-in id to replace it.

## Severity is derived

You supply likelihood and impact; severity is their product. Two rules describing
equally likely and equally damaging problems cannot disagree about how bad they are,
which is the failure mode of a free-text severity field.

| product | severity |
|---|---|
| 1 | low |
| 2 to 3 | medium |
| 4 to 8 | elevated |
| 9 to 12 | high |
| 16 | critical |

## Findings keep their identity

A finding's id is `rule-id@subject-id`, built from ids alone. Reword the rule,
re-lay-out the diagram, regenerate the report: the id does not move, so this keeps
pointing at the right thing.

```yaml
risk_tracking:
  unencrypted-communication@api_to_db:
    status: mitigated
    justification: TLS terminates at the database, verified in PR 412
    ticket: SEC-118
    checked_by: bshelton
```

A tracking key that stops matching anything fails the run rather than sitting there
quietly describing a risk that no longer exists.

## Commands

| | |
|---|---|
| `tmac init` | scaffold a model |
| `tmac validate` | schema and cross-reference check |
| `tmac analyze` | run the rules; `--format json,sarif,md,html,all` |
| `tmac analyze --fail-on high` | exit 1 on an open risk at or above a severity |
| `tmac diff old.yaml new.yaml` | semantic diff, security-relevant changes flagged |
| `tmac explain <rule-or-finding-id>` | why a rule exists and why a finding is uncertain |
| `tmac diagram` | data flow or data asset diagram as SVG |
| `tmac track seed` | write tracking entries for every open risk |
| `tmac import --from threat-dragon model.json` | convert from another tool |
| `tmac export --to tm-bom` | CycloneDX threat model BOM, or OTM |
| `tmac serve --write` | open the editor against the local file, and save back to it |
| `tmac schema -o tmac.schema.json` | JSON Schema for editor completion |

## The editor

```bash
tmac serve --write
```

A browser view of the model: the diagram, the findings with filters, the detail of
any element, flow or finding, and the report. Editing the source reanalyses as you
type, and Save writes back to the file on disk.

It is a static site that does its own parsing and analysis in the tab, running the
same core and the same rule library as the CLI rather than a second implementation
that can disagree with it (ADR 0006). Nothing is uploaded, and it works offline.

`tmac serve` binds to the loopback interface, serves one asset directory, and touches
exactly one file. It is read only unless you pass `--write`, and a save that would
not load is refused rather than written.

Findings, elements and flows are all linkable:

```
#tab=risks&risk=unencrypted-communication@api_to_token_store
```

## In CI

```yaml
- run: npx tmac analyze --format sarif --fail-on high
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: tm-out/risks.sarif
```

Findings appear on the pull request as code scanning alerts. Risks that are accepted
or mitigated in `risk_tracking` are uploaded as suppressed rather than dropped, so
GitHub shows them as dismissed rather than losing them.

## Interoperating

Importers read OWASP Threat Dragon v2, pytm, Threagile and Open Threat Model.
Exporters write Open Threat Model and a CycloneDX threat model BOM.

Two things are worth knowing before you trust an import.

**From pytm**, a control that reads `false` cannot be distinguished from one nobody
recorded, because pytm defaults them all to `False`. The importer brings those across
as unrecorded and tells you how many, so a freshly imported model produces
low-confidence findings where pytm produced confident ones. That is the import being
honest about what the source file actually knew.

**Through OTM**, a round trip keeps its meaning. OTM has no data asset of its own, so
`tmac` parks those and the shared runtimes under project attributes, which another
tool ignores and this one reads back. There is a test asserting the stronger property
that matters: the same model produces the same findings after a round trip, not
merely the same fields.

## Layout

| | |
|---|---|
| `packages/core` | schema, loader, model graph, diff, JSON Schema |
| `packages/rules` | expression evaluator, engine, built-in rule library |
| `packages/render` | Graphviz DOT and SVG, via WASM so there is no system dependency |
| `packages/report` | Markdown, HTML, SARIF, JSON |
| `packages/importers` | Threat Dragon, pytm, Threagile, OTM |
| `apps/cli` | the `tmac` command |
| `apps/web` | the browser viewer and editor |

## Documentation

- [Getting started](docs/getting-started.md)
- [The model file](docs/model-reference.md), every field
- [Writing a rule](docs/rule-authoring.md)
- [Running in CI](docs/ci-integration.md)
- [PLAN.md](PLAN.md), the design this was built from

Decisions and why:

- [ADR 0001: TypeScript monorepo](docs/adr/0001-typescript-monorepo.md)
- [ADR 0002: the expression language](docs/adr/0002-expression-language.md)
- [ADR 0003: layout lives outside the model](docs/adr/0003-layout-sidecar.md)
- [ADR 0004: a flat element taxonomy](docs/adr/0004-flat-element-taxonomy.md)
- [ADR 0005: synthetic ids and risk tracking](docs/adr/0005-synthetic-ids-and-tracking.md)
- [ADR 0006: a browser-capable core](docs/adr/0006-browser-capable-core.md)

## Status

Early but working end to end. 53 built-in rules, 308 tests.

Built and tested: the model format, the rule format and engine, the reporters, the
importers, the CLI, and a browser editor that reads, analyses and saves a model.

Not built: drag-and-drop diagram editing, and the hosted git provider integration
from [PLAN.md](PLAN.md). Editing today is the model text with live analysis, which is
the half of authoring that carries the value; the diagram is laid out automatically
and is read only.

## Releasing

Tag a version and the release workflow does the rest: it verifies, then packs the
CLI, installs it into a clean directory and runs it end to end, and only publishes
if that works. Publishing a CLI nobody has run from a tarball is how a broken
release reaches people.

```bash
npm version 0.1.0 --workspaces --include-workspace-root
git tag v0.1.0 && git push --tags
```

`npm` packages publish with provenance, and the container image is built with
provenance and an SBOM.

## Licence

Apache-2.0.
