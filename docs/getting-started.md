# Getting started

## Install

```bash
npx tmac --help
```

Or from the container, which needs nothing installed:

```bash
docker run --rm -v "$PWD:/work" ghcr.io/sheltowt/tmac --help
```

## Five minutes

```bash
mkdir payments && cd payments
npx tmac init
npx tmac analyze
```

`init` writes a small worked model and a `.tmac/` directory. `analyze` runs the rule
library over it and prints what it found.

Wire up editor completion once and the rest of the work is much faster:

```bash
npx tmac schema -o tmac.schema.json
```

The scaffolded model already carries the `yaml-language-server` comment that points
at it, so VS Code and anything else speaking the YAML language server will complete
every enum in the file.

## Reading the output

```
Risks  1 high | 3 elevated

SEVERITY  CONF  ID                                         TITLE
--------  ----  -----------------------------------------  -----
high      high  manual@T-001                               Settlement batch retains card data
elevated  low   sql-nosql-injection@batch_to_token_store    Nightly batch may build injectable queries
elevated  high  unencrypted-communication@api_to_token_store  Unencrypted link from Payment API

1 finding could not be settled
  These are model gaps, not confirmed flaws.
```

Two columns matter.

**SEVERITY** is likelihood times impact. You never set it directly; it follows from
the rule's assessment of how reachable the problem is and how much it would cost.

**CONF** is whether the rule could settle its condition. `high` means the model says
this is true. `low` means the model does not record something the rule needed, so the
finding is a question rather than a verdict.

Ask about any of them:

```bash
npx tmac explain sql-nosql-injection@batch_to_token_store
```

For a low-confidence finding that prints the exact fields nobody recorded.

## Closing a gap

`explain` answers this one finding at a time. To see the whole list at once, worst
first:

```bash
npx tmac questions
```

```
WORST     WAITING  RECORD THIS                                 FOR
--------  -------  ------------------------------------------  ---------------------
high      1        ops_to_api.controls.uses_mfa                missing-authentication-second-factor
elevated  2        token_store.controls.authenticates_source   missing-mutual-authentication
elevated  1        payment_api.controls.hardened               missing-hardening
```

That is the model's own to-do list. Work down it and the findings sharpen in both
directions.

Say it told you the model does not record whether the batch uses parameterised
queries. If it does:

```yaml
elements:
  settlement_batch:
    controls:
      uses_parameterized_queries: true
```

The finding disappears. If it does not, write `false` and the finding becomes
confirmed at full confidence. Either way the model now says something true, and the
next run is sharper.

Sometimes answering one question reveals another: a rule that could not get past an
earlier condition now evaluates further and asks about the next field along. That is
the model getting more specific rather than the list growing without end.

This is the loop the whole tool is built around. A threat model that does not record
what you know is not worth regenerating.

## Deciding about a risk

Some findings are real and you are going to live with them. Record that:

```yaml
risk_tracking:
  unencrypted-communication@api_to_token_store:
    status: accepted
    justification: The link is inside a dedicated VLAN with no other tenant.
    ticket: SEC-118
    date: 2026-09-06
    checked_by: bshelton
```

Statuses are `unchecked`, `in-discussion`, `accepted`, `in-progress`, `mitigated`,
`false-positive` and `transferred`. The last four take a risk off the open list.

The key is the finding id, which is built from the rule id and the element ids alone.
Reword the rule, move the diagram, regenerate the report: it keeps pointing at the
same thing. If it ever stops matching, the run fails rather than quietly leaving you
with a note about a risk that no longer exists.

On an existing system, seed the whole list at once:

```bash
npx tmac track seed --write
```

## Reports and diagrams

```bash
npx tmac analyze --format all --out tm-out
```

That writes `report.html` and `report.md`, the machine-readable `risks.json`,
`stats.json` and `technical-assets.json`, a SARIF file for code scanning, and both
diagrams as SVG and DOT. The HTML is self-contained, loads nothing from the network,
and prints to PDF.

## Looking at it in a browser

```bash
npx tmac serve --write
```

That opens a local editor on the file: the diagram, the findings with filters, the
detail of anything you click, and the report. Editing the source reanalyses as you
type, and Save writes back to the file.

It parses and analyses in the tab, using the same core and rule library as the
command line, so it cannot tell you something different from CI. Nothing is
uploaded. Without `--write` it is read only, and a save that would not load is
refused rather than written.

Any view is linkable, which is useful in a review comment:

```
http://127.0.0.1:7300/?model=/api/model#tab=risks&risk=sql-nosql-injection@batch_to_token_store
```

## Adding a rule

Rules are documents. Drop this in `.tmac/rules/no-public-buckets.rule.yaml`:

```yaml
id: no-public-buckets
title: Object storage exposed to the internet
stride: information-disclosure
cwe: 200
function: operations

detection_logic: >
  A datastore element marked internet_facing that holds data classified above
  internal.
false_positives: >
  Buckets that deliberately serve public assets. Reclassify that content as public
  rather than suppressing this rule.
mitigation: >
  Put the bucket behind a signed-URL service and remove public read.

scope: element
match: |
  element.kind == 'datastore'
  && element.internet_facing
  && element.confidentiality > 'internal'
likelihood: very-likely
impact: high
```

`tmac analyze` picks it up immediately. Give a rule the same `id` as a built-in and it
replaces that built-in, which is how you retune one that is noisy for you without
forking anything.

The full reference is in [rule authoring](rule-authoring.md).

## Coming from another tool

```bash
npx tmac import --from threat-dragon model.json -o threatmodel.yaml
npx tmac import --from pytm pytm-output.json -o threatmodel.yaml
npx tmac import --from threagile threagile.yaml -o threatmodel.yaml
```

Read the warnings. Importing from pytm in particular will report how many controls
were dropped because pytm cannot distinguish "absent" from "unrecorded", and those
are exactly the fields worth filling in first.

## Next

- [The model file](model-reference.md), every field
- [Writing a rule](rule-authoring.md)
- [Running in CI](ci-integration.md)
