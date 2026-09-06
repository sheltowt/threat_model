# Writing a rule

A rule is a YAML document. Drop it in `.tmc/rules/` in your repository and `tmc
analyze` picks it up; give it the same `id` as a built-in and it replaces that
built-in, which is how you retune a noisy rule without forking the tool.

There is no code to compile and no plugin to load. Threagile requires custom rules to
be Go `.so` plugins, which are Linux and CGO bound and version-locked to the host
binary. pytm stores Python expressions and evaluates them. Neither is a good place to
put logic that runs against a file someone hands you.

## The shape

```yaml
id: unencrypted-communication      # lower-case, hyphenated, unique
title: Unencrypted communication
stride: information-disclosure     # one of the six
linddun: data-disclosure           # optional, for privacy rules
cwe: 319
capec: [CAPEC-117]
asvs: V9.1
cheat_sheet: https://cheatsheetseries.owasp.org/...
function: operations               # business-side | architecture | development | operations

detection_logic: >                 # required: what the condition actually tests
false_positives: >                 # required: when this rule is wrong
mitigation: >                      # required: what fixes it
risk_assessment: >                 # optional: why these ratings
action: ...                        # optional: the instruction to the asset owner
check: ...                         # optional: how a reviewer confirms the fix

scope: flow                        # element | flow | boundary | data | model
match: |                           # the condition
  ...
likelihood: |                      # a literal or an expression
  ...
impact: |
  ...
data_breach_probability: probable  # improbable | possible | probable
risk_title: "... {{ flow.id }} ..." # optional per-finding title
tags: [transport]
```

`detection_logic`, `false_positives` and `mitigation` are mandatory. A rule whose
author cannot say when it is wrong is not ready to fire at anyone, and it is the
absence of exactly this text that makes generated threat models get ignored.

## A YAML trap worth knowing

A ternary in a plain scalar breaks parsing, because YAML reads `? ` and `: ` as
mapping syntax:

```yaml
likelihood: flow.crosses_network_boundary ? 'likely' : 'unlikely'   # parse error
```

Always use a block scalar for expressions:

```yaml
likelihood: |
  flow.crosses_network_boundary ? 'likely' : 'unlikely'
```

## Severity is not yours to set

You give `likelihood` and `impact`; severity is their product on a 1-to-4 scale, so
two rules describing equally likely and equally damaging problems cannot disagree
about how bad they are.

| product | severity |
|---|---|
| 1 | low |
| 2 to 3 | medium |
| 4 to 8 | elevated |
| 9 to 12 | high |
| 16 | critical |

## The expression language

A subset of CEL. Literals, field access, indexing, `!`, `-`, arithmetic,
comparisons, `in`, `&&`, `||`, and a ternary. No assignment, no loops, no way to
name a function. See ADR 0002.

Functions: `size`, `count`, `known`, `default`, `has`, `lower`, `upper`, `contains`,
`startsWith`, `endsWith`, `matches`, `int`, `string`, `min`, `max`.

Macros on lists: `.exists(v, pred)`, `.exists_one(v, pred)`, `.all(v, pred)`,
`.none(v, pred)`, `.filter(v, pred)`, `.map(v, expr)`.

```
el.stores.exists(d, d.credentials)
flow.carries.all(d, d.classification <= 'internal')
```

### Ordered values compare by rank, not spelling

`flow.max_classification >= 'confidential'` compares position in the confidentiality
order, so `internal < confidential` is true. Plain string comparison gets this
backwards, which is one of the reasons we do not use an off-the-shelf CEL runtime.

Ordered sets: confidentiality, criticality (integrity, availability, business
criticality), quantity, likelihood, impact, severity, encryption, authentication,
authorization, size.

### The third truth value

**This is the part that differs from every tool this one learns from.**

A control the model does not mention is *unknown*, not absent. Reading it yields
`unknown`, which propagates by Kleene logic:

| expression | result |
|---|---|
| `!unknown` | unknown |
| `unknown && false` | false |
| `unknown && true` | unknown |
| `unknown \|\| true` | true |
| `unknown \|\| false` | unknown |

A `match` of `true` produces a normal finding. A `match` of `unknown` produces one
marked `confidence: low` that names the fields it could not settle, so the reader can
tell "you have this problem" from "you have not told me whether you have this
problem". `false` produces nothing.

So write the natural thing:

```
!flow.from.controls.uses_parameterized_queries
```

It fires confidently when the control is recorded `false`, tentatively when nobody
recorded it, and not at all when it is recorded `true`. Do not write
`default(x, false)` to force certainty unless absence really does imply the flaw.

Catalogue attributes are the opposite: closed-world. `tech.vulnerable_to_xss` on a
technology that does not declare it is a definite `false`, never unknown.

## What is in scope

`model` is always present. The rest depends on `scope:`.

### model

`title`, `business_criticality`, `elements` (in scope only), `all_elements`, `flows`,
`boundaries`, `data`, `shared_runtimes`, `element_count`, `flow_count`.

### element (bound to `element`, also `el`)

`id` `name` `description` `kind` `size` `machine` `usage` `owner` `tags`
`internet_facing` `human` `custom_code` `multi_tenant` `out_of_scope` `encryption`
`confidentiality` `integrity` `availability` `raa` `internet_reachable`
`accepts_formats`

- `technology` — `.id`, `.kind`, and every catalogue attribute
- `controls.<name>` — tri-state
- `processes` `stores` `handles` — lists of data assets
- `boundary`, `boundaries` (innermost first), `shared_runtimes`
- `incoming`, `outgoing` — lists of flows

### flow (bound to `flow`)

`id` `name` `description` `authentication` `authorization` `usage` `vpn`
`ip_filtered` `readonly` `is_response` `tags` `controls.<name>`

- `from`, `to` — elements
- `protocol` — `.id` plus `encrypted`, `process_local`, `database_access`,
  `web_access`, `file_transfer`
- `sends` `receives` `carries` — data assets
- `max_classification` `max_integrity` `carries_credentials` `carries_pii`
- `crosses_boundary` `crosses_network_boundary` `process_local` `from_internet`

### boundary (bound to `boundary`)

`id` `name` `type` `is_network` `members` `all_members` `nested` `parent` `tags`

### data (bound to `data`)

`id` `classification` `integrity` `availability` `quantity` `usage` `pii`
`credentials` `regulations` `origin` `owner` `orphaned` `tags`, plus `processed_by`,
`stored_by`, `sent_via`, `received_via`.

## Out-of-scope elements

The engine already excludes them: `element` scope sees only in-scope elements, and
`flow` scope sees a flow only when at least one end is in scope. Do not re-test
`out_of_scope` unless the rule is specifically about the far end of a link.

## Identifiers

A finding's id is `rule-id@subject-id`, built from ids alone, so it survives
rewording, re-layout and regeneration. That is what lets `risk_tracking` in a model
file keep pointing at the right thing. Add `id_suffix` when one rule can fire more
than once on the same subject.

## What the loader checks before your rule ever runs

Rules are parsed and checked when they load, not when they first match, so a mistake
fails the command immediately and names the file.

The check worth knowing about is **scope binding**. Writing `element.internet_facing`
in a `scope: flow` rule is rejected:

```
match references "element", which is not available to a flow rule.
Available: flow, model. "element" is bound in element scope, not flow scope.
```

Without that check the rule would load, run, match nothing and report nothing, for
ever, because an unbound name reads as `unknown` rather than raising. A rule that is
quietly inert is worse than one that fails loudly.

## Testing a rule

`packages/rules/test/library.test.ts` describes one system three ways: with no
control recorded, with every control recorded absent, and with every control recorded
present. Every rule in the library runs against all three, and the suite asserts the
properties that matter across the whole library rather than rule by rule:

- no rule raises a runtime error or produces an unusable rating on any of them
- recording controls as absent turns uncertain findings into confirmed ones
- recording controls as present makes findings go away
- every low-confidence finding names the field it could not settle
- **no rule fires on every candidate**, which is the check that catches a condition
  written too broadly

That last one is the important one. A rule that always fires carries no information,
and it is the commonest way a generated threat model turns into something everyone
scrolls past.

When you add a rule, run the suite and then look at what it does to the worked
example:

```bash
npx vitest run packages/rules
node apps/cli/dist/index.js analyze examples/payment-service/threatmodel.yaml
```

If your rule fires on most of that model, the condition is too broad, not thorough.
If it needs a system shape the example does not have, add that shape to the fixture
in `library.test.ts` rather than writing a fixture pair of your own.
