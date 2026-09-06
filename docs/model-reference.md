# The model file

One YAML document describes the system. `tmac schema -o tmac.schema.json` emits the
JSON Schema, and pointing your editor at it gives completion and inline validation
for everything below.

Unknown keys are rejected rather than ignored, so a misspelt control cannot silently
disable itself.

## Controls are three-valued

This is the one thing to understand before anything else.

```yaml
controls:
  validates_input: true      # present
  rate_limited: false        # absent, and we know it
  # hardened:                nobody has recorded this
```

Omitting a control does not mean the control is missing. It means nobody has said.
Rules distinguish the two: a rule that depends on a control recorded `false` produces
a confirmed finding, and the same rule on an unrecorded control produces one marked
`confidence: low` that names the gap. Filling the model in makes findings sharper in
both directions.

## Top level

| key | notes |
|---|---|
| `schema` | must be `tmac/1.0` |
| `includes` | list of relative paths merged before validation |
| `meta` | required, see below |
| `data_assets` | map of id to data asset |
| `elements` | map of id to element |
| `flows` | list, each with its own `id` |
| `trust_boundaries` | map of id to boundary |
| `shared_runtimes` | map of id to runtime |
| `assumptions` | list |
| `manual_threats` | list |
| `risk_tracking` | map of finding id to status |
| `disabled_rules` | map of rule id to the reason |

Ids are map keys and must match `^[a-zA-Z0-9][a-zA-Z0-9_.-]*$`. They appear in
finding ids, so renaming one is a deliberate act that moves its tracking.

### includes

For a system too large for one file. Maps merge key-wise, lists concatenate, and a
scalar in the including file wins. A file included twice is used once.

```yaml
includes:
  - services/checkout.yaml
  - services/settlement.yaml
```

## meta

`title` is required. Everything else is optional.

| key | values |
|---|---|
| `title` `description` `owner` `author` `date` `version` | free text |
| `business_criticality` | `archive` `operational` `important` `critical` `mission-critical` |
| `management_summary` `business_overview` `technical_overview` | prose for the report |
| `questions` | map of question to answer; a `null` answer marks it open |
| `abuse_cases` | map of name to description |
| `security_requirements` | map of name to description |

Open questions appear in the report as a to-do list. Recording that you do not know
something is worth more than leaving it out.

## data_assets

```yaml
data_assets:
  card_data:
    description: Primary account number and expiry.
    classification: strictly-confidential
    integrity: critical
    availability: important
    quantity: many
    pii: true
    credentials: false
    regulations: [pci-dss]
    owner: payments
    justification: A pan is the archetypal regulated identifier.
```

| key | values | default |
|---|---|---|
| `classification` | `public` `internal` `restricted` `confidential` `strictly-confidential` | `internal` |
| `integrity` `availability` | `archive` `operational` `important` `critical` `mission-critical` | `operational` |
| `quantity` | `very-few` `few` `many` `very-many` | `few` |
| `usage` | `business` `devops` | `business` |
| `pii` `credentials` | boolean | `false` |
| `regulations` | free-form tags such as `pci-dss`, `gdpr`, `hipaa` | `[]` |

Classification drives element ratings, flow ratings, attacker attractiveness and most
rule conditions. It is the single highest-value field in the file.

`credentials: true` is what makes the credential-handling rules fire, so mark API
keys and signing secrets as data assets rather than leaving them implicit.

## elements

```yaml
elements:
  payment_api:
    name: Payment API
    technology: web-service-rest
    size: service
    machine: container
    internet_facing: true
    custom_code: true
    processes: [card_data]
    controls:
      validates_input: true
```

| key | values | default |
|---|---|---|
| `kind` | `actor` `process` `datastore` `external` | from the technology |
| `technology` | a catalogue entry | `unknown-technology` |
| `size` | `component` `application` `service` `system` | `application` |
| `machine` | `physical` `virtual` `container` `serverless` | unset |
| `usage` | `business` `devops` | `business` |
| `internet_facing` `human` `custom_code` `multi_tenant` `out_of_scope` | boolean | `false` |
| `encryption` | `none` `transparent` `symmetric-shared-key` `asymmetric-shared-key` `end-user-key` | `none` |
| `confidentiality` `integrity` `availability` | as for data assets | derived from data held |
| `processes` `stores` | data asset ids | `[]` |
| `accepts_formats` | `json` `xml` `yaml` `csv` `file` `serialization` `protobuf` `html` | `[]` |
| `controls` | see below | `{}` |

`processes` is data in flight, `stores` is data at rest. The distinction matters: a
stored asset counts roughly double towards attacker attractiveness, and the
encryption-at-rest rules only look at `stores`.

Leave `confidentiality`, `integrity` and `availability` unset and they are derived
from the highest-rated data the element holds. Set them to override.

`out_of_scope: true` removes an element from analysis. It wants a
`justification_out_of_scope`, and validation warns when one is missing, because an
unexplained exclusion is the commonest way a real risk disappears from a model.

### controls

Every one is optional and three-valued.

`authenticates_source` `authenticates_destination` `authorizes_source`
`checks_certificate_revocation` `checks_input_bounds` `encodes_output`
`has_access_control` `hardened` `implements_csrf_token` `implements_least_privilege`
`logs_security_events` `log_integrity_protected` `monitored` `rate_limited`
`redundant` `sanitizes_input` `uses_code_signing` `uses_content_security_policy`
`uses_mfa` `uses_parameterized_queries` `uses_secure_defaults`
`uses_strong_session_ids` `validates_content_type`
`validates_file_uploads` `validates_input` `validates_schema` `verifies_dependencies`
`content_filtered` `human_in_the_loop`

Flows carry the same block. A private tunnel is `vpn` on the flow rather than a
control, because a tunnel is a property of a route and not of an asset.

## flows

```yaml
flows:
  - id: api_to_db
    from: payment_api
    to: token_store
    protocol: sql-access-protocol-encrypted
    authentication: credentials
    authorization: technical-user
    sends: [payment_token]
    receives: [payment_token]
```

| key | values | default |
|---|---|---|
| `id` `from` `to` | required | |
| `protocol` | a catalogue entry | `unknown-protocol` |
| `authentication` | `none` `credentials` `session-id` `token` `client-certificate` `two-factor` | `none` |
| `authorization` | `none` `technical-user` `end-user-identity` | `none` |
| `vpn` `ip_filtered` `readonly` `is_response` | boolean | `false` |
| `sends` `receives` | data asset ids | `[]` |

Encryption is a property of the protocol, not a flag on the flow. Use
`sql-access-protocol-encrypted` rather than `sql-access-protocol` plus a note, so
every rule that asks about transport gets the same answer.

Mark the return leg of a request-response pair `is_response: true` and it stops
counting as an independent attack path.

## trust_boundaries

```yaml
trust_boundaries:
  internet:
    type: network-untrusted
    contains: [shopper]
  vpc:
    type: network-cloud-provider
    contains: [settlement_batch]
    nested: [web_tier]
  web_tier:
    type: network-policy-namespace-isolation
    contains: [storefront, payment_api]
```

Types: `network-untrusted` `network-on-prem` `network-dedicated-hoster`
`network-virtual-lan` `network-cloud-provider` `network-cloud-security-group`
`network-policy-namespace-isolation` `execution-environment`.

Every type except `execution-environment` counts as a network boundary, which is what
the transport rules test.

An element belongs to exactly one boundary and a boundary nests inside at most one
parent. Listing an element in two boundaries is an error; nest one inside the other
instead. Nesting cycles are rejected.

## assumptions

```yaml
assumptions:
  - id: A1
    text: TLS terminates at the load balancer, which is out of scope.
    suppresses: [unencrypted-communication@browser_to_api]
```

A suppressed finding stays in the output, marked with the assumption that suppressed
it, and is merely off the open list. An assumption that suppresses nothing produces a
warning, because it is either stale or misspelt.

## manual_threats

For anything a rule cannot see: a design concern from a review, a threat from a
workshop, an item from a penetration test.

```yaml
manual_threats:
  - id: T-001
    title: Settlement batch retains card data in temporary files
    element: settlement_batch
    stride: information-disclosure
    severity: high
    mitigation: Write intermediates to a tmpfs and delete on completion.
    cwe: 459
```

These join the generated risks in one list, with the id `manual@T-001`.

## risk_tracking

```yaml
risk_tracking:
  unencrypted-communication@api_to_db:
    status: mitigated
    justification: TLS terminates at the database, verified in PR 412
    ticket: SEC-118
    date: 2026-09-01
    checked_by: bshelton
  unnecessary-data-transfer@*:
    status: accepted
    justification: Reviewed as a group, the exposure is not material.
```

Statuses: `unchecked` `in-discussion` `accepted` `in-progress` `mitigated`
`false-positive` `transferred`. The last four take a risk off the open list.

Keys may end in `*`. The most specific matching key wins, so a blanket accept can be
overridden for one asset.

A key matching nothing **fails the run**, because the note attached to it now
describes a risk that does not exist. Pass `--allow-orphaned-tracking` to downgrade
that to a warning while you clean up.

`tmac track seed` writes an `unchecked` entry for every open risk, which is how you
adopt the tool on a system that already exists.

## disabled_rules

```yaml
disabled_rules:
  missing-build-infrastructure: This repository is infrastructure, not an application.
```

The reason is required, so the file records why rather than only what.

## Layout

Diagram coordinates live in `threatmodel.layout.json`, never in the model. Deleting
it is safe; the renderer falls back to automatic layout. This is what keeps a `git
diff` of the model showing security change rather than the fact that somebody moved a
box.
