# ADR 0004: A flat element taxonomy with a technology catalogue

Status: accepted (2026-09-06)

## Context

pytm models element types as a Python class hierarchy: `Element` to `Asset` to
`Server`, `Datastore`, `Process`, `SetOfProcesses`, `Lambda`, `ExternalEntity`, and
most recently `LLM` and `Agent`. Every genuinely new kind of thing needs a new class,
a new set of attributes and a release. The open issues on that repository include
"objects should be generic, with roles", "support containers" and "same threat to
multiple assets", which are all the same complaint.

Threat Dragon has the opposite problem: four shapes, `tm.Actor`, `tm.Process`,
`tm.Store` and `tm.Flow`, with a handful of booleans each. A message queue and a
payment gateway are both a process with nothing to distinguish them, so no rule can
say anything specific about either.

Threagile sits between the two: three asset types crossed with a long enumerated
`technology` list, and since its 1.0 work that list is data with boolean attributes
attached.

## Decision

Follow Threagile. An element is a `kind` (actor, process, datastore, external) plus a
`technology` drawn from a catalogue. The catalogue lives in
`packages/core/data/technologies.yaml` as data, each entry carrying boolean
attributes such as `web_application`, `identity_store`, `vulnerable_to_query_injection`
and `unprotected_communications_tolerated`.

**Rules never name a technology.** They ask about attributes:

```
flow.to.technology.vulnerable_to_query_injection && flow.from.custom_code
```

A project extends the catalogue in `.tmac/technologies.yaml` with only the entries it
is adding or changing.

pytm's `LLM` and `Agent` classes become the `ai-model` and `ai-agent` technologies,
with `ai`, `ai_agent` and `vulnerable_to_prompt_injection` attributes.

## Consequences

- Adding a technology is a data change a user can make locally, and every existing
  rule applies to it immediately with no code change and no release.
- Catalogue attributes are closed-world: an attribute a technology does not declare
  is definitely `false`. This is the opposite of security controls, which are
  open-world and tri-state (ADR 0002). The distinction is enforced at the graph
  boundary in `viewOf`, because collapsing it is what makes pytm noisy.
- A technology can carry an attribute no rule reads yet, which is how new rules
  become possible without touching the model format.
- The catalogue is a shared vocabulary and therefore a compatibility surface.
  Removing an attribute breaks project rules that read it.
