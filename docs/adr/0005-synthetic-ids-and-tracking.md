# ADR 0005: Findings are identified by rule and subject alone

Status: accepted (2026-09-06)

## Context

A generated threat model is regenerated constantly, and the notes a team attaches to
its findings ("accepted, the processor holds the risk, SEC-118") are the most
expensive content in the whole system. Those notes are worthless if they cannot be
reattached to the right finding after a regeneration.

Threat Dragon assigns each threat a UUID and a running `number` from a counter in the
file. The UUID survives, but only because the threat itself is stored by hand; the
tool cannot regenerate it. pytm has no persistent finding identity at all beyond the
threat id and the element, and its `Finding` objects are rebuilt from scratch on
every run. Threagile gets it right: a synthetic id built from the risk category and
the ids of the assets involved.

## Decision

A finding's id is `rule-id@subject-id`, with further `@`-joined parts when one rule
can fire more than once on the same subject. It is derived only from identifiers.
Nothing about the title, description, severity, position, rule ordering or run
timestamp enters into it.

Consequences that follow directly:

- Rewording a rule does not move its findings.
- Re-laying-out a diagram does not move its findings, because layout is not in the
  model at all (ADR 0003).
- Renaming an element *does* move its findings, and that is correct: an id is the
  name of the thing, and renaming one is a modelling decision that deserves a
  conscious update to the tracking.

`risk_tracking` in the model file is keyed by these ids, with `status`,
`justification`, `ticket`, `date` and `checked_by`. Keys may end in `*`, so a team
can accept a whole rule at once; the most specific matching key wins, so a blanket
accept can be overridden for one asset.

## Orphaned keys fail the run

A tracking key that matches no current finding is an error, not a warning, unless
`--allow-orphaned-tracking` is passed. An orphan means either the risk was fixed and
the note is stale, or an id was renamed and the note is now attached to nothing. In
both cases a file that reads as "this risk is accepted, see SEC-118" is describing a
risk that does not exist, and quietly ignoring it is how a threat model becomes
fiction. Threagile takes the same position and is right to.

## Suppression keeps the finding visible

An assumption may suppress a finding. The finding still appears in the output, marked
with the assumption that suppressed it, and is merely off the open list. pytm's
`Assumption(exclude=...)` removes the finding from the report entirely, which makes
an assumption an invisible way to delete a risk. A reviewer needs to be able to audit
what the assumptions are hiding.
