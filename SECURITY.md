# Security policy

## Reporting

Report a vulnerability privately through GitHub's security advisory form on this
repository. Please do not open a public issue first. We aim to acknowledge within
three working days.

## Threat model of the tool itself

`tmc` reads model files and rule files that may come from a repository the operator
does not fully control, so both are treated as untrusted input.

**Rule conditions.** Conditions are evaluated by a purpose-built interpreter in
`packages/rules/src/expr`. It has no `eval`, no dynamic `import`, no filesystem or
network access, no assignment, and no way to name a function outside a frozen table.
Property reads are blocked on `__proto__`, `constructor`, `prototype` and the
`__define*` accessors, values are read only through `hasOwnProperty`, and a
function-valued property is refused rather than returned. Evaluation is bounded by a
step budget and expression length, and `matches()` caps its pattern length.

This is deliberately unlike pytm, which evaluates Python expressions from a JSON
file, and unlike Threagile, whose custom rules are native Go plugins loaded into the
host process.

**Diagram output.** Every label passed into Graphviz DOT is escaped through one
helper, with a test that feeds it quotes, braces, backslashes, angle brackets and
newlines. Both Threat Dragon and pytm have shipped label-injection bugs here.

**Reports.** Generated HTML loads no external script, stylesheet or font, so a report
opened from a filesystem makes no network request. There is a test asserting this.

**What is not defended.** A model file can make the tool do a large amount of work,
for instance through a very large element count. There is no wall-clock limit on a
whole run, only per-expression bounds. Do not run `tmc` on an untrusted model in an
unbounded process.

## Supported versions

Pre-1.0. Only the latest release receives fixes.
