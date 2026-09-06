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

Report text is built from rule and model prose, which is untrusted, so the escapers
on that path are treated as security code. Markdown table cells escape the backslash
before the pipe, because escaping only the pipe turns `\|` into a literal backslash
followed by an unescaped pipe and the cell ends there. Whitespace collapsing uses one
unambiguous character class rather than a pattern with `\s` on both sides of a `\n`,
which backtracks quadratically on a long run of spaces.

**Embedding a diagram.** `svgBody` selects the `<svg>` element rather than deleting
the prologue, doctype and comments around it. Deleting them was unsound twice over:
removing a comment can splice its neighbours into a fresh `<!--`, so one pass does
not converge, and the lazy scans backtracked quadratically. It is an extractor, not
a sanitiser, and callers must only pass it SVG they generated.

**Includes.** `includes` is the one place a YAML document's keys are copied into an
object the tool already holds, which is the shape of a prototype pollution sink. Keys
that reach the prototype chain are refused with an error rather than merged.

**What is not defended.** A model file can make the tool do a large amount of work,
for instance through a very large element count. There is no wall-clock limit on a
whole run, only per-expression bounds. Do not run `tmc` on an untrusted model in an
unbounded process.

## Scanning

CodeQL runs on every pull request. The findings above were all raised by it against
this repository's own code and fixed, each with a test written as the attack it
prevents. An alert on our own scanner is treated as a defect, not as noise.

## Supported versions

Pre-1.0. Only the latest release receives fixes.
