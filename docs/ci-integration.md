# Running tmac in CI

## Exit codes

| code | meaning |
|---|---|
| 0 | clean |
| 1 | the model is invalid, or `--fail-on` was breached |
| 2 | the command was used wrongly |

## GitHub Actions, with findings on the pull request

```yaml
name: Threat model
on: [pull_request]

permissions:
  contents: read
  security-events: write

jobs:
  threat-model:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '22'
      - run: npx tmac validate
      - run: npx tmac analyze --format sarif --fail-on high
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: tm-out/risks.sarif
          category: threat-model
```

`if: always()` matters. When `--fail-on` trips, the step fails, and without it the
findings that explain the failure would never be uploaded.

Risks that `risk_tracking` records as accepted, mitigated, transferred or a false
positive are uploaded as SARIF suppressions rather than dropped, so GitHub shows them
as dismissed and you can still see them.

## Showing what changed

`tmac diff` compares two models semantically. Layout is not in the model, so its
output contains only security-relevant change.

```yaml
      - run: git fetch origin ${{ github.base_ref }} --depth=1
      - run: git show origin/${{ github.base_ref }}:threatmodel.yaml > /tmp/base.yaml
      - run: npx tmac diff /tmp/base.yaml threatmodel.yaml | tee /tmp/diff.txt
```

Lines marked `!` widen the attack surface.

## Container

```bash
docker run --rm -v "$PWD:/work" ghcr.io/sheltowt/tmac analyze --format all --fail-on high
```

The image carries WASM Graphviz, so diagram rendering has no system dependency and no
version of Graphviz to drift between your machine and the runner.

## Choosing a threshold

Start with `--fail-on critical` and tighten. A gate that fires on the first run
teaches everyone to pass `--exclude`.

Low-confidence findings are model gaps rather than confirmed flaws, and they count
towards `--fail-on` like any other. If that is too aggressive while a model is young,
gate on the report and read the low-confidence section as a to-do list for the model
rather than for the system.

## Seeding tracking

Adopting the tool on a system that already exists produces a long list at once.

```bash
npx tmac track seed --write
```

That writes an `unchecked` entry for every open risk. Work through them, setting a
status and a justification. From then on a new finding is genuinely new, because
everything old is already accounted for.
