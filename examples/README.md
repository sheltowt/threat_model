# Examples

## payment-service

A card-present checkout API with a storefront, a token store, a nightly settlement
batch and an out-of-scope card processor. It is deliberately imperfect: several
controls are recorded absent, several are left unrecorded, and one threat is written
by hand rather than generated.

```bash
node apps/cli/dist/index.js analyze examples/payment-service/threatmodel.yaml
```

It exists to exercise the parts of the format that are easy to get wrong, so it is
worth reading as a worked reference:

- **Nested boundaries.** A cloud VPC containing a namespace-isolated web tier and a
  security-group data tier, with the shopper, the operator and the processor outside
  in an untrusted network.
- **Data flowing across a scope edge.** Card data leaves for the processor, which is
  out of scope with a written justification. The link is still modelled; only the far
  side is excluded.
- **The three states of a control.** The payment API records
  `uses_parameterized_queries: true` and `rate_limited: false`, and says nothing about
  hardening. Each produces a different outcome: silence, a confirmed finding, and a
  low-confidence finding that names the gap.
- **A shared runtime** spanning the storefront, the API and the batch, which is what
  the mixed-tenancy rules look at.
- **Open questions** recorded as `null` answers in `meta.questions`, so the report
  carries them as a to-do list rather than losing them.
- **A manual threat** for something no rule can see: the batch writing intermediate
  files to local disk.

The settlement batch is the most instructive element. It reads tokens over an
unencrypted database protocol and records nothing about parameterised queries, so it
draws both a confirmed transport finding and an uncertain injection finding. Compare
`tmac explain` on the two.
