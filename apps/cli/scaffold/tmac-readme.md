# .tmac

Project configuration for `tmac`.

## rules/

Any `*.rule.yaml` here is loaded on top of the built-in library. Give a rule the
same `id` as a built-in and it replaces that built-in, which is how you retune a
rule that is noisy in your context without forking the tool.

See `tmac explain <rule-id>` for the shape of an existing rule, and the rule
authoring guide in the project documentation.

## technologies.yaml and protocols.yaml

Optional. Add entries to extend the catalogue with something you run in house:

```yaml
technologies:
  our-event-bus:
    kind: process
    message_queue: true
    high_value_target: true
```

You only list what you are adding or changing. Existing rules apply to your new
technology immediately, because rules test catalogue attributes rather than naming
technologies directly.
