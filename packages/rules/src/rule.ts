import { z } from 'zod';
import {
  DATA_BREACH_PROBABILITY,
  IMPACT,
  LIKELIHOOD,
  LINDDUN,
  RULE_FUNCTION,
  RULE_SCOPE,
  STRIDE,
} from '@tmc/core/browser';

/**
 * A rule is a document, not code.
 *
 * The metadata block is the union of Threagile's risk category and pytm's
 * CAPEC-linked threat entry: enough for a reader to judge the finding without
 * opening the rule, and enough for `tmc explain` to be a real answer. Two fields are
 * mandatory that neither project requires: `false_positives`, because a rule whose
 * author cannot say when it is wrong is not ready, and `detection_logic`, because a
 * finding nobody can trace back to a condition gets ignored.
 */
export const ruleSchema = z
  .object({
    id: z
      .string()
      .regex(/^[a-z][a-z0-9-]*$/, 'rule ids are lower-case words joined by hyphens'),
    title: z.string().min(1),

    stride: z.enum(STRIDE),
    linddun: z.enum(LINDDUN).optional(),
    cwe: z.number().int().positive().optional(),
    capec: z.array(z.string()).default([]),
    asvs: z.string().optional(),
    cheat_sheet: z.string().url().optional(),
    function: z.enum(RULE_FUNCTION),

    description: z.string().optional(),
    detection_logic: z.string().min(1),
    risk_assessment: z.string().optional(),
    false_positives: z.string().min(1),
    mitigation: z.string().min(1),
    /** What to do, phrased as an instruction to whoever owns the asset. */
    action: z.string().optional(),
    /** How a reviewer confirms the mitigation is really in place. */
    check: z.string().optional(),

    scope: z.enum(RULE_SCOPE),
    /** Expression selecting the candidates this rule fires on. */
    match: z.string().min(1),
    /** Expression or literal producing the likelihood. */
    likelihood: z.string().default('likely'),
    /** Expression or literal producing the impact. */
    impact: z.string().default('medium'),
    data_breach_probability: z.enum(DATA_BREACH_PROBABILITY).default('improbable'),

    /** Template for the per-risk title; `{{ }}` interpolates an expression. */
    risk_title: z.string().optional(),
    /** Extra ids appended to the synthetic id, keeping it unique per finding. */
    id_suffix: z.array(z.string()).default([]),

    /** A rule off by default is opt-in through `enabled_rules` in the model. */
    enabled: z.boolean().default(true),
    tags: z.array(z.string()).default([]),
  })
  .strict()
  .superRefine((rule, ctx) => {
    const literalLikelihood = (LIKELIHOOD as readonly string[]).includes(rule.likelihood);
    const literalImpact = (IMPACT as readonly string[]).includes(rule.impact);
    if (!literalLikelihood && !rule.likelihood.trim()) {
      ctx.addIssue({ code: 'custom', message: 'likelihood must be a value or an expression' });
    }
    if (!literalImpact && !rule.impact.trim()) {
      ctx.addIssue({ code: 'custom', message: 'impact must be a value or an expression' });
    }
  });

export type Rule = z.output<typeof ruleSchema>;
export type RuleInput = z.input<typeof ruleSchema>;
