import { z } from 'zod';
import {
  AUTHENTICATION,
  AUTHORIZATION,
  BOUNDARY_TYPE,
  CONFIDENTIALITY,
  CRITICALITY,
  DATA_FORMAT,
  ELEMENT_KIND,
  ENCRYPTION,
  LINDDUN,
  MACHINE,
  QUANTITY,
  RISK_STATUS,
  SIZE,
  STRIDE,
  USAGE,
} from './enums.js';

/**
 * An identifier used as a map key or cross-reference. Kept to a conservative
 * character set because these appear in synthetic risk IDs, file names and URLs.
 */
export const idSchema = z
  .string()
  .min(1)
  .max(120)
  .regex(/^[a-zA-Z0-9][a-zA-Z0-9_.-]*$/, 'must start alphanumeric and contain only [A-Za-z0-9_.-]');

/**
 * Security controls, deliberately tri-state.
 *
 * `true` asserts the control is present, `false` asserts it is absent, and omitting
 * the key means nobody has said. pytm collapses the third case into `false`, which
 * is why one unset flag there fires a dozen threats. Rules here see `unknown` and
 * downgrade the finding rather than inventing certainty. See ADR 0002.
 */
export const CONTROL_NAMES = [
  'authenticates_source',
  'authenticates_destination',
  'authorizes_source',
  'checks_certificate_revocation',
  'checks_input_bounds',
  'encodes_output',
  'has_access_control',
  'hardened',
  'implements_csrf_token',
  'implements_least_privilege',
  'logs_security_events',
  'log_integrity_protected',
  'monitored',
  'rate_limited',
  'redundant',
  'sanitizes_input',
  'uses_code_signing',
  'uses_content_security_policy',
  'uses_mfa',
  'uses_parameterized_queries',
  'uses_secure_defaults',
  'uses_strong_session_ids',
  'uses_vpn',
  'validates_content_type',
  'validates_file_uploads',
  'validates_input',
  'validates_schema',
  'verifies_dependencies',
  'content_filtered',
  'human_in_the_loop',
] as const;
export type ControlName = (typeof CONTROL_NAMES)[number];

const controlsSchema = z
  .object(
    Object.fromEntries(
      CONTROL_NAMES.map((name) => [name, z.boolean().optional()]),
    ) as Record<ControlName, z.ZodOptional<z.ZodBoolean>>,
  )
  .strict()
  .describe('Security controls. Omit a key to state that it is unknown, rather than false.');

export const dataAssetSchema = z
  .object({
    description: z.string().optional(),
    classification: z.enum(CONFIDENTIALITY).default('internal'),
    integrity: z.enum(CRITICALITY).default('operational'),
    availability: z.enum(CRITICALITY).default('operational'),
    quantity: z.enum(QUANTITY).default('few'),
    usage: z.enum(USAGE).default('business'),
    pii: z.boolean().default(false),
    credentials: z.boolean().default(false),
    /** Free-form compliance tags, for example pci-dss, gdpr, hipaa. */
    regulations: z.array(z.string()).default([]),
    origin: z.string().optional(),
    owner: z.string().optional(),
    justification: z.string().optional(),
    tags: z.array(z.string()).default([]),
  })
  .strict();

export const elementSchema = z
  .object({
    name: z.string().optional(),
    description: z.string().optional(),
    /** Defaults from the technology catalogue when omitted. */
    kind: z.enum(ELEMENT_KIND).optional(),
    technology: z.string().default('unknown-technology'),
    size: z.enum(SIZE).default('application'),
    machine: z.enum(MACHINE).optional(),
    usage: z.enum(USAGE).default('business'),
    internet_facing: z.boolean().default(false),
    human: z.boolean().default(false),
    custom_code: z.boolean().default(false),
    multi_tenant: z.boolean().default(false),
    out_of_scope: z.boolean().default(false),
    justification_out_of_scope: z.string().optional(),
    encryption: z.enum(ENCRYPTION).default('none'),
    owner: z.string().optional(),
    /** CIA ratings; when omitted these are derived from the data the element holds. */
    confidentiality: z.enum(CONFIDENTIALITY).optional(),
    integrity: z.enum(CRITICALITY).optional(),
    availability: z.enum(CRITICALITY).optional(),
    processes: z.array(idSchema).default([]),
    stores: z.array(idSchema).default([]),
    accepts_formats: z.array(z.enum(DATA_FORMAT)).default([]),
    controls: controlsSchema.default({}),
    tags: z.array(z.string()).default([]),
  })
  .strict();

export const flowSchema = z
  .object({
    id: idSchema,
    from: idSchema,
    to: idSchema,
    name: z.string().optional(),
    description: z.string().optional(),
    protocol: z.string().default('unknown-protocol'),
    authentication: z.enum(AUTHENTICATION).default('none'),
    authorization: z.enum(AUTHORIZATION).default('none'),
    usage: z.enum(USAGE).default('business'),
    vpn: z.boolean().default(false),
    ip_filtered: z.boolean().default(false),
    readonly: z.boolean().default(false),
    /** A response flow is not counted as an independent attack path. */
    is_response: z.boolean().default(false),
    sends: z.array(idSchema).default([]),
    receives: z.array(idSchema).default([]),
    controls: controlsSchema.default({}),
    tags: z.array(z.string()).default([]),
  })
  .strict();

export const trustBoundarySchema = z
  .object({
    name: z.string().optional(),
    description: z.string().optional(),
    type: z.enum(BOUNDARY_TYPE).default('network-on-prem'),
    contains: z.array(idSchema).default([]),
    nested: z.array(idSchema).default([]),
    tags: z.array(z.string()).default([]),
  })
  .strict();

export const sharedRuntimeSchema = z
  .object({
    name: z.string().optional(),
    description: z.string().optional(),
    runs: z.array(idSchema).default([]),
    tags: z.array(z.string()).default([]),
  })
  .strict();

export const assumptionSchema = z
  .object({
    id: idSchema,
    text: z.string(),
    /**
     * Synthetic risk IDs this assumption suppresses. pytm's `Assumption(exclude=...)`
     * idea, but the suppressed risk stays in the output marked as suppressed so a
     * reviewer can audit what an assumption is hiding.
     */
    suppresses: z.array(z.string()).default([]),
  })
  .strict();

export const manualThreatSchema = z
  .object({
    id: idSchema,
    title: z.string(),
    description: z.string().optional(),
    element: idSchema.optional(),
    flow: idSchema.optional(),
    stride: z.enum(STRIDE).optional(),
    linddun: z.enum(LINDDUN).optional(),
    severity: z.enum(['low', 'medium', 'elevated', 'high', 'critical']).default('medium'),
    mitigation: z.string().optional(),
    cwe: z.number().int().positive().optional(),
    tags: z.array(z.string()).default([]),
  })
  .strict();

export const riskTrackingSchema = z
  .object({
    status: z.enum(RISK_STATUS),
    justification: z.string().optional(),
    ticket: z.string().optional(),
    date: z.string().optional(),
    checked_by: z.string().optional(),
  })
  .strict();

export const metaSchema = z
  .object({
    title: z.string(),
    description: z.string().optional(),
    owner: z.string().optional(),
    author: z.string().optional(),
    date: z.string().optional(),
    version: z.union([z.string(), z.number()]).optional(),
    business_criticality: z.enum(CRITICALITY).default('important'),
    management_summary: z.string().optional(),
    business_overview: z.string().optional(),
    technical_overview: z.string().optional(),
    questions: z.record(z.string(), z.string().nullable()).default({}),
    abuse_cases: z.record(z.string(), z.string()).default({}),
    security_requirements: z.record(z.string(), z.string()).default({}),
  })
  .strict();

export const modelSchema = z
  .object({
    schema: z.literal('tmac/1.0'),
    /** Relative paths merged before validation, for models too large for one file. */
    includes: z.array(z.string()).default([]),
    meta: metaSchema,
    data_assets: z.record(idSchema, dataAssetSchema).default({}),
    elements: z.record(idSchema, elementSchema).default({}),
    flows: z.array(flowSchema).default([]),
    trust_boundaries: z.record(idSchema, trustBoundarySchema).default({}),
    shared_runtimes: z.record(idSchema, sharedRuntimeSchema).default({}),
    assumptions: z.array(assumptionSchema).default([]),
    manual_threats: z.array(manualThreatSchema).default([]),
    risk_tracking: z.record(z.string(), riskTrackingSchema).default({}),
    /** Rule IDs to skip entirely for this model, with a reason. */
    disabled_rules: z.record(z.string(), z.string()).default({}),
  })
  .strict();

export type Model = z.output<typeof modelSchema>;
export type ModelInput = z.input<typeof modelSchema>;
export type DataAsset = z.output<typeof dataAssetSchema>;
export type ElementDef = z.output<typeof elementSchema>;
export type FlowDef = z.output<typeof flowSchema>;
export type TrustBoundaryDef = z.output<typeof trustBoundarySchema>;
export type SharedRuntimeDef = z.output<typeof sharedRuntimeSchema>;
export type Assumption = z.output<typeof assumptionSchema>;
export type ManualThreat = z.output<typeof manualThreatSchema>;
export type RiskTracking = z.output<typeof riskTrackingSchema>;
export type Controls = z.output<typeof controlsSchema>;
