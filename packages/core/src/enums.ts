/**
 * Ordered and unordered enumerations used across the model.
 *
 * Ordered enums are declared as arrays: position in the array is the ordinal, and
 * the rule expression language compares them by ordinal rather than lexically.
 * Threagile gets this right and pytm does not; see ADR 0002.
 */

export const CONFIDENTIALITY = [
  'public',
  'internal',
  'restricted',
  'confidential',
  'strictly-confidential',
] as const;
export type Confidentiality = (typeof CONFIDENTIALITY)[number];

/** Used for integrity, availability and business criticality alike. */
export const CRITICALITY = [
  'archive',
  'operational',
  'important',
  'critical',
  'mission-critical',
] as const;
export type Criticality = (typeof CRITICALITY)[number];

export const QUANTITY = ['very-few', 'few', 'many', 'very-many'] as const;
export type Quantity = (typeof QUANTITY)[number];

export const LIKELIHOOD = ['unlikely', 'likely', 'very-likely', 'frequent'] as const;
export type Likelihood = (typeof LIKELIHOOD)[number];

export const IMPACT = ['low', 'medium', 'high', 'very-high'] as const;
export type Impact = (typeof IMPACT)[number];

export const SEVERITY = ['low', 'medium', 'elevated', 'high', 'critical'] as const;
export type Severity = (typeof SEVERITY)[number];

export const ENCRYPTION = [
  'none',
  'transparent',
  'symmetric-shared-key',
  'asymmetric-shared-key',
  'end-user-key',
] as const;
export type Encryption = (typeof ENCRYPTION)[number];

export const AUTHENTICATION = [
  'none',
  'credentials',
  'session-id',
  'token',
  'client-certificate',
  'two-factor',
] as const;
export type Authentication = (typeof AUTHENTICATION)[number];

export const AUTHORIZATION = ['none', 'technical-user', 'end-user-identity'] as const;
export type Authorization = (typeof AUTHORIZATION)[number];

export const SIZE = ['component', 'application', 'service', 'system'] as const;
export type ElementSize = (typeof SIZE)[number];

export const DATA_BREACH_PROBABILITY = ['improbable', 'possible', 'probable'] as const;
export type DataBreachProbability = (typeof DATA_BREACH_PROBABILITY)[number];

/**
 * Every ordered enum, keyed by name. The expression evaluator consults this table to
 * decide whether `>=` on two strings means ordinal or lexical comparison.
 */
export const ORDERED_ENUMS = {
  confidentiality: CONFIDENTIALITY,
  criticality: CRITICALITY,
  quantity: QUANTITY,
  likelihood: LIKELIHOOD,
  impact: IMPACT,
  severity: SEVERITY,
  encryption: ENCRYPTION,
  authentication: AUTHENTICATION,
  authorization: AUTHORIZATION,
  size: SIZE,
  data_breach_probability: DATA_BREACH_PROBABILITY,
} as const satisfies Record<string, readonly string[]>;

export type OrderedEnumName = keyof typeof ORDERED_ENUMS;

/** Reverse index from member value to the ordered enums that contain it. */
const MEMBER_INDEX = new Map<string, { name: OrderedEnumName; rank: number }[]>();
for (const [name, members] of Object.entries(ORDERED_ENUMS)) {
  members.forEach((member, rank) => {
    const existing = MEMBER_INDEX.get(member) ?? [];
    existing.push({ name: name as OrderedEnumName, rank });
    MEMBER_INDEX.set(member, existing);
  });
}

/**
 * Rank of a value within an ordered enum, or undefined when the value is not a
 * member. When `hint` is omitted the value must be unambiguous across all ordered
 * enums; `low` for instance belongs only to `impact`, but `none` belongs to both
 * `encryption` and `authentication`, so a hint is required there.
 */
export function rankOf(value: string, hint?: OrderedEnumName): number | undefined {
  if (hint) {
    const idx = ORDERED_ENUMS[hint].indexOf(value as never);
    return idx === -1 ? undefined : idx;
  }
  const hits = MEMBER_INDEX.get(value);
  if (!hits || hits.length === 0) return undefined;
  const first = hits[0]!;
  // Ambiguous members only compare when every candidate agrees on the rank.
  if (hits.some((h) => h.rank !== first.rank)) return undefined;
  return first.rank;
}

/** True when both values belong to the same ordered enum, so `<`/`>` are meaningful. */
export function comparableEnum(a: string, b: string): OrderedEnumName | undefined {
  const ha = MEMBER_INDEX.get(a);
  const hb = MEMBER_INDEX.get(b);
  if (!ha || !hb) return undefined;
  for (const x of ha) {
    if (hb.some((y) => y.name === x.name)) return x.name;
  }
  return undefined;
}

// --- Unordered enumerations -------------------------------------------------

export const ELEMENT_KIND = ['actor', 'process', 'datastore', 'external'] as const;
export type ElementKind = (typeof ELEMENT_KIND)[number];

export const MACHINE = ['physical', 'virtual', 'container', 'serverless'] as const;
export type Machine = (typeof MACHINE)[number];

export const USAGE = ['business', 'devops'] as const;
export type Usage = (typeof USAGE)[number];

export const DATA_FORMAT = [
  'json',
  'xml',
  'yaml',
  'csv',
  'file',
  'serialization',
  'protobuf',
  'html',
] as const;
export type DataFormat = (typeof DATA_FORMAT)[number];

export const BOUNDARY_TYPE = [
  'network-untrusted',
  'network-on-prem',
  'network-dedicated-hoster',
  'network-virtual-lan',
  'network-cloud-provider',
  'network-cloud-security-group',
  'network-policy-namespace-isolation',
  'execution-environment',
] as const;
export type BoundaryType = (typeof BOUNDARY_TYPE)[number];

/** Every boundary type except `execution-environment` separates networks. */
export function isNetworkBoundary(type: BoundaryType): boolean {
  return type !== 'execution-environment';
}

export const STRIDE = [
  'spoofing',
  'tampering',
  'repudiation',
  'information-disclosure',
  'denial-of-service',
  'elevation-of-privilege',
] as const;
export type Stride = (typeof STRIDE)[number];

/** LINDDUN privacy categories, used by the privacy rule set. */
export const LINDDUN = [
  'linking',
  'identifying',
  'non-repudiation',
  'detecting',
  'data-disclosure',
  'unawareness',
  'non-compliance',
] as const;
export type Linddun = (typeof LINDDUN)[number];

export const RULE_FUNCTION = [
  'business-side',
  'architecture',
  'development',
  'operations',
] as const;
export type RuleFunction = (typeof RULE_FUNCTION)[number];

export const RISK_STATUS = [
  'unchecked',
  'in-discussion',
  'accepted',
  'in-progress',
  'mitigated',
  'false-positive',
  'transferred',
] as const;
export type RiskStatus = (typeof RISK_STATUS)[number];

/** Statuses that take a risk off the open list. */
const RESOLVED: ReadonlySet<string> = new Set([
  'mitigated',
  'false-positive',
  'accepted',
  'transferred',
]);
export function isResolved(status: RiskStatus): boolean {
  return RESOLVED.has(status);
}

export const CONFIDENCE = ['low', 'medium', 'high'] as const;
export type Confidence = (typeof CONFIDENCE)[number];

export const RULE_SCOPE = ['element', 'flow', 'boundary', 'data', 'model'] as const;
export type RuleScope = (typeof RULE_SCOPE)[number];
