import { IMPACT, LIKELIHOOD, SEVERITY, type Impact, type Likelihood, type Severity } from 'tmac-core/browser';

/**
 * Severity is likelihood times impact, on Threagile's 1-to-4 weights.
 *
 * Deriving it means two rules that describe equally likely and equally damaging
 * problems cannot disagree about how bad they are, which is the failure mode of
 * Threat Dragon's free-text severity field, where the same issue is "High" in one
 * model and "Medium" in the next.
 */
export function weightOfLikelihood(l: Likelihood): number {
  return LIKELIHOOD.indexOf(l) + 1;
}

export function weightOfImpact(i: Impact): number {
  return IMPACT.indexOf(i) + 1;
}

export function calculateSeverity(likelihood: Likelihood, impact: Impact): Severity {
  const product = weightOfLikelihood(likelihood) * weightOfImpact(impact);
  if (product <= 1) return 'low';
  if (product <= 3) return 'medium';
  if (product <= 8) return 'elevated';
  if (product <= 12) return 'high';
  return 'critical';
}

/** Sort key placing the worst first. */
export function severityRank(s: Severity): number {
  return SEVERITY.indexOf(s);
}

export function atLeastSeverity(actual: Severity, threshold: Severity): boolean {
  return severityRank(actual) >= severityRank(threshold);
}

export function compareSeverity(a: Severity, b: Severity): number {
  return severityRank(b) - severityRank(a);
}
