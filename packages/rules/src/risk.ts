import type {
  Confidence,
  DataBreachProbability,
  Impact,
  Likelihood,
  Linddun,
  RiskStatus,
  RiskTracking,
  RuleFunction,
  Severity,
  Stride,
} from 'tmac-core/browser';

export interface RiskSubject {
  kind: 'element' | 'flow' | 'boundary' | 'data' | 'model';
  id: string;
  name: string;
}

export interface Risk {
  /** Synthetic id: rule@subject, stable across regeneration. */
  id: string;
  rule: string;
  title: string;

  severity: Severity;
  likelihood: Likelihood;
  impact: Impact;
  /**
   * `high` when the rule's condition was definitely true. `low` when the condition
   * could not be settled because the model does not record the controls it asks
   * about, in which case `unknowns` names them.
   */
  confidence: Confidence;
  unknowns: string[];

  stride: Stride;
  linddun?: Linddun;
  cwe?: number;
  capec: string[];
  asvs?: string;
  cheat_sheet?: string;
  function: RuleFunction;

  subject: RiskSubject;
  /** Element most worth looking at first, when the subject is not itself one. */
  most_relevant_element?: string;
  most_relevant_flow?: string;
  most_relevant_data?: string[];

  data_breach_probability: DataBreachProbability;
  data_breach_elements: string[];

  detection_logic: string;
  false_positives: string;
  mitigation: string;
  action?: string;
  check?: string;
  description?: string;

  status: RiskStatus;
  tracking?: RiskTracking & { key: string };
  /** Set when an assumption suppresses this risk; it stays in the output. */
  suppressed_by?: string;
  tags: string[];
}

export function isOpen(risk: Risk): boolean {
  if (risk.suppressed_by) return false;
  return risk.status === 'unchecked' || risk.status === 'in-discussion' || risk.status === 'in-progress';
}
