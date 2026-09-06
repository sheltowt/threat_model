/**
 * Synthetic risk identifiers.
 *
 * A risk's id is derived only from the rule and the model ids it concerns, never
 * from its title, description, position or the order rules ran in. That is what lets
 * `risk_tracking` in the model file survive a regeneration, a re-layout or a reworded
 * rule. Threagile establishes this idea; we keep the shape and tighten the rules
 * about what may appear in one.
 */

export interface SyntheticIdParts {
  rule: string;
  subject: string;
  secondary?: string[];
}

const SEP = '@';

export function syntheticId(parts: SyntheticIdParts): string {
  const tail = (parts.secondary ?? []).filter((s) => s.length > 0);
  return [parts.rule, parts.subject, ...tail].join(SEP);
}

export function parseSyntheticId(id: string): SyntheticIdParts | undefined {
  const bits = id.split(SEP);
  const rule = bits[0];
  const subject = bits[1];
  if (!rule || subject === undefined) return undefined;
  const parts: SyntheticIdParts = { rule, subject };
  if (bits.length > 2) parts.secondary = bits.slice(2);
  return parts;
}

/**
 * Match an id against a tracking key that may end in `*`, so a team can accept a
 * whole rule at once with `unnecessary-data-transfer@*`.
 */
export function matchesTrackingKey(key: string, id: string): boolean {
  if (key === id) return true;
  if (key === '*') return true;
  if (!key.includes('*')) return false;
  const pattern = key
    .split('*')
    .map((part) => part.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'))
    .join('.*');
  return new RegExp(`^${pattern}$`).test(id);
}

/**
 * Resolve which tracking key applies to a risk. Exact keys beat wildcards, and a
 * more specific wildcard beats a broader one, so a blanket accept can be overridden
 * for one asset.
 */
export function resolveTrackingKey(
  id: string,
  keys: Iterable<string>,
): string | undefined {
  let best: string | undefined;
  for (const key of keys) {
    if (!matchesTrackingKey(key, id)) continue;
    if (key === id) return key;
    if (best === undefined || key.length > best.length) best = key;
  }
  return best;
}
