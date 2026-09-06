/**
 * Selection and deep linking.
 *
 * The hash carries what the reader is looking at, so a link to a specific finding or
 * element can be pasted into a review comment and land on the same view.
 */

export type Selection =
  | { kind: 'none' }
  | { kind: 'element'; id: string }
  | { kind: 'flow'; id: string }
  | { kind: 'boundary'; id: string }
  | { kind: 'data'; id: string }
  | { kind: 'risk'; id: string };

export type Tab = 'diagram' | 'risks' | 'model' | 'report';

export interface Route {
  tab: Tab;
  selection: Selection;
}

const TABS: readonly Tab[] = ['diagram', 'risks', 'model', 'report'];

export const DEFAULT_ROUTE: Route = { tab: 'diagram', selection: { kind: 'none' } };

export function parseHash(hash: string): Route {
  const params = new URLSearchParams(hash.replace(/^#/, ''));
  const tab = params.get('tab');
  const route: Route = {
    tab: TABS.includes(tab as Tab) ? (tab as Tab) : DEFAULT_ROUTE.tab,
    selection: { kind: 'none' },
  };
  for (const kind of ['risk', 'element', 'flow', 'boundary', 'data'] as const) {
    const id = params.get(kind);
    if (id) {
      route.selection = { kind, id };
      break;
    }
  }
  return route;
}

export function formatHash(route: Route): string {
  const params = new URLSearchParams();
  params.set('tab', route.tab);
  if (route.selection.kind !== 'none') params.set(route.selection.kind, route.selection.id);
  return `#${params.toString()}`;
}

export function sameSelection(a: Selection, b: Selection): boolean {
  if (a.kind !== b.kind) return false;
  return a.kind === 'none' || b.kind === 'none' || a.id === b.id;
}
