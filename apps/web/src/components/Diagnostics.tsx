import type { Diagnostic } from 'tmac-core/browser';

/**
 * Diagnostics from the real loader, shown the way the CLI shows them.
 *
 * Warnings are worth surfacing rather than hiding: an out-of-scope element with no
 * justification, or an assumption that suppresses nothing, is exactly the sort of
 * thing that quietly removes a real risk from a model.
 */
export function Diagnostics({ diagnostics }: { diagnostics: readonly Diagnostic[] }) {
  if (diagnostics.length === 0) return null;
  const errors = diagnostics.filter((d) => d.severity === 'error');
  const warningOnly = errors.length === 0;

  return (
    <div className={`diagnostics${warningOnly ? ' warning-only' : ''}`}>
      <header>
        {warningOnly
          ? `${diagnostics.length} warning${diagnostics.length === 1 ? '' : 's'}`
          : `${errors.length} problem${errors.length === 1 ? '' : 's'} to fix before this model can be analysed`}
      </header>
      <ul>
        {diagnostics.map((d, i) => (
          <li key={`${d.code}-${d.path ?? i}`}>
            <div className={`sev-${d.severity}`}>{d.message}</div>
            {d.path && <div className="where">at {d.path}</div>}
            {d.hint && <div className="hint">{d.hint}</div>}
          </li>
        ))}
      </ul>
    </div>
  );
}
