import { useMemo, useState } from 'react';
import { SEVERITY, isResolved } from 'tmac-core/browser';
import { isOpen, type Analysis } from 'tmac-rules/browser';
import type { Selection } from '../state/selection.js';

interface Props {
  analysis: Analysis;
  selection: Selection;
  onSelect: (selection: Selection) => void;
}

type Show = 'open' | 'all';

export function SeveritySummary({ analysis }: { analysis: Analysis }) {
  const counts = analysis.stats.risksBySeverity;
  const cells = [...SEVERITY].reverse().filter((s) => (counts[s] ?? 0) > 0);
  if (cells.length === 0) return null;
  return (
    <div className="summary-grid">
      {cells.map((s) => (
        <div className="summary-cell" key={s}>
          <div className={`n sev-${s}`}>{counts[s]}</div>
          <div className="label">{s}</div>
        </div>
      ))}
      <div className="summary-cell">
        <div className="n">{analysis.stats.openRisks}</div>
        <div className="label">open</div>
      </div>
      <div className="summary-cell">
        <div className="n" style={{ color: 'var(--warn)' }}>
          {analysis.stats.lowConfidenceRisks}
        </div>
        <div className="label">unsettled</div>
      </div>
    </div>
  );
}

export function RiskList({ analysis, selection, onSelect }: Props) {
  const [query, setQuery] = useState('');
  const [show, setShow] = useState<Show>('open');
  const [severity, setSeverity] = useState<string>('all');
  const [confidence, setConfidence] = useState<string>('all');

  const risks = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return analysis.risks.filter((risk) => {
      if (show === 'open' && !isOpen(risk)) return false;
      if (severity !== 'all' && risk.severity !== severity) return false;
      if (confidence !== 'all' && risk.confidence !== confidence) return false;
      if (!needle) return true;
      return (
        risk.title.toLowerCase().includes(needle) ||
        risk.id.toLowerCase().includes(needle) ||
        risk.rule.toLowerCase().includes(needle) ||
        risk.subject.id.toLowerCase().includes(needle) ||
        risk.stride.includes(needle)
      );
    });
  }, [analysis.risks, query, show, severity, confidence]);

  const hidden = analysis.risks.length - risks.length;

  return (
    <div>
      <SeveritySummary analysis={analysis} />

      {analysis.stats.lowConfidenceRisks > 0 && (
        <p className="note">
          {analysis.stats.lowConfidenceRisks} finding
          {analysis.stats.lowConfidenceRisks === 1 ? '' : 's'} could not be settled, because the
          model does not record a control the rule asked about. These are gaps in the model
          rather than confirmed flaws. Select one to see which field it needed.
        </p>
      )}

      <div className="risk-toolbar">
        <input
          type="search"
          placeholder="Filter by title, id, rule or element"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          aria-label="Filter findings"
        />
        <select value={show} onChange={(e) => setShow(e.target.value as Show)} aria-label="Status">
          <option value="open">Open only</option>
          <option value="all">All statuses</option>
        </select>
        <select
          value={severity}
          onChange={(e) => setSeverity(e.target.value)}
          aria-label="Severity"
        >
          <option value="all">Any severity</option>
          {[...SEVERITY].reverse().map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>
        <select
          value={confidence}
          onChange={(e) => setConfidence(e.target.value)}
          aria-label="Confidence"
        >
          <option value="all">Any confidence</option>
          <option value="high">Confirmed</option>
          <option value="low">Unsettled</option>
        </select>
      </div>

      {risks.length === 0 ? (
        <p className="empty">
          {analysis.risks.length === 0
            ? 'No findings. Either the model is in good shape or it is not describing much yet.'
            : 'Nothing matches these filters.'}
        </p>
      ) : (
        <ul className="risk-list">
          {risks.map((risk) => (
            <li key={risk.id}>
              <button
                type="button"
                className={`risk-row${isResolved(risk.status) || risk.suppressed_by ? ' resolved' : ''}`}
                aria-current={selection.kind === 'risk' && selection.id === risk.id}
                onClick={() => onSelect({ kind: 'risk', id: risk.id })}
              >
                <span className={`pill sev-${risk.severity}`}>{risk.severity}</span>
                <span className={`conf${risk.confidence === 'low' ? ' low' : ''}`}>
                  {risk.confidence === 'low' ? 'gap' : 'sure'}
                </span>
                <span>
                  <span className="title">{risk.title}</span>
                  <br />
                  <span className="meta">
                    {risk.id}
                    {risk.status !== 'unchecked' ? ` · ${risk.status}` : ''}
                    {risk.suppressed_by ? ` · suppressed by ${risk.suppressed_by}` : ''}
                  </span>
                </span>
              </button>
            </li>
          ))}
        </ul>
      )}

      {hidden > 0 && (
        <p className="empty" style={{ paddingTop: 12 }}>
          {hidden} finding{hidden === 1 ? '' : 's'} hidden by the filters above.
        </p>
      )}
    </div>
  );
}
