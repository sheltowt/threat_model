import type { ModelGraph } from '@tmc/core/browser';
import type { Analysis, Risk } from '@tmc/rules/browser';
import type { Selection } from '../state/selection.js';

interface Props {
  graph: ModelGraph;
  analysis: Analysis;
  selection: Selection;
  onSelect: (selection: Selection) => void;
}

/** The right-hand panel: whatever is selected, explained. */
export function DetailPanel({ graph, analysis, selection, onSelect }: Props) {
  if (selection.kind === 'none') {
    return (
      <div>
        <h3>Nothing selected</h3>
        <p>
          Choose a finding from the list, or click a box or arrow in the diagram, and its detail
          appears here.
        </p>
      </div>
    );
  }

  if (selection.kind === 'risk') {
    const risk = analysis.risks.find((r) => r.id === selection.id);
    if (!risk) return <p className="empty">That finding is no longer present.</p>;
    return <RiskDetail risk={risk} onSelect={onSelect} />;
  }

  if (selection.kind === 'element') {
    const element = graph.elementById.get(selection.id);
    if (!element) return <p className="empty">No element with that id.</p>;
    const related = analysis.risks.filter(
      (r) => r.most_relevant_element === element.id || r.subject.id === element.id,
    );
    return (
      <div>
        <h2>{element.name}</h2>
        <p className="mono">{element.id}</p>
        {element.description && <p>{element.description}</p>}

        <h3>What it is</h3>
        <dl className="kv">
          <dt>Kind</dt>
          <dd>{element.kind}</dd>
          <dt>Technology</dt>
          <dd className="mono">{element.technology.id}</dd>
          <dt>Size</dt>
          <dd>{element.size}</dd>
          {element.machine && (
            <>
              <dt>Runs on</dt>
              <dd>{element.machine}</dd>
            </>
          )}
          <dt>Boundary</dt>
          <dd>{element.boundaries.map((b) => b.name).join(' inside ') || 'none'}</dd>
          <dt>Attractiveness</dt>
          <dd>{element.raa} of 100</dd>
        </dl>

        <h3>Exposure</h3>
        <dl className="kv">
          <dt>Internet facing</dt>
          <dd>{yesNo(element.internet_facing)}</dd>
          <dt>Internet reachable</dt>
          <dd>{yesNo(element.internet_reachable)}</dd>
          <dt>Custom code</dt>
          <dd>{yesNo(element.custom_code)}</dd>
          <dt>Multi tenant</dt>
          <dd>{yesNo(element.multi_tenant)}</dd>
          <dt>In scope</dt>
          <dd>{yesNo(!element.out_of_scope)}</dd>
        </dl>

        <h3>Ratings</h3>
        <dl className="kv">
          <dt>Confidentiality</dt>
          <dd>{element.confidentiality}</dd>
          <dt>Integrity</dt>
          <dd>{element.integrity}</dd>
          <dt>Availability</dt>
          <dd>{element.availability}</dd>
          <dt>Encryption</dt>
          <dd>{element.encryption}</dd>
        </dl>

        {element.handles.length > 0 && (
          <>
            <h3>Data</h3>
            <dl className="kv">
              {element.processes.length > 0 && (
                <>
                  <dt>Processes</dt>
                  <dd className="mono">{element.processes.map((d) => d.id).join(', ')}</dd>
                </>
              )}
              {element.stores.length > 0 && (
                <>
                  <dt>Stores</dt>
                  <dd className="mono">{element.stores.map((d) => d.id).join(', ')}</dd>
                </>
              )}
            </dl>
          </>
        )}

        <ControlsBlock controls={element.controls} />
        <RelatedRisks risks={related} onSelect={onSelect} />
      </div>
    );
  }

  if (selection.kind === 'flow') {
    const flow = graph.flowById.get(selection.id);
    if (!flow) return <p className="empty">No flow with that id.</p>;
    const related = analysis.risks.filter((r) => r.most_relevant_flow === flow.id);
    return (
      <div>
        <h2>{flow.name}</h2>
        <p className="mono">{flow.id}</p>
        {flow.description && <p>{flow.description}</p>}

        <h3>Route</h3>
        <dl className="kv">
          <dt>From</dt>
          <dd>
            <button type="button" className="btn" onClick={() => onSelect({ kind: 'element', id: flow.from.id })}>
              {flow.from.name}
            </button>
          </dd>
          <dt>To</dt>
          <dd>
            <button type="button" className="btn" onClick={() => onSelect({ kind: 'element', id: flow.to.id })}>
              {flow.to.name}
            </button>
          </dd>
          <dt>Protocol</dt>
          <dd className="mono">
            {flow.protocol.id}
            {flow.protocol['encrypted'] ? ' (encrypted)' : ''}
          </dd>
          <dt>Authentication</dt>
          <dd>{flow.authentication}</dd>
          <dt>Authorization</dt>
          <dd>{flow.authorization}</dd>
          <dt>Crosses network</dt>
          <dd>{yesNo(flow.crosses_network_boundary)}</dd>
        </dl>

        <h3>Carries</h3>
        <dl className="kv">
          <dt>Highest class</dt>
          <dd>{flow.max_classification}</dd>
          <dt>Credentials</dt>
          <dd>{yesNo(flow.carries_credentials)}</dd>
          <dt>Personal data</dt>
          <dd>{yesNo(flow.carries_pii)}</dd>
          {flow.carries.length > 0 && (
            <>
              <dt>Assets</dt>
              <dd className="mono">{flow.carries.map((d) => d.id).join(', ')}</dd>
            </>
          )}
        </dl>

        <ControlsBlock controls={flow.controls} />
        <RelatedRisks risks={related} onSelect={onSelect} />
      </div>
    );
  }

  if (selection.kind === 'data') {
    const asset = graph.dataById.get(selection.id);
    if (!asset) return <p className="empty">No data asset with that id.</p>;
    return (
      <div>
        <h2>{asset.id}</h2>
        {asset.description && <p>{asset.description}</p>}
        <h3>Rating</h3>
        <dl className="kv">
          <dt>Classification</dt>
          <dd>{asset.classification}</dd>
          <dt>Integrity</dt>
          <dd>{asset.integrity}</dd>
          <dt>Availability</dt>
          <dd>{asset.availability}</dd>
          <dt>Quantity</dt>
          <dd>{asset.quantity}</dd>
          <dt>Personal data</dt>
          <dd>{yesNo(asset.pii)}</dd>
          <dt>Credentials</dt>
          <dd>{yesNo(asset.credentials)}</dd>
          {asset.regulations.length > 0 && (
            <>
              <dt>Regulations</dt>
              <dd>{asset.regulations.join(', ')}</dd>
            </>
          )}
        </dl>
        <h3>Where it lives</h3>
        <dl className="kv">
          <dt>Stored by</dt>
          <dd className="mono">{asset.stored_by.map((e) => e.id).join(', ') || 'nowhere'}</dd>
          <dt>Processed by</dt>
          <dd className="mono">{asset.processed_by.map((e) => e.id).join(', ') || 'nothing'}</dd>
        </dl>
      </div>
    );
  }

  const boundary = graph.boundaryById.get(selection.id);
  if (!boundary) return <p className="empty">No trust boundary with that id.</p>;
  return (
    <div>
      <h2>{boundary.name}</h2>
      <p className="mono">{boundary.id}</p>
      <dl className="kv">
        <dt>Type</dt>
        <dd>{boundary.type}</dd>
        <dt>Separates networks</dt>
        <dd>{yesNo(boundary.is_network)}</dd>
        <dt>Contains</dt>
        <dd className="mono">{boundary.all_members.map((e) => e.id).join(', ') || 'nothing'}</dd>
      </dl>
    </div>
  );
}

function RiskDetail({ risk, onSelect }: { risk: Risk; onSelect: (s: Selection) => void }) {
  return (
    <div>
      <span className={`pill sev-${risk.severity}`}>{risk.severity}</span>{' '}
      <span className={`conf${risk.confidence === 'low' ? ' low' : ''}`}>
        {risk.confidence === 'low' ? 'unsettled' : 'confirmed'}
      </span>
      <h2 style={{ marginTop: 8 }}>{risk.title}</h2>
      <p className="mono">{risk.id}</p>

      {risk.confidence === 'low' && (
        <>
          <h3>Why this is unsettled</h3>
          <p>
            The rule could not decide, because the model does not record these fields. This is a
            gap in the model rather than a confirmed flaw. Record them and the finding will
            either disappear or become confirmed.
          </p>
          <ul className="unknowns">
            {risk.unknowns.map((u) => (
              <li key={u}>{u}</li>
            ))}
          </ul>
        </>
      )}

      <h3>Rating</h3>
      <dl className="kv">
        <dt>Severity</dt>
        <dd>
          {risk.severity} ({risk.likelihood} &times; {risk.impact})
        </dd>
        <dt>STRIDE</dt>
        <dd>{risk.stride}</dd>
        {risk.linddun && (
          <>
            <dt>LINDDUN</dt>
            <dd>{risk.linddun}</dd>
          </>
        )}
        {risk.cwe !== undefined && (
          <>
            <dt>CWE</dt>
            <dd>
              <a
                href={`https://cwe.mitre.org/data/definitions/${risk.cwe}.html`}
                target="_blank"
                rel="noreferrer noopener"
              >
                CWE-{risk.cwe}
              </a>
            </dd>
          </>
        )}
        <dt>Status</dt>
        <dd>{risk.status}</dd>
        <dt>Subject</dt>
        <dd>
          <button
            type="button"
            className="btn"
            onClick={() =>
              onSelect({
                kind: risk.subject.kind === 'model' ? 'none' : risk.subject.kind,
                id: risk.subject.id,
              } as Selection)
            }
          >
            {risk.subject.kind} {risk.subject.id}
          </button>
        </dd>
      </dl>

      <h3>What it detects</h3>
      <p>{risk.detection_logic}</p>

      <h3>When it is wrong</h3>
      <p>{risk.false_positives}</p>

      <h3>How to fix it</h3>
      <p>{risk.mitigation}</p>
      {risk.action && <p>{risk.action}</p>}

      {risk.check && (
        <>
          <h3>How to check the fix</h3>
          <p>{risk.check}</p>
        </>
      )}

      {risk.tracking && (
        <>
          <h3>Recorded decision</h3>
          <dl className="kv">
            <dt>Status</dt>
            <dd>{risk.tracking.status}</dd>
            {risk.tracking.justification && (
              <>
                <dt>Because</dt>
                <dd>{risk.tracking.justification}</dd>
              </>
            )}
            {risk.tracking.ticket && (
              <>
                <dt>Ticket</dt>
                <dd>{risk.tracking.ticket}</dd>
              </>
            )}
            {risk.tracking.checked_by && (
              <>
                <dt>By</dt>
                <dd>{risk.tracking.checked_by}</dd>
              </>
            )}
          </dl>
        </>
      )}

      {risk.cheat_sheet && (
        <p>
          <a href={risk.cheat_sheet} target="_blank" rel="noreferrer noopener">
            Further guidance
          </a>
        </p>
      )}
    </div>
  );
}

function ControlsBlock({ controls }: { controls: Record<string, boolean | undefined> }) {
  const entries = Object.entries(controls).filter(([, v]) => v !== undefined);
  return (
    <>
      <h3>Recorded controls</h3>
      {entries.length === 0 ? (
        <p>
          None recorded. Findings that depend on a control here will come back unsettled rather
          than confirmed.
        </p>
      ) : (
        <dl className="kv">
          {entries.map(([name, value]) => (
            <div key={name} style={{ display: 'contents' }}>
              <dt className="mono">{name}</dt>
              <dd style={{ color: value ? 'var(--ok)' : 'var(--danger)' }}>
                {value ? 'present' : 'absent'}
              </dd>
            </div>
          ))}
        </dl>
      )}
    </>
  );
}

function RelatedRisks({
  risks,
  onSelect,
}: {
  risks: readonly Risk[];
  onSelect: (s: Selection) => void;
}) {
  if (risks.length === 0) return null;
  return (
    <>
      <h3>Findings here ({risks.length})</h3>
      <ul className="risk-list">
        {risks.map((risk) => (
          <li key={risk.id}>
            <button
              type="button"
              className="risk-row"
              style={{ gridTemplateColumns: '84px minmax(0, 1fr)' }}
              onClick={() => onSelect({ kind: 'risk', id: risk.id })}
            >
              <span className={`pill sev-${risk.severity}`}>{risk.severity}</span>
              <span className="title">{risk.title}</span>
            </button>
          </li>
        ))}
      </ul>
    </>
  );
}

function yesNo(value: boolean): string {
  return value ? 'yes' : 'no';
}
