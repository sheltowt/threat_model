import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { EMPTY, evaluateModel, loadExample, loadFromUrl, urlTarget, type ModelState } from './state/model.js';
import {
  DEFAULT_ROUTE,
  formatHash,
  parseHash,
  type Route,
  type Selection,
  type Tab,
} from './state/selection.js';
import { Diagram } from './components/Diagram.js';
import { RiskList } from './components/RiskList.js';
import { DetailPanel } from './components/DetailPanel.js';
import { Diagnostics } from './components/Diagnostics.js';
import { ModelSource } from './components/ModelSource.js';
import { ReportView } from './components/ReportView.js';
import { saveTarget } from './lib/save.js';

const TABS: { id: Tab; label: string }[] = [
  { id: 'diagram', label: 'Diagram' },
  { id: 'risks', label: 'Findings' },
  { id: 'model', label: 'Model' },
  { id: 'report', label: 'Report' },
];

export function App() {
  const [state, setState] = useState<ModelState>(EMPTY);
  const [route, setRoute] = useState<Route>(() => parseHash(window.location.hash));
  const [loadError, setLoadError] = useState<string>('');
  const [dragging, setDragging] = useState(false);
  const fileInput = useRef<HTMLInputElement>(null);

  const open = useCallback((name: string, text: string) => {
    setLoadError('');
    setState(evaluateModel(name, text));
  }, []);

  // First load: a model named in the URL, otherwise the bundled example, so the
  // first thing anyone sees is a real model rather than an empty shell.
  useEffect(() => {
    const target = urlTarget(window.location.search);
    const start = async () => {
      try {
        const source = target.kind === 'url' && target.value
          ? await loadFromUrl(target.value)
          : await loadExample();
        open(source.name, source.text);
      } catch (err) {
        setLoadError((err as Error).message);
        try {
          const fallback = await loadExample();
          open(fallback.name, fallback.text);
        } catch {
          /* the example is bundled; if it fails there is nothing to fall back to */
        }
      }
    };
    void start();
  }, [open]);

  // Keep the address bar in step, so any view can be linked to.
  useEffect(() => {
    const next = formatHash(route);
    if (window.location.hash !== next) {
      window.history.replaceState(null, '', next);
    }
  }, [route]);

  useEffect(() => {
    const onHashChange = () => setRoute(parseHash(window.location.hash));
    window.addEventListener('hashchange', onHashChange);
    return () => window.removeEventListener('hashchange', onHashChange);
  }, []);

  const select = useCallback((selection: Selection) => {
    setRoute((current) => ({ ...current, selection }));
  }, []);

  const setTab = useCallback((tab: Tab) => {
    setRoute((current) => ({ ...current, tab }));
  }, []);

  const readFile = useCallback(
    (file: File) => {
      void file.text().then((text) => open(file.name, text));
    },
    [open],
  );

  const onDrop = useCallback(
    (event: React.DragEvent) => {
      event.preventDefault();
      setDragging(false);
      const file = event.dataTransfer.files[0];
      if (file) readFile(file);
    },
    [readFile],
  );

  const openCount = state.analysis?.stats.openRisks ?? 0;
  // Only a page served by `tmc serve` has somewhere to save to.
  const target = useMemo(() => saveTarget(window.location.search), []);

  const content = useMemo(() => {
    if (!state.ok || !state.graph || !state.analysis) {
      return (
        <>
          <Diagnostics diagnostics={state.diagnostics} />
          {state.text ? (
            <ModelSource
              text={state.text}
              name={state.name}
              diagnostics={state.diagnostics}
              elapsedMs={state.elapsedMs}
              onChange={(text) => open(state.name, text)}
              saveTo={target}
            />
          ) : (
            <p className="empty">Loading…</p>
          )}
        </>
      );
    }

    switch (route.tab) {
      case 'diagram':
        return (
          <>
            <Diagnostics diagnostics={state.diagnostics} />
            <Diagram
              graph={state.graph}
              risks={state.analysis.risks}
              selection={route.selection}
              onSelect={select}
            />
          </>
        );
      case 'risks':
        return (
          <>
            <Diagnostics diagnostics={state.diagnostics} />
            <RiskList analysis={state.analysis} selection={route.selection} onSelect={select} />
          </>
        );
      case 'model':
        return (
          <ModelSource
            text={state.text}
            name={state.name}
            diagnostics={state.diagnostics}
            elapsedMs={state.elapsedMs}
            onChange={(text) => open(state.name, text)}
            saveTo={target}
          />
        );
      case 'report':
        return <ReportView graph={state.graph} analysis={state.analysis} name={state.name} />;
    }
  }, [state, route, select, open, target]);

  const showPanel = state.ok && route.tab !== 'model' && route.tab !== 'report';

  return (
    <div
      className="app"
      onDragOver={(e) => {
        e.preventDefault();
        if (e.dataTransfer.types.includes('Files')) setDragging(true);
      }}
      // relatedTarget is null only when the pointer actually leaves the window,
      // so the overlay does not flicker as it crosses child elements.
      onDragLeave={(e) => {
        if (!e.relatedTarget) setDragging(false);
      }}
      onDrop={onDrop}
    >
      <header className="header">
        <span className="brand">
          tmc <small>threat models as code</small>
        </span>
        <span className="model-name" title={state.name}>
          {state.name}
        </span>
        <span className="spacer" />
        <input
          ref={fileInput}
          type="file"
          accept=".yaml,.yml,.json"
          hidden
          onChange={(e) => {
            const file = e.target.files?.[0];
            if (file) readFile(file);
            e.target.value = '';
          }}
        />
        <button type="button" className="btn" onClick={() => fileInput.current?.click()}>
          Open a file
        </button>
        <button
          type="button"
          className="btn"
          onClick={() => void loadExample().then((s) => open(s.name, s.text))}
        >
          Load the example
        </button>
      </header>

      <nav className="tabs" role="tablist">
        {TABS.map((tab) => (
          <button
            key={tab.id}
            type="button"
            role="tab"
            className="tab"
            aria-selected={route.tab === tab.id}
            onClick={() => setTab(tab.id)}
          >
            {tab.label}
            {tab.id === 'risks' && state.ok && <span className="count">{openCount}</span>}
          </button>
        ))}
      </nav>

      {dragging && (
        <div className="drop-overlay" aria-hidden="true">
          <div className="dropzone over">
            <h2>Drop a threat model here</h2>
            <p>A YAML or JSON model. It is read in this tab and never uploaded.</p>
          </div>
        </div>
      )}

      <div className={`main${showPanel ? '' : ' no-panel'}`}>
        <div className="content">
          {loadError && (
            <div className="note" style={{ borderLeftColor: 'var(--danger)' }}>
              Could not load that model: {loadError}. Showing the bundled example instead. A
              cross-origin fetch needs the other site to allow it, so a raw file URL usually
              works where a repository page does not.
            </div>
          )}
          {content}
        </div>
        {showPanel && state.graph && state.analysis && (
          <aside className="panel">
            <DetailPanel
              graph={state.graph}
              analysis={state.analysis}
              selection={route.selection}
              onSelect={select}
            />
          </aside>
        )}
      </div>

      <footer className="statusbar">
        {state.ok && state.graph ? (
          <>
            <span>{state.graph.elements.length} elements</span>
            <span className="sep">·</span>
            <span>{state.graph.flows.length} flows</span>
            <span className="sep">·</span>
            <span>{state.graph.data.length} data assets</span>
            <span className="sep">·</span>
            <span>{state.analysis?.risks.length ?? 0} findings</span>
            <span className="sep">·</span>
            <span>{state.analysis?.stats.rulesRun ?? 0} rules run</span>
            <span className="sep">·</span>
            <span>{state.elapsedMs.toFixed(0)} ms</span>
          </>
        ) : (
          <span>Model not valid</span>
        )}
        <span style={{ flex: 1 }} />
        <span>Everything runs in this tab. Nothing is uploaded.</span>
      </footer>
    </div>
  );
}
