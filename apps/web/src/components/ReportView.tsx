import { useEffect, useMemo, useState } from 'react';
import type { ModelGraph } from '@tmc/core/browser';
import type { Analysis } from '@tmc/rules/browser';
import { toHtml, toMarkdown } from '@tmc/report/browser';
import { dataAssetSvg, dataFlowSvg } from '../lib/render.js';

interface Props {
  graph: ModelGraph;
  analysis: Analysis;
  name: string;
}

/**
 * The same report the CLI writes, rendered in an iframe.
 *
 * An iframe rather than inline markup for two reasons: the report brings its own
 * complete stylesheet and would otherwise fight the app's, and printing it to PDF is
 * then a matter of printing the frame.
 */
export function ReportView({ graph, analysis, name }: Props) {
  const [html, setHtml] = useState<string>('');

  const markdown = useMemo(
    () => toMarkdown(analysis, graph, { modelPath: name }),
    [analysis, graph, name],
  );

  useEffect(() => {
    let cancelled = false;
    Promise.all([
      dataFlowSvg(graph, { risks: [...analysis.risks] }).catch(() => undefined),
      dataAssetSvg(graph).catch(() => undefined),
    ]).then(([dataFlow, dataAssets]) => {
      if (cancelled) return;
      setHtml(
        toHtml(analysis, graph, {
          modelPath: name,
          includeDiagrams: true,
          diagrams: {
            ...(dataFlow ? { dataFlow } : {}),
            ...(dataAssets ? { dataAssets } : {}),
          },
        }),
      );
    });
    return () => {
      cancelled = true;
    };
  }, [graph, analysis, name]);

  return (
    <div style={{ display: 'grid', gridTemplateRows: 'auto minmax(0, 1fr)', gap: 10, height: '100%' }}>
      <div className="diagram-controls">
        <button type="button" className="btn" onClick={() => printFrame()}>
          Print or save as PDF
        </button>
        <button
          type="button"
          className="btn"
          onClick={() => download(html, 'report.html', 'text/html')}
          disabled={!html}
        >
          Download HTML
        </button>
        <button
          type="button"
          className="btn"
          onClick={() => download(markdown, 'report.md', 'text/markdown')}
        >
          Download Markdown
        </button>
        <span style={{ flex: 1 }} />
        <span style={{ color: 'var(--muted)', fontSize: 12 }}>
          Identical to what <span className="mono">tmc analyze --format all</span> writes.
        </span>
      </div>
      {html ? (
        <iframe className="report-frame" title="Threat model report" srcDoc={html} id="report-frame" />
      ) : (
        <div className="empty">Building the report…</div>
      )}
    </div>
  );
}

function printFrame(): void {
  const frame = document.getElementById('report-frame') as HTMLIFrameElement | null;
  frame?.contentWindow?.focus();
  frame?.contentWindow?.print();
}

function download(text: string, file: string, type: string): void {
  const blob = new Blob([text], { type });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = file;
  a.click();
  URL.revokeObjectURL(url);
}
