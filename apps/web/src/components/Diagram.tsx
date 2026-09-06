import { useEffect, useRef, useState } from 'react';
import type { ModelGraph } from '@tmc/core/browser';
import type { Risk } from '@tmc/rules/browser';
import { dataAssetSvg, dataFlowSvg } from '../lib/render.js';
import type { Selection } from '../state/selection.js';

interface Props {
  graph: ModelGraph;
  risks: readonly Risk[];
  selection: Selection;
  onSelect: (selection: Selection) => void;
}

type Which = 'data-flow' | 'data-assets';

/**
 * The diagram is the same Graphviz output the CLI writes, rendered through WASM.
 *
 * Sharing it with the CLI means the picture in a review is the picture in the
 * report, and the layout engine is one that actually understands nested clusters.
 * Interactivity is added afterwards by reading the `<title>` Graphviz puts in each
 * node and edge group, which carries the element or flow id.
 */
export function Diagram({ graph, risks, selection, onSelect }: Props) {
  const [which, setWhich] = useState<Which>('data-flow');
  const [leftToRight, setLeftToRight] = useState(false);
  const [svg, setSvg] = useState<string>('');
  const [error, setError] = useState<string>('');
  const hostRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    let cancelled = false;
    setError('');
    const work =
      which === 'data-assets'
        ? dataAssetSvg(graph)
        : dataFlowSvg(graph, { risks: risks as Risk[], leftToRight });
    work
      .then((result) => {
        if (!cancelled) setSvg(result);
      })
      .catch((err: unknown) => {
        if (!cancelled) setError((err as Error).message);
      });
    return () => {
      cancelled = true;
    };
  }, [graph, risks, which, leftToRight]);

  // Wire clicks onto the rendered SVG. Graphviz writes the node id into <title>.
  useEffect(() => {
    const host = hostRef.current;
    if (!host) return;

    const groups = host.querySelectorAll<SVGGElement>('g.node, g.edge');
    const cleanups: (() => void)[] = [];

    for (const group of groups) {
      const title = group.querySelector('title')?.textContent?.trim();
      if (!title) continue;
      const isEdge = group.classList.contains('edge');
      // Graphviz writes an edge title as "from->to"; we select the source element.
      const id = isEdge ? title.split(/->|--/)[0]!.trim() : title;
      const kind: Selection['kind'] = isEdge ? 'flow' : 'element';

      const resolved: Selection = isEdge
        ? resolveFlow(graph, title) ?? { kind: 'element', id }
        : { kind, id };

      const handler = (event: Event) => {
        event.preventDefault();
        onSelect(resolved);
      };
      group.addEventListener('click', handler);
      group.setAttribute('tabindex', '0');
      group.setAttribute('role', 'button');
      cleanups.push(() => group.removeEventListener('click', handler));
    }

    return () => {
      for (const cleanup of cleanups) cleanup();
    };
  }, [svg, graph, onSelect]);

  // Highlight whatever is selected.
  useEffect(() => {
    const host = hostRef.current;
    if (!host) return;
    for (const group of host.querySelectorAll('g.node, g.edge')) {
      group.classList.remove('selected');
    }
    if (selection.kind === 'none') return;
    const wanted =
      selection.kind === 'flow' ? graph.flowById.get(selection.id) : undefined;
    for (const group of host.querySelectorAll<SVGGElement>('g.node, g.edge')) {
      const title = group.querySelector('title')?.textContent?.trim();
      if (!title) continue;
      if (selection.kind === 'element' && title === selection.id) {
        group.classList.add('selected');
      } else if (wanted && title === `${wanted.from.id}->${wanted.to.id}`) {
        group.classList.add('selected');
      }
    }
  }, [svg, selection, graph]);

  return (
    <div>
      <div className="diagram-controls">
        <button
          type="button"
          className={which === 'data-flow' ? 'btn primary' : 'btn'}
          onClick={() => setWhich('data-flow')}
        >
          Data flow
        </button>
        <button
          type="button"
          className={which === 'data-assets' ? 'btn primary' : 'btn'}
          onClick={() => setWhich('data-assets')}
        >
          Data assets
        </button>
        {which === 'data-flow' && (
          <label style={{ display: 'flex', gap: 6, alignItems: 'center', color: 'var(--muted)' }}>
            <input
              type="checkbox"
              checked={leftToRight}
              onChange={(e) => setLeftToRight(e.target.checked)}
            />
            Left to right
          </label>
        )}
        <span style={{ flex: 1 }} />
        <button type="button" className="btn" onClick={() => downloadSvg(svg, which)} disabled={!svg}>
          Download SVG
        </button>
      </div>

      {error ? (
        <div className="empty">The diagram could not be rendered: {error}</div>
      ) : (
        <div
          className="diagram"
          ref={hostRef}
          // The SVG is produced by our own renderer from the parsed model, and every
          // label passes through escapeLabel on the way in.
          dangerouslySetInnerHTML={{ __html: svg }}
        />
      )}
    </div>
  );
}

function resolveFlow(graph: ModelGraph, title: string): Selection | undefined {
  const [from, to] = title.split('->').map((s) => s.trim());
  if (!from || !to) return undefined;
  const flow = graph.flows.find((f) => f.from.id === from && f.to.id === to);
  return flow ? { kind: 'flow', id: flow.id } : undefined;
}

function downloadSvg(svg: string, which: Which): void {
  const blob = new Blob([svg], { type: 'image/svg+xml' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `${which}.svg`;
  a.click();
  URL.revokeObjectURL(url);
}
