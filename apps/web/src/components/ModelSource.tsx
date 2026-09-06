import { useEffect, useRef, useState } from 'react';
import type { Diagnostic } from '@tmc/core/browser';
import { saveModel, type SaveTarget } from '../lib/save.js';

interface Props {
  text: string;
  name: string;
  diagnostics: readonly Diagnostic[];
  elapsedMs: number;
  onChange: (text: string) => void;
  /** Present only when `tmc serve --write` is hosting this page. */
  saveTo?: SaveTarget | undefined;
}

/**
 * The model text, editable.
 *
 * This is the whole authoring surface for now, and it is deliberately the text
 * rather than a form over a hidden object: the file is the artefact people review in
 * a pull request, so editing it directly is the honest thing to offer. Edits are
 * debounced and reanalysed as you type, so the findings list stays live.
 */
export function ModelSource({ text, name, diagnostics, elapsedMs, onChange, saveTo }: Props) {
  const [draft, setDraft] = useState(text);
  const [dirty, setDirty] = useState(false);
  const [saveState, setSaveState] = useState<'idle' | 'saving' | 'saved' | 'failed'>('idle');
  const [saveMessage, setSaveMessage] = useState('');
  const timer = useRef<ReturnType<typeof setTimeout>>(undefined);

  // Adopt a new document from outside, but never clobber what someone is typing.
  useEffect(() => {
    if (!dirty) setDraft(text);
  }, [text, dirty]);

  useEffect(() => {
    return () => {
      if (timer.current) clearTimeout(timer.current);
    };
  }, []);

  const handleChange = (value: string) => {
    setDraft(value);
    setDirty(true);
    if (timer.current) clearTimeout(timer.current);
    timer.current = setTimeout(() => {
      onChange(value);
      setDirty(false);
    }, 300);
    setSaveState('idle');
  };

  const save = async () => {
    if (!saveTo) return;
    setSaveState('saving');
    const result = await saveModel(saveTo, draft);
    if (result.ok) {
      setSaveState('saved');
      setSaveMessage('');
    } else {
      setSaveState('failed');
      setSaveMessage(
        result.issues?.length
          ? `${result.message}: ${result.issues
              .slice(0, 3)
              .map((i) => `${i.path} ${i.message}`)
              .join('; ')}`
          : result.message,
      );
    }
  };

  const errors = diagnostics.filter((d) => d.severity === 'error').length;

  return (
    <div className="editor">
      <div className="editor-status">
        <strong>{name}</strong>
        <span className="sep">·</span>
        <span>{draft.split('\n').length} lines</span>
        <span className="sep">·</span>
        <span>
          {errors === 0 ? (
            <span style={{ color: 'var(--ok)' }}>valid</span>
          ) : (
            <span style={{ color: 'var(--danger)' }}>
              {errors} error{errors === 1 ? '' : 's'}
            </span>
          )}
        </span>
        <span className="sep">·</span>
        <span>{dirty ? 'analysing…' : `analysed in ${elapsedMs.toFixed(0)} ms`}</span>
        <span style={{ flex: 1 }} />
        {saveState === 'failed' && (
          <span style={{ color: 'var(--danger)' }}>{saveMessage}</span>
        )}
        {saveState === 'saved' && <span style={{ color: 'var(--ok)' }}>saved to disk</span>}
        {saveTo && (
          <button
            type="button"
            className="btn primary"
            onClick={() => void save()}
            disabled={saveState === 'saving' || errors > 0}
            title={errors > 0 ? 'Fix the errors above before saving' : 'Write to the file tmc serve is editing'}
          >
            {saveState === 'saving' ? 'Saving…' : 'Save'}
          </button>
        )}
        <button type="button" className="btn" onClick={() => download(draft, name)}>
          Download
        </button>
      </div>
      <textarea
        value={draft}
        onChange={(e) => handleChange(e.target.value)}
        spellCheck={false}
        aria-label="Threat model source"
      />
    </div>
  );
}

function download(text: string, name: string): void {
  const file = name.endsWith('.yaml') || name.endsWith('.yml') ? name : 'threatmodel.yaml';
  const blob = new Blob([text], { type: 'text/yaml' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = file;
  a.click();
  URL.revokeObjectURL(url);
}
