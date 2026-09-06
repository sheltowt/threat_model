/**
 * Saving back to the file `tmc serve` is editing.
 *
 * Only available when the app was opened with `?model=/api/model`, which is what
 * `tmc serve` prints. A model opened from a dropped file or a remote URL has nowhere
 * to save to, and the button is hidden rather than failing when pressed.
 */

export interface SaveTarget {
  url: string;
}

/** The local endpoint, when the page was opened against one. */
export function saveTarget(search: string): SaveTarget | undefined {
  const model = new URLSearchParams(search).get('model');
  // A relative path means our own server; an absolute URL is someone else's file.
  if (model && model.startsWith('/api/')) return { url: model };
  return undefined;
}

export type SaveResult =
  | { ok: true }
  | { ok: false; message: string; issues?: { path: string; message: string }[] };

export async function saveModel(target: SaveTarget, text: string): Promise<SaveResult> {
  let response: Response;
  try {
    response = await fetch(target.url, {
      method: 'PUT',
      headers: { 'content-type': 'text/yaml' },
      body: text,
    });
  } catch (err) {
    return { ok: false, message: `could not reach tmc serve: ${(err as Error).message}` };
  }

  if (response.ok) return { ok: true };

  const body = await response.text();
  if (response.status === 422) {
    try {
      const parsed = JSON.parse(body) as {
        error: string;
        issues?: { path: string; message: string }[];
      };
      return { ok: false, message: parsed.error, ...(parsed.issues ? { issues: parsed.issues } : {}) };
    } catch {
      /* fall through to the plain message */
    }
  }
  return { ok: false, message: body || `${response.status} ${response.statusText}` };
}
