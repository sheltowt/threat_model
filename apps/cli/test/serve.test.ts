import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { spawn, type ChildProcess } from 'node:child_process';
import { copyFileSync, mkdtempSync, readFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('../../..', import.meta.url));
const CLI = join(ROOT, 'apps/cli/dist/index.js');
const EXAMPLE = join(ROOT, 'examples/payment-service/threatmodel.yaml');

/** A port unlikely to collide with a developer's own server. */
const PORT = 7391;
const BASE = `http://127.0.0.1:${PORT}`;

let child: ChildProcess | undefined;
let modelPath = '';

async function waitForServer(timeoutMs = 15_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    try {
      const response = await fetch(`${BASE}/api/model`);
      if (response.ok) return;
    } catch {
      /* not up yet */
    }
    if (Date.now() > deadline) throw new Error('tmc serve did not start in time');
    await new Promise((r) => setTimeout(r, 150));
  }
}

beforeAll(async () => {
  if (!existsSync(CLI)) throw new Error('build the workspace first: npm run build');
  if (!existsSync(join(ROOT, 'apps/web/dist/index.html'))) {
    throw new Error('build the editor first: npm run build --workspace @tmc/web');
  }

  // A copy, because these tests write to it.
  const dir = mkdtempSync(join(tmpdir(), 'tmc-serve-'));
  modelPath = join(dir, 'threatmodel.yaml');
  copyFileSync(EXAMPLE, modelPath);

  child = spawn('node', [CLI, 'serve', modelPath, '--port', String(PORT), '--write'], {
    cwd: ROOT,
    stdio: ['ignore', 'pipe', 'pipe'],
    env: { ...process.env, NO_COLOR: '1' },
  });
  await waitForServer();
}, 30_000);

afterAll(() => {
  child?.kill('SIGTERM');
});

describe('the model endpoint', () => {
  it('serves the file being edited', async () => {
    const response = await fetch(`${BASE}/api/model`);
    expect(response.status).toBe(200);
    expect(await response.text()).toBe(readFileSync(modelPath, 'utf8'));
  });

  it('writes a valid model back to disk', async () => {
    const original = readFileSync(modelPath, 'utf8');
    const edited = original.replace('title: Payment Service', 'title: Payment Service v2');

    const response = await fetch(`${BASE}/api/model`, {
      method: 'PUT',
      headers: { 'content-type': 'text/yaml' },
      body: edited,
    });
    expect(response.status).toBe(200);
    expect(readFileSync(modelPath, 'utf8')).toContain('Payment Service v2');

    // Put it back, so the ordering of these tests does not matter.
    await fetch(`${BASE}/api/model`, { method: 'PUT', body: original });
  });

  it('refuses to write something that would not load', async () => {
    // Corrupting the file is a far worse outcome than rejecting a save.
    const before = readFileSync(modelPath, 'utf8');
    const response = await fetch(`${BASE}/api/model`, {
      method: 'PUT',
      body: 'schema: tmc/1.0\nmeta:\n  owner: nobody\n',
    });
    expect(response.status).toBe(422);
    const body = (await response.json()) as { error: string; issues: unknown[] };
    expect(body.error).toContain('not valid');
    expect(body.issues.length).toBeGreaterThan(0);
    expect(readFileSync(modelPath, 'utf8')).toBe(before);
  });

  it('rejects a method it does not implement', async () => {
    const response = await fetch(`${BASE}/api/model`, { method: 'DELETE' });
    expect(response.status).toBe(405);
  });
});

describe('static assets', () => {
  it('serves the editor', async () => {
    const response = await fetch(`${BASE}/`);
    expect(response.status).toBe(200);
    expect(await response.text()).toContain('<div id="root">');
  });

  it('sets headers that stop the page being framed or sniffed', async () => {
    const response = await fetch(`${BASE}/api/model`);
    expect(response.headers.get('x-content-type-options')).toBe('nosniff');
    expect(response.headers.get('cache-control')).toBe('no-store');
  });

  it('refuses to walk out of the asset directory', async () => {
    // The obvious attack on any static server, tried a few ways.
    for (const path of [
      '/../../../../etc/passwd',
      '/..%2f..%2f..%2fetc%2fpasswd',
      '/assets/../../../../package.json',
    ]) {
      const response = await fetch(`${BASE}${path}`);
      const body = await response.text();
      expect(body, `${path} must not escape the asset root`).not.toContain('root:x:');
      expect(body, `${path} must not escape the asset root`).not.toContain('"workspaces"');
    }
  });

  it('falls back to the app for an unknown path, so deep links work', async () => {
    const response = await fetch(`${BASE}/some/deep/link`);
    expect(response.status).toBe(200);
    expect(await response.text()).toContain('<div id="root">');
  });
});
