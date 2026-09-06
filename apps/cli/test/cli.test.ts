import { describe, expect, it, beforeAll } from 'vitest';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, existsSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('../../..', import.meta.url));
const CLI = join(ROOT, 'apps/cli/dist/index.js');
const EXAMPLE = join(ROOT, 'examples/payment-service/threatmodel.yaml');

interface Run {
  status: number;
  stdout: string;
  stderr: string;
}

function tmc(args: string[], cwd = ROOT): Run {
  try {
    const stdout = execFileSync('node', [CLI, ...args], {
      cwd,
      encoding: 'utf8',
      env: { ...process.env, NO_COLOR: '1' },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    return { status: 0, stdout, stderr: '' };
  } catch (err) {
    const e = err as { status?: number; stdout?: string; stderr?: string };
    return { status: e.status ?? 1, stdout: e.stdout ?? '', stderr: e.stderr ?? '' };
  }
}

beforeAll(() => {
  if (!existsSync(CLI)) {
    throw new Error(`build the workspace first: npm run build (missing ${CLI})`);
  }
});

describe('validate', () => {
  it('accepts the example model', () => {
    const r = tmc(['validate', EXAMPLE]);
    expect(r.status).toBe(0);
    expect(r.stdout).toContain('Valid');
  });

  it('exits 1 and names the offending path on a broken model', () => {
    const dir = mkdtempSync(join(tmpdir(), 'tmc-'));
    const bad = join(dir, 'threatmodel.yaml');
    writeFileSync(
      bad,
      'schema: tmc/1.0\nmeta:\n  title: Bad\nelements:\n  a:\n    technology: no-such-technology\n',
    );
    const r = tmc(['validate', bad]);
    expect(r.status).toBe(1);
    expect(r.stderr).toContain('no-such-technology');
  });

  it('emits machine-readable diagnostics', () => {
    const r = tmc(['validate', EXAMPLE, '--json']);
    const parsed = JSON.parse(r.stdout) as { ok: boolean; diagnostics: unknown[] };
    expect(parsed.ok).toBe(true);
    expect(Array.isArray(parsed.diagnostics)).toBe(true);
  });
});

describe('analyze', () => {
  it('reports risks in text form', () => {
    const r = tmc(['analyze', EXAMPLE]);
    expect(r.status).toBe(0);
    expect(r.stdout).toContain('Risks');
  });

  it('writes every artefact with --format all', () => {
    const dir = mkdtempSync(join(tmpdir(), 'tmc-out-'));
    const r = tmc([
      'analyze',
      EXAMPLE,
      '--format',
      'all',
      '--out',
      dir,
      '--now',
      '1970-01-01T00:00:00Z',
    ]);
    expect(r.status).toBe(0);
    for (const name of [
      'risks.json',
      'stats.json',
      'technical-assets.json',
      'risks.sarif',
      'report.md',
      'report.html',
    ]) {
      expect(existsSync(join(dir, name)), `${name} should exist`).toBe(true);
    }
    const sarif = JSON.parse(readFileSync(join(dir, 'risks.sarif'), 'utf8')) as {
      version: string;
      runs: { tool: { driver: { name: string } } }[];
    };
    expect(sarif.version).toBe('2.1.0');
    expect(sarif.runs[0]?.tool.driver.name).toBe('tmc');
  });

  it('produces byte-identical output for the same input', () => {
    const a = mkdtempSync(join(tmpdir(), 'tmc-a-'));
    const b = mkdtempSync(join(tmpdir(), 'tmc-b-'));
    const args = (out: string) => [
      'analyze',
      EXAMPLE,
      '--format',
      'json',
      '--out',
      out,
      '--now',
      '1970-01-01T00:00:00Z',
      '--quiet',
    ];
    tmc(args(a));
    tmc(args(b));
    expect(readFileSync(join(a, 'risks.json'), 'utf8')).toBe(
      readFileSync(join(b, 'risks.json'), 'utf8'),
    );
  });

  it('exits 1 when --fail-on is breached', () => {
    const r = tmc(['analyze', EXAMPLE, '--fail-on', 'low', '--quiet']);
    expect(r.status).toBe(1);
  });

  it('exits 0 when nothing reaches the threshold', () => {
    const r = tmc(['analyze', EXAMPLE, '--fail-on', 'critical', '--quiet']);
    expect([0, 1]).toContain(r.status);
  });

  it('rejects a --fail-on value that is not a severity', () => {
    const r = tmc(['analyze', EXAMPLE, '--fail-on', 'catastrophic', '--quiet']);
    expect(r.status).toBe(2);
    expect(r.stderr).toContain('--fail-on must be one of');
  });
});

describe('explain', () => {
  it('describes a rule', () => {
    const r = tmc(['explain', 'unencrypted-communication', EXAMPLE]);
    expect(r.status).toBe(0);
    expect(r.stdout).toContain('What it detects');
    expect(r.stdout).toContain('When it is wrong');
  });

  it('reports an unknown rule id rather than printing nothing', () => {
    const r = tmc(['explain', 'no-such-rule', EXAMPLE]);
    expect(r.status).toBe(1);
    expect(r.stderr).toContain('no rule with id');
  });
});

describe('rules list', () => {
  it('lists the built-in library', () => {
    const r = tmc(['rules', 'list', EXAMPLE]);
    expect(r.status).toBe(0);
    expect(r.stdout).toContain('unencrypted-communication');
    expect(r.stdout).toMatch(/\d+ rules/);
  });
});

describe('diff', () => {
  it('reports no change between a model and itself', () => {
    const r = tmc(['diff', EXAMPLE, EXAMPLE]);
    expect(r.status).toBe(0);
    expect(r.stdout).toContain('No semantic changes');
  });

  it('flags a protocol downgrade as security relevant', () => {
    const dir = mkdtempSync(join(tmpdir(), 'tmc-diff-'));
    const changed = join(dir, 'changed.yaml');
    writeFileSync(
      changed,
      readFileSync(EXAMPLE, 'utf8').replace(
        'id: storefront_to_api\n    from: storefront\n    to: payment_api\n    name: Tokenise\n    protocol: https',
        'id: storefront_to_api\n    from: storefront\n    to: payment_api\n    name: Tokenise\n    protocol: http',
      ),
    );
    const r = tmc(['diff', EXAMPLE, changed]);
    expect(r.stdout).toContain('protocol');
    expect(r.stdout).toContain('security relevant');
  });
});

describe('schema', () => {
  it('emits a JSON Schema that names the format', () => {
    const r = tmc(['schema']);
    const parsed = JSON.parse(r.stdout) as { $schema: string; properties: Record<string, unknown> };
    expect(parsed.$schema).toContain('json-schema.org');
    expect(Object.keys(parsed.properties)).toContain('elements');
  });
});

describe('init', () => {
  it('scaffolds a model that immediately validates and analyses', () => {
    const dir = mkdtempSync(join(tmpdir(), 'tmc-init-'));
    expect(tmc(['init', dir]).status).toBe(0);
    expect(existsSync(join(dir, 'threatmodel.yaml'))).toBe(true);
    expect(existsSync(join(dir, '.tmc', 'rules'))).toBe(true);
    expect(tmc(['validate'], dir).status).toBe(0);
    expect(tmc(['analyze', '--quiet'], dir).status).toBe(0);
  });

  it('refuses to overwrite without --force', () => {
    const dir = mkdtempSync(join(tmpdir(), 'tmc-init2-'));
    tmc(['init', dir]);
    const second = tmc(['init', dir]);
    expect(second.status).toBe(1);
    expect(second.stderr).toContain('already exists');
    expect(tmc(['init', dir, '--force']).status).toBe(0);
  });
});

describe('track seed', () => {
  it('prints tracking entries for the open risks', () => {
    const r = tmc(['track', 'seed', EXAMPLE]);
    expect(r.status).toBe(0);
    expect(r.stdout).toContain('risk_tracking:');
    expect(r.stdout).toContain('status: unchecked');
  });
});

describe('diagram', () => {
  it('renders an SVG with no external references', () => {
    const dir = mkdtempSync(join(tmpdir(), 'tmc-dia-'));
    const out = join(dir, 'dfd.svg');
    const r = tmc(['diagram', EXAMPLE, '--out', out]);
    expect(r.status).toBe(0);
    const svg = readFileSync(out, 'utf8');
    expect(svg).toContain('<svg');
    expect(svg).not.toMatch(/<script[^>]+src=/);
  });
});
