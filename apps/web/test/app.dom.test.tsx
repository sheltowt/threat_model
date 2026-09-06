// @vitest-environment happy-dom
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { cleanup, render, screen, waitFor, within } from '@testing-library/react';
import { App } from '../src/App.js';

// Under happy-dom `import.meta.url` is an http URL, so resolve from the repo root
// that vitest runs in rather than from this file.
const EXAMPLE = readFileSync(resolve('apps/web/src/example.yaml'), 'utf8');

/**
 * The app fetches its bundled example on first paint. Stub that, so the test
 * exercises the real parse, graph and rule engine without needing a server.
 *
 * Graphviz is loaded on demand and is not exercised here; the diagram has its own
 * coverage in `tmac-render`, and pulling a megabyte of WASM into every UI test
 * would make the suite slow for no extra assurance.
 */
beforeEach(() => {
  vi.stubGlobal(
    'fetch',
    vi.fn(async () => new Response(EXAMPLE, { status: 200 })),
  );
  window.location.hash = '';
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe('first paint', () => {
  it('opens the bundled example rather than an empty shell', async () => {
    render(<App />);
    await waitFor(() => {
      expect(screen.getByText(/payment-service/)).toBeTruthy();
    });
  });

  it('shows what the model contains in the status bar', async () => {
    render(<App />);
    await waitFor(() => expect(screen.getByText('8 elements')).toBeTruthy());
    expect(screen.getByText('7 flows')).toBeTruthy();
    expect(screen.getByText('5 data assets')).toBeTruthy();
  });

  it('says that nothing leaves the tab', async () => {
    render(<App />);
    await waitFor(() =>
      expect(screen.getByText(/Everything runs in this tab/)).toBeTruthy(),
    );
  });

  it('counts the open findings on the tab', async () => {
    render(<App />);
    const tab = await screen.findByRole('tab', { name: /Findings/ });
    await waitFor(() => {
      expect(Number(within(tab).getByText(/^\d+$/).textContent)).toBeGreaterThan(0);
    });
  });
});

describe('findings', () => {
  it('lists them with a severity and a confidence', async () => {
    const user = { click: (el: Element) => el.dispatchEvent(new MouseEvent('click', { bubbles: true })) };
    render(<App />);
    const tab = await screen.findByRole('tab', { name: /Findings/ });
    user.click(tab);

    await waitFor(() => {
      expect(screen.getAllByText('elevated').length).toBeGreaterThan(0);
    });
    // Confidence is a separate axis and must be visible as text, not colour alone.
    expect(screen.getAllByText(/^(sure|gap)$/).length).toBeGreaterThan(0);
  });

  it('explains the unsettled findings as model gaps', async () => {
    const click = (el: Element) => el.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    render(<App />);
    click(await screen.findByRole('tab', { name: /Findings/ }));
    await waitFor(() => {
      expect(screen.getByText(/could not be settled/)).toBeTruthy();
    });
    expect(screen.getByText(/gaps in the model rather than confirmed flaws/)).toBeTruthy();
  });

  it('shows the offending field when an unsettled finding is selected', async () => {
    const click = (el: Element) => el.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    render(<App />);
    click(await screen.findByRole('tab', { name: /Findings/ }));

    const row = await screen.findByText(/may build injectable queries/);
    click(row.closest('button')!);

    await waitFor(() => {
      expect(screen.getByText(/Why this is unsettled/)).toBeTruthy();
    });
    expect(screen.getByText('flow.from.controls.uses_parameterized_queries')).toBeTruthy();
  });
});

describe('deep links', () => {
  it('opens straight to a finding named in the hash', async () => {
    window.location.hash = '#tab=risks&risk=unencrypted-communication@api_to_token_store';
    render(<App />);
    await waitFor(() => {
      expect(screen.getByText(/How to fix it/)).toBeTruthy();
    });
  });

  it('opens straight to an element named in the hash', async () => {
    window.location.hash = '#tab=risks&element=payment_api';
    render(<App />);
    await waitFor(() => {
      expect(screen.getByText('Attractiveness')).toBeTruthy();
    });
    expect(screen.getByText('web-service-rest')).toBeTruthy();
  });
});

describe('editing', () => {
  it('reanalyses when the source changes and surfaces the error', async () => {
    const click = (el: Element) => el.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    render(<App />);
    click(await screen.findByRole('tab', { name: /Model/ }));

    const textarea = (await screen.findByLabelText(
      'Threat model source',
    )) as HTMLTextAreaElement;
    expect(textarea.value).toContain('Payment Service');

    // A model that references a data asset which does not exist.
    const broken = textarea.value.replace('processes: [card_data, customer_profile]', 'processes: [nope]');
    const setter = Object.getOwnPropertyDescriptor(
      HTMLTextAreaElement.prototype,
      'value',
    )!.set!;
    setter.call(textarea, broken);
    textarea.dispatchEvent(new Event('input', { bubbles: true }));

    await waitFor(
      () => {
        expect(screen.getByText(/"nope" is not defined/)).toBeTruthy();
      },
      { timeout: 3000 },
    );
  });
});
