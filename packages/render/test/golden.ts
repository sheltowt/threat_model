import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { expect } from 'vitest';

/**
 * Compare against a committed expected file.
 *
 * Run with `UPDATE_GOLDEN=1` to rewrite them after a deliberate change; review the
 * diff before committing, because that is the whole point of a golden test.
 */
export function expectGolden(path: string, actual: string): void {
  if (process.env['UPDATE_GOLDEN'] === '1' || !existsSync(path)) {
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, actual, 'utf8');
    if (process.env['UPDATE_GOLDEN'] !== '1') {
      throw new Error(`golden file ${path} did not exist; it has been written, review it`);
    }
    return;
  }
  expect(actual).toBe(readFileSync(path, 'utf8'));
}
