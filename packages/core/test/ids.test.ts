import { describe, expect, it } from 'vitest';
import { matchesTrackingKey, parseSyntheticId, resolveTrackingKey, syntheticId } from '@tmc/core';

describe('synthetic ids', () => {
  it('builds from rule and subject', () => {
    expect(syntheticId({ rule: 'unencrypted-communication', subject: 'api_to_db' })).toBe(
      'unencrypted-communication@api_to_db',
    );
  });

  it('appends secondary parts', () => {
    expect(syntheticId({ rule: 'r', subject: 's', secondary: ['a', 'b'] })).toBe('r@s@a@b');
  });

  it('ignores empty secondary parts, so an id stays stable', () => {
    expect(syntheticId({ rule: 'r', subject: 's', secondary: ['', 'a'] })).toBe('r@s@a');
  });

  it('round-trips', () => {
    expect(parseSyntheticId('r@s@a')).toEqual({ rule: 'r', subject: 's', secondary: ['a'] });
    expect(parseSyntheticId('nope')).toBeUndefined();
  });
});

describe('tracking keys', () => {
  it('matches exactly', () => {
    expect(matchesTrackingKey('r@s', 'r@s')).toBe(true);
    expect(matchesTrackingKey('r@s', 'r@t')).toBe(false);
  });

  it('supports wildcards', () => {
    expect(matchesTrackingKey('r@*', 'r@anything')).toBe(true);
    expect(matchesTrackingKey('*', 'r@s')).toBe(true);
    expect(matchesTrackingKey('r@*', 'other@s')).toBe(false);
  });

  it('does not let a wildcard leak through regex metacharacters', () => {
    expect(matchesTrackingKey('r.x@*', 'rax@s')).toBe(false);
  });

  it('prefers the most specific key so a blanket accept can be overridden', () => {
    const keys = ['*', 'unencrypted-communication@*', 'unencrypted-communication@api_to_db'];
    expect(resolveTrackingKey('unencrypted-communication@api_to_db', keys)).toBe(
      'unencrypted-communication@api_to_db',
    );
    expect(resolveTrackingKey('unencrypted-communication@other', keys)).toBe(
      'unencrypted-communication@*',
    );
    expect(resolveTrackingKey('another-rule@x', keys)).toBe('*');
  });
});
