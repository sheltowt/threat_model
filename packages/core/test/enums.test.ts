import { describe, expect, it } from 'vitest';
import { comparableEnum, isNetworkBoundary, isResolved, rankOf } from 'tmac-core';

describe('ordered enums', () => {
  it('ranks confidentiality', () => {
    expect(rankOf('public', 'confidentiality')).toBe(0);
    expect(rankOf('strictly-confidential', 'confidentiality')).toBe(4);
  });

  it('returns undefined for a non-member', () => {
    expect(rankOf('nonsense', 'confidentiality')).toBeUndefined();
  });

  it('refuses to rank a value that means different things in different enums', () => {
    // "none" is rank 0 in encryption, authentication and authorization alike, so it
    // is unambiguous; "critical" sits in both criticality and severity at different
    // ranks, so a bare rank would be a guess.
    expect(rankOf('none')).toBe(0);
    expect(rankOf('critical')).toBeUndefined();
  });

  it('finds a shared enum for two members', () => {
    expect(comparableEnum('public', 'confidential')).toBe('confidentiality');
    expect(comparableEnum('public', 'archive')).toBeUndefined();
  });
});

describe('boundary types', () => {
  it('treats every type but execution-environment as a network boundary', () => {
    expect(isNetworkBoundary('network-cloud-provider')).toBe(true);
    expect(isNetworkBoundary('network-untrusted')).toBe(true);
    expect(isNetworkBoundary('execution-environment')).toBe(false);
  });
});

describe('risk status', () => {
  it('counts the four settled statuses as resolved', () => {
    expect(isResolved('mitigated')).toBe(true);
    expect(isResolved('accepted')).toBe(true);
    expect(isResolved('false-positive')).toBe(true);
    expect(isResolved('transferred')).toBe(true);
    expect(isResolved('unchecked')).toBe(false);
    expect(isResolved('in-progress')).toBe(false);
    expect(isResolved('in-discussion')).toBe(false);
  });
});
