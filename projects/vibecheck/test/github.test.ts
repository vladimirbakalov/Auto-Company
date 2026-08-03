import { describe, it, expect } from 'vitest';
import { parseRepoUrl } from '../src/github';
import { ScanError } from '../src/types';

describe('parseRepoUrl', () => {
  it('parses a full https URL', () => {
    expect(parseRepoUrl('https://github.com/vercel/next.js')).toEqual({
      owner: 'vercel',
      repo: 'next.js',
    });
  });

  it('parses a bare owner/repo string with no host', () => {
    expect(parseRepoUrl('vercel/next.js')).toEqual({ owner: 'vercel', repo: 'next.js' });
  });

  it('strips a trailing .git suffix', () => {
    expect(parseRepoUrl('https://github.com/facebook/react.git')).toEqual({
      owner: 'facebook',
      repo: 'react',
    });
  });

  it('strips trailing slashes', () => {
    expect(parseRepoUrl('https://github.com/facebook/react///')).toEqual({
      owner: 'facebook',
      repo: 'react',
    });
  });

  it('accepts a www. prefix and http scheme', () => {
    expect(parseRepoUrl('http://www.github.com/facebook/react')).toEqual({
      owner: 'facebook',
      repo: 'react',
    });
  });

  it('ignores a trailing /tree/<branch> path segment', () => {
    expect(parseRepoUrl('https://github.com/facebook/react/tree/main')).toEqual({
      owner: 'facebook',
      repo: 'react',
    });
  });

  it('allows dots, dashes, and underscores in owner/repo names', () => {
    expect(parseRepoUrl('my-org_1/my.repo_name')).toEqual({
      owner: 'my-org_1',
      repo: 'my.repo_name',
    });
  });

  it('throws on empty input', () => {
    expect(() => parseRepoUrl('')).toThrow(ScanError);
    expect(() => parseRepoUrl('   ')).toThrow('Repo URL is required');
  });

  it('throws when only an owner is given as a github.com URL (no repo segment)', () => {
    expect(() => parseRepoUrl('https://github.com/justowner')).toThrow(ScanError);
  });

  it('throws on input with too many path segments and no github.com host', () => {
    expect(() => parseRepoUrl('owner/repo/extra')).toThrow(
      'Could not parse a GitHub owner/repo from that input'
    );
  });

  it('throws on invalid characters in owner or repo', () => {
    expect(() => parseRepoUrl('owner name/repo!')).toThrow(
      'Owner or repo name contains invalid characters'
    );
  });

  it('throws on a single-segment bare string', () => {
    expect(() => parseRepoUrl('justarepo')).toThrow(ScanError);
  });
});
