import { describe, expect, it, vi } from 'vitest';
import { ApiError, api, errorMessage, setUnauthorizedHandler, tokenStore } from '../src/api.js';
import { mockApi } from './helpers.jsx';

describe('errorMessage', () => {
  it('reads Django REST Framework error shapes', () => {
    expect(errorMessage({ detail: 'Nope.' }, 403)).toBe('Nope.');
    expect(errorMessage({ non_field_errors: ['Unable to log in.'] }, 400)).toBe('Unable to log in.');
    expect(errorMessage({ threshold: ['Ensure this value is greater than or equal to 1.'] }, 400)).toBe('threshold: Ensure this value is greater than or equal to 1.');
    expect(errorMessage(null, 429)).toMatch(/Too many requests/);
    expect(errorMessage(null, 500)).toBe('Something went wrong (HTTP 500).');
  });
});

describe('api', () => {
  it('sends the token and skips empty query values', async () => {
    tokenStore.set('abc');
    const calls = mockApi({ 'GET /api/alerts/': { body: { results: [] } } });
    await api('/alerts/', { query: { severity: 'high', ip: '', page: null } });
    expect(calls[0].search).toBe('?severity=high');
    expect(calls[0].headers.Authorization).toBe('Token abc');
  });

  it('clears the token and tells the app when the server says 401', async () => {
    tokenStore.set('old');
    const handler = vi.fn();
    setUnauthorizedHandler(handler);
    mockApi({ 'GET /api/me/': { status: 401, body: { detail: 'This token has expired. Sign in again.' } } });
    await expect(api('/me/')).rejects.toThrow('This token has expired');
    expect(tokenStore.get()).toBeNull();
    expect(handler).toHaveBeenCalledOnce();
  });

  it('does not treat a failed sign-in as an expired session', async () => {
    const handler = vi.fn();
    setUnauthorizedHandler(handler);
    mockApi({ 'POST /api/auth/token/': { status: 400, body: { non_field_errors: ['Unable to log in with provided credentials.'] } } });
    await expect(api('/auth/token/', { method: 'POST', body: { username: 'a', password: 'b' } })).rejects.toBeInstanceOf(ApiError);
    expect(handler).not.toHaveBeenCalled();
  });

  it('explains a network failure', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => { throw new TypeError('failed'); }));
    await expect(api('/stats/')).rejects.toThrow(/Cannot reach the ThreatLens API/);
  });
});
