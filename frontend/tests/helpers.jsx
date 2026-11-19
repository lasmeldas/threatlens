import { render } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { vi } from 'vitest';
import { AuthProvider } from '../src/auth.jsx';

/** Replaces fetch with a function that answers from a { 'METHOD /api/path': response } table. Records every call. */
export function mockApi(routes) {
  const calls = [];
  vi.stubGlobal('fetch', vi.fn(async (url, init = {}) => {
    const u = new URL(url);
    const key = `${init.method || 'GET'} ${u.pathname}`;
    calls.push({ key, search: u.search, body: init.body, headers: init.headers });
    const route = routes[key];
    if (!route) return new Response(JSON.stringify({ detail: `no mock for ${key}` }), { status: 404 });
    const { status = 200, body } = typeof route === 'function' ? route(init, u) : route;
    return new Response(status === 204 ? null : JSON.stringify(body), { status });
  }));
  return calls;
}

export function renderApp(ui, { path = '/' } = {}) {
  return render(<MemoryRouter initialEntries={[path]}><AuthProvider>{ui}</AuthProvider></MemoryRouter>);
}

export const alertFixture = (over = {}) => ({
  id: 1, upload: 1, severity: 'critical', kind: 'success_after_failures', ip: '203.0.113.45', failures: 7, users: ['root', 'admin'],
  first_seen: '2026-11-08T03:12:01Z', last_seen: '2026-11-08T03:12:30Z', detail: "Login as 'ubuntu' succeeded after 7 failures.", status: 'new',
  created_at: '2026-11-18T10:00:00Z', updated_at: '2026-11-18T10:00:00Z', ...over,
});
