// Thin wrapper around fetch for the ThreatLens API. The token lives in sessionStorage, so closing the tab signs you out.

const KEY = 'threatlens.token';
let onUnauthorized = () => {};

export const tokenStore = {
  get() { try { return sessionStorage.getItem(KEY); } catch { return null; } },
  set(value) { try { sessionStorage.setItem(KEY, value); } catch { /* storage unavailable: stay signed in for this page only */ } },
  clear() { try { sessionStorage.removeItem(KEY); } catch { /* nothing to clear */ } },
};

export function setUnauthorizedHandler(fn) { onUnauthorized = fn; }

/** Turns the different error shapes Django REST Framework returns into one readable sentence. */
export function errorMessage(data, status) {
  if (data && typeof data === 'object') {
    if (typeof data.detail === 'string') return data.detail;
    const parts = Object.entries(data).map(([field, value]) => {
      const text = Array.isArray(value) ? value.join(' ') : String(value);
      return field === 'non_field_errors' ? text : `${field}: ${text}`;
    });
    if (parts.length) return parts.join(' ');
  }
  if (status === 429) return 'Too many requests. Wait a moment and try again.';
  return `Something went wrong (HTTP ${status}).`;
}

export class ApiError extends Error {
  constructor(message, status) { super(message); this.status = status; }
}

export async function api(path, { method = 'GET', body, query } = {}) {
  const url = new URL('/api' + path, window.location.origin);
  for (const [k, v] of Object.entries(query || {})) if (v !== '' && v != null) url.searchParams.set(k, v);
  const headers = {};
  const token = tokenStore.get();
  if (token) headers.Authorization = `Token ${token}`;
  let payload;
  if (body instanceof FormData) payload = body;
  else if (body !== undefined) { headers['Content-Type'] = 'application/json'; payload = JSON.stringify(body); }
  let response;
  try {
    response = await fetch(url, { method, headers, body: payload });
  } catch {
    throw new ApiError('Cannot reach the ThreatLens API. Is it running?', 0);
  }
  if (response.status === 204) return null;
  let data = null;
  try { data = await response.json(); } catch { /* not JSON */ }
  if (!response.ok) {
    if (response.status === 401 && token) { tokenStore.clear(); onUnauthorized(); }
    throw new ApiError(errorMessage(data, response.status), response.status);
  }
  return data;
}
