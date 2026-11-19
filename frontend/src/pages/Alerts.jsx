import { useEffect, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { api } from '../api.js';
import SeverityBadge from '../components/SeverityBadge.jsx';

export const STATUSES = [['new', 'New'], ['investigating', 'Investigating'], ['resolved', 'Resolved'], ['false_positive', 'False positive']];
export const statusLabel = (s) => (STATUSES.find(([v]) => v === s) || [s, s])[1];
export const fmt = (iso) => new Date(iso).toISOString().replace('T', ' ').slice(0, 19) + ' UTC';

const FILTERS = ['severity', 'status', 'kind', 'source', 'ip', 'ordering', 'page'];
const KIND_LABELS = { success_after_failures: 'success after failures', brute_force: 'brute force', username_spray: 'username spray', network_attack: 'network attack (ML)' };
export const kindLabel = (k) => KIND_LABELS[k] || k.replace(/_/g, ' ');

export default function Alerts() {
  const [params, setParams] = useSearchParams();
  const [data, setData] = useState(null);
  const [error, setError] = useState('');
  const query = Object.fromEntries(FILTERS.map((k) => [k, params.get(k) || '']));

  useEffect(() => {
    let current = true;
    setError('');
    api('/alerts/', { query }).then((d) => current && setData(d)).catch((e) => current && setError(e.message));
    return () => { current = false; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [params]);

  function change(key, value) {
    const next = new URLSearchParams(params);
    if (value) next.set(key, value); else next.delete(key);
    if (key !== 'page') next.delete('page');
    setParams(next);
  }
  const page = Number(query.page) || 1;

  return (
    <>
      <h1>Alerts</h1>
      <div className="filters card" role="search" aria-label="Filter alerts">
        <label>Severity
          <select value={query.severity} onChange={(e) => change('severity', e.target.value)}>
            <option value="">All</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option>
          </select>
        </label>
        <label>Status
          <select value={query.status} onChange={(e) => change('status', e.target.value)}>
            <option value="">All</option>{STATUSES.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
          </select>
        </label>
        <label>Type
          <select value={query.kind} onChange={(e) => change('kind', e.target.value)}>
            <option value="">All</option><option value="success_after_failures">Success after failures</option><option value="brute_force">Brute force</option><option value="username_spray">Username spray</option><option value="network_attack">Network attack (ML)</option>
          </select>
        </label>
        <label>IP address <input value={query.ip} onChange={(e) => change('ip', e.target.value.trim())} placeholder="203.0.113.45" /></label>
        <label>Sort by
          <select value={query.ordering} onChange={(e) => change('ordering', e.target.value)}>
            <option value="">Newest</option><option value="severity">Severity</option><option value="failures">Most failures</option>
          </select>
        </label>
      </div>
      {error && <p role="alert" className="error">{error}</p>}
      {!data && !error && <p className="muted">Loading...</p>}
      {data && (data.results.length === 0 ? <p className="muted">No alerts match these filters.</p> : (
        <div className="tablewrap">
          <table>
            <thead><tr><th>Severity</th><th>Type</th><th>Address</th><th>Evidence</th><th>Last seen</th><th>Status</th></tr></thead>
            <tbody>
              {data.results.map((a) => (
                <tr key={a.id}>
                  <td><SeverityBadge severity={a.severity} /></td>
                  <td><Link to={`/alerts/${a.id}`}>{kindLabel(a.kind)}</Link></td>
                  <td className="mono">{a.ip || 'n/a'}</td>
                  <td>{a.score != null ? `${Math.round(a.score * 100)}% attack chance` : `${a.failures} failures`}</td>
                  <td>{fmt(a.last_seen)}</td>
                  <td>{statusLabel(a.status)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ))}
      {data && (
        <div className="pager">
          <button type="button" className="btn" disabled={!data.previous} onClick={() => change('page', page - 1 > 1 ? String(page - 1) : '')}>Previous</button>
          <span className="muted">{data.count} alert{data.count === 1 ? '' : 's'}</span>
          <button type="button" className="btn" disabled={!data.next} onClick={() => change('page', String(page + 1))}>Next</button>
        </div>
      )}
    </>
  );
}
