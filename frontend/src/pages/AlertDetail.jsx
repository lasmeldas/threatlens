import { useEffect, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { api } from '../api.js';
import { useAuth } from '../auth.jsx';
import SeverityBadge from '../components/SeverityBadge.jsx';
import { STATUSES, fmt, kindLabel, statusLabel } from './Alerts.jsx';

export default function AlertDetail() {
  const { id } = useParams();
  const { canEdit } = useAuth();
  const [alert, setAlert] = useState(null);
  const [error, setError] = useState('');
  const [saving, setSaving] = useState(false);

  useEffect(() => { api(`/alerts/${id}/`).then(setAlert).catch((e) => setError(e.message)); }, [id]);

  async function setStatus(status) {
    setSaving(true); setError('');
    try { setAlert(await api(`/alerts/${id}/`, { method: 'PATCH', body: { status } })); } catch (e) { setError(e.message); } finally { setSaving(false); }
  }
  if (error && !alert) return <p role="alert" className="error">{error}</p>;
  if (!alert) return <p className="muted">Loading...</p>;
  return (
    <>
      <p><Link to="/alerts">&larr; All alerts</Link></p>
      <h1><SeverityBadge severity={alert.severity} /> {kindLabel(alert.kind)}</h1>
      <section className="card">
        <p>{alert.detail}</p>
        <dl className="facts">
          {alert.source === 'ml' ? (
            <>
              <div><dt>Found by</dt><dd>The ML model (see the Model page)</dd></div>
              <div><dt>Attack chance</dt><dd data-testid="score">{Math.round(alert.score * 100)}%</dd></div>
            </>
          ) : (
            <>
              <div><dt>Address</dt><dd className="mono"><Link to={`/alerts?ip=${encodeURIComponent(alert.ip)}`}>{alert.ip}</Link></dd></div>
              <div><dt>Failures</dt><dd>{alert.failures}</dd></div>
              <div><dt>Usernames tried</dt><dd className="mono">{alert.users.join(', ')}</dd></div>
            </>
          )}
          <div><dt>First seen</dt><dd>{fmt(alert.first_seen)}</dd></div>
          <div><dt>Last seen</dt><dd>{fmt(alert.last_seen)}</dd></div>
          <div><dt>Status</dt><dd data-testid="status">{statusLabel(alert.status)}</dd></div>
        </dl>
      </section>
      {canEdit ? (
        <section className="card" aria-label="Change status">
          <h2>Change status</h2>
          <div className="row">
            {STATUSES.map(([value, label]) => (
              <button key={value} type="button" className={'btn' + (alert.status === value ? ' primary' : '')} aria-pressed={alert.status === value} disabled={saving || alert.status === value} onClick={() => setStatus(value)}>{label}</button>
            ))}
          </div>
          {error && <p role="alert" className="error">{error}</p>}
        </section>
      ) : <p className="muted">Your role is read-only, so the status cannot be changed.</p>}
    </>
  );
}
