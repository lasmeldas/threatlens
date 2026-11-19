import { useCallback, useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { api } from '../api.js';
import { useAuth } from '../auth.jsx';
import BarChart from '../components/BarChart.jsx';
import UploadPanel from '../components/UploadPanel.jsx';

export const SEVERITY_COLORS = { critical: '#ff4d6d', high: '#ffb86b', medium: '#38bdf8' };
const STATUS_LABELS = { new: 'New', investigating: 'Investigating', resolved: 'Resolved', false_positive: 'False positive' };
const KIND_LABELS = { success_after_failures: 'Success after failures', brute_force: 'Brute force', username_spray: 'Username spray' };

export default function Overview() {
  const { canEdit } = useAuth();
  const [stats, setStats] = useState(null);
  const [error, setError] = useState('');
  const load = useCallback(() => { api('/stats/').then(setStats).catch((e) => setError(e.message)); }, []);
  useEffect(load, [load]);

  if (error) return <p role="alert" className="error">{error}</p>;
  if (!stats) return <p className="muted">Loading...</p>;
  const rows = (obj, labels = {}, colors = {}) => Object.entries(obj).map(([k, value]) => ({ label: labels[k] || k, value, color: colors[k] }));
  return (
    <>
      <h1>Overview</h1>
      <section className="cards" aria-label="Totals">
        <div className="card stat"><strong>{stats.alerts}</strong><span>alerts</span></div>
        <div className="card stat"><strong>{stats.open}</strong><span>still open</span></div>
        <div className="card stat"><strong>{stats.by_severity.critical || 0}</strong><span>critical</span></div>
        <div className="card stat"><strong>{stats.uploads}</strong><span>logs analysed</span></div>
      </section>
      <section className="grid">
        <div className="card"><BarChart title="By severity" data={rows(stats.by_severity, {}, SEVERITY_COLORS)} /></div>
        <div className="card"><BarChart title="By status" data={rows(stats.by_status, STATUS_LABELS)} /></div>
        <div className="card"><BarChart title="By type" data={rows(stats.by_kind, KIND_LABELS)} /></div>
        <div className="card">
          <h2>Most-flagged addresses</h2>
          {stats.top_ips.length === 0 ? <p className="muted">No alerts yet.</p> : (
            <ol className="plain">{stats.top_ips.map((t) => <li key={t.ip}><Link to={`/alerts?ip=${encodeURIComponent(t.ip)}`}>{t.ip}</Link> <span className="muted">{t.alerts} alert{t.alerts === 1 ? '' : 's'}</span></li>)}</ol>
          )}
        </div>
      </section>
      {canEdit ? <UploadPanel onDone={load} /> : <p className="muted">Your role is read-only, so uploading logs is turned off.</p>}
    </>
  );
}
