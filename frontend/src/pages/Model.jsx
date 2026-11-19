import { useEffect, useState } from 'react';
import { api } from '../api.js';
import BarChart from '../components/BarChart.jsx';

const pct = (x) => `${(x * 100).toFixed(1)}%`;
const NAMES = { logistic_regression: 'Logistic regression (baseline)', random_forest: 'Random forest', gradient_boosting: 'Gradient boosting' };
const FAMILY = { normal: 'Normal traffic', DoS: 'DoS (floods)', Probe: 'Probe (scans)', R2L: 'R2L (e.g. password guessing)', U2R: 'U2R (privilege escalation)' };

export default function Model() {
  const [m, setM] = useState(null);
  const [error, setError] = useState('');
  useEffect(() => { api('/ml/model/').then(setM).catch((e) => setError(e.message)); }, []);
  if (error) return <p role="alert" className="error">{error}</p>;
  if (!m) return <p className="muted">Loading...</p>;
  const t = m.test;
  return (
    <>
      <h1>The attack-detection model</h1>
      <p className="muted">{NAMES[m.selected_model]}, trained on {m.dataset}: {m.train_records.toLocaleString()} training and {m.test_records.toLocaleString()} test connections. These numbers come from the official test file, which the model never trained on.</p>
      <section className="cards" aria-label="Test results">
        <div className="card stat"><strong>{pct(t.accuracy)}</strong><span>accuracy</span></div>
        <div className="card stat"><strong>{pct(t.precision)}</strong><span>right when it says attack</span></div>
        <div className="card stat"><strong>{pct(t.recall)}</strong><span>of attacks caught</span></div>
        <div className="card stat"><strong>{pct(t.false_positive_rate)}</strong><span>false alarms</span></div>
      </section>
      <section className="grid">
        <div className="card">
          <BarChart title="Connections classified correctly, by family" scaleMax={100} data={Object.entries(m.by_category).map(([k, v]) => ({ label: FAMILY[k] || k, value: Math.round(v.correctly_classified * 100), color: k === 'normal' ? 'var(--accent)' : v.correctly_classified < 0.5 ? '#ff4d6d' : '#38bdf8' }))} />
          <p className="muted">Percent of that family classified correctly.</p>
        </div>
        <div className="card">
          <h2>New attacks</h2>
          <p>The test file has {m.unseen_attacks.records_of_unseen_types.toLocaleString()} attack records of types the model never saw in training. It catches <strong>{pct(m.unseen_attacks.detected_unseen)}</strong> of those, against <strong>{pct(m.unseen_attacks.detected_seen)}</strong> for types it did see.</p>
        </div>
      </section>
      <section className="card">
        <h2>Models compared on the test file</h2>
        <div className="tablewrap"><table>
          <thead><tr><th>Model</th><th>Accuracy</th><th>Precision</th><th>Recall</th><th>False alarms</th></tr></thead>
          <tbody>{Object.entries(m.compared_on_test).map(([name, r]) => (
            <tr key={name}><td>{NAMES[name]}{name === m.selected_model ? ' (used here)' : ''}</td><td>{pct(r.accuracy)}</td><td>{pct(r.precision)}</td><td>{pct(r.recall)}</td><td>{pct(r.false_positive_rate)}</td></tr>
          ))}</tbody>
        </table></div>
      </section>
      <section className="card">
        <h2>How much to trust it</h2>
        <ul>
          <li>It is good at loud attacks (floods and scans) and weak at quiet ones that look like normal sessions, which are the ones that matter most to a defender.</li>
          <li>It misses about a third of attacks overall, so treat a clean result as "nothing obvious", never as "safe".</li>
          <li>NSL-KDD is old, lab-made traffic. Use this to learn from, not as your only defence.</li>
          <li>It adds to the SSH rules and to human review. It does not replace them.</li>
        </ul>
      </section>
    </>
  );
}
