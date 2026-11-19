import { useState } from 'react';
import { useAuth } from '../auth.jsx';

export default function Login() {
  const { login } = useAuth();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  async function submit(e) {
    e.preventDefault();
    setBusy(true); setError('');
    try { await login(username, password); } catch (err) { setError(err.message); } finally { setBusy(false); }
  }
  return (
    <div className="center">
      <form className="card login" onSubmit={submit}>
        <h1><span aria-hidden="true">◉</span> ThreatLens</h1>
        <p className="muted">Sign in to see your alerts.</p>
        <label htmlFor="u">Username</label>
        <input id="u" autoComplete="username" value={username} onChange={(e) => setUsername(e.target.value)} required />
        <label htmlFor="p">Password</label>
        <input id="p" type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} required />
        <button className="btn primary" disabled={busy}>{busy ? 'Signing in...' : 'Sign in'}</button>
        {error && <p role="alert" className="error">{error}</p>}
      </form>
    </div>
  );
}
