import { useState } from 'react';
import { api } from '../api.js';

export default function UploadPanel({ onDone }) {
  const [log, setLog] = useState('');
  const [file, setFile] = useState(null);
  const [opts, setOpts] = useState({ threshold: 5, window: 300, spray_users: 5 });
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState(null);

  async function submit(e) {
    e.preventDefault();
    setBusy(true); setMessage(null);
    try {
      const form = new FormData();
      if (file) form.append('file', file); else form.append('log', log);
      for (const [k, v] of Object.entries(opts)) form.append(k, v);
      const result = await api('/uploads/', { method: 'POST', body: form });
      setMessage({ ok: true, text: `Analysed ${result.events} login events (${result.failed} failed): ${result.alert_count} alert${result.alert_count === 1 ? '' : 's'} raised.` });
      setLog(''); setFile(null);
      onDone?.();
    } catch (error) {
      setMessage({ ok: false, text: error.message });
    } finally { setBusy(false); }
  }
  const set = (k) => (e) => setOpts({ ...opts, [k]: e.target.value });

  return (
    <form className="card" onSubmit={submit} aria-label="Analyse a log">
      <h2>Analyse an SSH auth log</h2>
      <label htmlFor="log-text">Paste log lines</label>
      <textarea id="log-text" rows={5} value={log} onChange={(e) => setLog(e.target.value)} disabled={!!file} spellCheck="false" placeholder="Nov  8 03:12:01 web01 sshd[3101]: Failed password for root from 203.0.113.45 port 51234 ssh2" />
      <label htmlFor="log-file">or choose a file</label>
      <input id="log-file" type="file" onChange={(e) => setFile(e.target.files[0] || null)} />
      <div className="row">
        <label>Failures per burst <input type="number" min="1" value={opts.threshold} onChange={set('threshold')} /></label>
        <label>Window (seconds) <input type="number" min="1" value={opts.window} onChange={set('window')} /></label>
        <label>Usernames for a spray <input type="number" min="1" value={opts.spray_users} onChange={set('spray_users')} /></label>
      </div>
      <button className="btn primary" disabled={busy || (!log.trim() && !file)}>{busy ? 'Analysing...' : 'Analyse'}</button>
      {message && <p role={message.ok ? 'status' : 'alert'} className={message.ok ? 'ok' : 'error'}>{message.text}</p>}
    </form>
  );
}
