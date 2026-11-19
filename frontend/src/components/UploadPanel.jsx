import { useState } from 'react';
import { api } from '../api.js';

const SSH_HINT = 'Nov  8 03:12:01 web01 sshd[3101]: Failed password for root from 203.0.113.45 port 51234 ssh2';
const CONN_HINT = '0,tcp,ftp_data,SF,491,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,2,2,0.00,0.00,0.00,0.00,1.00,0.00,0.00,150,25,0.17,0.03,0.17,0.00,0.00,0.00,0.05,0.00';

export default function UploadPanel({ onDone }) {
  const [mode, setMode] = useState('ssh');
  const [text, setText] = useState('');
  const [file, setFile] = useState(null);
  const [opts, setOpts] = useState({ threshold: 5, window: 300, spray_users: 5 });
  const [cutoff, setCutoff] = useState(0.5);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState(null);
  const ssh = mode === 'ssh';

  function switchMode(next) { setMode(next); setText(''); setFile(null); setMessage(null); }

  async function submit(e) {
    e.preventDefault();
    setBusy(true); setMessage(null);
    try {
      const form = new FormData();
      if (file) form.append('file', file); else form.append(ssh ? 'log' : 'csv', text);
      if (ssh) for (const [k, v] of Object.entries(opts)) form.append(k, v); else form.append('threshold', cutoff);
      const result = await api(ssh ? '/uploads/' : '/connections/', { method: 'POST', body: form });
      setMessage({ ok: true, text: ssh ? summarySsh(result) : summaryConnections(result) });
      setText(''); setFile(null);
      onDone?.();
    } catch (error) {
      setMessage({ ok: false, text: error.message });
    } finally { setBusy(false); }
  }
  const set = (k) => (e) => setOpts({ ...opts, [k]: e.target.value });

  return (
    <form className="card" onSubmit={submit} aria-label="Analyse data">
      <h2>Analyse data</h2>
      <div className="tabs" role="tablist" aria-label="Kind of data">
        <button type="button" role="tab" className="tab" aria-selected={ssh} onClick={() => switchMode('ssh')}>SSH auth log (rules)</button>
        <button type="button" role="tab" className="tab" aria-selected={!ssh} onClick={() => switchMode('conn')}>Network connections (ML model)</button>
      </div>
      <label htmlFor="data-text">{ssh ? 'Paste log lines' : 'Paste connection records (CSV, 41 values per row, labels optional)'}</label>
      <textarea id="data-text" rows={5} value={text} onChange={(e) => setText(e.target.value)} disabled={!!file} spellCheck="false" placeholder={ssh ? SSH_HINT : CONN_HINT} />
      <label htmlFor="data-file">or choose a file</label>
      <input id="data-file" key={mode} type="file" onChange={(e) => setFile(e.target.files[0] || null)} />
      {ssh ? (
        <div className="row">
          <label>Failures per burst <input type="number" min="1" value={opts.threshold} onChange={set('threshold')} /></label>
          <label>Window (seconds) <input type="number" min="1" value={opts.window} onChange={set('window')} /></label>
          <label>Usernames for a spray <input type="number" min="1" value={opts.spray_users} onChange={set('spray_users')} /></label>
        </div>
      ) : (
        <div className="row">
          <label>Flag a record when the attack chance is at least {Math.round(cutoff * 100)}%
            <input type="range" min="0.1" max="0.99" step="0.01" value={cutoff} onChange={(e) => setCutoff(Number(e.target.value))} />
          </label>
        </div>
      )}
      <button className="btn primary" disabled={busy || (!text.trim() && !file)}>{busy ? 'Analysing...' : 'Analyse'}</button>
      {message && <p role={message.ok ? 'status' : 'alert'} className={message.ok ? 'ok' : 'error'}>{message.text}</p>}
    </form>
  );
}

const plural = (n, word) => `${n} ${word}${n === 1 ? '' : 's'}`;
function summarySsh(r) { return `Analysed ${r.events} login events (${r.failed} failed): ${plural(r.alert_count, 'alert')} raised.`; }
function summaryConnections(r) {
  let text = `Scored ${plural(r.records, 'connection record')}: ${r.flagged} flagged as likely attacks, ${plural(r.alerts_created, 'alert')} raised.`;
  if (r.against_labels) {
    const l = r.against_labels;
    text += ` Against the labels you included: ${l.agreed} of ${l.records} agree, ${l.attacks_missed} attacks missed, ${l.false_alarms} false alarms.`;
  }
  return text;
}
