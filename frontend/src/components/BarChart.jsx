/** Horizontal bars drawn as plain HTML. `data` is [{label, value, color?}]. Bar width is relative to the largest value. */
export default function BarChart({ title, data, empty = 'No data yet.' }) {
  const max = Math.max(0, ...data.map((d) => d.value));
  return (
    <figure className="chart">
      <figcaption>{title}</figcaption>
      {max === 0 ? <p className="muted">{empty}</p> : (
        <ul>
          {data.map((d) => (
            <li key={d.label}>
              <span className="chart-label">{d.label}</span>
              <span className="chart-track"><span className="chart-bar" role="presentation" data-testid={`bar-${d.label}`} style={{ width: `${(d.value / max) * 100}%`, background: d.color || 'var(--accent)' }} /></span>
              <span className="chart-value">{d.value}</span>
            </li>
          ))}
        </ul>
      )}
    </figure>
  );
}
