/** Horizontal bars drawn as plain HTML. `data` is [{label, value, color?}]. Bars are scaled to the largest value, or to `scaleMax` when given (use 100 for percentages). */
export default function BarChart({ title, data, empty = 'No data yet.', scaleMax }) {
  const largest = Math.max(0, ...data.map((d) => d.value));
  const max = scaleMax || largest;
  return (
    <figure className="chart">
      <figcaption>{title}</figcaption>
      {largest === 0 ? <p className="muted">{empty}</p> : (
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
