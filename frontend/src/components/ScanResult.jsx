const SEVERITY_STYLES = {
  High: "text-severity-high border-severity-high/40 bg-severity-high/10",
  Medium: "text-severity-medium border-severity-medium/40 bg-severity-medium/10",
  Low: "text-severity-low border-severity-low/40 bg-severity-low/10",
  None: "text-severity-none border-base-border bg-base-panelAlt",
};

function Stat({ label, children }) {
  return (
    <div>
      <div className="text-xs uppercase tracking-wide text-ink-faint">{label}</div>
      <div className="mt-1 font-mono text-sm text-ink">{children}</div>
    </div>
  );
}

export default function ScanResult({ result }) {
  const severityClass = SEVERITY_STYLES[result.severity] || SEVERITY_STYLES.None;

  return (
    <section className="rounded-lg border border-base-border bg-base-panel p-6">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h2 className="text-sm font-medium uppercase tracking-wide text-ink-muted">
            Scan summary
          </h2>
          <p className="mt-1 break-all font-mono text-sm text-ink">{result.target}</p>
        </div>
        <span
          className={`inline-flex items-center rounded-full border px-3 py-1 text-xs font-medium ${
            result.vulnerability_detected
              ? "border-severity-high/40 bg-severity-high/10 text-severity-high"
              : "border-severity-low/40 bg-severity-low/10 text-severity-low"
          }`}
        >
          Vulnerability Detected: {result.vulnerability_detected ? "YES" : "NO"}
        </span>
      </div>

      <div className="mt-6 grid grid-cols-2 gap-6 sm:grid-cols-4">
        <Stat label="Scan status">{result.scan_status}</Stat>
        <Stat label="Confidence">{result.confidence}</Stat>
        <Stat label="Timestamp">
          {new Date(result.timestamp).toLocaleString()}
        </Stat>
        <div>
          <div className="text-xs uppercase tracking-wide text-ink-faint">Severity</div>
          <div
            className={`mt-1 inline-flex rounded border px-2 py-0.5 font-mono text-sm ${severityClass}`}
          >
            {result.severity}
          </div>
        </div>
      </div>

      <div className="mt-5 space-y-2 border-t border-base-border pt-4 text-sm text-ink-muted">
        <p>
          <span className="text-ink-faint">Severity reasoning — </span>
          {result.severity_reasoning}
        </p>
        <p>
          <span className="text-ink-faint">Confidence reasoning — </span>
          {result.confidence_reasoning}
        </p>
      </div>

      {result.warnings && result.warnings.length > 0 && (
        <ul className="mt-4 space-y-1 border-t border-base-border pt-4">
          {result.warnings.map((w, i) => (
            <li key={i} className="flex gap-2 text-xs text-ink-faint">
              <span className="text-severity-medium">·</span>
              {w}
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
