const WEIGHT_STYLES = {
  high: "text-severity-high",
  medium: "text-severity-medium",
  low: "text-ink-faint",
};

export default function EvidenceCard({ baseline, evidence }) {
  return (
    <section className="rounded-lg border border-base-border bg-base-panel p-6">
      <h2 className="text-sm font-medium uppercase tracking-wide text-ink-muted">
        Evidence
      </h2>

      <div className="mt-4 overflow-x-auto rounded-md border border-base-border bg-base-panelAlt">
        <table className="w-full min-w-[420px] font-mono text-xs">
          <tbody className="divide-y divide-base-border">
            <Row label="HTTP status" value={baseline.status_code ?? "—"} />
            <Row
              label="Response length"
              value={baseline.response_length != null ? `${baseline.response_length} bytes` : "—"}
            />
            <Row
              label="Response time"
              value={baseline.response_time_ms != null ? `${baseline.response_time_ms} ms` : "—"}
            />
            <Row label="Safe response signature" value={baseline.response_signature ?? "—"} />
            {baseline.error && <Row label="Baseline error" value={baseline.error} />}
          </tbody>
        </table>
      </div>

      <h3 className="mt-6 text-xs uppercase tracking-wide text-ink-faint">
        Detection signals
      </h3>
      <ul className="mt-3 space-y-3">
        {evidence.map((item, i) => (
          <li
            key={i}
            className="rounded-md border border-base-border bg-base-panelAlt px-4 py-3"
          >
            <div className="flex items-center justify-between gap-3">
              <span className="font-mono text-xs text-ink">{item.signal}</span>
              <span
                className={`font-mono text-[11px] uppercase ${
                  WEIGHT_STYLES[item.weight] || "text-ink-faint"
                }`}
              >
                {item.weight} weight
              </span>
            </div>
            <p className="mt-1.5 text-sm text-ink-muted">{item.description}</p>
            <p className="mt-1.5 break-all font-mono text-xs text-ink-faint">
              observed: {item.observed}
            </p>
          </li>
        ))}
      </ul>
    </section>
  );
}

function Row({ label, value }) {
  return (
    <tr>
      <td className="px-4 py-2.5 text-ink-faint">{label}</td>
      <td className="break-all px-4 py-2.5 text-right text-ink">{value}</td>
    </tr>
  );
}
