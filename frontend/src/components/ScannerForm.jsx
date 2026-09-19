import { useState } from "react";

const STAGES = [
  "Validation",
  "Baseline",
  "Controlled checks",
  "Evidence",
  "AI interpretation",
];

export default function ScannerForm({ onScan, status }) {
  const [targetUrl, setTargetUrl] = useState(
    "http://localhost:8080/fetch?url=http://localhost:8080/internal"
  );

  const isLoading = status === "loading";

  function handleSubmit(e) {
    e.preventDefault();
    if (!targetUrl.trim() || isLoading) return;
    onScan(targetUrl.trim());
  }

  return (
    <section className="rounded-lg border border-base-border bg-base-panel p-6">
      <h2 className="text-sm font-medium uppercase tracking-wide text-ink-muted">
        Scan configuration
      </h2>

      <form onSubmit={handleSubmit} className="mt-4">
        <label htmlFor="target_url" className="mb-2 block text-sm text-ink">
          Enter Authorized Lab URL
        </label>
        <div className="flex flex-col gap-3 sm:flex-row">
          <input
            id="target_url"
            type="text"
            value={targetUrl}
            onChange={(e) => setTargetUrl(e.target.value)}
            placeholder="http://localhost:8080/fetch?url=..."
            className="flex-1 rounded-md border border-base-border bg-base-panelAlt px-3 py-2.5 font-mono text-sm text-ink placeholder:text-ink-faint focus:border-signal"
            disabled={isLoading}
          />
          <button
            type="submit"
            disabled={isLoading}
            className="inline-flex items-center justify-center gap-2 rounded-md bg-signal px-5 py-2.5 text-sm font-medium text-base transition-colors hover:bg-signal-dim disabled:cursor-not-allowed disabled:opacity-60"
          >
            {isLoading && (
              <span className="h-3.5 w-3.5 animate-spin rounded-full border-2 border-base/40 border-t-base" />
            )}
            {isLoading ? "Scanning…" : "Scan URL"}
          </button>
        </div>
        <p className="mt-2 text-xs text-ink-faint">
          Only localhost / 127.0.0.1 / configured lab hosts are accepted. All
          other targets are rejected by the backend allowlist.
        </p>
      </form>

      {status && status !== "idle" && (
        <div className="mt-6 border-t border-base-border pt-5">
          <ol className="flex flex-wrap gap-x-6 gap-y-2">
            {STAGES.map((stage, i) => (
              <li
                key={stage}
                className={`flex items-center gap-2 font-mono text-xs ${
                  isLoading ? "text-ink-muted" : "text-signal"
                }`}
              >
                <span
                  className={`h-1.5 w-1.5 rounded-full ${
                    isLoading ? "bg-ink-faint scan-pulse" : "bg-signal"
                  }`}
                  style={isLoading ? { animationDelay: `${i * 0.15}s` } : undefined}
                />
                {stage}
              </li>
            ))}
          </ol>
        </div>
      )}
    </section>
  );
}
