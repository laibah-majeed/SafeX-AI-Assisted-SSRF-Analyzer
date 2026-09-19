export default function Header() {
  return (
    <header className="border-b border-base-border bg-base-panel/60">
      <div className="mx-auto max-w-5xl px-6 py-8">
        <div className="flex items-center gap-3">
          <div className="flex h-9 w-9 items-center justify-center rounded-md border border-signal/40 bg-signal/10">
            <svg
              width="18"
              height="18"
              viewBox="0 0 24 24"
              fill="none"
              stroke="#4FD1C5"
              strokeWidth="1.8"
            >
              <path d="M12 2 4 5v6c0 5 3.4 8.7 8 11 4.6-2.3 8-6 8-11V5l-8-3Z" />
              <path d="m9 12 2 2 4-4" />
            </svg>
          </div>
          <span className="font-mono text-xs uppercase tracking-wide text-ink-faint">
            Local lab build · v1.0.0
          </span>
        </div>

        <h1 className="mt-4 text-3xl font-semibold text-ink sm:text-4xl">
          AI-Assisted SSRF Analyzer
        </h1>
        <p className="mt-2 max-w-2xl text-ink-muted">
          Defensive Server-Side Request Forgery detection for authorized labs.
        </p>

        <div className="mt-5 flex items-start gap-3 rounded-md border border-severity-medium/30 bg-severity-medium/10 px-4 py-3">
          <svg
            className="mt-0.5 h-4 w-4 flex-none text-severity-medium"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
          >
            <path d="M12 9v4M12 17h.01" />
            <path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0Z" />
          </svg>
          <p className="text-sm text-ink-muted">
            Only scan systems you own or are explicitly authorized to test.
            This tool refuses any target outside its configured allowlist.
          </p>
        </div>
      </div>
    </header>
  );
}
