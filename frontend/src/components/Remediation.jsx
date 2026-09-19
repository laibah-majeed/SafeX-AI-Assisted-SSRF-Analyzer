export default function Remediation({ items }) {
  return (
    <section className="rounded-lg border border-base-border bg-base-panel p-6">
      <h2 className="text-sm font-medium uppercase tracking-wide text-ink-muted">
        Recommended remediation
      </h2>
      <ul className="mt-4 space-y-2.5">
        {items.map((item, i) => (
          <li key={i} className="flex items-start gap-2.5 text-sm text-ink-muted">
            <svg
              className="mt-0.5 h-4 w-4 flex-none text-severity-low"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
            >
              <path d="M20 6 9 17l-5-5" />
            </svg>
            {item}
          </li>
        ))}
      </ul>
    </section>
  );
}
