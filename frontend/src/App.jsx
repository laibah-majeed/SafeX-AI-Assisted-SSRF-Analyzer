import { useState } from "react";
import Header from "./components/Header.jsx";
import ScannerForm from "./components/ScannerForm.jsx";
import ScanResult from "./components/ScanResult.jsx";
import EvidenceCard from "./components/EvidenceCard.jsx";
import AIAnalysis from "./components/AIAnalysis.jsx";
import Remediation from "./components/Remediation.jsx";
import { scanTarget, ApiError } from "./services/api.js";

export default function App() {
  const [status, setStatus] = useState("idle"); // idle | loading | success | error
  const [result, setResult] = useState(null);
  const [errorMessage, setErrorMessage] = useState("");

  async function handleScan(targetUrl) {
    setStatus("loading");
    setErrorMessage("");
    setResult(null);
    try {
      const data = await scanTarget(targetUrl);
      setResult(data);
      setStatus("success");
    } catch (err) {
      const message =
        err instanceof ApiError
          ? err.message
          : "Something went wrong while scanning. Please try again.";
      setErrorMessage(message);
      setStatus("error");
    }
  }

  return (
    <div className="min-h-screen">
      <Header />

      <main className="mx-auto max-w-5xl space-y-6 px-6 py-8">
        <ScannerForm onScan={handleScan} status={status} />

        {status === "error" && (
          <div className="rounded-lg border border-severity-high/40 bg-severity-high/10 p-5">
            <p className="text-sm font-medium text-severity-high">Scan failed</p>
            <p className="mt-1 text-sm text-ink-muted">{errorMessage}</p>
          </div>
        )}

        {status === "success" && result && (
          <>
            <ScanResult result={result} />
            <EvidenceCard baseline={result.baseline} evidence={result.evidence} />
            <AIAnalysis text={result.ai_interpretation} />
            <Remediation items={result.remediation} />
          </>
        )}

        {status === "idle" && (
          <div className="rounded-lg border border-dashed border-base-border p-8 text-center text-sm text-ink-faint">
            Enter an authorized lab URL above and run a scan to see results
            here.
          </div>
        )}
      </main>

      <footer className="mx-auto max-w-5xl px-6 pb-10 pt-4 text-xs text-ink-faint">
        AI-Assisted SSRF Analyzer — academic defensive security tool. For
        authorized local lab use only.
      </footer>
    </div>
  );
}
