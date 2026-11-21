import { useEffect, useRef, useState } from "react";
import { getScans, quickScan, fullScan } from "../services/api.js";
import { usePoll } from "../hooks/usePoll.js";
export default function ScanActivity() {
  const { data, error, loading, refresh } = usePoll(getScans, 5000);
  const [busy, setBusy] = useState(null);
  const [visibleCount, setVisibleCount] = useState(50);
  const [actionError, setActionError] = useState(null);
  const action = useRef(null);
  useEffect(() => () => action.current?.abort(), []);
  async function run(label, operation) {
    if (action.current) return;
    const controller = new AbortController();
    action.current = controller;
    setBusy(label);
    setActionError(null);
    try {
      await operation({ signal: controller.signal });
      if (!controller.signal.aborted) await refresh();
    } catch (error) {
      if (!controller.signal.aborted) setActionError(error.message);
    } finally {
      action.current = null;
      if (!controller.signal.aborted) setBusy(null);
    }
  }
  const scans = data?.scans ?? [];
  return (
    <section aria-labelledby="scan-title" aria-busy={loading || !!busy}>
      <h2 id="scan-title" className="page-title">
        Scan Activity
      </h2>
      <p className="notice">
        These API scans are simulations and do not inspect files. Use the
        desktop Scan tab for a folder scan.
      </p>
      {(actionError || error) && (
        <p role="alert" className="error-message">
          {actionError || error}
        </p>
      )}
      <div className="flex flex-wrap gap-3 mb-6">
        <button
          disabled={!!busy}
          onClick={() => run("Quick", quickScan)}
          className="primary-button"
        >
          {busy === "Quick" ? "Recording…" : "Simulate Quick Scan"}
        </button>
        <button
          disabled={!!busy}
          onClick={() => run("Full", fullScan)}
          className="secondary-button"
        >
          {busy === "Full" ? "Recording…" : "Simulate Full Scan"}
        </button>
      </div>
      <div className="panel divide-y divide-slate-800">
        {loading && (
          <p role="status" className="p-4 muted">
            Loading scan records…
          </p>
        )}
        {!loading && scans.length === 0 && (
          <p className="p-4 muted">No scans recorded yet.</p>
        )}
        {scans.slice(0, visibleCount).map((scan) => (
          <div
            key={scan.id}
            className="p-4 grid gap-2 md:grid-cols-[1fr_2fr_auto] text-sm"
          >
            <span className="font-medium">{scan.type}</span>
            <span className="text-slate-300">{scan.result}</span>
            <time className="text-slate-400">{scan.timestamp}</time>
          </div>
        ))}
      </div>
      {scans.length > visibleCount && (
        <button
          className="secondary-button mt-4"
          onClick={() => setVisibleCount((count) => count + 50)}
        >
          Show 50 more records
        </button>
      )}
    </section>
  );
}
