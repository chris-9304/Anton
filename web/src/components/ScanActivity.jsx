import { useEffect, useState } from "react";
import { getScans, quickScan, fullScan } from "../services/api.js";

export default function ScanActivity() {
  const [scans, setScans] = useState([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);

  async function refresh() {
    try {
      const data = await getScans();
      setScans(data.scans ?? []);
      setError(null);
    } catch (e) {
      setError(e.message);
    }
  }

  useEffect(() => {
    refresh();
  }, []);

  async function run(action) {
    setBusy(true);
    try {
      await action();
      await refresh();
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div>
      <h2 className="text-2xl font-bold mb-6">Scan Activity</h2>

      {error && <div className="mb-4 text-sm text-red-400">{error}</div>}

      <div className="flex gap-3 mb-6">
        <button
          disabled={busy}
          onClick={() => run(quickScan)}
          className="px-4 py-2 bg-blue-600 hover:bg-blue-500 disabled:opacity-50 rounded-lg text-sm font-medium"
        >
          Quick Scan
        </button>
        <button
          disabled={busy}
          onClick={() => run(fullScan)}
          className="px-4 py-2 bg-slate-800 hover:bg-slate-700 disabled:opacity-50 rounded-lg text-sm font-medium"
        >
          Full Scan
        </button>
      </div>

      <div className="bg-slate-900 border border-slate-800 rounded-lg divide-y divide-slate-800">
        {scans.length === 0 && (
          <div className="p-4 text-sm text-slate-500">No scans run yet.</div>
        )}
        {scans.map((s) => (
          <div key={s.id} className="p-3 flex justify-between text-sm">
            <span>{s.scan_type}</span>
            <span className="text-slate-400">{s.result}</span>
            <span className="text-slate-500">{s.timestamp}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
