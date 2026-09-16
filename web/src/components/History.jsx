import { useEffect, useState } from "react";
import { getLogs } from "../services/api.js";

export default function History() {
  const [logs, setLogs] = useState([]);
  const [error, setError] = useState(null);

  useEffect(() => {
    let cancelled = false;
    async function poll() {
      try {
        const data = await getLogs();
        if (!cancelled) {
          setLogs(data.logs ?? []);
          setError(null);
        }
      } catch (e) {
        if (!cancelled) setError(e.message);
      }
    }
    poll();
    const interval = setInterval(poll, 5000);
    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, []);

  return (
    <div>
      <h2 className="text-2xl font-bold mb-6">History</h2>
      {error && <div className="mb-4 text-sm text-red-400">{error}</div>}
      <div className="bg-slate-900 border border-slate-800 rounded-lg p-4 font-mono text-xs space-y-1 max-h-[70vh] overflow-y-auto">
        {logs.length === 0 && <div className="text-slate-500">No activity logged yet.</div>}
        {logs.map((line, i) => (
          <div key={i} className="text-slate-300">
            {line}
          </div>
        ))}
      </div>
    </div>
  );
}
