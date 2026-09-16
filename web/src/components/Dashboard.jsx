import { useEffect, useState } from "react";
import { getStatus, getDetections } from "../services/api.js";
import StatCard from "./StatCard.jsx";

export default function Dashboard() {
  const [status, setStatus] = useState(null);
  const [detections, setDetections] = useState([]);
  const [error, setError] = useState(null);

  useEffect(() => {
    let cancelled = false;

    async function poll() {
      try {
        const [s, d] = await Promise.all([getStatus(), getDetections()]);
        if (!cancelled) {
          setStatus(s);
          setDetections(d.detections ?? []);
          setError(null);
        }
      } catch (e) {
        if (!cancelled) setError(e.message);
      }
    }

    poll();
    const interval = setInterval(poll, 3000);
    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, []);

  return (
    <div>
      <h2 className="text-2xl font-bold mb-6">Dashboard</h2>

      {error && (
        <div className="mb-4 text-sm text-red-400">
          Could not reach anton_api at http://localhost:8080 ({error}). Is it running?
        </div>
      )}

      <div className="flex gap-4 mb-4">
        <StatCard label="Threats Blocked" value={status?.threats_blocked ?? "—"} accent="text-red-400" />
        <StatCard label="Files Monitored" value={status?.files_monitored ?? "—"} accent="text-blue-400" />
        <StatCard label="Heuristic Score" value={status ? `${status.heuristic_score}%` : "—"} accent="text-green-400" />
        <StatCard label="Scans Run" value={status?.scan_count ?? "—"} accent="text-purple-400" />
      </div>

      <div className="flex gap-4 mb-8 text-sm">
        <span className={status?.ai_enabled ? "text-green-400" : "text-slate-500"}>
          AI Detection: {status?.ai_enabled ? "Enabled" : "Disabled"}
        </span>
        <span className={status?.monitoring_enabled ? "text-green-400" : "text-slate-500"}>
          Monitoring: {status?.monitoring_enabled ? "Enabled" : "Disabled"}
        </span>
      </div>

      <h3 className="text-lg font-semibold mb-3">Recent Detections</h3>
      <div className="bg-slate-900 border border-slate-800 rounded-lg divide-y divide-slate-800">
        {detections.length === 0 && (
          <div className="p-4 text-sm text-slate-500">No detections yet.</div>
        )}
        {detections.map((d, i) => (
          <div key={i} className="p-3 flex justify-between text-sm">
            <span className={d.level === "Critical" || d.level === "High" ? "text-red-400" : "text-slate-300"}>
              {d.kind}
            </span>
            <span className="text-slate-500">{Math.round(d.confidence * 100)}%</span>
          </div>
        ))}
      </div>
    </div>
  );
}
