import { getDashboard } from "../services/api.js";
import { usePoll } from "../hooks/usePoll.js";
import StatCard from "./StatCard.jsx";

const kinds = {
  ransomwareold: "Ransomware pattern",
  ransomwaremodern: "Rapid ransomware pattern",
  wipermalware: "Deletion burst",
  ransomwaretraverser: "Coordinated file changes",
  honeytokentouched: "Canary file changed",
  highentropystorm: "High entropy burst",
  benign: "Normal activity",
};
export default function Dashboard() {
  const { data, error, loading } = usePoll(getDashboard);
  const status = data?.status;
  const detections = data?.detections ?? [];
  const health = status?.monitoring_health;
  return (
    <section aria-labelledby="dashboard-title" aria-busy={loading}>
      <h2 id="dashboard-title" className="page-title">
        Dashboard
      </h2>
      {error && (
        <p role="alert" className="error-message">
          Connection unavailable. Retrying… {error}
        </p>
      )}
      {loading && (
        <p role="status" className="muted mb-4">
          Loading system status…
        </p>
      )}
      {status?.demo_mode && (
        <p className="notice">
          Demo environment · File count and heuristic score are sample values.
          Monitoring applies to TestRun.
        </p>
      )}
      <div className="grid grid-cols-1 min-[400px]:grid-cols-2 xl:grid-cols-4 gap-4 mb-5">
        <StatCard
          label="High-severity Detections"
          value={status?.threats_blocked ?? "—"}
          accent="text-red-400"
        />
        <StatCard
          label="Files Monitored (sample)"
          value={status?.files_monitored ?? "—"}
          accent="text-blue-400"
        />
        <StatCard
          label="Heuristic Score (sample)"
          value={status ? `${status.heuristic_score}%` : "—"}
          accent="text-green-400"
        />
        <StatCard
          label="Scan Records"
          value={status?.scan_count ?? "—"}
          accent="text-purple-400"
        />
      </div>
      <div
        className="flex flex-wrap gap-x-6 gap-y-2 mb-8 text-sm"
        role="status"
      >
        <span>
          AI Detection:{" "}
          {status
            ? status.ai_enabled
              ? "Enabled"
              : "Disabled — canaries remain active"
            : "—"}
        </span>
        <span
          className={
            health === "degraded" || health === "stopped"
              ? "text-amber-300"
              : "text-slate-300"
          }
        >
          Monitoring: {health ?? "—"}
        </span>
        {status?.dropped_events > 0 && (
          <span className="text-amber-300">
            {status.dropped_events} event batches dropped · Restart monitoring
          </span>
        )}
      </div>
      <h3 className="text-lg font-semibold mb-3">Recent Detections</h3>
      <div className="panel divide-y divide-slate-800">
        {!loading && detections.length === 0 && (
          <p className="p-4 muted">No detections yet.</p>
        )}
        {detections.map((detection, index) => (
          <div
            key={`${detection.timestamp}-${index}`}
            className="p-4 flex items-start gap-4 justify-between text-sm"
          >
            <div className="min-w-0">
              <p
                className={
                  ["critical", "high"].includes(detection.level)
                    ? "text-red-400 font-medium"
                    : "text-slate-300"
                }
              >
                {kinds[detection.kind] ?? detection.kind}
              </p>
              {detection.file_path && (
                <p className="muted break-words mt-1">{detection.file_path}</p>
              )}
            </div>
            <span className="shrink-0 text-slate-400">
              {Math.round(detection.confidence * 100)}% · {detection.level}
            </span>
          </div>
        ))}
      </div>
    </section>
  );
}
