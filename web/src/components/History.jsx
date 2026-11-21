import { getLogs } from "../services/api.js";
import { usePoll } from "../hooks/usePoll.js";
export default function History() {
  const { data, error, loading } = usePoll(getLogs, 5000);
  const logs = data?.logs ?? [];
  return (
    <section aria-labelledby="history-title" aria-busy={loading}>
      <h2 id="history-title" className="page-title">
        History
      </h2>
      <p className="muted mb-4">
        Latest activity in this session. Older entries are discarded
        automatically.
      </p>
      {error && (
        <p role="alert" className="error-message">
          Connection unavailable. Retrying… {error}
        </p>
      )}
      <div className="panel p-4 font-mono text-xs space-y-2 max-h-[70vh] overflow-y-auto break-words">
        {loading && (
          <p role="status" className="muted">
            Loading activity…
          </p>
        )}
        {!loading && logs.length === 0 && (
          <p className="muted">No activity logged yet.</p>
        )}
        {logs.map((line, index) => (
          <p key={`${index}-${line}`} className="text-slate-300">
            {line}
          </p>
        ))}
      </div>
    </section>
  );
}
