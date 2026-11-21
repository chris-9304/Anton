import { useEffect, useRef, useState } from "react";
import {
  getStatus,
  setAiEnabled,
  setMonitoringEnabled,
} from "../services/api.js";
import { usePoll } from "../hooks/usePoll.js";
function Toggle({ label, description, checked, disabled, onChange }) {
  return (
    <label className="flex items-center justify-between gap-4 panel p-4 cursor-pointer">
      <span>
        <span className="block text-sm font-medium">{label}</span>
        <span className="block muted mt-1">{description}</span>
      </span>
      <input
        type="checkbox"
        checked={checked}
        disabled={disabled}
        onChange={(e) => onChange(e.target.checked)}
        className="w-5 h-5 shrink-0 accent-blue-600 disabled:opacity-50"
      />
    </label>
  );
}
export default function Settings() {
  const { data, error, loading, refresh } = usePoll(getStatus, 5000);
  const [busy, setBusy] = useState(false);
  const [actionError, setActionError] = useState(null);
  const action = useRef(null);
  useEffect(() => () => action.current?.abort(), []);
  async function toggle(operation, value) {
    if (action.current) return;
    const controller = new AbortController();
    action.current = controller;
    setBusy(true);
    setActionError(null);
    try {
      await operation(value, { signal: controller.signal });
      if (!controller.signal.aborted) await refresh();
    } catch (error) {
      if (!controller.signal.aborted)
        setActionError(`Setting was not confirmed. ${error.message}`);
    } finally {
      action.current = null;
      if (!controller.signal.aborted) setBusy(false);
    }
  }
  return (
    <section aria-labelledby="settings-title" aria-busy={loading || busy}>
      <h2 id="settings-title" className="page-title">
        Settings
      </h2>
      {(actionError || error) && (
        <p role="alert" className="error-message">
          {actionError || error}
        </p>
      )}
      {loading && (
        <p role="status" className="muted mb-4">
          Loading settings…
        </p>
      )}
      <div className="space-y-3 max-w-xl">
        <Toggle
          label="AI Detection Engine"
          description="Analyze file-change patterns. Canary protection remains active when AI is disabled."
          checked={data?.ai_enabled ?? false}
          disabled={!data || busy}
          onChange={(value) => toggle(setAiEnabled, value)}
        />
        <Toggle
          label="Real-time Monitoring"
          description="Monitor the TestRun demo directory. Pausing also pauses canary protection and automatic recovery."
          checked={data?.monitoring_enabled ?? false}
          disabled={!data || busy}
          onChange={(value) => toggle(setMonitoringEnabled, value)}
        />
      </div>
      {busy && (
        <p role="status" className="muted mt-4">
          Saving settings…
        </p>
      )}
      <p className="muted mt-6 max-w-xl">
        Individual detector settings are available in the desktop app. Network
        analysis is unavailable until a network event source is connected.
      </p>
    </section>
  );
}
