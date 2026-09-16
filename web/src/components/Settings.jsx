import { useEffect, useState } from "react";
import { getStatus, setAiEnabled, setMonitoringEnabled } from "../services/api.js";

function Toggle({ label, checked, onChange }) {
  return (
    <label className="flex items-center justify-between bg-slate-900 border border-slate-800 rounded-lg p-4 cursor-pointer">
      <span className="text-sm font-medium">{label}</span>
      <input
        type="checkbox"
        checked={checked}
        onChange={(e) => onChange(e.target.checked)}
        className="w-5 h-5 accent-blue-600"
      />
    </label>
  );
}

export default function Settings() {
  const [aiEnabled, setAi] = useState(true);
  const [monitoringEnabled, setMonitoring] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    getStatus()
      .then((s) => {
        setAi(s.ai_enabled);
        setMonitoring(s.monitoring_enabled);
      })
      .catch((e) => setError(e.message));
  }, []);

  async function toggleAi(value) {
    setAi(value);
    try {
      await setAiEnabled(value);
    } catch (e) {
      setError(e.message);
    }
  }

  async function toggleMonitoring(value) {
    setMonitoring(value);
    try {
      await setMonitoringEnabled(value);
    } catch (e) {
      setError(e.message);
    }
  }

  return (
    <div>
      <h2 className="text-2xl font-bold mb-6">Settings</h2>
      {error && <div className="mb-4 text-sm text-red-400">{error}</div>}
      <div className="space-y-3 max-w-md">
        <Toggle label="AI Detection Engine" checked={aiEnabled} onChange={toggleAi} />
        <Toggle label="Real-time Monitoring" checked={monitoringEnabled} onChange={toggleMonitoring} />
      </div>
      <p className="text-xs text-slate-500 mt-6">
        Per-detector toggles (extension monitoring, rate limiting, entropy analysis,
        DNS analysis) are available in the Slint desktop app's Settings tab.
      </p>
    </div>
  );
}
