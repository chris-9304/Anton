// Thin client for anton_api (src/api_server.rs), which listens on :8080 and already
// sets CorsLayer::permissive(), so this can be called directly from the Vite dev
// server (:5173) or the built bundle without a proxy.
const BASE_URL = "http://localhost:8080";

async function get(path) {
  const res = await fetch(`${BASE_URL}${path}`);
  if (!res.ok) throw new Error(`GET ${path} failed: ${res.status}`);
  return res.json();
}

async function post(path, body) {
  const res = await fetch(`${BASE_URL}${path}`, {
    method: "POST",
    headers: body ? { "content-type": "application/json" } : undefined,
    body: body ? JSON.stringify(body) : undefined,
  });
  if (!res.ok) throw new Error(`POST ${path} failed: ${res.status}`);
  return res.json();
}

export const getStatus = () => get("/api/status");
export const getDetections = () => get("/api/detections");
export const getLogs = () => get("/api/logs");
export const getScans = () => get("/api/scans");
export const setAiEnabled = (enabled) => post("/api/settings/ai", { enabled });
export const setMonitoringEnabled = (enabled) => post("/api/settings/monitoring", { enabled });
export const quickScan = () => post("/api/scan/quick");
export const fullScan = () => post("/api/scan/full");
