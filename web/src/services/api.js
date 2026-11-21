export const BASE_URL = (
  import.meta.env?.VITE_API_BASE_URL ?? "http://localhost:8080"
).replace(/\/$/, "");

export async function request(
  path,
  { method = "GET", body, signal, timeout = 10000 } = {},
) {
  const controller = new AbortController();
  const abort = () => controller.abort(signal.reason);
  if (signal?.aborted) abort();
  else signal?.addEventListener("abort", abort, { once: true });
  const timer = setTimeout(
    () =>
      controller.abort(new DOMException("Request timed out", "TimeoutError")),
    timeout,
  );
  try {
    const response = await fetch(`${BASE_URL}${path}`, {
      method,
      signal: controller.signal,
      headers:
        body === undefined ? undefined : { "content-type": "application/json" },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    if (!response.ok) throw new Error(`Request failed (${response.status})`);
    return await response.json();
  } finally {
    clearTimeout(timer);
    signal?.removeEventListener("abort", abort);
  }
}

export const getStatus = (options) => request("/api/status", options);
export const getDetections = (options) => request("/api/detections", options);
export const getLogs = (options) => request("/api/logs", options);
export const getScans = (options) => request("/api/scans", options);
export const setAiEnabled = (enabled, options) =>
  request("/api/settings/ai", {
    ...options,
    method: "POST",
    body: { enabled },
  });
export const setMonitoringEnabled = (enabled, options) =>
  request("/api/settings/monitoring", {
    ...options,
    method: "POST",
    body: { enabled },
  });
export const quickScan = (options) =>
  request("/api/scan/quick", { ...options, method: "POST" });
export const fullScan = (options) =>
  request("/api/scan/full", { ...options, method: "POST" });
export async function getDashboard(options) {
  const [status, detections] = await Promise.all([
    getStatus(options),
    getDetections(options),
  ]);
  return { status, detections: detections.detections ?? [] };
}
