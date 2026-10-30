// Thin, typed client for the SENTIVRA FastAPI backend.
// The browser talks to the backend directly; its CORS allowlist admits the
// dashboard's origin (SENTIVRA_CORS_ORIGINS in the backend .env). Every call
// carries the session's bearer token. Browsers never attach that header on
// their own, so a hostile page can't make authenticated requests (no CSRF).

import { clearToken, getToken } from "@/lib/auth";
import type {
  AlertStatus,
  BatchAnalysisResponse,
  FileAnalysisResponse,
  NetworkAnalysisResponse,
  TextAnalysisResponse,
  SimulationRun,
  LabTelemetryRun,
} from "@/types/api";

export const API_BASE = (process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8000").replace(/\/$/, "");

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const headers = new Headers(init?.headers);
  const token = getToken();
  if (token) headers.set("Authorization", `Bearer ${token}`);
  let response: Response;
  try {
    response = await fetch(`${API_BASE}${path}`, { ...init, headers });
  } catch {
    // fetch() rejects the same way for "server down" and "blocked by CORS",
    // so name both causes and how to fix each.
    const origin = typeof window === "undefined" ? "this dashboard" : window.location.origin;
    throw new ApiError(
      0,
      `Can't reach the SENTIVRA backend at ${API_BASE}. Check that it's running, and that ${origin} is listed in ` +
        "SENTIVRA_CORS_ORIGINS on the backend.",
    );
  }
  if (response.status === 401) {
    // Expired, revoked, or signed with a key the backend no longer has
    // (e.g. its .sentivra/ state was reset). Back to the sign-in screen.
    clearToken();
    throw new ApiError(401, "Your session has ended. Sign in again.");
  }
  if (!response.ok) {
    let detail = response.statusText;
    try {
      const body = await response.json();
      detail = typeof body.detail === "string" ? body.detail : JSON.stringify(body.detail ?? body);
    } catch {
      // non-JSON error body: keep the status text
    }
    throw new ApiError(response.status, detail);
  }
  return response.json() as Promise<T>;
}

export async function downloadMarkdown(path: string, fallbackFilename: string) {
  const headers = new Headers();
  const token = getToken();
  if (token) headers.set("Authorization", `Bearer ${token}`);
  let response: Response;
  try {
    response = await fetch(`${API_BASE}${path}`, { headers });
  } catch {
    throw new ApiError(0, `Can't reach the SENTIVRA backend at ${API_BASE}.`);
  }
  if (response.status === 401) {
    clearToken();
    throw new ApiError(401, "Your session has ended. Sign in again.");
  }
  if (!response.ok) {
    let detail = response.statusText;
    try {
      const body = await response.json();
      detail = typeof body.detail === "string" ? body.detail : JSON.stringify(body.detail ?? body);
    } catch {
      // Keep the HTTP status text for non-JSON failures.
    }
    throw new ApiError(response.status, detail);
  }
  const blob = await response.blob();
  const disposition = response.headers.get("content-disposition") ?? "";
  const encoded = disposition.match(/filename\*=UTF-8''([^;]+)/i)?.[1];
  const filename = encoded ? decodeURIComponent(encoded) : disposition.match(/filename="?([^";]+)"?/i)?.[1] ?? fallbackFilename;
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
  return filename;
}

async function downloadBinary(path: string, fallbackFilename: string) {
  const headers = new Headers();
  const token = getToken();
  if (token) headers.set("Authorization", `Bearer ${token}`);
  let response: Response;
  try {
    response = await fetch(`${API_BASE}${path}`, { headers });
  } catch {
    throw new ApiError(0, `Can't reach the SENTIVRA backend at ${API_BASE}.`);
  }
  if (response.status === 401) {
    clearToken();
    throw new ApiError(401, "Your session has ended. Sign in again.");
  }
  if (!response.ok) throw new ApiError(response.status, response.statusText);
  const blob = await response.blob();
  const disposition = response.headers.get("content-disposition") ?? "";
  const filename = disposition.match(/filename="?([^";]+)"?/i)?.[1] ?? fallbackFilename;
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
  return filename;
}

export async function streamLabTelemetry(
  onSample: (sample: import("@/types/api").HostTelemetrySample) => void,
  signal: AbortSignal,
) {
  const headers = new Headers({ Accept: "text/event-stream" });
  const token = getToken();
  if (token) headers.set("Authorization", `Bearer ${token}`);
  const response = await fetch(`${API_BASE}/api/v1/lab-telemetry/stream`, { headers, signal, cache: "no-store" });
  if (!response.ok || !response.body) throw new ApiError(response.status, response.statusText || "Telemetry stream unavailable");
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  while (!signal.aborted) {
    const next = await reader.read();
    if (next.done) break;
    buffer += decoder.decode(next.value, { stream: true });
    const frames = buffer.split("\n\n");
    buffer = frames.pop() ?? "";
    for (const frame of frames) {
      const data = frame.split("\n").find((line) => line.startsWith("data: "))?.slice(6);
      if (!data) continue;
      try {
        const parsed = JSON.parse(data) as { type?: string; sample?: import("@/types/api").HostTelemetrySample };
        if (parsed.type === "host_sample" && parsed.sample) onSample(parsed.sample);
      } catch {
        // Ignore malformed keep-alive frames; the next complete SSE frame is authoritative.
      }
    }
  }
  reader.releaseLock();
}

/** SWR fetcher: the key is the API path. */
export const fetcher = <T,>(path: string) => request<T>(path);

function upload<T>(path: string, file: File | Blob, filename?: string): Promise<T> {
  const form = new FormData();
  form.append("file", file, filename ?? (file instanceof File ? file.name : "upload"));
  return request<T>(path, { method: "POST", body: form });
}

export const api = {
  setAlertStatus: (alertId: string, status: AlertStatus, note?: string) =>
    request<{ alert_id: string; status: AlertStatus; previous_status: AlertStatus }>(
      `/api/v1/alerts/${encodeURIComponent(alertId)}`,
      { method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ status, note }) },
    ),
  analyzeFile: (file: File | Blob, filename?: string) =>
    upload<FileAnalysisResponse>("/api/v1/analyze/file", file, filename),
  analyzeNetwork: (file: File) => upload<NetworkAnalysisResponse>("/api/v1/network/analyze", file),
  networkDemo: () => request<NetworkAnalysisResponse>("/api/v1/network/demo", { method: "POST" }),
  analyzeOsquery: (file: File) => upload<BatchAnalysisResponse>("/api/v1/endpoint/osquery", file),
  endpointDemo: () => request<BatchAnalysisResponse>("/api/v1/endpoint/demo", { method: "POST" }),
  analyzeLogs: (file: File) => upload<BatchAnalysisResponse>("/api/v1/logs/analyze", file),
  analyzeText: (text: string) => request<TextAnalysisResponse>("/api/v1/analyze/text", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ text }) }),
  analyzePrompt: (prompt: string) => request<TextAnalysisResponse>("/api/v1/analyze/prompt", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ prompt }) }),
  analyzeSql: (sql: string) => request<TextAnalysisResponse>("/api/v1/analyze/sql", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ sql }) }),
  analyzeUrl: (url: string) => request<TextAnalysisResponse>("/api/v1/analyze/url", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ url }) }),
  runSimulation: (scenarioId: string, requestKey: string) => request<SimulationRun>("/api/simulation/run", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ scenario_id: scenarioId, mode: "simulation", request_key: requestKey }),
  }),
  downloadExecutionReport: (executionId: string) => downloadMarkdown(
    `/api/v1/cyber-defense/executions/${encodeURIComponent(executionId)}/report.md`,
    `sentivra-report-${executionId.slice(0, 8)}.md`,
  ),
  downloadFilteredReport: (verdict?: string) => downloadMarkdown(
    `/api/v1/cyber-defense/executions/report.md${verdict ? `?verdict=${encodeURIComponent(verdict)}` : ""}`,
    "sentivra-filtered-reports.md",
  ),
  startLabTelemetry: (scenarioId: string, scenarioRunId: string) => request<LabTelemetryRun>("/api/v1/lab-telemetry/runs/start", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ scenario_id: scenarioId, scenario_run_id: scenarioRunId, mode: "mode_a" }),
  }),
  getLabTelemetry: (scenarioRunId: string) => request<LabTelemetryRun>(`/api/v1/lab-telemetry/runs/${encodeURIComponent(scenarioRunId)}`),
  downloadLabTelemetry: (scenarioRunId: string, format: "json" | "zip" | "html") => downloadBinary(
    `/api/v1/lab-telemetry/runs/${encodeURIComponent(scenarioRunId)}/export.${format}`,
    `sentivra-lab-${scenarioRunId.slice(0, 12)}.${format}`,
  ),
};
