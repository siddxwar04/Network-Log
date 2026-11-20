// Every request to the netlog API goes through here, so errors look the same everywhere.

import type {
  Audience,
  DemoScenario,
  Explanation,
  Health,
  IncidentDetail,
  IncidentSummary,
  IncidentTimeline,
  LinesAround,
  Live,
  LogEvent,
  Page,
  PipelineStatus,
  Upload,
  UploadDetail,
  UploadListItem,
  UploadSummary,
} from "./types";

export const START_SERVER = "python -m uvicorn netlog.api.app:app";

export class ApiError extends Error {
  // 0 when the server could not be reached at all.
  readonly status: number;
  readonly code: string;

  constructor(status: number, code: string, message: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
  }

  get unreachable(): boolean {
    return this.code === "unreachable";
  }
}

function unreachable(): ApiError {
  return new ApiError(
    0,
    "unreachable",
    `Cannot reach the netlog server. Is it running? Start it with: ${START_SERVER}`,
  );
}

/** Turn an answer into its data, or into an ApiError with a readable message. */
function settle<T>(status: number, text: string): T {
  if (status === 204) return undefined as T;
  let body: unknown = null;
  try {
    body = text ? JSON.parse(text) : null;
  } catch {
    body = null;
  }
  if (status >= 200 && status < 300) return body as T;
  const problem = (body as { error?: { code?: string; message?: string } } | null)?.error;
  if (!problem && status >= 500) {
    // No answer in the API's own error shape: the development proxy is saying that nothing
    // is listening behind it.
    throw unreachable();
  }
  throw new ApiError(
    status,
    problem?.code ?? "error",
    problem?.message ?? `The server answered with status ${status}.`,
  );
}

// Empty in development: the Vite server passes /api on to the backend.
const BASE: string = import.meta.env.VITE_API_BASE ?? "";

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let response: Response;
  let text: string;
  try {
    response = await fetch(BASE + path, init);
    text = response.status === 204 ? "" : await response.text();
  } catch {
    throw unreachable();
  }
  return settle<T>(response.status, text);
}

export interface UploadOptions {
  year?: number;
  timezone?: string;
}

/** Send a file, reporting how much of it has gone (0 to 1). fetch cannot report upload
 * progress, so this one request uses XMLHttpRequest. */
function sendFile(
  file: File,
  options: UploadOptions,
  onProgress?: (fraction: number) => void,
): Promise<Upload> {
  const form = new FormData();
  form.append("file", file, file.name);
  if (options.year !== undefined) form.append("year", String(options.year));
  if (options.timezone) form.append("timezone", options.timezone);
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open("POST", `${BASE}/api/uploads`);
    xhr.upload.onprogress = (event) => {
      if (event.lengthComputable && event.total > 0) onProgress?.(event.loaded / event.total);
    };
    xhr.onload = () => {
      try {
        resolve(settle<Upload>(xhr.status, xhr.responseText));
      } catch (error) {
        reject(error);
      }
    };
    xhr.onerror = () => reject(unreachable());
    xhr.send(form);
  });
}

export const api = {
  health: () => request<Health>("/api/health"),

  uploads: (limit = 20, offset = 0) =>
    request<Page<UploadListItem>>(`/api/uploads?limit=${limit}&offset=${offset}`),

  upload: (id: number | string) => request<UploadDetail>(`/api/uploads/${id}`),

  status: (id: number | string) => request<PipelineStatus>(`/api/uploads/${id}/status`),

  summary: (id: number | string) => request<UploadSummary>(`/api/uploads/${id}/summary`),

  incidents: (id: number | string) =>
    request<Page<IncidentSummary>>(`/api/uploads/${id}/incidents?limit=500`),

  unparsedLines: (id: number | string, limit = 25) =>
    request<Page<LogEvent>>(`/api/uploads/${id}/events?parse_status=unparsed&limit=${limit}`),

  deleteUpload: (id: number) => request<void>(`/api/uploads/${id}`, { method: "DELETE" }),

  uploadFile: sendFile,

  incident: (id: number | string, incidentId: string) =>
    request<IncidentDetail>(`/api/uploads/${id}/incidents/${encodeURIComponent(incidentId)}`),

  explanation: (id: number | string, incidentId: string, mode: Audience) =>
    request<Explanation>(
      `/api/uploads/${id}/incidents/${encodeURIComponent(incidentId)}/explanation?mode=${mode}`,
    ),

  regenerate: (id: number | string, incidentId: string, mode: Audience) =>
    request<Explanation>(
      `/api/uploads/${id}/incidents/${encodeURIComponent(incidentId)}/explanation/regenerate?mode=${mode}`,
      { method: "POST" },
    ),

  timeline: (id: number | string, incidentId: string) =>
    request<IncidentTimeline>(
      `/api/uploads/${id}/incidents/${encodeURIComponent(incidentId)}/timeline`,
    ),

  /** Where the post-mortem of an incident downloads from. A plain link: the browser
   * saves the file itself. */
  postmortemUrl: (id: number | string, incidentId: string, mode: Audience) =>
    `${BASE}/api/uploads/${id}/incidents/${encodeURIComponent(incidentId)}/postmortem?mode=${mode}`,

  linesAround: (id: number | string, line: number, context = 3) =>
    request<LinesAround>(`/api/uploads/${id}/lines?around=${line}&context=${context}`),

  live: () => request<Live>("/api/live"),

  demos: () => request<Page<DemoScenario>>("/api/demo/scenarios?limit=100"),

  loadDemo: (name: string) =>
    request<Upload>(`/api/demo/scenarios/${encodeURIComponent(name)}`, { method: "POST" }),
};
