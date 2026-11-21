// A stand-in for the netlog API: `fetch` is replaced, so no test ever needs a server.

import { vi } from "vitest";
import type {
  DemoScenario,
  IncidentSummary,
  UploadSummary,
  Health,
  Page,
  PipelineStatus,
  Stage,
  UploadDetail,
  UploadListItem,
} from "../api/types";

export interface Call {
  method: string;
  path: string;
  query: URLSearchParams;
  body: BodyInit | null | undefined;
}

type Answer = { status?: number; body?: unknown } | "unreachable";
type Handler = (call: Call) => Answer | unknown | Promise<Answer | unknown>;

/** Replace fetch and XMLHttpRequest. Each route is "METHOD /path" (the query string is
 * ignored), answered by a plain value (sent as JSON with status 200), an `{status, body}`
 * pair, "unreachable", or a function that returns any of those. A route that is not listed
 * answers 404. */
export function mockApi(routes: Record<string, Handler | Answer | object>) {
  const calls: Call[] = [];

  async function answer(method: string, input: string, body: BodyInit | null | undefined) {
    const url = new URL(input, "http://test");
    const call = { method: method.toUpperCase(), path: url.pathname, query: url.searchParams, body };
    calls.push(call);
    const route = routes[`${call.method} ${url.pathname}`];
    let result: unknown = route === undefined ? notFound() : route;
    if (typeof result === "function") result = await (result as Handler)(call);
    if (result === "unreachable") return "unreachable" as const;
    const { status, body: data } = isAnswer(result) ? result : { status: 200, body: result };
    const code = status ?? 200;
    return { status: code, text: code === 204 ? "" : JSON.stringify(data ?? null) };
  }

  const fetchStub = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const result = await answer(init?.method ?? "GET", typeof input === "string" ? input : input.toString(), init?.body);
    if (result === "unreachable") throw new TypeError("Failed to fetch");
    if (result.status === 204) return new Response(null, { status: 204 });
    return new Response(result.text, { status: result.status, headers: { "content-type": "application/json" } });
  });

  // Enough of XMLHttpRequest for an upload with progress: the whole file "goes" at once.
  class FakeXhr {
    status = 0;
    responseText = "";
    upload: { onprogress: ((event: ProgressEvent) => void) | null } = { onprogress: null };
    onload: (() => void) | null = null;
    onerror: (() => void) | null = null;
    private method = "GET";
    private url = "";
    open(method: string, url: string) {
      this.method = method;
      this.url = url;
    }
    send(body: BodyInit | null) {
      setTimeout(async () => {
        const result = await answer(this.method, this.url, body);
        if (result === "unreachable") {
          this.onerror?.();
          return;
        }
        this.upload.onprogress?.({ lengthComputable: true, loaded: 100, total: 100 } as ProgressEvent);
        this.status = result.status;
        this.responseText = result.text;
        this.onload?.();
      }, 0);
    }
  }

  vi.stubGlobal("fetch", fetchStub);
  vi.stubGlobal("XMLHttpRequest", FakeXhr);
  return { calls, fetch: fetchStub };
}

function isAnswer(value: unknown): value is { status?: number; body?: unknown } {
  return typeof value === "object" && value !== null && "status" in value && typeof (value as { status: unknown }).status === "number";
}

export function notFound(code = "not_found", message = "There is nothing at this address.") {
  return { status: 404, body: { error: { code, message } } };
}

export function apiError(status: number, code: string, message: string) {
  return { status, body: { error: { code, message } } };
}

// --- Sample answers ----------------------------------------------------------------------

export const HEALTH: Health = {
  status: "ok",
  version: "0.1.0",
  database_schema: 9,
  llm: { configured: false, provider: "" },
  redaction: { enabled: true },
  demo: { active: true, stored_explanations: 0 },
  max_upload_bytes: 50 * 1024 * 1024,
  stages: ["queued", "parsing", "templates", "detection", "correlation", "explanation", "done"],
};

export function page<T>(items: T[]): Page<T> {
  return { items, total: items.length, limit: 20, offset: 0 };
}

const NONE = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };

export function uploadItem(overrides: Partial<UploadListItem> = {}): UploadListItem {
  return {
    id: 1,
    filename: "02_cascade.log",
    source: "file",
    size_bytes: 530682,
    status: "done",
    stage: "done",
    failed_stage: null,
    error: null,
    year: 2026,
    timezone: null,
    lines: 5000,
    blank_lines: 0,
    parsed: 5000,
    partial: 0,
    unparsed: 0,
    classified: 5000,
    percent_parsed: 100,
    created_at: "2026-11-20T14:17:48.028427Z",
    finished_at: "2026-11-20T14:17:52.000000Z",
    incidents_by_severity: { ...NONE, critical: 1 },
    ...overrides,
  };
}

export function uploadDetail(overrides: Partial<UploadDetail> = {}): UploadDetail {
  return {
    ...uploadItem(),
    counts: { lines: 5000, templates: 34, findings: 166, incidents: 1 },
    ...overrides,
  };
}

export function status(stage: Stage, overrides: Partial<PipelineStatus> = {}): PipelineStatus {
  const finished = stage === "done" || stage === "failed";
  return {
    id: 1,
    status: stage === "done" ? "done" : stage === "failed" ? "failed" : "processing",
    stage,
    failed_stage: null,
    error: null,
    finished,
    stages: HEALTH.stages,
    counts: { lines: 0, templates: 0, findings: 0, incidents: 0 },
    ...overrides,
  };
}

export const DEMOS: DemoScenario[] = [
  {
    name: "02_cascade",
    description: "R1 lost its transit link (GigabitEthernet0/1); OSPF and BGP to R1 dropped on R2, R3 and R4",
    lines: 5000,
    year: 2026,
    incidents: [{ type: "link_failure", title: "R1 lost its transit link", expected_severity: "critical" }],
  },
  {
    name: "08_noise",
    description: "A normal day. No incident.",
    lines: 5000,
    year: 2026,
    incidents: [],
  },
];

// --- The dashboard of the cascade sample ---------------------------------------------------

export function summary(overrides: Partial<UploadSummary> = {}): UploadSummary {
  const upload = uploadItem();
  return {
    upload,
    file: {
      name: "02_cascade.log",
      size_bytes: 530682,
      lines: 5000,
      blank_lines: 0,
      parsed: 5000,
      partial: 0,
      unparsed: 0,
      classified: 5000,
      percent_parsed: 100,
      start: "2026-03-03T00:00:01Z",
      end: "2026-03-03T05:59:58Z",
      devices: [
        { host: "R1", lines: 640 },
        { host: "dhcp1", lines: 1810 },
        { host: "srv1", lines: 1450 },
        { host: "SW1", lines: 300 },
      ],
      templates: 34,
    },
    summary: {
      min_severity: "low",
      incidents: 1,
      incidents_by_severity: { critical: 1, high: 0, medium: 0, low: 0, info: 0 },
      by_severity: { critical: 6, high: 6, medium: 0, low: 0, info: 154 },
      shown: 12,
      hidden: 154,
    },
    top_templates: [
      { pattern: "DHCPACK on <IP> to <MAC> (<HOST>) via <IF>", count: 761, event_key: "dhcp.ack", source_type: "dhcp", hosts: ["dhcp1"] },
      { pattern: "Interface <IF>, changed state to down", count: 40, event_key: "LINK-3-UPDOWN", source_type: "cisco", hosts: ["R1"] },
    ],
    events_over_time: {
      bucket_seconds: 300,
      buckets: [
        { start: "2026-03-03T02:40:00Z", count: 60 },
        { start: "2026-03-03T02:45:00Z", count: 95 },
        // 02:50 had no events and is left out, as the API does.
        { start: "2026-03-03T02:55:00Z", count: 50 },
      ],
    },
    incident_periods: [
      {
        id: "inc-6f861a94c9",
        headline: "Interface GigabitEthernet0/1 on R1 was down for 8m 36s",
        severity: "critical",
        start: "2026-03-03T02:46:11.719Z",
        end: "2026-03-03T02:46:52.302Z",
      },
    ],
    assumptions: ["The log lines carry no year; 2026 was used, as given."],
    warnings: [],
    ...overrides,
  };
}

export function incident(overrides: Partial<IncidentSummary> = {}): IncidentSummary {
  return {
    id: "inc-6f861a94c9",
    headline: "Interface GigabitEthernet0/1 on R1 was down for 8m 36s",
    title: "BGP session from R1 to 10.255.0.2 went down, with 11 related findings on R1, R2, R3, R4",
    severity: "critical",
    severity_reason: 'Critical: the most serious finding is "BGP session from R1 to 10.255.0.2 went down".',
    start: "2026-03-03T02:46:11.719Z",
    end: "2026-03-03T02:46:52.302Z",
    duration_seconds: 40.583,
    devices: ["R1", "R2", "R3", "R4"],
    root_cause: {
      kind: "interface_down",
      summary: "Interface GigabitEthernet0/1 on R1 was down for 8m 36s",
      devices: ["R1"],
      entity: "GigabitEthernet0/1",
      findings: [72],
      explains: 12,
    },
    confidence: "high",
    confidence_reason: "every finding is accounted for",
    findings: 12,
    ...overrides,
  };
}

/** Everything the dashboard of upload `id` asks for. */
export function dashboard(id = 1, parts: { summary?: UploadSummary; incidents?: IncidentSummary[] } = {}) {
  return {
    [`GET /api/uploads/${id}`]: uploadDetail({ id }),
    [`GET /api/uploads/${id}/summary`]: parts.summary ?? summary(),
    [`GET /api/uploads/${id}/incidents`]: page(parts.incidents ?? [incident()]),
  };
}
