// The shapes the netlog API returns. They mirror backend/netlog/api/app.py; when a field
// there changes, change it here and the type checker points at every place that uses it.

export type Level = "critical" | "high" | "medium" | "low" | "info";
export const LEVELS: Level[] = ["critical", "high", "medium", "low", "info"];

export type Stage =
  | "queued"
  | "parsing"
  | "templates"
  | "detection"
  | "correlation"
  | "explanation"
  | "done"
  | "failed";

export interface Page<T> {
  items: T[];
  total: number;
  limit: number;
  offset: number;
}

export interface Upload {
  id: number;
  filename: string;
  source: "file" | "demo";
  size_bytes: number;
  status: "processing" | "done" | "failed";
  stage: Stage;
  failed_stage: Stage | null;
  error: string | null;
  year: number | null;
  timezone: string | null;
  lines: number;
  blank_lines: number;
  parsed: number;
  partial: number;
  unparsed: number;
  classified: number;
  percent_parsed: number;
  created_at: string;
  finished_at: string | null;
}

export type SeverityCounts = Record<Level, number>;

export interface UploadListItem extends Upload {
  incidents_by_severity: SeverityCounts;
}

export interface Counts {
  lines: number;
  templates: number;
  findings: number;
  incidents: number;
}

export interface UploadDetail extends UploadListItem {
  counts: Counts;
}

export interface PipelineStatus {
  id: number;
  status: Upload["status"];
  stage: Stage;
  failed_stage: Stage | null;
  error: string | null;
  finished: boolean;
  stages: Stage[];
  counts: Counts;
}

export interface Health {
  status: string;
  version: string;
  database_schema: number;
  llm: { configured: boolean; provider: string };
  max_upload_bytes: number;
  stages: Stage[];
}

export interface DemoScenario {
  name: string;
  description: string;
  lines: number | null;
  year: number | null;
  incidents: { type: string; title: string; expected_severity: Level }[];
}

// --- The dashboard ------------------------------------------------------------------------

export interface DeviceLines {
  host: string;
  lines: number;
}

export interface FileFacts {
  name: string;
  size_bytes: number;
  lines: number;
  blank_lines: number;
  parsed: number;
  partial: number;
  unparsed: number;
  classified: number;
  percent_parsed: number;
  start: string | null;
  end: string | null;
  devices: DeviceLines[];
  templates: number;
}

export interface TopTemplate {
  pattern: string;
  count: number;
  event_key: string | null;
  source_type: string;
  hosts: string[];
}

export interface IncidentPeriod {
  id: string;
  headline: string;
  severity: Level;
  start: string;
  end: string;
}

export interface UploadSummary {
  upload: Upload;
  file: FileFacts;
  summary: {
    min_severity: Level;
    incidents: number;
    incidents_by_severity: SeverityCounts;
    by_severity: SeverityCounts;
    shown: number;
    hidden: number;
  };
  top_templates: TopTemplate[];
  events_over_time: { bucket_seconds: number | null; buckets: { start: string; count: number }[] };
  incident_periods: IncidentPeriod[];
  assumptions: string[];
  warnings: string[];
}

export interface RootCause {
  kind: string;
  summary: string;
  devices: string[];
  entity: string | null;
  findings: number[];
  explains: number;
}

export interface IncidentSummary {
  id: string;
  headline: string;
  title: string;
  severity: Level;
  severity_reason: string;
  start: string;
  end: string;
  duration_seconds: number;
  devices: string[];
  root_cause: RootCause | null;
  confidence: "high" | "medium" | "low";
  confidence_reason: string;
  findings: number;
}

export interface LogEvent {
  id: number;
  line_no: number;
  raw: string;
  timestamp: string | null;
  host: string | null;
  event_key: string | null;
  message: string;
  parse_status: "parsed" | "partial" | "unparsed";
}
