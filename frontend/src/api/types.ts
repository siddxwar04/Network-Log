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
  source: "file" | "demo" | "live";
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
  /** Whether addresses, device names and usernames are replaced by stand-ins before an
   * evidence pack is sent to the LLM. */
  redaction: { enabled: boolean };
  /** With no LLM set up the app runs in demo mode: the demo scenarios use explanations
   * an LLM wrote earlier and that are stored with the app. */
  demo: { active: boolean; stored_explanations: number };
  max_upload_bytes: number;
  /** The incident replay: how long Play stays on a step, in seconds. */
  replay: { step_seconds: number };
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

// --- One incident -------------------------------------------------------------------------

/** What a log line is about, for colors, shapes and the legend. */
export type EventKind = "link" | "ospf" | "bgp" | "login" | "config" | "dhcp" | "system";

/** One log line as evidence: where it is in the file, when, on which device, and its text.
 * The text is untrusted: it is only ever shown as plain text. */
export interface EvidenceLine {
  line: number;
  time: string | null;
  host: string | null;
  event_key: string | null;
  kind: EventKind;
  text: string;
  findings?: number[];
}

export interface ChainLink {
  cause: number;
  effect: number;
  prior: string;
  certainty: "direct" | "plausible" | "possible";
  explanation: string;
  delay_seconds: number;
}

/** One step of the story the rules tell: the root cause at depth 0, its effects below. */
export interface StoryStep {
  depth: number;
  label: string;
  when: string;
  certainty: string | null;
  explanation: string | null;
  explained: boolean;
  findings: number[];
  evidence: { line: number; text: string }[];
}

export interface FindingDetail {
  id: number;
  incident: string;
  role: string;
  severity: Level;
  severity_reason: string;
  rule: string;
  incident_type: string;
  title: string;
  host: string | null;
  start: string;
  end: string;
  duration_seconds: number;
  flags: string[];
  evidence_count: number;
  evidence: { line: number; text: string }[];
}

export interface IncidentDetail extends Omit<IncidentSummary, "findings"> {
  upload_id: number;
  alternatives: RootCause[];
  unknowns: string[];
  findings: number[];
  context: number[];
  chain: ChainLink[];
  story: StoryStep[];
  finding_details: FindingDetail[];
  evidence: EvidenceLine[];
}

export type Audience = "junior" | "senior";

/** A statement of an explanation and the log lines it rests on. */
export interface CitedStatement {
  text: string;
  lines: number[];
  evidence: string[];
}

export interface Hypothesis extends CitedStatement {
  against_lines: number[];
  against: string[];
}

export interface Explanation {
  upload_id: number;
  incident_id: string;
  /** llm: written now by the LLM; cache: an earlier LLM answer; stored: an LLM answer kept
   * with the demo scenarios; fallback: the built-in templates. */
  source: "llm" | "cache" | "stored" | "fallback";
  written_by: string;
  audience: Audience;
  provider: string;
  model: string;
  fallback_reason: string | null;
  summary: string;
  timeline: CitedStatement[];
  hypotheses: Hypothesis[];
  impact: CitedStatement[];
  fix_steps: { text: string; review_before_running: boolean }[];
  verification_commands: { command: string; purpose: string }[];
  unknowns: string[];
  usage: { requests: number; input_tokens: number; output_tokens: number; latency_ms: number };
  cited_lines: EvidenceLine[];
}

export interface LinesAround {
  upload_id: number;
  around: number;
  context: number;
  lines: EvidenceLine[];
}

/** One event of an incident's timeline: an evidence line that says which findings it
 * belongs to and whether it is part of the root cause. */
export interface TimelineEvent extends EvidenceLine {
  id: number;
  findings: number[];
  root_cause: boolean;
}

export interface IncidentTimeline {
  upload_id: number;
  incident_id: string;
  start: string | null;
  end: string | null;
  /** One lane per device, the root-cause device first. */
  lanes: string[];
  kinds: EventKind[];
  events: TimelineEvent[];
  total_events: number;
  truncated: boolean;
}

// --- The live listener --------------------------------------------------------------------

export interface LiveIncident extends IncidentSummary {
  state: "open" | "closed";
  opened_at: string;
  changed_at: string;
  closed_at: string | null;
}

export interface LiveStatus {
  enabled: true;
  listening: Record<string, string>;
  upload_id: number;
  counters: {
    received: number;
    accepted: number;
    stored: number;
    refused: number;
    rate_limited: number;
    oversized: number;
    not_text: number;
    malformed: number;
    dropped: number;
  };
  per_minute: number;
  queued: number;
  senders: { address: string; messages: number; discarded: number; last_seen: string | null }[];
  warnings: string[];
  last_detection: string | null;
  lines: number;
  open_incidents: LiveIncident[];
  closed_incidents: LiveIncident[];
}

export type Live = LiveStatus | { enabled: false };

// --- Evaluation: how accurate the tool is on logs with known answers ---------------------

export interface DetectionScore {
  expected: number;
  found: number;
  false_alarms: number;
  precision: number | null;
  recall: number | null;
  f1: number | null;
}

export interface Rate {
  correct: number;
  of: number;
  rate: number | null;
}

export interface EvaluationSet {
  files: number;
  lines: number;
  overall: DetectionScore;
  by_type: Record<string, DetectionScore>;
  root_cause: Rate;
  severity: Rate;
  devices: Rate;
  correlation: { split: number; merged: number; expected: number };
  false_alarms_per_10k_lines: number | null;
  lines_per_second: number | null;
}

export interface EvaluationProblem {
  set: string;
  file: string;
  scenario: string;
  seed: number | null;
  variant: string;
  kind: string;
  reason: string;
}

export interface Evaluation {
  generated_at: string;
  limits: string;
  matching_rule: string;
  topology: boolean;
  sets: Partial<Record<"tuned" | "heldout" | "noise", EvaluationSet>>;
  efficiency?: {
    compression_ratio: number | null;
    lines: number;
    templates: number;
    evidence_pack_tokens: { incidents: number; median: number | null; largest: number | null; limit: number };
  };
  explanations?: { measured: boolean; why: string };
  problems: EvaluationProblem[];
}
