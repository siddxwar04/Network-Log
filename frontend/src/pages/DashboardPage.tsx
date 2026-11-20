// The dashboard of one upload: is anything wrong in this log, and how bad?
//
//   1. stat tiles   2. events over time, with incident bands   3. incident cards
//   4. the noisiest message patterns and the busiest devices

import { CalendarClock, FileText, Info, ListTree, Percent, Server, ShieldCheck, TriangleAlert } from "lucide-react";
import { lazy, Suspense, useMemo, useState, type ReactNode } from "react";
import { Link, Navigate, useNavigate, useParams } from "react-router";
import { useIncidents, useSummary, useUnparsedLines, useUpload } from "../api/queries";
import type { IncidentSummary, UploadSummary } from "../api/types";
import { LEVELS } from "../api/types";
import { IncidentCard } from "../components/IncidentCard";
import { Button, EmptyState, ErrorState, PageHeader, Panel, SkeletonRows } from "../components/ui";
import { describeEvents, eventsSeries } from "../lib/eventsChart";
import { formatBytes, formatDuration, formatLocalTime, formatNumber, plural, utcSpan } from "../lib/format";
import { SeverityCounts } from "../lib/severity";

const EventsChart = lazy(() => import("../components/EventsChart"));

// Below this share of understood lines, problems may have been missed.
const COVERAGE_WARNING = 95;

function Tile({
  label,
  icon,
  value,
  sub,
  tone,
}: {
  label: string;
  icon: ReactNode;
  value: ReactNode;
  sub?: ReactNode;
  tone?: "warn";
}) {
  return (
    <div
      className={`rounded-lg border bg-panel p-3 shadow-panel ${tone === "warn" ? "border-warn/60" : "border-line"}`}
    >
      <dt className="eyebrow flex items-center gap-1.5">
        {icon}
        {label}
      </dt>
      <dd className="mt-1.5 text-2xl font-semibold tracking-tight text-ink tabular-nums">{value}</dd>
      {sub && <dd className="mt-0.5 truncate text-xs text-muted">{sub}</dd>}
    </div>
  );
}

function Stats({ summary }: { summary: UploadSummary }) {
  const file = summary.file;
  const span =
    file.start && file.end ? (Date.parse(file.end) - Date.parse(file.start)) / 1000 : null;
  const perPattern = file.templates ? Math.round(file.lines / file.templates) : 0;
  const lowCoverage = file.percent_parsed < COVERAGE_WARNING;
  const incidents = summary.summary.incidents_by_severity;
  const total = LEVELS.reduce((sum, level) => sum + incidents[level], 0);
  const icon = "size-3.5";
  return (
    <dl className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
      <Tile
        label="Lines"
        icon={<FileText aria-hidden="true" className={icon} />}
        value={formatNumber(file.lines)}
        sub={formatBytes(file.size_bytes)}
      />
      <Tile
        label="Devices"
        icon={<Server aria-hidden="true" className={icon} />}
        value={formatNumber(file.devices.length)}
        sub={file.devices.slice(0, 4).map((d) => d.host).join(", ") + (file.devices.length > 4 ? ", ..." : "")}
      />
      <Tile
        label="Time span"
        icon={<CalendarClock aria-hidden="true" className={icon} />}
        value={span === null ? "-" : formatDuration(span)}
        sub={file.start && file.end ? utcSpan(file.start, file.end) : "No times in the file"}
      />
      <Tile
        label="Parsed"
        icon={<Percent aria-hidden="true" className={icon} />}
        value={`${file.percent_parsed.toFixed(1)}%`}
        sub={file.unparsed ? `${plural(file.unparsed, "line")} not understood` : "Every line understood"}
        tone={lowCoverage ? "warn" : undefined}
      />
      <Tile
        label="Message patterns"
        icon={<ListTree aria-hidden="true" className={icon} />}
        value={formatNumber(file.templates)}
        sub={perPattern ? `${formatNumber(perPattern)} lines per pattern` : undefined}
      />
      <Tile
        label="Incidents"
        icon={<TriangleAlert aria-hidden="true" className={icon} />}
        value={formatNumber(total)}
        sub={<SeverityCounts counts={incidents} />}
      />
    </dl>
  );
}

function CoverageWarning({ id, summary }: { id: string; summary: UploadSummary }) {
  const [open, setOpen] = useState(false);
  const lines = useUnparsedLines(id, open);
  if (summary.file.percent_parsed >= COVERAGE_WARNING) return null;
  return (
    <div role="alert" className="rounded-lg border border-warn/60 bg-warn/10 p-4 text-sm">
      <p className="flex items-start gap-2 text-ink">
        <TriangleAlert aria-hidden="true" className="mt-0.5 size-4 shrink-0 text-warn" />
        <span>
          {summary.warnings[0] ??
            `Only ${summary.file.percent_parsed.toFixed(1)}% of lines were understood, so problems may have been missed.`}
        </span>
      </p>
      <Button className="mt-3" onClick={() => setOpen((v) => !v)} aria-expanded={open}>
        {open ? "Hide the lines not understood" : "Show the lines not understood"}
      </Button>
      {open && (
        <div className="mt-3 overflow-hidden rounded-md border border-line bg-sunken">
          {lines.error ? (
            <ErrorState error={lines.error} onRetry={() => lines.refetch()} />
          ) : !lines.data ? (
            <SkeletonRows rows={3} />
          ) : (
            <>
              <ol className="max-h-72 overflow-auto py-1 font-mono text-xs">
                {lines.data.items.map((line) => (
                  <li key={line.id} className="flex gap-3 px-3 py-0.5">
                    <span className="w-14 shrink-0 text-right text-faint tabular-nums">{line.line_no}</span>
                    <span className="break-all whitespace-pre-wrap text-ink">{line.raw}</span>
                  </li>
                ))}
              </ol>
              <p className="border-t border-line px-3 py-1.5 text-xs text-faint">
                The first {lines.data.items.length} of {formatNumber(lines.data.total)} lines not understood, with
                their line numbers in the file.
              </p>
            </>
          )}
        </div>
      )}
    </div>
  );
}

function Timeline({ summary, onOpen }: { summary: UploadSummary; onOpen: (id: string) => void }) {
  const series = useMemo(
    () => eventsSeries(summary.events_over_time, summary.incident_periods),
    [summary.events_over_time, summary.incident_periods],
  );
  const description = describeEvents(series);
  return (
    <Panel
      title="Events over time"
      action={
        series.bands.length > 0 && (
          <span className="text-xs text-faint">Shaded: incidents. Click one to open it.</span>
        )
      }
    >
      <figure className="px-2 pt-2" role="img" aria-label={description}>
        {series.bars.length === 0 ? (
          <EmptyState title="No events with a time to chart." />
        ) : (
          <Suspense fallback={<div className="h-64 animate-pulse rounded bg-raised" />}>
            <EventsChart series={series} onOpenIncident={onOpen} />
          </Suspense>
        )}
        <figcaption className="sr-only">{description}</figcaption>
      </figure>
    </Panel>
  );
}

function Incidents({ id, incidents }: { id: string; incidents: IncidentSummary[] }) {
  if (incidents.length === 0) {
    return (
      <Panel>
        <EmptyState
          title="No incidents found in this log."
          icon={<ShieldCheck aria-hidden="true" className="mb-2 size-8 text-ok" />}
        >
          Nothing reached low severity or above. Routine events, such as configuration changes and
          single interfaces going down, are recorded but are not problems on their own.
        </EmptyState>
      </Panel>
    );
  }
  return (
    <ul className="grid gap-3 lg:grid-cols-2">
      {incidents.map((incident) => (
        <li key={incident.id}>
          <IncidentCard uploadId={id} incident={incident} />
        </li>
      ))}
    </ul>
  );
}

function BarList({
  rows,
  mono,
}: {
  rows: { key: string; label: string; count: number; title?: string }[];
  mono?: boolean;
}) {
  const top = Math.max(1, ...rows.map((row) => row.count));
  return (
    <ol className="divide-y divide-line">
      {rows.map((row) => (
        <li key={row.key} className="relative px-4 py-2 text-sm" title={row.title ?? row.label}>
          <span
            aria-hidden="true"
            className="absolute inset-y-1 left-0 rounded-r bg-accent/10"
            style={{ width: `${(row.count / top) * 100}%` }}
          />
          <span className="relative flex items-baseline justify-between gap-3">
            <span className={`truncate text-ink ${mono ? "font-mono text-xs" : ""}`}>{row.label}</span>
            <span className="shrink-0 text-xs text-muted tabular-nums">{formatNumber(row.count)}</span>
          </span>
        </li>
      ))}
    </ol>
  );
}

function SideLists({ summary }: { summary: UploadSummary }) {
  const devices = [...summary.file.devices].sort((a, b) => b.lines - a.lines || a.host.localeCompare(b.host));
  return (
    <div className="grid gap-4 lg:grid-cols-[3fr_2fr]">
      <Panel title="Noisiest message patterns" action={<span className="text-xs text-faint">lines</span>}>
        {summary.top_templates.length === 0 ? (
          <EmptyState title="No message patterns." />
        ) : (
          <BarList
            mono
            rows={summary.top_templates.map((t, i) => ({
              key: `${i}`,
              label: t.pattern,
              count: t.count,
              title: `${t.pattern} (${t.event_key ?? t.source_type})`,
            }))}
          />
        )}
      </Panel>
      <Panel title="Busiest devices" action={<span className="text-xs text-faint">lines</span>}>
        {devices.length === 0 ? (
          <EmptyState title="No devices named in the file." />
        ) : (
          <BarList rows={devices.slice(0, 10).map((d) => ({ key: d.host, label: d.host, count: d.lines }))} />
        )}
      </Panel>
    </div>
  );
}

export default function DashboardPage() {
  const { id = "" } = useParams();
  const navigate = useNavigate();
  const upload = useUpload(id);
  const done = upload.data?.status === "done";
  const summary = useSummary(id, done);
  const incidents = useIncidents(id, done);

  const error = upload.error ?? summary.error ?? incidents.error;
  if (error) {
    return (
      <Panel>
        <ErrorState error={error} onRetry={() => [upload, summary, incidents].forEach((q) => q.refetch())} />
      </Panel>
    );
  }
  if (upload.data && !done) {
    // Still being processed, or failed: the processing screen says where it stands.
    return <Navigate to={`/uploads/${id}/processing`} replace />;
  }
  const name = upload.data?.filename ?? `Upload ${id}`;
  const header = (
    <PageHeader
      crumbs={[{ label: "Uploads", to: "/" }, { label: name }]}
      title={<span className="font-mono">{name}</span>}
      meta={
        upload.data && (
          <>
            Analyzed {formatLocalTime(upload.data.finished_at ?? upload.data.created_at)}
            {upload.data.source === "demo" && " · demo scenario"}
          </>
        )
      }
      actions={
        <Link
          to={`/uploads/${id}/incidents`}
          className="inline-flex items-center rounded-md border border-line-strong bg-raised px-3 py-1.5 text-sm font-medium text-ink hover:border-faint"
        >
          All incidents
        </Link>
      }
    />
  );
  if (!summary.data || !incidents.data) {
    return (
      <div>
        {header}
        <div className="space-y-4">
          <Panel>
            <SkeletonRows rows={2} />
          </Panel>
          <Panel>
            <SkeletonRows rows={6} />
          </Panel>
        </div>
      </div>
    );
  }
  const data = summary.data;
  return (
    <div>
      {header}
      <div className="space-y-5">
        <Stats summary={data} />
        <CoverageWarning id={id} summary={data} />
        <Timeline
          summary={data}
          onOpen={(incidentId) => navigate(`/uploads/${id}/incidents/${encodeURIComponent(incidentId)}`)}
        />
        <section aria-labelledby="incidents-heading" className="space-y-3">
          <h2 id="incidents-heading" className="text-sm font-semibold text-ink">
            Incidents <span className="font-normal text-muted">most severe first</span>
          </h2>
          <Incidents id={id} incidents={incidents.data.items} />
        </section>
        <SideLists summary={data} />
        {data.assumptions.length > 0 && (
          <Panel title="Assumptions">
            <ul className="space-y-1.5 p-4 text-sm text-muted">
              {data.assumptions.map((text) => (
                <li key={text} className="flex gap-2">
                  <Info aria-hidden="true" className="mt-0.5 size-4 shrink-0 text-faint" />
                  {text}
                </li>
              ))}
            </ul>
          </Panel>
        )}
      </div>
    </div>
  );
}
