// The timeline section of the incident page: the chart, its legend, a reset for the zoom,
// and the same picture described in words.

import { ZoomOut } from "lucide-react";
import { lazy, Suspense, useMemo, useState } from "react";
import type { IncidentTimeline as Timeline, TimelineEvent } from "../api/types";
import { formatDuration, plural, utcSpan } from "../lib/format";
import {
  clusterEvents,
  describeTimeline,
  KIND_STYLE,
  KINDS,
  laneHeight,
  laneNames,
  timelineRange,
  type TimeRange,
} from "../lib/timeline";
import { Button } from "./ui";

const TimelineChart = lazy(() => import("./TimelineChart"));

function Legend({ kinds }: { kinds: Set<string> }) {
  return (
    <ul aria-label="Legend" className="flex flex-wrap gap-x-4 gap-y-1 text-2xs text-muted">
      {KINDS.filter((kind) => kinds.has(kind)).map((kind) => (
        <li key={kind} className="inline-flex items-center gap-1.5">
          <svg viewBox="-1 -1 12 12" className="size-3" aria-hidden="true">
            <path d={KIND_STYLE[kind].path} style={{ fill: `var(${KIND_STYLE[kind].cssVar})` }} />
          </svg>
          {KIND_STYLE[kind].label}
        </li>
      ))}
      <li className="inline-flex items-center gap-1.5">
        <svg viewBox="-2 -2 14 14" className="size-3.5" aria-hidden="true">
          <circle cx="5" cy="5" r="5" className="fill-faint stroke-ink" strokeWidth="2" />
        </svg>
        Root cause (outlined)
      </li>
      <li className="inline-flex items-center gap-1.5">×12 = alike events close together</li>
    </ul>
  );
}

export function IncidentTimeline({
  timeline,
  onSelect,
  current = null,
}: {
  timeline: Timeline;
  onSelect: (event: TimelineEvent) => void;
  /** The log lines of the replay's current step: their markers are marked, the rest dimmed. */
  current?: ReadonlySet<number> | null;
}) {
  const full = useMemo(() => timelineRange(timeline), [timeline]);
  const [zoom, setZoom] = useState<TimeRange | null>(null);
  const range = zoom ?? full;
  const lanes = useMemo(() => laneNames(timeline), [timeline]);
  const clusters = useMemo(() => (range ? clusterEvents(timeline, range) : []), [timeline, range]);
  const kinds = useMemo(() => new Set(timeline.events.map((event) => event.kind)), [timeline]);

  if (!full || !range) {
    return <p className="px-4 py-4 text-sm text-muted">None of this incident&apos;s events has a time, so there is no timeline to draw.</p>;
  }
  const shown = clusters.reduce((sum, cluster) => sum + cluster.events.length, 0);
  return (
    <figure className="m-0">
      <div className="flex flex-wrap items-center justify-between gap-2 px-4 pt-3">
        <Legend kinds={kinds} />
        <div className="flex items-center gap-2">
          {zoom && (
            <span className="text-2xs text-muted">
              {utcSpan(new Date(zoom.start).toISOString(), new Date(zoom.end).toISOString())} ({formatDuration((zoom.end - zoom.start) / 1000)})
            </span>
          )}
          <Button className="px-2 py-1 text-xs" onClick={() => setZoom(null)} disabled={!zoom}>
            <ZoomOut aria-hidden="true" className="size-3.5" />
            Reset zoom
          </Button>
        </div>
      </div>
      <div role="img" aria-label={describeTimeline(timeline)} className="px-2">
        <Suspense fallback={<div style={{ height: laneHeight(lanes.length) }} className="animate-pulse rounded bg-raised" />}>
          <TimelineChart lanes={lanes} clusters={clusters} range={range} current={current} onZoom={setZoom} onSelect={onSelect} />
        </Suspense>
      </div>
      <figcaption className="px-4 pb-3 text-2xs text-faint">
        {plural(shown, "event")} in {plural(clusters.length, "marker")}
        {timeline.truncated && `; only the first ${timeline.events.length} of ${timeline.total_events} events are drawn`}.
        Hover a marker to read its log line; click it to find the line in the evidence.
      </figcaption>
    </figure>
  );
}
