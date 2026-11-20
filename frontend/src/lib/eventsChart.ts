// What the events-over-time chart shows, worked out without drawing anything, so it can be
// tested on its own and described in words for screen readers.

import type { IncidentPeriod, Level, UploadSummary } from "../api/types";
import { formatDuration, formatNumber, utcSpan, utcTime } from "./format";

export interface Bar {
  start: number; // milliseconds since 1970, UTC
  count: number;
}

export interface Band {
  id: string;
  headline: string;
  severity: Level;
  start: number;
  // At least one bar wide, so an incident of a few seconds can still be seen and clicked.
  end: number;
}

export interface EventsSeries {
  bucketSeconds: number;
  bars: Bar[];
  bands: Band[];
  busiest: Bar | null;
  total: number;
}

/** Every bucket from the first to the last, including the empty ones the API leaves out,
 * so the time axis is even. */
export function eventsSeries(
  over: UploadSummary["events_over_time"],
  periods: IncidentPeriod[],
): EventsSeries {
  const size = (over.bucket_seconds ?? 60) * 1000;
  const counts = new Map(over.buckets.map((b) => [Date.parse(b.start), b.count]));
  const bars: Bar[] = [];
  if (over.buckets.length > 0) {
    const first = Date.parse(over.buckets[0].start);
    const last = Date.parse(over.buckets[over.buckets.length - 1].start);
    for (let t = first; t <= last; t += size) bars.push({ start: t, count: counts.get(t) ?? 0 });
  }
  const bands = periods.map((period) => {
    const start = Date.parse(period.start);
    const end = Math.max(Date.parse(period.end), start + size);
    return { id: period.id, headline: period.headline, severity: period.severity, start, end };
  });
  const busiest = bars.reduce<Bar | null>((top, bar) => (!top || bar.count > top.count ? bar : top), null);
  const total = bars.reduce((sum, bar) => sum + bar.count, 0);
  return { bucketSeconds: size / 1000, bars, bands, busiest, total };
}

export function bucketLabel(seconds: number): string {
  return formatDuration(seconds).replace(/^(\d+)m$/, "$1 min").replace(/^(\d+)s$/, "$1 s").replace(/^(\d+)h$/, "$1 h");
}

/** The chart in words: its span, its busiest moment, and where each incident sits. */
export function describeEvents(series: EventsSeries): string {
  if (series.bars.length === 0) return "No events with a time to chart.";
  const first = new Date(series.bars[0].start).toISOString();
  const last = new Date(series.bars[series.bars.length - 1].start + series.bucketSeconds * 1000).toISOString();
  const parts = [
    `Events over time from ${utcSpan(first, last)}, ${formatNumber(series.total)} events in bars of ${bucketLabel(series.bucketSeconds)}.`,
  ];
  if (series.busiest) {
    parts.push(
      `Busiest: ${formatNumber(series.busiest.count)} events at ${utcTime(new Date(series.busiest.start).toISOString())} UTC.`,
    );
  }
  if (series.bands.length === 0) {
    parts.push("No incident periods.");
  } else {
    for (const band of series.bands) {
      parts.push(
        `${band.severity} incident from ${utcTime(new Date(band.start).toISOString())} UTC: ${band.headline}.`,
      );
    }
  }
  return parts.join(" ");
}
