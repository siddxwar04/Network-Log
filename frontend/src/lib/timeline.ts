// What the incident timeline shows, worked out without drawing anything: the look of each
// kind of event, events close together merged into one marker with a count, and the whole
// picture described in words for screen readers.

import type { EventKind, IncidentTimeline, TimelineEvent } from "../api/types";
import { formatDuration, plural, utcTime } from "./format";

/** Marker shapes as SVG paths in a 10 by 10 box. The chart and the legend draw the same
 * ones, so each kind is told apart by shape as well as color. */
export const KIND_STYLE: Record<EventKind, { label: string; path: string; cssVar: string }> = {
  link: { label: "Link", path: "M5 0a5 5 0 1 0 0.001 0Z", cssVar: "--kind-link" },
  ospf: { label: "OSPF", path: "M5 0L10 9.5H0Z", cssVar: "--kind-ospf" },
  bgp: { label: "BGP", path: "M5 0L10 5L5 10L0 5Z", cssVar: "--kind-bgp" },
  login: { label: "Login", path: "M0.5 0.5H9.5V9.5H0.5Z", cssVar: "--kind-login" },
  config: { label: "Config", path: "M3.5 0H6.5V3.5H10V6.5H6.5V10H3.5V6.5H0V3.5H3.5Z", cssVar: "--kind-config" },
  dhcp: { label: "DHCP", path: "M2.5 0.7H7.5L10 5L7.5 9.3H2.5L0 5Z", cssVar: "--kind-dhcp" },
  system: { label: "System", path: "M0 10L5 0L10 10L5 7Z", cssVar: "--kind-system" },
};

export const KINDS: EventKind[] = ["link", "ospf", "bgp", "login", "config", "dhcp", "system"];

// The visible time range is cut into this many slots; events of one kind on one device that
// fall within a slot of each other are drawn as one marker. Zooming in splits them apart.
export const CLUSTER_SLOTS = 90;

/** How tall the chart is: room for every lane. */
export function laneHeight(lanes: number): number {
  return Math.max(150, lanes * 42 + 72);
}

export interface Cluster {
  key: string;
  lane: number;
  kind: EventKind;
  start: number; // milliseconds since 1970, UTC
  end: number;
  root: boolean;
  events: TimelineEvent[];
}

export interface TimeRange {
  start: number;
  end: number;
}

export function timelineRange(timeline: IncidentTimeline): TimeRange | null {
  const times = timeline.events.filter((e) => e.time).map((e) => Date.parse(e.time!));
  if (!times.length) return null;
  const start = Math.min(...times);
  const end = Math.max(...times);
  return { start, end: end > start ? end : start + 1000 };
}

/** The markers to draw for the events inside a time range. Events of the same kind, on the
 * same device, and alike in being or not being the root cause, are merged while each is
 * within one slot of the first of its run. */
export function clusterEvents(timeline: IncidentTimeline, range: TimeRange, slots = CLUSTER_SLOTS): Cluster[] {
  const gap = (range.end - range.start) / slots;
  const lanes = new Map(timeline.lanes.map((lane, i) => [lane, i]));
  const runs = new Map<string, Cluster>();
  const clusters: Cluster[] = [];
  const sorted = timeline.events
    .filter((event) => event.time)
    .map((event) => ({ event, at: Date.parse(event.time!) }))
    .filter(({ at }) => at >= range.start && at <= range.end)
    .sort((a, b) => a.at - b.at || a.event.line - b.event.line);

  for (const { event, at } of sorted) {
    const lane = lanes.get(event.host ?? "") ?? lanes.size;
    const group = `${lane}|${event.kind}|${event.root_cause}`;
    const run = runs.get(group);
    if (run && at - run.start <= gap) {
      run.events.push(event);
      run.end = at;
      continue;
    }
    const cluster: Cluster = {
      key: `${group}|${event.line}`,
      lane,
      kind: event.kind,
      start: at,
      end: at,
      root: event.root_cause,
      events: [event],
    };
    runs.set(group, cluster);
    clusters.push(cluster);
  }
  return clusters;
}

/** The lanes to draw: the API's, plus one for events that name no device. */
export function laneNames(timeline: IncidentTimeline): string[] {
  const unnamed = timeline.events.some((event) => !event.host || !timeline.lanes.includes(event.host));
  return unnamed ? [...timeline.lanes, "(no device)"] : timeline.lanes;
}

/** The timeline in words, for screen readers: which device spoke first, about what, and
 * what followed on the others. */
export function describeTimeline(timeline: IncidentTimeline): string {
  const timed = timeline.events.filter((e) => e.time).sort((a, b) => Date.parse(a.time!) - Date.parse(b.time!));
  if (!timed.length) return "No timed events to show.";
  const first = timed[0];
  const last = timed[timed.length - 1];
  const span = (Date.parse(last.time!) - Date.parse(first.time!)) / 1000;
  const parts = [
    `${plural(timed.length, "event")} on ${plural(timeline.lanes.length, "device")} over ${formatDuration(span)}.`,
    `First: a ${KIND_STYLE[first.kind].label} event on ${first.host ?? "an unnamed device"} at ${utcTime(first.time!)} UTC${first.root_cause ? ", part of the root cause" : ""}.`,
  ];
  for (const lane of timeline.lanes) {
    const own = timed.filter((e) => e.host === lane);
    if (!own.length) continue;
    const kinds = [...new Set(own.map((e) => KIND_STYLE[e.kind].label))].join(", ");
    parts.push(`${lane}: ${plural(own.length, "event")} (${kinds}) from ${utcTime(own[0].time!)} UTC.`);
  }
  if (timeline.truncated) parts.push(`Only the first ${timeline.events.length} of ${timeline.total_events} events are shown.`);
  return parts.join(" ");
}
