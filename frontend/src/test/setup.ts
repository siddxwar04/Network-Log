import "@testing-library/jest-dom/vitest";
import { cleanup, configure } from "@testing-library/react";
import { createElement } from "react";
import { afterEach, vi } from "vitest";
import type { TimelineChartProps } from "../components/TimelineChart";
import type { EventsSeries } from "../lib/eventsChart";
import { clusterOfFindings } from "../lib/timeline";

// jsdom cannot lay out or draw a chart. The chart is replaced by a stand-in with one button
// per incident band, so tests can still click a band. What the chart shows is tested on its
// own, in eventsChart.test.ts.
vi.mock("../components/EventsChart", () => ({
  default: ({ series, onOpenIncident }: { series: EventsSeries; onOpenIncident: (id: string) => void }) =>
    createElement(
      "div",
      { "data-testid": "events-chart", "data-bars": series.bars.length },
      series.bands.map((band) =>
        createElement("button", { key: band.id, type: "button", onClick: () => onOpenIncident(band.id) }, `Band: ${band.headline}`),
      ),
    ),
}));

// The incident timeline likewise: one button per marker, and one that zooms into the first
// half of the range as a drag across the chart would. Clustering is tested on its own.
vi.mock("../components/TimelineChart", () => ({
  default: ({ lanes, clusters, range, current, onZoom, onSelect }: TimelineChartProps) =>
    createElement(
      "div",
      { "data-testid": "timeline-chart", "data-lanes": lanes.join(","), "data-markers": clusters.length },
      createElement(
        "button",
        { type: "button", onClick: () => onZoom({ start: range.start, end: range.start + (range.end - range.start) / 2 }) },
        "Drag to zoom",
      ),
      clusters.map((cluster) =>
        createElement(
          "button",
          {
            key: cluster.key,
            type: "button",
            "data-current": current && clusterOfFindings(cluster, current) ? "true" : undefined,
            onClick: () => onSelect(cluster.events[0]),
          },
          `Marker: ${cluster.kind} on ${lanes[cluster.lane]} x${cluster.events.length}`,
        ),
      ),
    ),
}));

// Screens load lazily; on a busy machine the first render can take more than a second.
configure({ asyncUtilTimeout: 4000 });

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  vi.useRealTimers();
  localStorage.clear();
  document.documentElement.className = "dark";
});
