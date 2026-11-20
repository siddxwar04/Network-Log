import "@testing-library/jest-dom/vitest";
import { cleanup } from "@testing-library/react";
import { createElement } from "react";
import { afterEach, vi } from "vitest";
import type { EventsSeries } from "../lib/eventsChart";

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

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  vi.useRealTimers();
  localStorage.clear();
  document.documentElement.className = "dark";
});
