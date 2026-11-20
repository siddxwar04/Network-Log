// The incident timeline drawn with ECharts: one lane per device, a marker per event (or per
// run of alike events, with a count), colored and shaped by kind. Dragging across it picks
// a time range to zoom into. Loaded only with the incident page.

import { ScatterChart } from "echarts/charts";
import { BrushComponent, GridComponent, MarkLineComponent, TooltipComponent } from "echarts/components";
import * as echarts from "echarts/core";
import { SVGRenderer } from "echarts/renderers";
import { useEffect, useRef } from "react";
import type { TimelineEvent } from "../api/types";
import { useApp } from "../lib/app-state";
import { formatNumber, utcTime } from "../lib/format";
import { KIND_STYLE, KINDS, laneHeight, type Cluster, type TimeRange } from "../lib/timeline";

echarts.use([ScatterChart, GridComponent, TooltipComponent, MarkLineComponent, BrushComponent, SVGRenderer]);

export interface TimelineChartProps {
  lanes: string[];
  clusters: Cluster[];
  range: TimeRange;
  onZoom: (range: TimeRange) => void;
  onSelect: (event: TimelineEvent) => void;
}

function token(name: string): string {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
}

function escape(text: string): string {
  // Tooltips are HTML, and a log line is untrusted text.
  return text.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
}

function iso(ms: number): string {
  return new Date(ms).toISOString();
}

export default function TimelineChart({ lanes, clusters, range, onZoom, onSelect }: TimelineChartProps) {
  const box = useRef<HTMLDivElement>(null);
  const { theme } = useApp();
  const handlers = useRef({ onZoom, onSelect });
  handlers.current = { onZoom, onSelect };

  useEffect(() => {
    const element = box.current;
    if (!element) return;
    const chart = echarts.init(element, undefined, { renderer: "svg" });
    const ink = token("--ink");
    const muted = token("--muted");
    const faint = token("--faint");
    const line = token("--line");
    const raised = token("--raised");
    const accent = token("--accent");
    const roots = clusters.filter((cluster) => cluster.root);
    const firstRoot = roots.length ? Math.min(...roots.map((cluster) => cluster.start)) : null;
    // A little room at each end, so the first and last markers clear the axes.
    const margin = Math.max(500, (range.end - range.start) * 0.03);

    const series = KINDS.map((kind) => ({
      type: "scatter" as const,
      name: KIND_STYLE[kind].label,
      symbol: `path://${KIND_STYLE[kind].path}`,
      data: clusters
        .map((cluster, index) => ({ cluster, index }))
        .filter(({ cluster }) => cluster.kind === kind)
        .map(({ cluster, index }) => {
          const count = cluster.events.length;
          const size = (count > 1 ? 13 + Math.min(9, Math.log2(count) * 2) : 11) + (cluster.root ? 3 : 0);
          return {
            value: [cluster.start, cluster.lane, count, index],
            symbolSize: size,
            itemStyle: {
              color: token(KIND_STYLE[kind].cssVar),
              borderColor: cluster.root ? ink : "transparent",
              borderWidth: cluster.root ? 2 : 0,
            },
            label: {
              show: count > 1,
              position: "right" as const,
              distance: 3,
              formatter: `×${formatNumber(count)}`,
              color: muted,
              fontSize: 10,
            },
          };
        }),
      emphasis: { scale: 1.3 },
      ...(kind === KINDS[0] && firstRoot !== null
        ? {
            markLine: {
              silent: true,
              symbol: "none",
              data: [{ xAxis: firstRoot }],
              lineStyle: { color: ink, type: "dashed" as const, width: 1 },
              label: { formatter: "Root cause", color: ink, fontSize: 10, position: "start" as const },
            },
          }
        : {}),
    }));

    chart.setOption({
      useUTC: true,
      animation: false,
      grid: { left: 88, right: 40, top: 30, bottom: 40 },
      brush: {
        xAxisIndex: 0,
        brushType: "lineX",
        brushMode: "single",
        transformable: false,
        throttleType: "debounce",
        brushStyle: { color: "rgba(106, 160, 255, 0.15)", borderColor: accent, borderWidth: 1 },
        outOfBrush: { colorAlpha: 1 },
      },
      tooltip: {
        trigger: "item",
        backgroundColor: raised,
        borderColor: line,
        textStyle: { color: ink, fontSize: 12 },
        extraCssText: "max-width: 420px; white-space: normal;",
        formatter: (params: { value: [number, number, number, number] }) => {
          const cluster = clusters[params.value[3]];
          if (!cluster) return "";
          const first = cluster.events[0];
          const head = `${KIND_STYLE[cluster.kind].label} on ${escape(lanes[cluster.lane] ?? "")}${cluster.root ? " · root cause" : ""}`;
          const when =
            cluster.events.length > 1
              ? `${formatNumber(cluster.events.length)} events, ${utcTime(iso(cluster.start))} to ${utcTime(iso(cluster.end))} UTC. The first:`
              : `${utcTime(iso(cluster.start))} UTC`;
          return `<b>${head}</b><br/>${when}<div style="margin-top:4px;font-family:var(--font-mono);font-size:11px;word-break:break-all">Line ${first.line}: ${escape(first.text)}</div>`;
        },
      },
      xAxis: {
        type: "time",
        min: range.start - margin,
        max: range.end + margin,
        name: "Time (UTC). Drag across the chart to zoom in.",
        nameLocation: "middle",
        nameGap: 26,
        nameTextStyle: { color: muted, fontSize: 11 },
        axisLine: { lineStyle: { color: line } },
        axisLabel: { color: faint, fontSize: 11, hideOverlap: true, formatter: "{HH}:{mm}:{ss}" },
        splitLine: { show: true, lineStyle: { color: line, type: "dashed" } },
      },
      yAxis: {
        type: "category",
        data: lanes,
        inverse: true, // the first lane, the root-cause device, at the top
        axisLine: { lineStyle: { color: line } },
        axisTick: { show: false },
        axisLabel: { color: ink, fontSize: 11, fontFamily: token("--font-mono") || "monospace" },
        splitLine: { show: true, lineStyle: { color: line } },
      },
      series,
    });

    chart.dispatchAction({ type: "takeGlobalCursor", key: "brush", brushOption: { brushType: "lineX", brushMode: "single" } });
    chart.on("brushEnd", (params: unknown) => {
      const picked = (params as { areas?: { coordRange?: [number, number] }[] }).areas?.[0]?.coordRange;
      chart.dispatchAction({ type: "brush", areas: [] });
      if (picked && picked[1] - picked[0] >= 1) {
        handlers.current.onZoom({ start: Math.floor(picked[0]), end: Math.ceil(picked[1]) });
      }
    });
    chart.on("click", (params) => {
      const value = params.value as [number, number, number, number] | undefined;
      const cluster = value ? clusters[value[3]] : undefined;
      if (cluster) handlers.current.onSelect(cluster.events[0]);
    });

    const observer = typeof ResizeObserver === "undefined" ? null : new ResizeObserver(() => chart.resize());
    observer?.observe(element);
    return () => {
      observer?.disconnect();
      chart.dispose();
    };
  }, [lanes, clusters, range, theme]);

  return <div ref={box} style={{ height: laneHeight(lanes.length) }} className="w-full" aria-hidden="true" />;
}
