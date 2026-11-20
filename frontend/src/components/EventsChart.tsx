// The events-over-time chart: a bar per time bucket, each incident's period as a band in
// its severity color. Hovering a bar shows its count; clicking a band opens that incident.
// Loaded only with the dashboard, so ECharts is not part of the first download.

import { BarChart } from "echarts/charts";
import {
  AriaComponent,
  GridComponent,
  MarkAreaComponent,
  TooltipComponent,
} from "echarts/components";
import * as echarts from "echarts/core";
import { SVGRenderer } from "echarts/renderers";
import { useEffect, useRef } from "react";
import { useApp } from "../lib/app-state";
import { bucketLabel, type EventsSeries } from "../lib/eventsChart";
import { formatNumber, utcTime } from "../lib/format";
import { SEVERITY, severityColor } from "../lib/severity";

echarts.use([BarChart, GridComponent, TooltipComponent, MarkAreaComponent, AriaComponent, SVGRenderer]);

function token(name: string): string {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
}

function withAlpha(color: string, alpha: number): string {
  const hex = color.replace("#", "");
  if (hex.length !== 6) return color;
  const [r, g, b] = [0, 2, 4].map((i) => parseInt(hex.slice(i, i + 2), 16));
  return `rgba(${r}, ${g}, ${b}, ${alpha})`;
}

function escape(text: string): string {
  // Tooltips are HTML; an incident headline can hold text from a log line.
  return text.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
}

export default function EventsChart({
  series,
  onOpenIncident,
}: {
  series: EventsSeries;
  onOpenIncident: (id: string) => void;
}) {
  const box = useRef<HTMLDivElement>(null);
  const { theme } = useApp();
  const open = useRef(onOpenIncident);
  open.current = onOpenIncident;

  useEffect(() => {
    const element = box.current;
    if (!element) return;
    const chart = echarts.init(element, undefined, { renderer: "svg" });
    const ink = token("--ink");
    const muted = token("--muted");
    const faint = token("--faint");
    const line = token("--line");
    const panel = token("--raised");
    const size = series.bucketSeconds * 1000;
    const multiDay = series.bars.length > 0 && series.bars[series.bars.length - 1].start - series.bars[0].start > 86_400_000;

    chart.setOption({
      useUTC: true,
      animationDuration: 300,
      aria: { enabled: true },
      grid: { left: 56, right: 16, top: 28, bottom: 44 },
      tooltip: {
        trigger: "axis",
        axisPointer: { type: "shadow" },
        backgroundColor: panel,
        borderColor: line,
        textStyle: { color: ink, fontSize: 12 },
        formatter: (params: { value: [number, number] }[]) => {
          const [at, count] = params[0].value;
          const inside = series.bands.filter((band) => band.start < at + size && band.end > at);
          const from = utcTime(new Date(at).toISOString());
          const to = utcTime(new Date(at + size).toISOString());
          const rows = inside
            .map((band) => `<div style="margin-top:4px">${SEVERITY[band.severity].label}: ${escape(band.headline)}</div>`)
            .join("");
          return `<b>${formatNumber(count)} events</b><br/>${from} to ${to} UTC${rows}`;
        },
      },
      xAxis: {
        type: "time",
        name: "Time (UTC)",
        nameLocation: "middle",
        nameGap: 28,
        nameTextStyle: { color: muted, fontSize: 11 },
        axisLine: { lineStyle: { color: line } },
        axisTick: { show: false },
        axisLabel: {
          color: faint,
          fontSize: 11,
          hideOverlap: true,
          formatter: multiDay ? "{d} {MMM} {HH}:{mm}" : "{HH}:{mm}",
        },
        splitLine: { show: false },
      },
      yAxis: {
        type: "value",
        name: `Events per ${bucketLabel(series.bucketSeconds)}`,
        nameTextStyle: { color: muted, fontSize: 11, align: "left" },
        axisLabel: { color: faint, fontSize: 11 },
        splitLine: { lineStyle: { color: line, type: "dashed" } },
      },
      series: [
        {
          type: "bar",
          name: "Events",
          barWidth: "70%",
          data: series.bars.map((bar) => [bar.start + size / 2, bar.count]),
          itemStyle: { color: withAlpha(faint.startsWith("#") ? faint : "#7d8899", 0.75), borderRadius: [2, 2, 0, 0] },
          emphasis: { itemStyle: { color: token("--accent") } },
          markArea: {
            silent: false,
            label: { show: false },
            emphasis: { label: { show: false } },
            data: series.bands.map((band) => {
              const color = severityColor(band.severity);
              return [
                {
                  name: band.headline,
                  xAxis: band.start,
                  itemStyle: { color: withAlpha(color, 0.18), borderColor: color, borderWidth: 1 },
                },
                { xAxis: band.end },
              ];
            }),
          },
        },
      ],
    });
    chart.on("click", (params: { componentType?: string; dataIndex?: number }) => {
      if (params.componentType === "markArea" && params.dataIndex !== undefined) {
        const band = series.bands[params.dataIndex];
        if (band) open.current(band.id);
      }
    });

    const observer = typeof ResizeObserver === "undefined" ? null : new ResizeObserver(() => chart.resize());
    observer?.observe(element);
    return () => {
      observer?.disconnect();
      chart.dispose();
    };
  }, [series, theme]);

  return <div ref={box} className="h-64 w-full" aria-hidden="true" />;
}
