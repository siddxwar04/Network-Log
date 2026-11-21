// The severity colors, defined once and used everywhere. A color never stands alone: each
// level also has its own icon shape and its name, for readers who cannot tell the colors
// apart and for screen readers. The colors themselves are tokens in index.css.

import {
  CircleAlert,
  CircleDot,
  Info,
  OctagonAlert,
  TriangleAlert,
  type LucideIcon,
} from "lucide-react";
import type { Level, SeverityCounts as Counts } from "../api/types";
import { LEVELS } from "../api/types";

interface LevelStyle {
  label: string;
  icon: LucideIcon;
  // A filled badge with readable contrast in both themes.
  badge: string;
  // The color alone, for an icon, a bar or a left edge.
  text: string;
  bar: string;
  edge: string;
  // A tinted surface with a colored border, for the one thing on a screen that matters most.
  wash: string;
  // The name of the CSS variable holding the solid color, for charts.
  cssVar: string;
}

export const SEVERITY: Record<Level, LevelStyle> = {
  critical: {
    label: "Critical",
    icon: OctagonAlert,
    badge: "bg-sev-critical-bg text-sev-critical-fg ring-sev-critical/45",
    text: "text-sev-critical",
    bar: "bg-sev-critical",
    edge: "border-l-sev-critical",
    wash: "border-sev-critical/50 bg-sev-critical-bg",
    cssVar: "--sev-critical",
  },
  high: {
    label: "High",
    icon: TriangleAlert,
    badge: "bg-sev-high-bg text-sev-high-fg ring-sev-high/45",
    text: "text-sev-high",
    bar: "bg-sev-high",
    edge: "border-l-sev-high",
    wash: "border-sev-high/50 bg-sev-high-bg",
    cssVar: "--sev-high",
  },
  medium: {
    label: "Medium",
    icon: CircleAlert,
    badge: "bg-sev-medium-bg text-sev-medium-fg ring-sev-medium/45",
    text: "text-sev-medium",
    bar: "bg-sev-medium",
    edge: "border-l-sev-medium",
    wash: "border-sev-medium/50 bg-sev-medium-bg",
    cssVar: "--sev-medium",
  },
  low: {
    label: "Low",
    icon: CircleDot,
    badge: "bg-sev-low-bg text-sev-low-fg ring-sev-low/45",
    text: "text-sev-low",
    bar: "bg-sev-low",
    edge: "border-l-sev-low",
    wash: "border-sev-low/50 bg-sev-low-bg",
    cssVar: "--sev-low",
  },
  info: {
    label: "Info",
    icon: Info,
    badge: "bg-sev-info-bg text-sev-info-fg ring-sev-info/45",
    text: "text-sev-info",
    bar: "bg-sev-info",
    edge: "border-l-sev-info",
    wash: "border-sev-info/50 bg-sev-info-bg",
    cssVar: "--sev-info",
  },
};

export function SeverityIcon({ level, className = "size-4" }: { level: Level; className?: string }) {
  const Icon = SEVERITY[level].icon;
  return <Icon aria-hidden="true" className={`${SEVERITY[level].text} shrink-0 ${className}`} />;
}

export function SeverityBadge({ level, count }: { level: Level; count?: number }) {
  const style = SEVERITY[level];
  const Icon = style.icon;
  return (
    <span
      className={`inline-flex items-center gap-1 rounded-sm px-1.5 py-0.5 text-xs font-medium ring-1 ring-inset ${style.badge}`}
    >
      <Icon aria-hidden="true" className="size-3.5 shrink-0" />
      {count !== undefined && <span className="tabular-nums">{count}</span>}
      <span>{style.label}</span>
    </span>
  );
}

/** One small badge per severity that has incidents, most severe first. */
export function SeverityCounts({ counts }: { counts: Counts }) {
  const present = LEVELS.filter((level) => (counts[level] ?? 0) > 0);
  if (present.length === 0) {
    return <span className="text-sm text-muted">None</span>;
  }
  return (
    <span className="flex flex-wrap gap-1">
      {present.map((level) => (
        <SeverityBadge key={level} level={level} count={counts[level]} />
      ))}
    </span>
  );
}

/** The solid color of a level as the current theme draws it, for a chart. */
export function severityColor(level: Level): string {
  if (typeof document === "undefined") return "#888";
  const value = getComputedStyle(document.documentElement).getPropertyValue(SEVERITY[level].cssVar);
  return value.trim() || "#888";
}
