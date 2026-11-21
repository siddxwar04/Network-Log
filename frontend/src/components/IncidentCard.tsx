// One incident as a card: how serious, what happened, the likely cause, where and how long.

import { ChevronRight, Clock, HelpCircle, Server } from "lucide-react";
import { Link } from "react-router";
import type { IncidentSummary } from "../api/types";
import { formatDuration, utcTime } from "../lib/format";
import { SEVERITY, SeverityBadge } from "../lib/severity";

const CONFIDENCE: Record<IncidentSummary["confidence"], string> = {
  high: "High confidence",
  medium: "Medium confidence",
  low: "Low confidence",
};

export function IncidentCard({ uploadId, incident }: { uploadId: string | number; incident: IncidentSummary }) {
  const root = incident.root_cause;
  // A configuration change can be pointed at, never proven.
  const causeLabel = root?.kind === "config_change" ? "Suspect" : "Likely cause";
  return (
    <Link
      to={`/uploads/${uploadId}/incidents/${encodeURIComponent(incident.id)}`}
      className={`group block rounded-lg border border-l-4 border-line bg-panel p-4 shadow-panel transition-colors hover:border-line-strong hover:bg-raised/40 ${SEVERITY[incident.severity].edge}`}
    >
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <SeverityBadge level={incident.severity} />
            {incident.confidence === "low" ? (
              // The cause is a weak reading: said with an icon and a word, not left as faint text.
              <span className="inline-flex items-center gap-1 text-xs font-medium text-warn">
                <HelpCircle aria-hidden="true" className="size-3.5" />
                {CONFIDENCE.low}, cause uncertain
              </span>
            ) : (
              <span className="text-xs text-faint">{CONFIDENCE[incident.confidence]}</span>
            )}
          </div>
          <h3 className="mt-2 font-medium text-ink group-hover:text-accent">{incident.headline}</h3>
        </div>
        <ChevronRight aria-hidden="true" className="mt-1 size-4 shrink-0 text-faint group-hover:text-accent" />
      </div>
      {root && (
        <p className="mt-2 text-sm text-muted">
          <span className="text-faint">{causeLabel}: </span>
          {root.summary}
        </p>
      )}
      <div className="mt-3 flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-muted">
        <span className="inline-flex items-center gap-1">
          <Server aria-hidden="true" className="size-3.5 text-faint" />
          <span className="sr-only">Devices: </span>
          <span className="font-mono">{incident.devices.join(", ")}</span>
        </span>
        <span className="inline-flex items-center gap-1">
          <Clock aria-hidden="true" className="size-3.5 text-faint" />
          <span className="tabular-nums">{utcTime(incident.start)} UTC</span>
          <span className="text-faint">for {formatDuration(incident.duration_seconds)}</span>
        </span>
        <span className="text-faint">
          {incident.findings} {incident.findings === 1 ? "finding" : "findings"}
        </span>
      </div>
    </Link>
  );
}
