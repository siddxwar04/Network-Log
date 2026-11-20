// The live view: messages arriving from devices, and incidents opening, growing and
// closing as they happen. It asks the API every two seconds; nothing needs a reload.

import { Activity, Radio, RadioTower } from "lucide-react";
import { useLive } from "../api/queries";
import type { LiveIncident, LiveStatus } from "../api/types";
import { IncidentCard } from "../components/IncidentCard";
import { Code, EmptyState, ErrorState, PageHeader, Panel, SkeletonRows } from "../components/ui";
import { formatNumber, formatLocalTime, plural } from "../lib/format";

const DROPPED: { key: keyof LiveStatus["counters"]; label: string }[] = [
  { key: "malformed", label: "not syslog" },
  { key: "not_text", label: "not text" },
  { key: "oversized", label: "too long" },
  { key: "rate_limited", label: "over a sender's rate" },
  { key: "refused", label: "from an address not allowed" },
  { key: "dropped", label: "dropped in a burst" },
];

function Tile({ label, value, note }: { label: string; value: string; note?: string }) {
  return (
    <div className="rounded-lg border border-line bg-panel p-4 shadow-panel">
      <dt className="eyebrow">{label}</dt>
      <dd className="mt-1 text-2xl font-semibold text-ink tabular-nums">{value}</dd>
      {note && <dd className="mt-0.5 text-xs text-muted">{note}</dd>}
    </div>
  );
}

function Off() {
  return (
    <Panel>
      <EmptyState title="The live listener is off" icon={<RadioTower aria-hidden="true" className="mb-2 size-8 text-faint" />}>
        <p>
          Start the API with it switched on, in PowerShell: <Code>$env:NETLOG_LIVE = "1"</Code>, then{" "}
          <Code>.venv\Scripts\python -m uvicorn netlog.api.app:app</Code>. Or set <Code>enabled = true</Code> under{" "}
          <Code>[live]</Code> in your settings.
        </p>
        <p className="mt-2">
          Then send it a sample, sped up 60 times: <Code>.venv\Scripts\netlog replay data\scenarios\02_cascade.log --speed 60 --start 02:44</Code>
        </p>
      </EmptyState>
    </Panel>
  );
}

function IncidentList({ uploadId, items, empty }: { uploadId: number; items: LiveIncident[]; empty: string }) {
  if (!items.length) return <p className="px-4 py-6 text-sm text-muted">{empty}</p>;
  return (
    <ul className="grid gap-3 p-4 md:grid-cols-2">
      {items.map((incident) => (
        <li key={incident.id}>
          <p className="mb-1 text-2xs text-faint">
            {incident.state === "open"
              ? `Open since ${formatLocalTime(incident.opened_at)}, last change ${formatLocalTime(incident.changed_at)}`
              : `Closed ${incident.closed_at ? formatLocalTime(incident.closed_at) : ""}`}
          </p>
          <IncidentCard uploadId={uploadId} incident={incident} />
        </li>
      ))}
    </ul>
  );
}

export default function LivePage() {
  const live = useLive();
  const crumbs = [{ label: "Live" }];
  if (live.error) {
    return (
      <div>
        <PageHeader crumbs={crumbs} title="Live" />
        <Panel>
          <ErrorState error={live.error} onRetry={() => live.refetch()} />
        </Panel>
      </div>
    );
  }
  if (!live.data) {
    return (
      <div>
        <PageHeader crumbs={crumbs} title="Live" />
        <Panel>
          <SkeletonRows rows={4} />
        </Panel>
      </div>
    );
  }
  if (!live.data.enabled) {
    return (
      <div>
        <PageHeader crumbs={crumbs} title="Live" />
        <Off />
      </div>
    );
  }
  const status = live.data;
  const counters = status.counters;
  const discarded = DROPPED.filter(({ key }) => counters[key] > 0);
  return (
    <div>
      <PageHeader
        crumbs={crumbs}
        title="Live"
        meta={
          <span className="inline-flex flex-wrap items-center gap-2">
            <span className="inline-flex items-center gap-1.5 text-ok">
              <Radio aria-hidden="true" className="size-4 animate-pulse" />
              Listening
            </span>
            {Object.entries(status.listening).map(([protocol, address]) => (
              <span key={protocol} className="font-mono text-xs">
                {protocol.toUpperCase()} {address}
              </span>
            ))}
          </span>
        }
      />

      <dl className="mb-4 grid grid-cols-2 gap-3 lg:grid-cols-4">
        <Tile label="Messages per minute" value={formatNumber(status.per_minute)} />
        <Tile label="Senders" value={formatNumber(status.senders.length)} />
        <Tile label="Open incidents" value={formatNumber(status.open_incidents.length)} />
        <Tile
          label="Stored"
          value={formatNumber(counters.stored)}
          note={`of ${plural(counters.received, "message")} received`}
        />
      </dl>

      {(discarded.length > 0 || status.warnings.length > 0) && (
        <Panel title="Not stored" className="mb-4">
          <ul className="space-y-1 px-4 py-3 text-sm text-ink">
            {discarded.map(({ key, label }) => (
              <li key={key}>
                <span className="font-medium tabular-nums">{formatNumber(counters[key])}</span> {label}
              </li>
            ))}
            {status.warnings.map((warning) => (
              <li key={warning} className="text-warn">
                {warning}
              </li>
            ))}
          </ul>
        </Panel>
      )}

      <Panel title="Open incidents" className="mb-4">
        <IncidentList
          uploadId={status.upload_id}
          items={status.open_incidents}
          empty="Nothing open. An incident appears here as soon as the rules find one."
        />
      </Panel>

      <div className="grid gap-4 lg:grid-cols-[minmax(0,2fr)_minmax(0,1fr)]">
        <Panel title="Recently closed">
          <IncidentList uploadId={status.upload_id} items={status.closed_incidents} empty="None yet." />
        </Panel>
        <Panel title="Senders">
          {status.senders.length ? (
            <table className="w-full text-sm">
              <caption className="sr-only">Devices that sent messages</caption>
              <thead>
                <tr className="text-left text-2xs text-faint uppercase">
                  <th className="px-4 py-2 font-medium">Address</th>
                  <th className="px-4 py-2 text-right font-medium">Messages</th>
                  <th className="px-4 py-2 text-right font-medium">Not stored</th>
                </tr>
              </thead>
              <tbody>
                {status.senders.map((sender) => (
                  <tr key={sender.address} className="border-t border-line">
                    <td className="px-4 py-2 font-mono text-xs">{sender.address}</td>
                    <td className="px-4 py-2 text-right tabular-nums">{formatNumber(sender.messages)}</td>
                    <td className="px-4 py-2 text-right tabular-nums">{formatNumber(sender.discarded)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <p className="flex items-center gap-2 px-4 py-6 text-sm text-muted">
              <Activity aria-hidden="true" className="size-4" /> No messages yet.
            </p>
          )}
        </Panel>
      </div>
    </div>
  );
}
