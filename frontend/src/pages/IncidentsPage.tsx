// Every incident of one upload, as cards, sorted the way the reader asks.

import { ShieldCheck } from "lucide-react";
import { useMemo, useState } from "react";
import { Navigate, useParams } from "react-router";
import { useIncidents, useUpload } from "../api/queries";
import { LEVELS } from "../api/types";
import { IncidentCard } from "../components/IncidentCard";
import { EmptyState, ErrorState, PageHeader, Panel, SkeletonRows } from "../components/ui";

type Order = "severity" | "time";

export default function IncidentsPage() {
  const { id = "" } = useParams();
  const upload = useUpload(id);
  const done = upload.data?.status === "done";
  const incidents = useIncidents(id, done);
  const [order, setOrder] = useState<Order>("severity");

  const sorted = useMemo(() => {
    const items = [...(incidents.data?.items ?? [])];
    return order === "time"
      ? items.sort((a, b) => a.start.localeCompare(b.start))
      : items.sort((a, b) => LEVELS.indexOf(a.severity) - LEVELS.indexOf(b.severity) || a.start.localeCompare(b.start));
  }, [incidents.data, order]);

  const error = upload.error ?? incidents.error;
  if (error) {
    return (
      <Panel>
        <ErrorState error={error} onRetry={() => [upload, incidents].forEach((q) => q.refetch())} />
      </Panel>
    );
  }
  if (upload.data && !done) return <Navigate to={`/uploads/${id}/processing`} replace />;

  const name = upload.data?.filename ?? `Upload ${id}`;
  return (
    <div>
      <PageHeader
        crumbs={[{ label: "Uploads", to: "/" }, { label: name, to: `/uploads/${id}` }, { label: "Incidents" }]}
        title="Incidents"
        meta={incidents.data && `${incidents.data.total} in ${name}`}
        actions={
          <div role="group" aria-label="Sort by" className="inline-flex rounded-md border border-line-strong p-0.5">
            {(["severity", "time"] as Order[]).map((value) => (
              <button
                key={value}
                type="button"
                aria-pressed={order === value}
                onClick={() => setOrder(value)}
                className={`rounded px-2.5 py-1 text-sm ${order === value ? "bg-raised text-ink" : "text-muted hover:text-ink"}`}
              >
                {value === "severity" ? "Most severe" : "Earliest"}
              </button>
            ))}
          </div>
        }
      />
      {!incidents.data ? (
        <Panel>
          <SkeletonRows rows={5} />
        </Panel>
      ) : sorted.length === 0 ? (
        <Panel>
          <EmptyState title="No incidents found in this log." icon={<ShieldCheck aria-hidden="true" className="mb-2 size-8 text-ok" />} />
        </Panel>
      ) : (
        <ul className="grid gap-3 lg:grid-cols-2">
          {sorted.map((incident) => (
            <li key={incident.id}>
              <IncidentCard uploadId={id} incident={incident} />
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
