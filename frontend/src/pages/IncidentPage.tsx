// One incident. For now the facts the rules decided; the explanation beside its evidence,
// with clickable citations, is the next step (prompt 4.4).

import { Link, useParams } from "react-router";
import { useIncidents, useUpload } from "../api/queries";
import { ErrorState, PageHeader, Panel, SkeletonRows } from "../components/ui";
import { formatDuration, utcSpan } from "../lib/format";
import { SeverityBadge } from "../lib/severity";

export default function IncidentPage() {
  const { id = "", incidentId = "" } = useParams();
  const upload = useUpload(id);
  const incidents = useIncidents(id, upload.data?.status === "done");
  const incident = incidents.data?.items.find((item) => item.id === incidentId);

  const error = upload.error ?? incidents.error;
  if (error) {
    return (
      <Panel>
        <ErrorState error={error} onRetry={() => [upload, incidents].forEach((q) => q.refetch())} />
      </Panel>
    );
  }
  const name = upload.data?.filename ?? `Upload ${id}`;
  const crumbs = [
    { label: "Uploads", to: "/" },
    { label: name, to: `/uploads/${id}` },
    { label: "Incidents", to: `/uploads/${id}/incidents` },
    { label: incidentId },
  ];
  if (!incidents.data) {
    return (
      <div>
        <PageHeader crumbs={crumbs} title="Incident" />
        <Panel>
          <SkeletonRows rows={5} />
        </Panel>
      </div>
    );
  }
  if (!incident) {
    return (
      <div>
        <PageHeader crumbs={crumbs} title="Incident not found" />
        <Panel>
          <div className="space-y-2 p-5 text-sm">
            <p role="alert" className="text-ink">
              {name} has no incident with the id <span className="font-mono">{incidentId}</span>.
            </p>
            <Link to={`/uploads/${id}/incidents`} className="text-accent hover:underline">
              See the incidents it does have
            </Link>
          </div>
        </Panel>
      </div>
    );
  }
  const root = incident.root_cause;
  return (
    <div>
      <PageHeader
        crumbs={crumbs}
        title={incident.headline}
        meta={
          <span className="flex flex-wrap items-center gap-2">
            <SeverityBadge level={incident.severity} />
            <span>{utcSpan(incident.start, incident.end)}</span>
            <span className="text-faint">({formatDuration(incident.duration_seconds)})</span>
          </span>
        }
      />
      <Panel>
        <dl className="grid gap-4 p-5 text-sm sm:grid-cols-2">
          <div>
            <dt className="eyebrow">{root?.kind === "config_change" ? "Suspect" : "Likely cause"}</dt>
            <dd className="mt-1 text-ink">{root?.summary ?? "The logs do not point to one cause."}</dd>
          </div>
          <div>
            <dt className="eyebrow">Confidence</dt>
            <dd className="mt-1 text-ink">
              <span className="capitalize">{incident.confidence}</span>: {incident.confidence_reason}
            </dd>
          </div>
          <div>
            <dt className="eyebrow">Severity</dt>
            <dd className="mt-1 text-ink">{incident.severity_reason}</dd>
          </div>
          <div>
            <dt className="eyebrow">Devices</dt>
            <dd className="mt-1 font-mono text-ink">{incident.devices.join(", ")}</dd>
          </div>
        </dl>
        <p className="border-t border-line px-5 py-3 text-sm text-muted">
          The plain-English explanation, the evidence lines and clickable citations come to this page
          in the next step. Until then, the command line shows them:{" "}
          <code className="font-mono text-xs text-ink">netlog analyze {name}</code>
        </p>
      </Panel>
    </div>
  );
}
