// Processing: the pipeline's stages and running counts, live, until it is done.

import { useQueryClient } from "@tanstack/react-query";
import { ArrowLeft, Wifi } from "lucide-react";
import { useEffect } from "react";
import { Link, useNavigate, useParams } from "react-router";
import { keys, usePipelineStatus, useUpload } from "../api/queries";
import type { PipelineStatus } from "../api/types";
import { Stepper, STEPS } from "../components/Stepper";
import { ErrorState, PageHeader, Panel, Spinner } from "../components/ui";
import { formatNumber } from "../lib/format";

// A moment to see that every step is done before moving on to the dashboard.
export const DONE_PAUSE_MS = 600;

function Count({ label, value }: { label: string; value: number | undefined }) {
  return (
    <div className="rounded-md border border-line bg-sunken px-3 py-2.5">
      <dt className="eyebrow">{label}</dt>
      <dd className="mt-0.5 text-xl font-semibold text-ink tabular-nums">
        {value === undefined ? "-" : formatNumber(value)}
      </dd>
    </div>
  );
}

function describe(status: PipelineStatus | undefined): string {
  if (!status || status.stage === "queued") return "Waiting to start";
  if (status.stage === "done") return "Done. Opening the dashboard...";
  if (status.stage === "failed") return "Stopped";
  return STEPS.find((step) => step.stage === status.stage)?.doing ?? "Working";
}

export function ProcessingPage() {
  const { id = "" } = useParams();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const upload = useUpload(id);
  const query = usePipelineStatus(id);
  // The last answer stays on screen while the server cannot be reached.
  const status = query.data;
  const error = query.error;

  useEffect(() => {
    if (status?.stage !== "done") return;
    // What was read about this upload while it was being processed is out of date now.
    for (const key of [keys.upload(id), keys.uploads]) queryClient.invalidateQueries({ queryKey: key });
    const timer = setTimeout(() => navigate(`/uploads/${id}`, { replace: true }), DONE_PAUSE_MS);
    return () => clearTimeout(timer);
  }, [status?.stage, id, navigate, queryClient]);

  if (error?.status === 404) {
    return (
      <Panel>
        <div className="space-y-3 p-4">
          <p role="alert" className="text-sm text-ink">
            {error.message} It may have been deleted.
          </p>
          <Link to="/" className="inline-flex items-center gap-1 text-sm text-accent hover:underline">
            <ArrowLeft aria-hidden="true" className="size-4" /> Back to uploads
          </Link>
        </div>
      </Panel>
    );
  }

  const failed = status?.stage === "failed";
  const failedStep = STEPS.find((step) => step.stage === status?.failed_stage);
  const name = upload.data?.filename;
  return (
    <div className="mx-auto max-w-3xl">
      <PageHeader
        crumbs={[{ label: "Uploads", to: "/" }, { label: name ?? `Upload ${id}` }]}
        title={
          name ? (
            <>
              Analyzing <span className="font-mono">{name}</span>
            </>
          ) : (
            "Analyzing the upload"
          )
        }
      />
      <div className="space-y-4">
        <Panel>
          <div className="space-y-5 p-4 sm:p-5">
            {status ? <Stepper stage={status.stage} failedStage={status.failed_stage} /> : !error && <Spinner label="Connecting..." />}
            <p className="text-sm text-muted" aria-live="polite">
              {status ? describe(status) : ""}
            </p>
            <dl className="grid grid-cols-2 gap-2 sm:grid-cols-4">
              <Count label="Lines read" value={status?.counts.lines} />
              <Count label="Message patterns" value={status?.counts.templates} />
              <Count label="Findings" value={status?.counts.findings} />
              <Count label="Incidents" value={status?.counts.incidents} />
            </dl>
            {status?.stage === "done" && (
              <Link to={`/uploads/${id}`} replace className="text-sm text-accent hover:underline">
                Go to the dashboard now
              </Link>
            )}
          </div>
        </Panel>

        {error && (
          <Panel>
            {error.unreachable ? (
              <div role="alert" className="flex items-start gap-3 p-4 text-sm">
                <Wifi aria-hidden="true" className="mt-0.5 size-5 shrink-0 text-warn" />
                <div>
                  <p className="font-medium text-ink">Lost contact with the CauseLine server.</p>
                  <p className="mt-1 text-muted">
                    Retrying every few seconds. If the server was stopped, an upload it was working on
                    is marked as failed when it starts again.
                  </p>
                </div>
              </div>
            ) : (
              <ErrorState error={error} />
            )}
          </Panel>
        )}

        {failed && status && (
          <Panel>
            <div role="alert" className="space-y-3 p-4">
              <p className="font-medium text-danger">Failed at the {failedStep ? `${failedStep.label} step` : "start"}.</p>
              <p className="text-sm text-ink">{status.error ?? "No reason was recorded."}</p>
              <Link
                to="/"
                className="inline-flex items-center gap-1 rounded-md border border-line-strong bg-raised px-3 py-1.5 text-sm font-medium text-ink hover:border-faint"
              >
                <ArrowLeft aria-hidden="true" className="size-4" /> Back to uploads
              </Link>
            </div>
          </Panel>
        )}
      </div>
    </div>
  );
}
