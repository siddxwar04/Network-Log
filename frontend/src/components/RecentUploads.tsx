// The table of recent uploads on the home screen.

import { CircleCheck, CircleX, LoaderCircle, Trash2 } from "lucide-react";
import { useState } from "react";
import { Link, useNavigate } from "react-router";
import { useDeleteUpload, useUploads } from "../api/queries";
import type { UploadListItem } from "../api/types";
import { useApp } from "../lib/app-state";
import { formatLocalTime, formatNumber } from "../lib/format";
import { SeverityCounts } from "../lib/severity";
import { ConfirmDialog } from "./ConfirmDialog";
import { STEPS } from "./Stepper";
import { useToast } from "./Toasts";
import { EmptyState, ErrorState, Panel, SkeletonRows } from "./ui";

/** Where a row leads: the dashboard once it is done, the processing screen before that. */
export function uploadHome(upload: Pick<UploadListItem, "id" | "status">): string {
  return upload.status === "done" ? `/uploads/${upload.id}` : `/uploads/${upload.id}/processing`;
}

function StatusChip({ upload }: { upload: UploadListItem }) {
  if (upload.status === "done") {
    return (
      <span className="inline-flex items-center gap-1 text-sm text-ok">
        <CircleCheck aria-hidden="true" className="size-4" /> Done
      </span>
    );
  }
  if (upload.status === "failed") {
    return (
      <span className="inline-flex items-center gap-1 text-sm text-danger" title={upload.error ?? undefined}>
        <CircleX aria-hidden="true" className="size-4" /> Failed
      </span>
    );
  }
  const step = STEPS.find((s) => s.stage === upload.stage);
  return (
    <span className="inline-flex items-center gap-1 text-sm text-accent">
      <LoaderCircle aria-hidden="true" className="size-4 animate-spin" />
      {step ? step.label : "Waiting"}
    </span>
  );
}

export function RecentUploads() {
  const navigate = useNavigate();
  const notify = useToast();
  const { currentUpload, setCurrentUpload } = useApp();
  const list = useUploads();
  const remove = useDeleteUpload();
  const [target, setTarget] = useState<UploadListItem | null>(null);

  function confirmDelete() {
    if (!target) return;
    const doomed = target;
    remove.mutate(doomed, {
      onSuccess: () => {
        if (currentUpload === doomed.id) setCurrentUpload(null);
        setTarget(null);
        notify({ title: `Deleted ${doomed.filename}` });
      },
    });
  }

  const items = list.data?.items ?? [];
  const more = (list.data?.total ?? 0) - items.length;
  return (
    <Panel
      title="Recent uploads"
      action={list.data && <span className="text-xs text-faint tabular-nums">{formatNumber(list.data.total)}</span>}
    >
      {list.error && !list.data ? (
        <ErrorState error={list.error} onRetry={() => list.refetch()} />
      ) : !list.data ? (
        <SkeletonRows rows={4} />
      ) : items.length === 0 ? (
        <EmptyState title="No uploads yet.">Drop a log file above, or try one of the demo scenarios.</EmptyState>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead className="border-b border-line">
              <tr>
                <th scope="col" className="eyebrow px-4 py-2">File</th>
                <th scope="col" className="eyebrow hidden px-4 py-2 md:table-cell">Uploaded</th>
                <th scope="col" className="eyebrow hidden px-4 py-2 text-right sm:table-cell">Lines</th>
                <th scope="col" className="eyebrow px-4 py-2">Incidents</th>
                <th scope="col" className="eyebrow px-4 py-2">Status</th>
                <th scope="col" className="w-10 px-2 py-2"><span className="sr-only">Actions</span></th>
              </tr>
            </thead>
            <tbody className="divide-y divide-line">
              {items.map((item) => (
                <tr key={item.id} onClick={() => navigate(uploadHome(item))} className="cursor-pointer hover:bg-raised/60">
                  <td className="max-w-[18rem] px-4 py-2.5">
                    <Link
                      to={uploadHome(item)}
                      onClick={(event) => event.stopPropagation()}
                      className="block truncate font-mono text-[13px] text-ink hover:underline"
                      title={item.filename}
                    >
                      {item.filename}
                    </Link>
                    {item.source === "demo" && <span className="text-xs text-faint">demo scenario</span>}
                  </td>
                  <td className="hidden px-4 py-2.5 whitespace-nowrap text-muted md:table-cell">
                    {formatLocalTime(item.created_at)}
                  </td>
                  <td className="hidden px-4 py-2.5 text-right text-muted tabular-nums sm:table-cell">
                    {item.status === "processing" && item.lines === 0 ? "-" : formatNumber(item.lines)}
                  </td>
                  <td className="px-4 py-2.5">
                    {item.status === "done" ? (
                      <SeverityCounts counts={item.incidents_by_severity} />
                    ) : (
                      <span className="text-faint">-</span>
                    )}
                  </td>
                  <td className="px-4 py-2.5 whitespace-nowrap">
                    <StatusChip upload={item} />
                  </td>
                  <td className="px-2 py-2.5">
                    <button
                      type="button"
                      onClick={(event) => {
                        event.stopPropagation();
                        remove.reset();
                        setTarget(item);
                      }}
                      disabled={item.status === "processing"}
                      aria-label={`Delete ${item.filename}`}
                      title={item.status === "processing" ? "Wait until it has finished" : "Delete"}
                      className="rounded p-1.5 text-faint hover:bg-raised hover:text-danger disabled:cursor-not-allowed disabled:opacity-40"
                    >
                      <Trash2 aria-hidden="true" className="size-4" />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {more > 0 && (
            <p className="border-t border-line px-4 py-2 text-xs text-faint">
              Showing the {items.length} most recent of {formatNumber(list.data.total)} uploads.
            </p>
          )}
        </div>
      )}
      <ConfirmDialog
        open={target !== null}
        title="Delete this upload?"
        confirmLabel="Delete"
        busy={remove.isPending}
        error={remove.error?.message}
        onConfirm={confirmDelete}
        onCancel={() => setTarget(null)}
      >
        <p>
          <span className="font-mono text-ink">{target?.filename}</span> and everything found in it will
          be deleted. This cannot be undone.
        </p>
      </ConfirmDialog>
    </Panel>
  );
}
