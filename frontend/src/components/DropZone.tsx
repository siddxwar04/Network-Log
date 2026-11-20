// Where a log file is dropped, or chosen with the file picker. While a file is sent, it
// shows how much has gone.

import { FileUp } from "lucide-react";
import { useRef, useState, type DragEvent } from "react";
import { formatBytes } from "../lib/format";

export interface Sending {
  name: string;
  size: number;
  fraction: number; // 0 to 1
}

export function DropZone({
  maxBytes,
  sending,
  disabled,
  onFile,
}: {
  maxBytes: number | undefined;
  sending: Sending | null;
  disabled?: boolean;
  onFile: (file: File) => void;
}) {
  const input = useRef<HTMLInputElement>(null);
  const [over, setOver] = useState(false);
  const busy = sending !== null || Boolean(disabled);

  function take(files: FileList | null) {
    const file = files?.[0];
    if (file && !busy) onFile(file);
  }

  function onDrop(event: DragEvent) {
    event.preventDefault();
    setOver(false);
    take(event.dataTransfer.files);
  }

  const percent = sending ? Math.round(sending.fraction * 100) : 0;
  return (
    <div
      onDragOver={(event) => {
        event.preventDefault();
        if (!busy) setOver(true);
      }}
      onDragLeave={() => setOver(false)}
      onDrop={onDrop}
      onClick={() => !busy && input.current?.click()}
      data-testid="drop-zone"
      className={`relative flex min-h-44 cursor-pointer flex-col items-center justify-center gap-3 overflow-hidden rounded-lg border-2 border-dashed px-6 py-8 text-center transition-colors ${
        over ? "border-accent bg-accent/10" : "border-line-strong bg-panel hover:border-faint"
      } ${busy ? "cursor-wait" : ""}`}
    >
      {sending ? (
        <div className="w-full max-w-sm">
          <p className="truncate text-sm font-medium text-ink">
            Uploading <span className="font-mono">{sending.name}</span>
          </p>
          <div
            role="progressbar"
            aria-label={`Uploading ${sending.name}`}
            aria-valuemin={0}
            aria-valuemax={100}
            aria-valuenow={percent}
            className="mt-3 h-1.5 overflow-hidden rounded-full bg-raised"
          >
            <div className="h-full rounded-full bg-accent transition-[width]" style={{ width: `${percent}%` }} />
          </div>
          <p className="mt-2 text-xs text-muted tabular-nums">
            {percent < 100
              ? `${percent}% of ${formatBytes(sending.size)}`
              : "Sent. Starting the analysis..."}
          </p>
        </div>
      ) : (
        <>
          <span className="flex size-11 items-center justify-center rounded-full bg-raised">
            <FileUp aria-hidden="true" className="size-5 text-muted" />
          </span>
          <div>
            <p className="text-base font-medium text-ink">Drop a log file here</p>
            <p className="mt-1 text-sm text-muted">
              Syslog, Cisco IOS, Linux auth or ISC dhcpd
              {maxBytes !== undefined && <> &middot; up to {formatBytes(maxBytes)}</>}
            </p>
          </div>
          <button
            type="button"
            disabled={busy}
            onClick={(event) => {
              event.stopPropagation();
              input.current?.click();
            }}
            className="rounded-md bg-accent px-3 py-1.5 text-sm font-medium text-accent-ink hover:brightness-110 disabled:opacity-50"
          >
            Choose a file
          </button>
        </>
      )}
      <input
        ref={input}
        type="file"
        className="hidden"
        data-testid="file-input"
        aria-label="Log file"
        onChange={(event) => {
          take(event.target.files);
          event.target.value = ""; // the same file can be chosen again
        }}
      />
    </div>
  );
}
