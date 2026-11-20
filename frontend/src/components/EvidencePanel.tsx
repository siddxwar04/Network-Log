// The right side of the incident page: the log lines the incident rests on, grouped by step
// of the causal chain. Each shows its line number, device, time and raw text, and can show
// the lines around it. Log text is untrusted, so it is only ever a text node.

import { ChevronsUpDown, Crosshair } from "lucide-react";
import { useState } from "react";
import { useLinesAround } from "../api/queries";
import type { EvidenceLine } from "../api/types";
import { lineAnchor, type EvidenceGroup } from "../lib/evidence";
import { plural, utcTime } from "../lib/format";
import { ErrorState, Spinner } from "./ui";

function LineText({ text, faint = false }: { text: string; faint?: boolean }) {
  return (
    <span
      className={`block font-mono text-xs break-all whitespace-pre-wrap ${faint ? "text-faint" : "text-ink"}`}
    >
      {text}
    </span>
  );
}

function Context({ uploadId, line }: { uploadId: string; line: number }) {
  const around = useLinesAround(uploadId, line, true);
  if (around.error) return <ErrorState error={around.error} onRetry={() => around.refetch()} />;
  if (!around.data) return <Spinner label="Reading the lines around it" className="px-3 py-2" />;
  return (
    <ol aria-label={`Lines around line ${line}`} className="mt-2 space-y-1 border-l-2 border-line pl-3">
      {around.data.lines.map((item) => (
        <li key={item.line} className="flex gap-2">
          <span className="w-12 shrink-0 text-right font-mono text-2xs text-faint">{item.line}</span>
          <LineText text={item.text} faint={item.line !== line} />
        </li>
      ))}
    </ol>
  );
}

function Row({
  uploadId,
  line,
  selected,
}: {
  uploadId: string;
  line: EvidenceLine;
  selected: boolean;
}) {
  const [context, setContext] = useState(false);
  return (
    <li
      id={lineAnchor(line.line)}
      tabIndex={-1}
      data-selected={selected || undefined}
      aria-current={selected ? "true" : undefined}
      className={`scroll-mt-4 rounded-md border px-3 py-2 transition-colors ${
        selected ? "border-accent bg-accent/10 ring-2 ring-accent/40" : "border-transparent hover:bg-raised"
      }`}
    >
      <div className="flex flex-wrap items-center gap-x-3 gap-y-0.5 text-2xs text-muted">
        <span className="font-mono font-medium text-ink">Line {line.line}</span>
        {line.host && <span className="font-mono">{line.host}</span>}
        {line.time && <span>{utcTime(line.time)} UTC</span>}
        {selected && (
          <span className="inline-flex items-center gap-1 font-medium text-accent">
            <Crosshair aria-hidden="true" className="size-3" /> cited
          </span>
        )}
        <button
          type="button"
          onClick={() => setContext((open) => !open)}
          aria-expanded={context}
          className="ml-auto inline-flex items-center gap-1 rounded-sm px-1 hover:bg-raised hover:text-ink"
        >
          <ChevronsUpDown aria-hidden="true" className="size-3" />
          {context ? "Hide context" : "Show context"}
        </button>
      </div>
      <div className="mt-1">
        <LineText text={line.text} />
      </div>
      {context && <Context uploadId={uploadId} line={line.line} />}
    </li>
  );
}

export function EvidencePanel({
  uploadId,
  groups,
  selected,
}: {
  uploadId: string;
  groups: EvidenceGroup[];
  selected: ReadonlySet<number>;
}) {
  const total = groups.reduce((sum, group) => sum + group.lines.length, 0);
  return (
    <div>
      <p className="px-4 pt-3 text-xs text-muted">
        {plural(total, "line")} from the uploaded file, by step of the chain. Click a line number in
        the explanation to find it here.
      </p>
      {groups.map((group) => (
        <section key={group.key} aria-label={group.title} className="px-2 pt-3 pb-1">
          <h3 className="flex flex-wrap items-baseline gap-x-2 px-2 text-xs font-semibold text-ink">
            {group.root && (
              <span className="rounded-sm bg-accent/15 px-1 text-2xs font-medium text-accent">
                Root cause
              </span>
            )}
            <span>{group.root ? group.title.replace(/^Root cause: /, "") : group.title}</span>
            {group.when && <span className="font-normal text-faint">{group.when}</span>}
          </h3>
          <ul className="mt-1 space-y-0.5">
            {group.lines.map((line) => (
              <Row key={line.line} uploadId={uploadId} line={line} selected={selected.has(line.line)} />
            ))}
          </ul>
        </section>
      ))}
    </div>
  );
}
