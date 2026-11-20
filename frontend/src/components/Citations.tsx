// The clickable line numbers after each statement of an explanation. Clicking one shows
// that line in the evidence panel; hovering or focusing it previews the line in place.

import { useId, useState } from "react";
import type { EvidenceLine } from "../api/types";
import { utcTime } from "../lib/format";

// A statement can rest on many lines; past this many, the rest wait behind "+N more".
const SHOWN = 6;

export function Citation({
  line,
  evidence,
  against = false,
  onSelect,
}: {
  line: number;
  evidence?: EvidenceLine;
  against?: boolean;
  onSelect: (line: number) => void;
}) {
  const preview = useId();
  return (
    <span className="group relative inline-block">
      <button
        type="button"
        onClick={() => onSelect(line)}
        aria-describedby={evidence ? preview : undefined}
        aria-label={`${against ? "Line against it" : "Line"} ${line}${evidence?.host ? ` on ${evidence.host}` : ""}`}
        className={`rounded-sm px-1 font-mono text-2xs leading-4 ring-1 ring-inset transition ${
          against
            ? "text-danger ring-danger/40 hover:bg-danger/10"
            : "text-accent ring-accent/40 hover:bg-accent/10"
        }`}
      >
        L{line}
      </button>
      {evidence && (
        // The log line is untrusted: it is a text node here, never markup.
        <span
          id={preview}
          role="tooltip"
          className="pointer-events-none invisible absolute top-full left-0 z-30 mt-1 w-80 max-w-[80vw] rounded-md border border-line-strong bg-raised p-2 text-left opacity-0 shadow-pop transition group-focus-within:visible group-focus-within:opacity-100 group-hover:visible group-hover:opacity-100"
        >
          <span className="block text-2xs text-faint">
            Line {line}
            {evidence.host && ` · ${evidence.host}`}
            {evidence.time && ` · ${utcTime(evidence.time)} UTC`}
          </span>
          <span className="mt-0.5 block font-mono text-2xs break-all whitespace-pre-wrap text-ink">
            {evidence.text}
          </span>
        </span>
      )}
    </span>
  );
}

/** The citations of one statement, with "+N more" when there are many. */
export function CitationList({
  lines,
  against = [],
  lookup,
  onSelect,
}: {
  lines: number[];
  against?: number[];
  lookup: Map<number, EvidenceLine>;
  onSelect: (line: number) => void;
}) {
  const [all, setAll] = useState(false);
  const shown = all ? lines : lines.slice(0, SHOWN);
  if (!lines.length && !against.length) return null;
  return (
    <span className="ml-1 inline-flex flex-wrap items-center gap-1 align-baseline">
      {shown.map((line) => (
        <Citation key={line} line={line} evidence={lookup.get(line)} onSelect={onSelect} />
      ))}
      {lines.length > shown.length && (
        <button
          type="button"
          onClick={() => setAll(true)}
          className="text-2xs text-muted underline-offset-2 hover:text-ink hover:underline"
        >
          +{lines.length - shown.length} more
        </button>
      )}
      {against.length > 0 && <span className="text-2xs text-faint">against:</span>}
      {against.map((line) => (
        <Citation key={`a${line}`} line={line} evidence={lookup.get(line)} against onSelect={onSelect} />
      ))}
    </span>
  );
}
