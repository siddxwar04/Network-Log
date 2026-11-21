// The left side of the incident page: the plain-English explanation, every statement
// followed by the line numbers it rests on. All of it is shown as plain text, whoever wrote
// it: an LLM's answer is untrusted output, just as log lines are untrusted input.

import { Bot, Check, Copy, FileText, ShieldAlert, TriangleAlert } from "lucide-react";
import { useState } from "react";
import type { EvidenceLine, Explanation } from "../api/types";
import { CitationList } from "./Citations";
import { useToast } from "./Toasts";

export function CopyButton({ text, label }: { text: string; label: string }) {
  const [copied, setCopied] = useState(false);
  const notify = useToast();
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 2000);
    } catch {
      notify({ title: "Could not copy", description: "Select the text and copy it by hand.", tone: "error" });
    }
  };
  return (
    <button
      type="button"
      onClick={copy}
      aria-label={copied ? `Copied ${label}` : `Copy ${label}`}
      className="inline-flex shrink-0 items-center gap-1 rounded-md border border-line px-2 py-1 text-2xs text-muted hover:border-line-strong hover:text-ink"
    >
      {copied ? <Check aria-hidden="true" className="size-3 text-ok" /> : <Copy aria-hidden="true" className="size-3" />}
      {copied ? "Copied" : "Copy"}
    </button>
  );
}

/** Who wrote this explanation, said plainly: an LLM, or the built-in templates. */
export function SourceBadge({ explanation }: { explanation: Explanation }) {
  if (explanation.source === "fallback") {
    return (
      <span className="inline-flex items-center gap-1 rounded-sm bg-raised px-1.5 py-0.5 text-2xs font-medium text-muted ring-1 ring-line-strong ring-inset">
        <FileText aria-hidden="true" className="size-3" />
        Built-in explanation (fallback)
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1 rounded-sm bg-accent/10 px-1.5 py-0.5 text-2xs font-medium text-accent ring-1 ring-accent/30 ring-inset">
      <Bot aria-hidden="true" className="size-3" />
      Written by an LLM{explanation.model ? ` (${explanation.model})` : ""}
      {explanation.source === "stored" && ", stored with the demo"}
    </span>
  );
}

const NO_PROVIDER = "no LLM provider is configured";

/** Why the built-in explanation is shown. With no LLM set up that is normal; when an LLM's
 * answer was refused, it is worth a warning. */
export function FallbackNote({ explanation }: { explanation: Explanation }) {
  if (explanation.source === "stored") {
    return (
      <p className="text-xs text-muted">
        Demo mode: an LLM wrote this explanation earlier, and it is stored with the app. It was
        checked against the evidence again just now. No request was made.
      </p>
    );
  }
  if (explanation.source !== "fallback") return null;
  const reason = explanation.fallback_reason ?? "";
  const expected = !reason || reason === NO_PROVIDER || reason.includes("switched off");
  if (expected) {
    return (
      <p className="text-xs text-muted">
        No LLM is set up, so this explanation comes from the built-in templates. It states only
        what the rules found, and Regenerate stays off: it would give the same text again.
      </p>
    );
  }
  return (
    <p role="note" className="flex gap-2 rounded-md border border-warn/40 bg-warn/10 px-3 py-2 text-xs text-ink">
      <TriangleAlert aria-hidden="true" className="mt-0.5 size-3.5 shrink-0 text-warn" />
      <span>
        The LLM&apos;s explanation could not be used ({reason}), so the built-in explanation is shown
        instead.
      </span>
    </p>
  );
}

function Section({ title, id, children }: { title: string; id?: string; children: React.ReactNode }) {
  return (
    <section id={id} className="scroll-mt-16 border-t border-line px-4 py-4">
      <h3 className="eyebrow mb-2">{title}</h3>
      {children}
    </section>
  );
}

export function ExplanationBody({
  explanation,
  lookup,
  onSelect,
}: {
  explanation: Explanation;
  lookup: Map<number, EvidenceLine>;
  onSelect: (line: number) => void;
}) {
  return (
    <div>
      <section className="px-4 py-4">
        <h3 className="eyebrow mb-2">Summary</h3>
        <p className="text-sm leading-relaxed whitespace-pre-line text-ink">{explanation.summary}</p>
      </section>

      {explanation.fix_steps.length > 0 && (
        <Section title="What to do" id="what-to-do">
          <ol className="space-y-2">
            {explanation.fix_steps.map((step, i) => (
              <li key={i} className="flex gap-2 text-sm text-ink">
                <span className="mt-0.5 font-mono text-2xs text-faint">{i + 1}.</span>
                <span>
                  {step.review_before_running && (
                    <span className="mr-1.5 inline-flex items-center gap-1 rounded-sm bg-warn/15 px-1.5 py-0.5 align-middle text-2xs font-semibold tracking-wide text-warn uppercase">
                      <ShieldAlert aria-hidden="true" className="size-3" />
                      Review before running
                    </span>
                  )}
                  {step.text}
                </span>
              </li>
            ))}
          </ol>
        </Section>
      )}

      {explanation.verification_commands.length > 0 && (
        <Section title="Check it">
          <p className="mb-2 text-xs text-muted">
            These commands only read: they change nothing on the device.
          </p>
          <ul className="space-y-2">
            {explanation.verification_commands.map((item, i) => (
              <li key={i} className="rounded-md border border-line bg-sunken p-2">
                <div className="flex items-start gap-2">
                  <code className="min-w-0 flex-1 font-mono text-xs break-all text-ink">{item.command}</code>
                  <CopyButton text={item.command} label={item.command} />
                </div>
                <p className="mt-1 text-xs text-muted">Healthy: {item.purpose}</p>
              </li>
            ))}
          </ul>
        </Section>
      )}

      {explanation.timeline.length > 0 && (
        <Section title="What happened, step by step">
          <ol className="space-y-2">
            {explanation.timeline.map((step, i) => (
              <li key={i} className="flex gap-2 text-sm text-ink">
                <span className="mt-0.5 font-mono text-2xs text-faint">{i + 1}.</span>
                <span>
                  {step.text}
                  <CitationList lines={step.lines} lookup={lookup} onSelect={onSelect} />
                </span>
              </li>
            ))}
          </ol>
        </Section>
      )}

      {explanation.hypotheses.length > 0 && (
        <Section title="Likely root cause">
          <ul className="space-y-3">
            {explanation.hypotheses.map((hypothesis, i) => (
              <li key={i} className="rounded-md border border-line bg-sunken p-3 text-sm">
                <p className="text-ink">{hypothesis.text}</p>
                <dl className="mt-2 grid gap-1 text-xs">
                  <div className="flex flex-wrap items-baseline gap-1">
                    <dt className="text-muted">Supported by</dt>
                    <dd>
                      {hypothesis.lines.length ? (
                        <CitationList lines={hypothesis.lines} lookup={lookup} onSelect={onSelect} />
                      ) : (
                        <span className="text-faint">no line cited</span>
                      )}
                    </dd>
                  </div>
                  <div className="flex flex-wrap items-baseline gap-1">
                    <dt className="text-muted">Against it</dt>
                    <dd>
                      {hypothesis.against_lines.length ? (
                        <CitationList lines={[]} against={hypothesis.against_lines} lookup={lookup} onSelect={onSelect} />
                      ) : (
                        <span className="text-faint">nothing in these logs</span>
                      )}
                    </dd>
                  </div>
                </dl>
              </li>
            ))}
          </ul>
        </Section>
      )}

      {explanation.impact.length > 0 && (
        <Section title="Impact">
          <ul className="list-disc space-y-2 pl-5 text-sm text-ink">
            {explanation.impact.map((item, i) => (
              <li key={i}>
                {item.text}
                <CitationList lines={item.lines} lookup={lookup} onSelect={onSelect} />
              </li>
            ))}
          </ul>
        </Section>
      )}
    </div>
  );
}

/** What these logs cannot tell us. Shown with weight: saying what is not known is part of
 * what makes the rest believable. */
export function Unknowns({ items }: { items: string[] }) {
  if (!items.length) return null;
  return (
    <section
      aria-labelledby="unknowns-heading"
      className="rounded-lg border border-warn/40 border-l-4 border-l-warn bg-warn/5 p-4"
    >
      <h2 id="unknowns-heading" className="flex items-center gap-2 text-sm font-semibold text-ink">
        <TriangleAlert aria-hidden="true" className="size-4 text-warn" />
        What these logs cannot tell us
      </h2>
      <ul className="mt-2 list-disc space-y-1.5 pl-6 text-sm text-ink">
        {items.map((item) => (
          <li key={item}>{item}</li>
        ))}
      </ul>
    </section>
  );
}
