// One incident, in the order a reader in a hurry needs it: how bad, the likely cause and
// what to do first at the top; then the chain of cause and effect; then the explanation on
// the left with the log lines behind it on the right; the full timeline last. Every
// statement's line numbers are buttons that find the line on the right, so a reader can
// check any claim against the log itself.

import { ArrowDown, Download, HelpCircle, ListVideo, RefreshCw, ShieldAlert } from "lucide-react";
import { useCallback, useMemo, type ReactNode, useRef, useState } from "react";
import { Link, useParams, useSearchParams } from "react-router";
import { api } from "../api/client";
import { useExplanation, useHealth, useIncident, useRegenerate, useTimeline, useUpload } from "../api/queries";
import type { Audience, EvidenceLine, Explanation, TimelineEvent } from "../api/types";
import { CausalChain } from "../components/CausalChain";
import { ConfirmDialog } from "../components/ConfirmDialog";
import { EvidencePanel } from "../components/EvidencePanel";
import { IncidentTimeline } from "../components/IncidentTimeline";
import { ExplanationBody, FallbackNote, SourceBadge, Unknowns } from "../components/Explanation";
import { ReplayBar } from "../components/Replay";
import { useToast } from "../components/Toasts";
import { Button, ErrorState, LinkButton, PageHeader, Panel, SkeletonRows, Spinner } from "../components/ui";
import type { ChainNode } from "../lib/chain";
import { evidenceLines, groupEvidence, lineAnchor, linesOfFindings } from "../lib/evidence";
import { formatDuration, plural, utcSpan } from "../lib/format";
import { prefersReducedMotion, replaySteps } from "../lib/replay";
import { SEVERITY, SeverityBadge } from "../lib/severity";

function Fact({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="min-w-0">
      <dt className="eyebrow">{label}</dt>
      <dd className="mt-1 text-sm text-ink">{children}</dd>
    </div>
  );
}

/** One of the three answers at the top of the page: a question and its answer, large. */
function Answer({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="min-w-0">
      <dt className="text-xs font-semibold tracking-wide text-muted uppercase">{label}</dt>
      <dd className="mt-1.5 text-sm text-ink">{children}</dd>
    </div>
  );
}

/** The first thing to do, taken from the explanation, with the way to the full list. */
function FirstStep({ explanation, failed }: { explanation?: Explanation; failed: boolean }) {
  if (failed) return <span className="text-muted">The steps could not be loaded. Try again below.</span>;
  if (!explanation) {
    return (
      <span aria-hidden="true" className="block space-y-2 pt-1">
        <span className="block h-3.5 w-full animate-pulse rounded bg-ink/10" />
        <span className="block h-3.5 w-2/3 animate-pulse rounded bg-ink/10" />
      </span>
    );
  }
  const steps = explanation.fix_steps;
  if (steps.length === 0) {
    return <span className="text-muted">No step is suggested for this incident. Read the summary below.</span>;
  }
  return (
    <>
      <span className="block text-base leading-snug font-medium">{steps[0].text}</span>
      {steps[0].review_before_running && (
        <span className="mt-1.5 inline-flex items-center gap-1 text-xs font-medium text-warn">
          <ShieldAlert aria-hidden="true" className="size-3.5" />
          This changes the device. Check it before you run it.
        </span>
      )}
      <a
        href="#what-to-do"
        className="mt-1.5 flex w-fit items-center gap-1 text-xs font-medium text-accent hover:underline"
      >
        <ArrowDown aria-hidden="true" className="size-3.5" />
        {steps.length > 1 ? `All ${steps.length} steps, and how to check` : "How to check it"}
      </a>
    </>
  );
}

function AudienceToggle({ mode, onChange }: { mode: Audience; onChange: (mode: Audience) => void }) {
  const options: { value: Audience; label: string }[] = [
    { value: "junior", label: "Junior" },
    { value: "senior", label: "Senior" },
  ];
  return (
    <div role="group" aria-label="Written for" className="inline-flex rounded-md border border-line p-0.5">
      {options.map((option) => (
        <button
          key={option.value}
          type="button"
          aria-pressed={mode === option.value}
          onClick={() => onChange(option.value)}
          className={`rounded px-2.5 py-1 text-xs font-medium transition ${
            mode === option.value ? "bg-accent text-accent-ink" : "text-muted hover:text-ink"
          }`}
        >
          {option.label}
        </button>
      ))}
    </div>
  );
}

export default function IncidentPage() {
  const { id = "", incidentId = "" } = useParams();
  const [search, setSearch] = useSearchParams();
  const mode: Audience = search.get("mode") === "junior" ? "junior" : "senior";
  const upload = useUpload(id);
  const incident = useIncident(id, incidentId);
  const explanation = useExplanation(id, incidentId, mode);
  const timeline = useTimeline(id, incidentId);
  const health = useHealth();
  const regenerate = useRegenerate(id, incidentId);
  const notify = useToast();
  const [selected, setSelected] = useState<ReadonlySet<number>>(new Set());
  const [step, setStep] = useState<number | null>(null);
  // Lines picked on the timeline that the evidence panel did not list yet.
  const [extra, setExtra] = useState<EvidenceLine[]>([]);
  const [confirming, setConfirming] = useState(false);
  // The replay: which step it is on, or null when none is running; and the page as it was
  // when the replay began, to put back when it ends.
  const [replay, setReplay] = useState<number | null>(null);
  const [playing, setPlaying] = useState(false);
  const before = useRef<{ selected: ReadonlySet<number>; step: number | null; scroll: number } | null>(null);

  const lookup = useMemo(
    () => (incident.data ? evidenceLines(incident.data, explanation.data, extra) : new Map<number, EvidenceLine>()),
    [incident.data, explanation.data, extra],
  );
  const groups = useMemo(
    () => (incident.data ? groupEvidence(incident.data, lookup) : []),
    [incident.data, lookup],
  );

  // Lines were picked: bring the first into view, mark them all, and move focus to the
  // first so a keyboard or screen reader user lands there too.
  const show = useCallback((lines: number[]) => {
    setSelected(new Set(lines));
    if (!lines.length) return;
    window.requestAnimationFrame(() => {
      const row = document.getElementById(lineAnchor(lines[0]));
      row?.scrollIntoView?.({ block: "center", behavior: "smooth" });
      row?.focus({ preventScroll: true });
    });
  }, []);

  // A citation was clicked.
  const select = useCallback(
    (line: number) => {
      setStep(null);
      show([line]);
    },
    [show],
  );

  // A marker on the timeline was clicked. Its line may not be in the panel yet.
  const selectEvent = useCallback(
    (event: TimelineEvent) => {
      setExtra((known) => (known.some((line) => line.line === event.line) ? known : [...known, event]));
      setStep(null);
      show([event.line]);
    },
    [show],
  );

  // A step of the causal chain was clicked: every line of its findings.
  const selectStep = useCallback(
    (node: ChainNode) => {
      if (!incident.data) return;
      setStep(node.index);
      show(linesOfFindings(incident.data, lookup, node.step.findings));
    },
    [incident.data, lookup, show],
  );

  const steps = useMemo(
    () => (incident.data ? replaySteps(incident.data, explanation.data, lookup) : []),
    [incident.data, explanation.data, lookup],
  );

  // A step of the replay: mark its box in the chain and its log lines, and bring both into
  // view inside their own panels. Focus stays on the controls.
  const showStep = useCallback(
    (index: number) => {
      const current = steps[index];
      if (!current) return;
      setReplay(index);
      setStep(current.node.index);
      setSelected(new Set(current.lines));
      const behavior = prefersReducedMotion() ? "auto" : "smooth";
      window.requestAnimationFrame(() => {
        const row = current.lines.length ? document.getElementById(lineAnchor(current.lines[0])) : null;
        const pane = row?.closest<HTMLElement>(".log-surface");
        if (row && pane) {
          const top = row.getBoundingClientRect().top - pane.getBoundingClientRect().top + pane.scrollTop;
          pane.scrollTo?.({ top: Math.max(0, top - pane.clientHeight / 3), behavior });
        }
        document
          .querySelector(`#causal-chain [role="button"][aria-pressed="true"]`)
          ?.scrollIntoView?.({ block: "nearest", inline: "center", behavior });
      });
    },
    [steps],
  );

  const startReplay = useCallback(() => {
    before.current = { selected, step, scroll: window.scrollY };
    document.getElementById("causal-chain")?.scrollIntoView?.({ block: "start", behavior: prefersReducedMotion() ? "auto" : "smooth" });
    showStep(0);
    setPlaying(steps.length > 1);
  }, [selected, step, showStep, steps.length]);

  // Leaving puts the page back as it was: what was marked, where it was scrolled, and focus
  // on the button that started the replay.
  const exitReplay = useCallback(() => {
    const was = before.current;
    before.current = null;
    setReplay(null);
    setPlaying(false);
    setSelected(was?.selected ?? new Set());
    setStep(was?.step ?? null);
    window.requestAnimationFrame(() => {
      if (was) window.scrollTo?.({ top: was.scroll, behavior: "auto" });
      document.getElementById("replay-start")?.focus({ preventScroll: true });
    });
  }, []);

  const current = useMemo(
    () => (replay === null || !steps[replay] ? null : new Set(steps[replay].findings)),
    [replay, steps],
  );

  const name = upload.data?.filename ?? `Upload ${id}`;
  const crumbs = [
    { label: "Uploads", to: "/" },
    { label: name, to: `/uploads/${id}` },
    { label: "Incidents", to: `/uploads/${id}/incidents` },
    { label: incidentId },
  ];

  if (incident.error?.status === 404 || upload.error?.status === 404) {
    return (
      <div>
        <PageHeader crumbs={crumbs} title="Incident not found" />
        <Panel>
          <div className="space-y-2 p-5 text-sm">
            <p role="alert" className="text-ink">
              {upload.error ? `There is no upload ${id}.` : `${name} has no incident with the id `}
              {!upload.error && <span className="font-mono">{incidentId}</span>}
            </p>
            <Link to={upload.error ? "/" : `/uploads/${id}/incidents`} className="text-accent hover:underline">
              {upload.error ? "Back to the uploads" : "See the incidents it does have"}
            </Link>
          </div>
        </Panel>
      </div>
    );
  }
  if (incident.error) {
    return (
      <div>
        <PageHeader crumbs={crumbs} title="Incident" />
        <Panel>
          <ErrorState error={incident.error} onRetry={() => incident.refetch()} />
        </Panel>
      </div>
    );
  }
  if (!incident.data) {
    return (
      <div>
        <PageHeader crumbs={crumbs} title="Incident" />
        <Panel>
          <SkeletonRows rows={6} />
        </Panel>
      </div>
    );
  }

  const facts = incident.data;
  const root = facts.root_cause;
  const llmReady = Boolean(health.data?.llm.configured);
  const unknowns = [...new Set([...facts.unknowns, ...(explanation.data?.unknowns ?? [])])];

  const doRegenerate = () =>
    regenerate.mutate(mode, {
      onSuccess: (fresh) => {
        setConfirming(false);
        notify(
          fresh.source === "fallback"
            ? { title: "The LLM's new answer could not be used", description: "The built-in explanation is shown.", tone: "error" }
            : { title: "Explanation regenerated" },
        );
      },
    });

  return (
    <div className={replay === null ? "settle" : "settle pb-28"}>
      <PageHeader
        crumbs={crumbs}
        title={facts.headline}
        meta={facts.title !== facts.headline ? facts.title : undefined}
        actions={
          <LinkButton href={api.postmortemUrl(id, incidentId, mode)} download>
            <Download aria-hidden="true" className="size-4" />
            Download post-mortem
          </LinkButton>
        }
      />

      <section
        aria-label="At a glance"
        className={`mb-4 overflow-hidden rounded-lg border border-l-4 shadow-panel ${SEVERITY[facts.severity].wash} ${SEVERITY[facts.severity].edge}`}
      >
        <dl className="grid gap-x-8 gap-y-5 p-5 lg:grid-cols-3">
          <Answer label="How bad">
            <SeverityBadge level={facts.severity} />
            <span className="mt-1.5 block text-muted">{facts.severity_reason}</span>
          </Answer>
          <Answer label={root?.kind === "config_change" ? "Suspect" : "Likely cause"}>
            <span className="block text-base leading-snug font-medium">
              {root?.summary ?? "The logs do not point to one cause."}
            </span>
            <span className="mt-1.5 block">
              {facts.confidence === "low" && (
                <span className="mr-1.5 inline-flex items-center gap-1 rounded-sm bg-warn/15 px-1.5 py-0.5 align-middle text-2xs font-semibold tracking-wide text-warn uppercase">
                  <HelpCircle aria-hidden="true" className="size-3" />
                  Uncertain
                </span>
              )}
              <span className="font-medium capitalize">{facts.confidence}</span>
              <span className="text-muted"> confidence</span>
              <span className="text-muted">: {facts.confidence_reason}</span>
            </span>
          </Answer>
          <Answer label="Do this first">
            <FirstStep explanation={explanation.data} failed={Boolean(explanation.error)} />
          </Answer>
        </dl>
        <dl className="grid gap-4 border-t border-line bg-panel px-5 py-3 sm:grid-cols-3">
          <Fact label="When">
            {utcSpan(facts.start, facts.end)}
            <span className="block text-xs text-muted">lasted {formatDuration(facts.duration_seconds)}</span>
          </Fact>
          <Fact label="Devices">
            <span className="font-mono">{facts.devices.join(", ")}</span>
          </Fact>
          <Fact label="Explanation">
            {explanation.data ? (
              <SourceBadge explanation={explanation.data} />
            ) : explanation.error ? (
              <span className="text-danger">could not be loaded</span>
            ) : (
              <span className="text-muted">being written...</span>
            )}
          </Fact>
        </dl>
      </section>

      <div className="mb-4">
        <Unknowns items={unknowns} />
      </div>

      <Panel
        title="What caused what"
        action={<span className="text-xs text-faint">Click a step to see its log lines.</span>}
        className="mb-4 min-w-0"
      >
        <div id="causal-chain" className="scroll-mt-28">
          <CausalChain incident={facts} selected={step} onSelect={selectStep} />
        </div>
      </Panel>

      <div className="grid items-start gap-4 lg:grid-cols-[minmax(0,1.1fr)_minmax(0,1fr)]">
        <Panel
          title="Explanation"
          action={
            <div className="flex items-center gap-2">
              <AudienceToggle mode={mode} onChange={(next) => setSearch(next === "senior" ? {} : { mode: next }, { replace: true })} />
              <Button
                variant="ghost"
                className="px-2 py-1 text-xs"
                onClick={() => setConfirming(true)}
                disabled={!llmReady || !explanation.data || regenerate.isPending}
                title={llmReady ? "Ask the LLM again" : "Demo mode: no LLM is set up, so there is nothing to ask"}
              >
                <RefreshCw aria-hidden="true" className={`size-3.5 ${regenerate.isPending ? "animate-spin" : ""}`} />
                Regenerate
              </Button>
            </div>
          }
        >
          {explanation.error ? (
            <ErrorState error={explanation.error} onRetry={() => explanation.refetch()} />
          ) : !explanation.data ? (
            <div aria-busy="true">
              <Spinner label={`Writing the ${mode} explanation. The facts and evidence are already shown.`} className="px-4 pt-4" />
              <SkeletonRows rows={6} />
            </div>
          ) : (
            <>
              {(explanation.data.source === "fallback" || explanation.data.source === "stored") && (
                <div className="px-4 pt-3">
                  <FallbackNote explanation={explanation.data} />
                </div>
              )}
              <ExplanationBody explanation={explanation.data} lookup={lookup} onSelect={select} />
              <div className="flex flex-wrap items-center gap-x-3 gap-y-1.5 border-t border-line px-4 py-3">
                <Button id="replay-start" onClick={startReplay} disabled={replay !== null || steps.length === 0}>
                  <ListVideo aria-hidden="true" className="size-4" />
                  Replay step by step
                </Button>
                <span className="text-xs text-muted">
                  Walks through the {plural(steps.length, "step")} of the chain in order, with the log lines behind each.
                </span>
              </div>
            </>
          )}
        </Panel>

        <Panel
          title="Evidence"
          className="overflow-hidden lg:sticky lg:top-16"
          bodyClassName="log-surface max-h-[calc(100vh-8rem)] overflow-y-auto pb-3"
        >
          <EvidencePanel uploadId={id} groups={groups} selected={selected} />
        </Panel>
      </div>

      <Panel
        title="Timeline"
        action={<span className="text-xs text-faint">Every event of the incident, by device.</span>}
        className="mt-4 min-w-0"
      >
        {timeline.error ? (
          <ErrorState error={timeline.error} onRetry={() => timeline.refetch()} />
        ) : timeline.data ? (
          <IncidentTimeline timeline={timeline.data} onSelect={selectEvent} current={current} />
        ) : (
          <SkeletonRows rows={4} />
        )}
      </Panel>

      {replay !== null && steps.length > 0 && (
        <ReplayBar
          steps={steps}
          index={Math.min(replay, steps.length - 1)}
          playing={playing}
          stepSeconds={health.data?.replay?.step_seconds ?? 0}
          onStep={showStep}
          onPlaying={setPlaying}
          onExit={exitReplay}
        />
      )}

      <ConfirmDialog
        open={confirming}
        title="Regenerate the explanation?"
        confirmLabel="Regenerate"
        busyLabel="Asking the LLM..."
        tone="primary"
        busy={regenerate.isPending}
        error={regenerate.error?.message}
        onConfirm={doRegenerate}
        onCancel={() => setConfirming(false)}
      >
        This asks the LLM again for the {mode} explanation, which costs one API request. The
        facts above do not change: the rules decided them.
      </ConfirmDialog>
    </div>
  );
}
