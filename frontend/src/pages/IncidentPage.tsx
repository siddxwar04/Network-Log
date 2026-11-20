// One incident: the facts the rules decided at the top, the explanation on the left, and the
// log lines behind it on the right. Every statement's line numbers are buttons that find
// the line on the right, so a reader can check any claim against the log itself.

import { Download, HelpCircle, RefreshCw } from "lucide-react";
import { useCallback, useMemo, useState, type ReactNode } from "react";
import { Link, useParams, useSearchParams } from "react-router";
import { api } from "../api/client";
import { useExplanation, useHealth, useIncident, useRegenerate, useTimeline, useUpload } from "../api/queries";
import type { Audience, EvidenceLine, IncidentDetail, TimelineEvent } from "../api/types";
import { CausalChain } from "../components/CausalChain";
import { ConfirmDialog } from "../components/ConfirmDialog";
import { EvidencePanel } from "../components/EvidencePanel";
import { IncidentTimeline } from "../components/IncidentTimeline";
import { ExplanationBody, FallbackNote, SourceBadge, Unknowns } from "../components/Explanation";
import { useToast } from "../components/Toasts";
import { Button, ErrorState, PageHeader, Panel, SkeletonRows, Spinner } from "../components/ui";
import type { ChainNode } from "../lib/chain";
import { evidenceLines, groupEvidence, lineAnchor, linesOfFindings } from "../lib/evidence";
import { formatDuration, utcSpan } from "../lib/format";
import { SeverityBadge } from "../lib/severity";

function Fact({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="min-w-0">
      <dt className="eyebrow">{label}</dt>
      <dd className="mt-1 text-sm text-ink">{children}</dd>
    </div>
  );
}

/** The severity badge, with the rule's reason for it one click away. */
function Severity({ incident }: { incident: IncidentDetail }) {
  const [open, setOpen] = useState(false);
  return (
    <span className="inline-flex flex-wrap items-center gap-1.5">
      <SeverityBadge level={incident.severity} />
      <button
        type="button"
        onClick={() => setOpen((value) => !value)}
        aria-expanded={open}
        title={incident.severity_reason}
        className="inline-flex items-center gap-1 rounded-sm text-xs text-muted hover:text-ink"
      >
        <HelpCircle aria-hidden="true" className="size-3.5" />
        Why {incident.severity}?
      </button>
      {open && <span className="basis-full text-xs text-muted">{incident.severity_reason}</span>}
    </span>
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
    <div>
      <PageHeader
        crumbs={crumbs}
        title={facts.headline}
        meta={facts.title !== facts.headline ? facts.title : undefined}
        actions={
          <a
            href={api.postmortemUrl(id, incidentId, mode)}
            download
            className="inline-flex items-center gap-1.5 rounded-md border border-line-strong bg-raised px-3 py-1.5 text-sm font-medium text-ink hover:border-faint"
          >
            <Download aria-hidden="true" className="size-4" />
            Download post-mortem
          </a>
        }
      />

      <Panel className="mb-4">
        <dl className="grid gap-4 p-4 sm:grid-cols-2 lg:grid-cols-4">
          <Fact label="Severity">
            <Severity incident={facts} />
          </Fact>
          <Fact label={root?.kind === "config_change" ? "Suspect" : "Likely cause"}>
            {root?.summary ?? "The logs do not point to one cause."}
          </Fact>
          <Fact label="Confidence">
            <span className="font-medium capitalize">{facts.confidence}</span>
            <span className="text-muted">: {facts.confidence_reason}</span>
          </Fact>
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
      </Panel>

      <div className="mb-4">
        <Unknowns items={unknowns} />
      </div>

      <div className="mb-4 grid gap-4">
        <Panel title="Timeline" className="min-w-0">
          {timeline.error ? (
            <ErrorState error={timeline.error} onRetry={() => timeline.refetch()} />
          ) : timeline.data ? (
            <IncidentTimeline timeline={timeline.data} onSelect={selectEvent} />
          ) : (
            <SkeletonRows rows={4} />
          )}
        </Panel>
        <Panel title="Causal chain" className="min-w-0">
          <CausalChain incident={facts} selected={step} onSelect={selectStep} />
        </Panel>
      </div>

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
            </>
          )}
        </Panel>

        <Panel title="Evidence" className="lg:sticky lg:top-4" bodyClassName="max-h-[calc(100vh-7rem)] overflow-y-auto pb-3">
          <EvidencePanel uploadId={id} groups={groups} selected={selected} />
        </Panel>
      </div>

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
