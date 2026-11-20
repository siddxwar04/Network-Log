// Home: upload a file, load a demo scenario, or reopen a recent upload.

import { useQueryClient } from "@tanstack/react-query";
import { FlaskConical, ShieldCheck } from "lucide-react";
import { useState } from "react";
import { useNavigate } from "react-router";
import { api, ApiError } from "../api/client";
import { keys, useDemos, useHealth } from "../api/queries";
import type { DemoScenario } from "../api/types";
import { DropZone, type Sending } from "../components/DropZone";
import { RecentUploads } from "../components/RecentUploads";
import { EmptyState, ErrorState, Panel, SkeletonRows, Spinner } from "../components/ui";
import { formatBytes, formatNumber, scenarioTitle } from "../lib/format";
import { SeverityBadge } from "../lib/severity";

function DemoCard({
  scenario,
  loading,
  disabled,
  onLoad,
}: {
  scenario: DemoScenario;
  loading: boolean;
  disabled: boolean;
  onLoad: () => void;
}) {
  const levels = scenario.incidents.map((incident) => incident.expected_severity);
  return (
    <button
      type="button"
      onClick={onLoad}
      disabled={disabled}
      className="group flex min-h-[8.5rem] flex-col rounded-lg border border-line bg-panel p-3 text-left shadow-panel transition-colors hover:border-accent disabled:cursor-not-allowed disabled:opacity-60"
    >
      <span className="flex items-baseline justify-between gap-2">
        <span className="font-medium text-ink group-hover:text-accent">{scenarioTitle(scenario.name)}</span>
        {loading && <Spinner />}
      </span>
      <span className="font-mono text-2xs text-faint">{scenario.name}.log</span>
      <span className="mt-2 line-clamp-2 text-sm text-muted">{scenario.description}</span>
      <span className="mt-auto flex flex-wrap items-center gap-1 pt-2">
        {levels.length === 0 ? (
          <span className="text-xs text-ok">No incident</span>
        ) : (
          levels.map((level, i) => <SeverityBadge key={i} level={level} />)
        )}
        {scenario.lines !== null && (
          <span className="ml-auto text-xs text-faint tabular-nums">{formatNumber(scenario.lines)} lines</span>
        )}
      </span>
    </button>
  );
}

function YearAndTimezone({
  year,
  timezone,
  onYear,
  onTimezone,
}: {
  year: string;
  timezone: string;
  onYear: (value: string) => void;
  onTimezone: (value: string) => void;
}) {
  return (
    <details className="mt-3 rounded-md border border-line bg-panel px-3 py-2 text-sm">
      <summary className="cursor-pointer text-muted">Options for logs that carry no year or timezone</summary>
      <div className="mt-3 flex flex-wrap gap-4 pb-1">
        <label className="flex flex-col gap-1">
          <span className="text-xs text-muted">Year of the first line</span>
          <input
            type="number"
            inputMode="numeric"
            min={1970}
            max={2100}
            value={year}
            onChange={(event) => onYear(event.target.value)}
            placeholder={String(new Date().getFullYear())}
            className="w-32 rounded border border-line-strong bg-sunken px-2 py-1 text-ink"
          />
        </label>
        <label className="flex flex-col gap-1">
          <span className="text-xs text-muted">Devices' timezone</span>
          <input
            type="text"
            value={timezone}
            onChange={(event) => onTimezone(event.target.value)}
            placeholder="UTC or +05:30"
            className="w-40 rounded border border-line-strong bg-sunken px-2 py-1 text-ink"
          />
        </label>
      </div>
    </details>
  );
}

export function HomePage() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const health = useHealth();
  const demos = useDemos();
  const [sending, setSending] = useState<Sending | null>(null);
  const [loadingDemo, setLoadingDemo] = useState<string | null>(null);
  const [problem, setProblem] = useState<string>();
  const [year, setYear] = useState("");
  const [timezone, setTimezone] = useState("");
  const maxBytes = health.data?.max_upload_bytes;
  const busy = sending !== null || loadingDemo !== null;

  function started(id: number) {
    queryClient.invalidateQueries({ queryKey: keys.uploads });
    navigate(`/uploads/${id}/processing`);
  }

  async function send(file: File) {
    setProblem(undefined);
    if (file.size === 0) {
      setProblem(`${file.name} is empty.`);
      return;
    }
    if (maxBytes !== undefined && file.size > maxBytes) {
      setProblem(`${file.name} is ${formatBytes(file.size)}, larger than the ${formatBytes(maxBytes)} limit.`);
      return;
    }
    const givenYear = year.trim() === "" ? undefined : Number(year);
    if (givenYear !== undefined && !(Number.isInteger(givenYear) && givenYear >= 1970 && givenYear <= 2100)) {
      setProblem("The year must be a whole number between 1970 and 2100.");
      return;
    }
    setSending({ name: file.name, size: file.size, fraction: 0 });
    try {
      const created = await api.uploadFile(file, { year: givenYear, timezone: timezone.trim() || undefined }, (fraction) =>
        setSending((current) => (current ? { ...current, fraction } : current)),
      );
      started(created.id);
    } catch (error) {
      setProblem(error instanceof ApiError ? error.message : "The file could not be uploaded.");
      setSending(null);
    }
  }

  async function loadDemo(name: string) {
    setProblem(undefined);
    setLoadingDemo(name);
    try {
      const created = await api.loadDemo(name);
      started(created.id);
    } catch (error) {
      setProblem(error instanceof ApiError ? error.message : "The scenario could not be loaded.");
      setLoadingDemo(null);
    }
  }

  return (
    <div className="space-y-8">
      <section aria-labelledby="upload-heading" className="grid gap-6 lg:grid-cols-[1fr_20rem]">
        <div>
          <h1 id="upload-heading" className="text-2xl font-semibold tracking-tight text-ink">
            Analyze a log file
          </h1>
          <p className="mt-1 mb-4 max-w-2xl text-sm text-muted">
            netlog finds the incidents in router, switch, server and DHCP logs, works out what caused
            what, and explains each one with the log lines that prove it.
          </p>
          <DropZone maxBytes={maxBytes} sending={sending} disabled={loadingDemo !== null} onFile={send} />
          <YearAndTimezone year={year} timezone={timezone} onYear={setYear} onTimezone={setTimezone} />
          {problem && (
            <p role="alert" className="mt-3 rounded-md border border-danger/40 bg-danger/10 px-3 py-2 text-sm text-ink">
              {problem}
            </p>
          )}
        </div>
        <aside className="rounded-lg border border-line bg-sunken p-4 text-sm lg:mt-12">
          <p className="flex items-center gap-2 font-medium text-ink">
            <ShieldCheck aria-hidden="true" className="size-4 text-ok" /> Stays on this machine
          </p>
          <ul className="mt-2 space-y-1.5 text-muted">
            <li>Detection, grouping and severity are fixed rules, not guesses.</li>
            <li>An AI model is used only if you set one up, and only sees a short case file with addresses and names replaced.</li>
            <li>Every statement in an explanation points to the lines of your file behind it.</li>
          </ul>
        </aside>
      </section>

      <section aria-labelledby="demo-heading">
        <h2 id="demo-heading" className="mb-3 flex flex-wrap items-center gap-x-2 text-sm font-semibold text-ink">
          <FlaskConical aria-hidden="true" className="size-4 text-muted" />
          Try a demo scenario
          <span className="font-normal text-muted">generated logs with a known incident hidden inside</span>
        </h2>
        {demos.error && !demos.data ? (
          <Panel>
            <ErrorState error={demos.error} onRetry={() => demos.refetch()} />
          </Panel>
        ) : !demos.data ? (
          <Panel>
            <SkeletonRows rows={2} />
          </Panel>
        ) : demos.data.items.length === 0 ? (
          <Panel>
            <EmptyState title="No demo scenarios are installed." />
          </Panel>
        ) : (
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-5">
            {demos.data.items.map((scenario) => (
              <DemoCard
                key={scenario.name}
                scenario={scenario}
                loading={loadingDemo === scenario.name}
                disabled={busy}
                onLoad={() => loadDemo(scenario.name)}
              />
            ))}
          </div>
        )}
      </section>

      <RecentUploads />
    </div>
  );
}
