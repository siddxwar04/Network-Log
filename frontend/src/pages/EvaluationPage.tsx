// How accurate the tool is: the latest results of the evaluation harness, which runs the
// tool on generated logs whose answers are known. The page only reads what the harness
// wrote; it runs nothing.

import type { ReactNode } from "react";
import { useEvaluation } from "../api/queries";
import type { DetectionScore, Evaluation, EvaluationSet } from "../api/types";
import { Code, EmptyState, ErrorState, PageHeader, Panel, SkeletonRows } from "../components/ui";
import { formatLocalTime, formatNumber } from "../lib/format";

const SETS: { key: "heldout" | "tuned" | "noise"; label: string; note: string }[] = [
  { key: "heldout", label: "Held-out", note: "new variants the rules were never tuned on: the headline" },
  { key: "tuned", label: "Tuned", note: "the sample logs the rules were developed against" },
  { key: "noise", label: "Noise only", note: "normal traffic, for false alarms" },
];

function percent(value: number | null | undefined): string {
  return value === null || value === undefined ? "n/a" : `${(value * 100).toFixed(1)}%`;
}

function Cell({ children }: { children: ReactNode }) {
  return <td className="px-3 py-2 text-right tabular-nums">{children}</td>;
}

function Head({ children, left = false }: { children: ReactNode; left?: boolean }) {
  return (
    <th scope="col" className={`px-3 py-2 font-medium ${left ? "text-left" : "text-right"}`}>
      {children}
    </th>
  );
}

function SetsTable({ data }: { data: Evaluation }) {
  const rows = SETS.filter(({ key }) => data.sets[key]);
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <caption className="sr-only">Detection results by test set</caption>
        <thead className="border-b border-line text-xs text-muted">
          <tr>
            <Head left>Set</Head>
            <Head>Files</Head>
            <Head>Lines</Head>
            <Head>Incidents</Head>
            <Head>Found</Head>
            <Head>False alarms</Head>
            <Head>Precision</Head>
            <Head>Recall</Head>
            <Head>F1</Head>
            <Head>Root cause</Head>
            <Head>Severity</Head>
            <Head>Devices</Head>
            <Head>Split / merged</Head>
          </tr>
        </thead>
        <tbody>
          {rows.map(({ key, label, note }) => {
            const s = data.sets[key] as EvaluationSet;
            const o = s.overall;
            return (
              <tr key={key} className="border-b border-line last:border-0">
                <th scope="row" className="px-3 py-2 text-left font-medium text-ink">
                  {label}
                  <span className="block text-2xs font-normal text-faint">{note}</span>
                </th>
                <Cell>{formatNumber(s.files)}</Cell>
                <Cell>{formatNumber(s.lines)}</Cell>
                <Cell>{o.expected}</Cell>
                <Cell>{o.found}</Cell>
                <Cell>{o.false_alarms}</Cell>
                <Cell>{percent(o.precision)}</Cell>
                <Cell>{percent(o.recall)}</Cell>
                <Cell>{percent(o.f1)}</Cell>
                <Cell>{percent(s.root_cause.rate)}</Cell>
                <Cell>{percent(s.severity.rate)}</Cell>
                <Cell>{percent(s.devices?.rate)}</Cell>
                <Cell>
                  {s.correlation.split} / {s.correlation.merged}
                </Cell>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

function TypesTable({ types }: { types: Record<string, DetectionScore> }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <caption className="sr-only">Held-out results by incident type</caption>
        <thead className="border-b border-line text-xs text-muted">
          <tr>
            <Head left>Incident type</Head>
            <Head>Incidents</Head>
            <Head>Found</Head>
            <Head>False alarms</Head>
            <Head>Precision</Head>
            <Head>Recall</Head>
            <Head>F1</Head>
          </tr>
        </thead>
        <tbody>
          {Object.entries(types).map(([name, b]) => (
            <tr key={name} className="border-b border-line last:border-0">
              <th scope="row" className="px-3 py-2 text-left font-mono text-xs text-ink">
                {name}
              </th>
              <Cell>{b.expected}</Cell>
              <Cell>{b.found}</Cell>
              <Cell>{b.false_alarms}</Cell>
              <Cell>{percent(b.precision)}</Cell>
              <Cell>{percent(b.recall)}</Cell>
              <Cell>{percent(b.f1)}</Cell>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function Problems({ data }: { data: Evaluation }) {
  if (!data.problems.length) {
    return <p className="px-4 py-4 text-sm text-muted">No misses, false alarms, wrong causes, severities or devices.</p>;
  }
  return (
    <ul className="divide-y divide-line text-sm">
      {data.problems.map((item, i) => (
        <li key={i} className="px-4 py-2">
          <span className="font-medium text-ink">{item.kind}</span>{" "}
          <span className="font-mono text-xs text-muted">
            {item.set} / {item.file}
          </span>
          {item.variant && <span className="text-xs text-faint"> ({item.variant})</span>}
          <p className="text-muted">{item.reason}</p>
        </li>
      ))}
    </ul>
  );
}

function Results({ data }: { data: Evaluation }) {
  const noise = data.sets.noise;
  const eff = data.efficiency;
  const speeds = Object.values(data.sets)
    .map((s) => s?.lines_per_second)
    .filter((v): v is number => typeof v === "number");
  return (
    <div className="space-y-5">
      <p role="note" className="rounded-md border border-warn/40 bg-warn/10 px-4 py-3 text-sm text-ink">
        {data.limits}
      </p>
      <Panel title="Detection">
        <SetsTable data={data} />
        <p className="border-t border-line px-4 py-3 text-xs text-muted">{data.matching_rule}</p>
      </Panel>
      {data.sets.heldout && (
        <Panel title="Held-out, by incident type">
          <TypesTable types={data.sets.heldout.by_type} />
        </Panel>
      )}
      <Panel title="Other measures">
        <ul className="list-disc space-y-1 px-8 py-4 text-sm text-ink">
          {noise?.false_alarms_per_10k_lines !== null && noise?.false_alarms_per_10k_lines !== undefined && (
            <li>
              False alarms on normal traffic: {noise.false_alarms_per_10k_lines.toFixed(2)} per 10,000 lines (
              {formatNumber(noise.lines)} lines).
            </li>
          )}
          {speeds.length > 0 && (
            <li>
              Speed: {formatNumber(Math.round(Math.min(...speeds)))} to {formatNumber(Math.round(Math.max(...speeds)))}{" "}
              lines per second for reading, detection and correlation.
            </li>
          )}
          {eff?.compression_ratio && (
            <li>
              Compression: {formatNumber(eff.lines)} lines become {eff.templates} message patterns,{" "}
              {Math.round(eff.compression_ratio)} to 1.
            </li>
          )}
          {eff && (
            <li>
              Evidence pack, what an LLM would be shown: median {eff.evidence_pack_tokens.median ?? "n/a"} and largest{" "}
              {eff.evidence_pack_tokens.largest ?? "n/a"} tokens (estimated), against a limit of{" "}
              {formatNumber(eff.evidence_pack_tokens.limit)}.
            </li>
          )}
          {data.explanations && !data.explanations.measured && (
            <li>Explanations: not measured ({data.explanations.why}).</li>
          )}
        </ul>
      </Panel>
      <Panel title={`Misses and false alarms (${data.problems.length})`}>
        <Problems data={data} />
      </Panel>
    </div>
  );
}

export default function EvaluationPage() {
  const evaluation = useEvaluation();
  const crumbs = [{ label: "Accuracy" }];
  let body;
  if (evaluation.error) {
    body =
      evaluation.error.status === 404 ? (
        <EmptyState title="No results yet">
          <p>
            Generate the test sets and run the harness, in PowerShell: <Code>.venv\Scripts\python -m eval.heldout</Code>{" "}
            then <Code>.venv\Scripts\python -m eval.harness</Code>.
          </p>
        </EmptyState>
      ) : (
        <ErrorState error={evaluation.error} onRetry={() => evaluation.refetch()} />
      );
    body = <Panel>{body}</Panel>;
  } else if (!evaluation.data) {
    body = (
      <Panel>
        <SkeletonRows rows={4} />
      </Panel>
    );
  } else {
    body = <Results data={evaluation.data} />;
  }
  return (
    <div>
      <PageHeader
        crumbs={crumbs}
        title="Accuracy"
        meta={
          evaluation.data ? (
            <span>
              Measured {formatLocalTime(evaluation.data.generated_at)}
              {evaluation.data.topology ? ", with a topology file" : ", from the logs alone"}
            </span>
          ) : undefined
        }
      />
      {body}
    </div>
  );
}
