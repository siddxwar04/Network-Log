// The replay of an incident, worked out without drawing anything: the explanation's own
// account of what happened, one sentence at a time, each with the log lines it cites. Every
// sentence is placed under the step of the causal chain its lines belong to, so the box that
// lights up, and whether it is the root cause or an effect, still come from the rules. With
// no explanation to walk through, the steps are the causal chain's own.

import type { EvidenceLine, Explanation, IncidentDetail } from "../api/types";
import { chainLayout, nodeTitle, offsetLabel, type ChainNode } from "./chain";
import { linesOfFindings } from "./evidence";

export interface ReplayStep {
  /** The step of the causal chain this belongs to. */
  node: ChainNode;
  /** "Root cause", "Possible cause", "Effect" or "Not explained by the root cause". */
  title: string;
  /** What happened, in one sentence. */
  sentence: string;
  /** Whether the sentence is the explanation's or the chain step's own label. */
  from: "explanation" | "chain";
  /** When it happened, if its lines or findings have a time. */
  time: string | null;
  /** The chain step's offset from the root cause, for example "+4s"; "start" for the root cause. */
  offset: string;
  devices: string[];
  /** The log lines that support the step, in file order. */
  lines: number[];
}

/** One step per step of the causal chain, in the chain's order. */
function chainSteps(incident: IncidentDetail, lookup: Map<number, EvidenceLine>): ReplayStep[] {
  const starts = new Map(incident.finding_details.map((finding) => [finding.id, finding.start]));
  return chainLayout(incident).nodes.map((node) => {
    const times = node.step.findings
      .map((id) => starts.get(id))
      .filter((time): time is string => Boolean(time))
      .sort();
    return {
      node,
      title: nodeTitle(node),
      sentence: node.step.label,
      from: "chain",
      time: times[0] ?? null,
      offset: offsetLabel(node),
      devices: node.devices,
      lines: linesOfFindings(incident, lookup, node.step.findings),
    };
  });
}

/** The steps of the replay: the sentences of the explanation's timeline, in its order. Each
 * takes the chain step it shares the most log lines with; one that shares none stays with
 * the step before it. Without such sentences, the steps are the chain's own. */
export function replaySteps(
  incident: IncidentDetail,
  explanation: Explanation | undefined,
  lookup: Map<number, EvidenceLine>,
): ReplayStep[] {
  const chain = chainSteps(incident, lookup);
  const statements = explanation?.timeline ?? [];
  if (!chain.length || !statements.length) return chain;

  let previous = 0;
  return statements.map((statement) => {
    const cited = new Set(statement.lines);
    let best = previous;
    let most = 0;
    chain.forEach((step, i) => {
      const shared = step.lines.filter((line) => cited.has(line)).length;
      if (shared > most) {
        best = i;
        most = shared;
      }
    });
    previous = best;
    const own = [...cited].filter((line) => lookup.has(line)).sort((a, b) => a - b);
    const known = own.map((line) => lookup.get(line)!);
    const times = known.map((line) => line.time).filter((time): time is string => Boolean(time)).sort();
    const hosts = [...new Set(known.map((line) => line.host).filter((host): host is string => Boolean(host)))];
    return {
      ...chain[best],
      sentence: statement.text,
      from: "explanation" as const,
      time: times[0] ?? chain[best].time,
      devices: hosts.length ? hosts : chain[best].devices,
      lines: own.length ? own : chain[best].lines,
    };
  });
}

/** Whether the system asks for less motion. Steps then change with no animation. */
export function prefersReducedMotion(): boolean {
  return typeof window.matchMedia === "function" && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
}

/** What a screen reader hears when a step is shown. */
export function announce(step: ReplayStep, index: number, total: number): string {
  const devices = step.devices.length ? ` On ${step.devices.join(", ")}.` : "";
  return `Step ${index + 1} of ${total}. ${step.title}: ${step.sentence}${/[.!?]$/.test(step.sentence) ? "" : "."}${devices}`;
}
