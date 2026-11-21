// The replay of an incident, worked out without drawing anything: one step per step of the
// causal chain, in the chain's own order. The rules decided the steps and their order; the
// replay only walks through them. Each sentence of the explanation's timeline goes to the
// step whose log lines it rests on. A step with exactly one such sentence is told in that
// sentence; a step with several keeps its own label and lists them beneath.

import type { EvidenceLine, Explanation, IncidentDetail } from "../api/types";
import { chainLayout, nodeTitle, offsetLabel, type ChainNode } from "./chain";
import { linesOfFindings } from "./evidence";

export interface ReplayStep {
  /** The step of the causal chain this is. */
  node: ChainNode;
  /** "Root cause", "Possible cause", "Effect" or "Not explained by the root cause". */
  title: string;
  /** What happened, in one sentence. */
  sentence: string;
  /** Whether the sentence is the explanation's or the step's own label. */
  from: "explanation" | "chain";
  /** The explanation's sentences about the step, when it has more than one. */
  details: string[];
  /** When the step began, if any of its findings has a time. */
  time: string | null;
  /** The offset from the root cause, for example "+4s"; "start" for the root cause. */
  offset: string;
  devices: string[];
  /** The log lines in the evidence panel that support the step, in file order. */
  lines: number[];
  findings: number[];
}

/** How many of a step's sentences the replay lists before it says "and N more". */
export const DETAILS_SHOWN = 3;

/** The steps of the replay. An incident with one finding has one step. Each sentence of the
 * explanation's timeline is used once, for the step it shares the most lines with. */
export function replaySteps(
  incident: IncidentDetail,
  explanation: Explanation | undefined,
  lookup: Map<number, EvidenceLine>,
): ReplayStep[] {
  const starts = new Map(incident.finding_details.map((finding) => [finding.id, finding.start]));
  const steps: ReplayStep[] = chainLayout(incident).nodes.map((node) => {
    const times = node.step.findings
      .map((id) => starts.get(id))
      .filter((time): time is string => Boolean(time))
      .sort();
    return {
      node,
      title: nodeTitle(node),
      sentence: node.step.label,
      from: "chain",
      details: [],
      time: times[0] ?? null,
      offset: offsetLabel(node),
      devices: node.devices,
      lines: linesOfFindings(incident, lookup, node.step.findings),
      findings: node.step.findings,
    };
  });

  const told: string[][] = steps.map(() => []);
  for (const statement of explanation?.timeline ?? []) {
    const cited = new Set(statement.lines);
    let best = -1;
    let most = 0;
    steps.forEach((step, i) => {
      const shared = step.lines.filter((line) => cited.has(line)).length;
      if (shared > most) {
        best = i;
        most = shared;
      }
    });
    if (best >= 0) told[best].push(statement.text);
  }
  return steps.map((step, i) =>
    told[i].length === 1
      ? { ...step, sentence: told[i][0], from: "explanation" as const }
      : { ...step, details: told[i] },
  );
}

/** Whether the system asks for less motion. Steps then change with no animation. */
export function prefersReducedMotion(): boolean {
  return typeof window.matchMedia === "function" && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
}

/** What a screen reader hears when a step is shown. */
export function announce(step: ReplayStep, index: number, total: number): string {
  const devices = step.devices.length ? ` On ${step.devices.join(", ")}.` : "";
  const offset = step.offset && step.offset !== "start" ? ` ${step.offset} after the root cause.` : "";
  return `Step ${index + 1} of ${total}. ${step.title}: ${step.sentence}${/[.!?]$/.test(step.sentence) ? "" : "."}${devices}${offset}`;
}
