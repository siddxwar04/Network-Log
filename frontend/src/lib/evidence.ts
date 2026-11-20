// Turning an incident and its explanation into the evidence panel: every log line either
// one cites, grouped under the step of the causal chain it belongs to.

import type { EvidenceLine, Explanation, IncidentDetail, StoryStep } from "../api/types";

export interface EvidenceGroup {
  key: string;
  title: string;
  when: string;
  root: boolean;
  lines: EvidenceLine[];
}

/** Every line the incident or its explanation points to, once each, by line number. */
export function evidenceLines(
  incident: IncidentDetail,
  explanation?: Explanation,
  extra: EvidenceLine[] = [],
): Map<number, EvidenceLine> {
  const lines = new Map<number, EvidenceLine>();
  for (const line of [...incident.evidence, ...(explanation?.cited_lines ?? []), ...extra]) {
    const known = lines.get(line.line);
    lines.set(line.line, known?.findings ? known : { ...line, findings: line.findings ?? known?.findings });
  }
  return lines;
}

/** Which findings each line is evidence for. A finding lists only some of its lines, and
 * the incident's own evidence lists others, so both are read. */
function findingsByLine(incident: IncidentDetail): Map<number, Set<number>> {
  const owners = new Map<number, Set<number>>();
  const add = (line: number, finding: number) => {
    if (!owners.has(line)) owners.set(line, new Set());
    owners.get(line)!.add(finding);
  };
  for (const line of incident.evidence) for (const id of line.findings ?? []) add(line.line, id);
  for (const finding of incident.finding_details) {
    for (const line of finding.evidence) add(line.line, finding.id);
  }
  return owners;
}

function stepTitle(step: StoryStep, index: number): string {
  return index === 0 && step.depth === 0 ? `Root cause: ${step.label}` : step.label;
}

/** The lines grouped by step of the causal chain, in the chain's order. Each line shows
 * once, under the first step it belongs to; lines that belong to no step come last. */
export function groupEvidence(
  incident: IncidentDetail,
  lines: Map<number, EvidenceLine>,
): EvidenceGroup[] {
  const owners = findingsByLine(incident);
  const placed = new Set<number>();
  const sorted = [...lines.values()].sort((a, b) => a.line - b.line);
  const groups: EvidenceGroup[] = [];

  incident.story.forEach((step, index) => {
    const wanted = new Set(step.findings);
    const members = sorted.filter(
      (line) =>
        !placed.has(line.line) && [...(owners.get(line.line) ?? [])].some((id) => wanted.has(id)),
    );
    members.forEach((line) => placed.add(line.line));
    if (members.length) {
      groups.push({
        key: `step-${index}`,
        title: stepTitle(step, index),
        when: step.when,
        root: index === 0 && step.depth === 0,
        lines: members,
      });
    }
  });

  const rest = sorted.filter((line) => !placed.has(line.line));
  if (rest.length) {
    groups.push({ key: "other", title: "Other cited lines", when: "", root: false, lines: rest });
  }
  return groups;
}

/** The lines in the panel that are evidence for any of these findings, in file order. */
export function linesOfFindings(
  incident: IncidentDetail,
  lines: Map<number, EvidenceLine>,
  findings: number[],
): number[] {
  const owners = findingsByLine(incident);
  const wanted = new Set(findings);
  return [...lines.keys()]
    .filter((line) => [...(owners.get(line) ?? [])].some((id) => wanted.has(id)))
    .sort((a, b) => a - b);
}

/** The id of a line's row in the evidence panel, for scrolling to it. */
export function lineAnchor(line: number): string {
  return `evidence-line-${line}`;
}
