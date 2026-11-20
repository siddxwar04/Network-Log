// The causal chain as a diagram: the root cause on the left, its effects to the right,
// branching where one cause has several effects. Laid out here, without drawing, so the
// layout can be tested and the same chain told in words.

import type { IncidentDetail, StoryStep } from "../api/types";

export const NODE = { width: 232, height: 84, columnGap: 56, rowGap: 14 };

export interface ChainNode {
  index: number;
  step: StoryStep;
  parent: number | null;
  column: number;
  row: number;
  x: number;
  y: number;
  devices: string[];
  root: boolean;
  /** A configuration change that came shortly before: a possible cause, not a proven one. */
  suspect: boolean;
  /** A finding the root cause does not account for. It is shown apart, unconnected. */
  apart: boolean;
}

export interface ChainEdge {
  from: number;
  to: number;
  certainty: string | null;
}

export interface ChainLayout {
  nodes: ChainNode[];
  edges: ChainEdge[];
  width: number;
  height: number;
}

function devicesOf(incident: IncidentDetail, step: StoryStep): string[] {
  const byId = new Map(incident.finding_details.map((finding) => [finding.id, finding]));
  const hosts = step.findings.map((id) => byId.get(id)?.host).filter((host): host is string => Boolean(host));
  return [...new Set(hosts)];
}

/** Places each step of the story. The story lists steps depth first, so a step's parent is
 * the nearest step before it one level up. Leaves take one row each, in story order, and a
 * parent sits level with the middle of its children. */
export function chainLayout(incident: IncidentDetail): ChainLayout {
  const steps = incident.story;
  const parents: (number | null)[] = [];
  steps.forEach((step, i) => {
    let parent: number | null = null;
    for (let j = i - 1; j >= 0; j -= 1) {
      if (steps[j].depth === step.depth - 1) {
        parent = j;
        break;
      }
    }
    parents.push(step.depth === 0 || !step.explained ? null : parent);
  });
  const children = steps.map((_, i) => parents.flatMap((p, j) => (p === i ? [j] : [])));

  const rows: number[] = new Array(steps.length).fill(0);
  let next = 0;
  const place = (i: number): number => {
    if (!children[i].length) {
      rows[i] = next;
      next += 1;
    } else {
      const placed = children[i].map(place);
      rows[i] = (placed[0] + placed[placed.length - 1]) / 2;
    }
    return rows[i];
  };
  steps.forEach((_, i) => {
    if (parents[i] === null) place(i);
  });

  const rootKind = incident.root_cause?.kind;
  const nodes: ChainNode[] = steps.map((step, i) => {
    const apart = !step.explained;
    const root = i === 0 && step.depth === 0 && !apart;
    const column = apart ? 0 : step.depth;
    return {
      index: i,
      step,
      parent: parents[i],
      column,
      row: rows[i],
      x: column * (NODE.width + NODE.columnGap),
      y: rows[i] * (NODE.height + NODE.rowGap),
      devices: devicesOf(incident, step),
      root,
      suspect: root && rootKind === "config_change",
      apart,
    };
  });
  const edges = nodes.flatMap((node) =>
    node.parent === null ? [] : [{ from: node.parent, to: node.index, certainty: node.step.certainty }],
  );
  const columns = Math.max(1, ...nodes.map((node) => node.column + 1));
  const lastRow = Math.max(0, ...nodes.map((node) => node.row));
  return {
    nodes,
    edges,
    width: columns * NODE.width + (columns - 1) * NODE.columnGap,
    height: (lastRow + 1) * NODE.height + lastRow * NODE.rowGap,
  };
}

/** When a step happened, measured from the root cause. */
export function offsetLabel(node: ChainNode): string {
  if (node.root) return "start";
  return node.step.when || "";
}

export function nodeTitle(node: ChainNode): string {
  if (node.suspect) return "Possible cause";
  if (node.root) return "Root cause";
  if (node.apart) return "Not explained by the root cause";
  return "Effect";
}

/** Split a label into at most `lines` lines of about `width` characters, ending with an
 * ellipsis when it does not fit. SVG text does not wrap by itself. */
export function wrap(text: string, width = 32, lines = 2): string[] {
  const words = text.split(/\s+/);
  const out: string[] = [];
  let current = "";
  for (const word of words) {
    const candidate = current ? `${current} ${word}` : word;
    if (candidate.length <= width || !current) {
      current = candidate;
      continue;
    }
    out.push(current);
    current = word;
    if (out.length === lines) break;
  }
  if (out.length < lines && current) out.push(current);
  const used = out.join(" ").length;
  if (used < text.length) {
    const last = out[out.length - 1];
    out[out.length - 1] = `${last.slice(0, Math.max(0, width - 1)).trimEnd()}…`;
  }
  return out.map((line) => (line.length > width + 1 ? `${line.slice(0, width - 1)}…` : line));
}

/** The chain in words, one sentence per step, for screen readers and for reading. */
export function chainSentences(layout: ChainLayout): string[] {
  return layout.nodes.map((node) => {
    if (node.suspect) return `Possible cause, not proven: ${node.step.label}.`;
    if (node.root) return `Root cause: ${node.step.label}.`;
    if (node.apart) return `Not explained by the root cause: ${node.step.label}.`;
    const parent = layout.nodes[node.parent ?? 0];
    const when = node.step.when ? ` (${node.step.when})` : "";
    const certainty = node.step.certainty ? `, ${node.step.certainty}` : "";
    return `${node.step.label}${when}, caused by "${parent.step.label}"${certainty}.`;
  });
}
