// The cause-and-effect chain of an incident as a diagram, read left to right: the root cause
// first, then what it set off. Each box is a button that shows its evidence. The same chain
// is also written out as text, for screen readers and for anyone who prefers to read it.

import type { KeyboardEvent } from "react";
import type { IncidentDetail } from "../api/types";
import { chainLayout, chainSentences, NODE, nodeTitle, offsetLabel, wrap, type ChainNode } from "../lib/chain";

function edgePath(from: ChainNode, to: ChainNode): string {
  const x1 = from.x + NODE.width;
  const y1 = from.y + NODE.height / 2;
  const x2 = to.x;
  const y2 = to.y + NODE.height / 2;
  const bend = (x2 - x1) / 2;
  return `M${x1} ${y1} C${x1 + bend} ${y1} ${x2 - bend} ${y2} ${x2 - 6} ${y2}`;
}

function Node({
  node,
  selected,
  onSelect,
}: {
  node: ChainNode;
  selected: boolean;
  onSelect: (node: ChainNode) => void;
}) {
  const kind = nodeTitle(node);
  const lines = wrap(node.step.label, 34, 2);
  const devices = node.devices.join(", ");
  const press = (event: KeyboardEvent) => {
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      onSelect(node);
    }
  };
  const border = selected
    ? "stroke-accent"
    : node.suspect
      ? "stroke-warn"
      : node.root
        ? "stroke-root"
        : node.apart
          ? "stroke-faint"
          : "stroke-line-strong";
  return (
    <g
      transform={`translate(${node.x} ${node.y})`}
      role="button"
      tabIndex={0}
      aria-pressed={selected}
      aria-label={`${kind}: ${node.step.label}${devices ? `, on ${devices}` : ""}${offsetLabel(node) && !node.root ? `, ${offsetLabel(node)}` : ""}. Show its evidence.`}
      onClick={() => onSelect(node)}
      onKeyDown={press}
      className="cursor-pointer outline-none [&:focus-visible>rect]:stroke-accent [&:focus-visible>rect]:stroke-[3px]"
    >
      <title>{node.step.label}</title>
      <rect
        width={NODE.width}
        height={NODE.height}
        rx={8}
        className={`${node.suspect ? "fill-panel" : node.root ? "fill-root/15" : "fill-panel"} ${border} transition-colors`}
        strokeWidth={selected ? 3 : node.root ? 2 : 1}
        strokeDasharray={node.suspect || node.apart ? "6 4" : undefined}
      />
      <text x={12} y={20} className={`text-[10px] font-semibold tracking-wide uppercase ${node.suspect ? "fill-warn" : node.root ? "fill-root" : "fill-faint"}`}>
        {kind}
      </text>
      <text x={NODE.width - 12} y={20} textAnchor="end" className="fill-muted font-mono text-[10px]">
        {offsetLabel(node)}
      </text>
      {lines.map((line, i) => (
        <text key={i} x={12} y={40 + i * 15} className="fill-ink text-[12px]">
          {line}
        </text>
      ))}
      {devices && (
        <text x={12} y={74} className="fill-muted font-mono text-[10px]">
          {devices.length > 36 ? `${devices.slice(0, 35)}…` : devices}
        </text>
      )}
    </g>
  );
}

export function CausalChain({
  incident,
  selected,
  onSelect,
}: {
  incident: IncidentDetail;
  selected: number | null;
  onSelect: (node: ChainNode) => void;
}) {
  const layout = chainLayout(incident);
  const sentences = chainSentences(layout);
  const pad = 4;
  const described = `chain-text-${incident.id}`;
  return (
    <div>
      <div className="overflow-x-auto px-4 pt-4 pb-2">
        <svg
          role="group"
          aria-label={`Causal chain diagram with ${layout.nodes.length} ${layout.nodes.length === 1 ? "step" : "steps"}`}
          width={layout.width + pad * 2}
          height={layout.height + pad * 2}
          viewBox={`${-pad} ${-pad} ${layout.width + pad * 2} ${layout.height + pad * 2}`}
          aria-describedby={described}
          className="block font-sans"
        >
          <defs>
            <marker id="chain-arrow" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="7" markerHeight="7" orient="auto">
              <path d="M0 0L8 4L0 8Z" className="fill-faint" />
            </marker>
          </defs>
          {layout.edges.map((edge) => {
            const from = layout.nodes[edge.from];
            const to = layout.nodes[edge.to];
            const sure = edge.certainty === "direct";
            return (
              <path
                key={`${edge.from}-${edge.to}`}
                d={edgePath(from, to)}
                fill="none"
                markerEnd="url(#chain-arrow)"
                className={from.suspect ? "stroke-warn" : "stroke-faint"}
                strokeWidth={1.5}
                strokeDasharray={sure ? undefined : "5 4"}
              />
            );
          })}
          {layout.nodes.map((node) => (
            <Node key={node.index} node={node} selected={selected === node.index} onSelect={onSelect} />
          ))}
        </svg>
      </div>
      <div className="flex flex-wrap items-center gap-x-4 gap-y-1 px-4 pb-2 text-2xs text-muted">
        <span className="inline-flex items-center gap-1.5">
          <svg width="22" height="6" aria-hidden="true"><path d="M0 3H22" className="stroke-faint" strokeWidth="1.5" /></svg>
          direct: how the protocols work
        </span>
        <span className="inline-flex items-center gap-1.5">
          <svg width="22" height="6" aria-hidden="true"><path d="M0 3H22" className="stroke-faint" strokeWidth="1.5" strokeDasharray="5 4" /></svg>
          likely, not certain
        </span>
        {layout.nodes.some((node) => node.suspect) && (
          <span className="inline-flex items-center gap-1.5">
            <svg width="22" height="10" aria-hidden="true"><rect x="1" y="1" width="20" height="8" rx="2" fill="none" className="stroke-warn" strokeDasharray="4 3" /></svg>
            possible cause: came shortly before, not proven
          </span>
        )}
      </div>
      <p id={described} className="sr-only">
        {sentences.join(" ")}
      </p>
      <details className="border-t border-line px-4 py-2 text-sm">
        <summary className="cursor-pointer text-xs text-muted hover:text-ink">Read the chain as text</summary>
        <ol aria-label="The causal chain as text" className="mt-2 list-decimal space-y-1 pl-5 text-ink">
          {sentences.map((sentence, i) => (
            <li key={i}>{sentence}</li>
          ))}
        </ol>
      </details>
    </div>
  );
}
