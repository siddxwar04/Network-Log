import { screen, waitFor, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import type { Explanation, IncidentDetail, IncidentTimeline, TimelineEvent } from "../api/types";
import { chainLayout, chainSentences, wrap } from "../lib/chain";
import { clusterEvents, describeTimeline, laneNames, timelineRange } from "../lib/timeline";
import cascadeIncident from "./fixtures/cascade-incident.json";
import cascadeSenior from "./fixtures/cascade-explanation-senior.json";
import cascadeTimeline from "./fixtures/cascade-timeline.json";
import configIncident from "./fixtures/config-incident.json";
import configSenior from "./fixtures/config-explanation-senior.json";
import configTimeline from "./fixtures/config-timeline.json";
import flapIncident from "./fixtures/flap-incident.json";
import flapSenior from "./fixtures/flap-explanation-senior.json";
import flapTimeline from "./fixtures/flap-timeline.json";
import { HEALTH, mockApi, uploadDetail } from "./mockApi";
import { renderApp } from "./render";

// Real answers of the API, saved from runs of the backend on the sample scenarios.
const CASCADE = cascadeIncident as unknown as IncidentDetail;
const CASCADE_TIMELINE = cascadeTimeline as unknown as IncidentTimeline;
const FLAP = flapIncident as unknown as IncidentDetail;
const FLAP_TIMELINE = flapTimeline as unknown as IncidentTimeline;
const CONFIG = configIncident as unknown as IncidentDetail;

function open(incident: IncidentDetail, explanation: unknown, timeline: IncidentTimeline) {
  const base = `/api/uploads/1/incidents/${incident.id}`;
  mockApi({
    "GET /api/health": HEALTH,
    "GET /api/uploads/1": uploadDetail(),
    [`GET ${base}`]: incident,
    [`GET ${base}/explanation`]: explanation as Explanation,
    [`GET ${base}/timeline`]: timeline,
  });
  return renderApp(`/uploads/1/incidents/${incident.id}`);
}

/** An incident on 10 devices with 500 events, as a big outage would give: each device
 * reports a burst of 50 link and OSPF events, one every 1.2 seconds. */
function large(): IncidentTimeline {
  const lanes = Array.from({ length: 10 }, (_, i) => `SW${i + 1}`);
  const kinds = ["link", "ospf", "bgp", "login", "config", "dhcp", "system"] as const;
  const start = Date.parse("2026-03-03T02:00:00Z");
  const events: TimelineEvent[] = Array.from({ length: 500 }, (_, i) => ({
    id: i + 1,
    line: 1000 + i,
    time: new Date(start + i * 1200).toISOString(),
    host: lanes[Math.floor(i / 50)],
    event_key: null,
    kind: i % 2 ? "ospf" : "link",
    text: `event ${i}`,
    findings: [1],
    root_cause: i === 0,
  }));
  return {
    upload_id: 1,
    incident_id: "inc-big",
    start: events[0].time,
    end: events[499].time,
    lanes,
    kinds: [...kinds],
    events,
    total_events: 500,
    truncated: false,
  };
}

describe("the incident timeline", () => {
  it("scenario 2: the uplink fails first, at the top, and the routing protocols follow", () => {
    const lanes = laneNames(CASCADE_TIMELINE);
    expect(lanes[0]).toBe("R1"); // the root-cause device is on top
    const clusters = clusterEvents(CASCADE_TIMELINE, timelineRange(CASCADE_TIMELINE)!);
    const first = clusters.reduce((a, b) => (b.start < a.start ? b : a));
    expect(first.kind).toBe("link");
    expect(first.root).toBe(true);
    expect(lanes[first.lane]).toBe("R1");
    // OSPF and BGP markers follow, on the other routers too.
    const later = clusters.filter((cluster) => cluster.start > first.start);
    for (const kind of ["ospf", "bgp"]) {
      expect(later.some((cluster) => cluster.kind === kind && lanes[cluster.lane] !== "R1")).toBe(true);
    }
    expect(describeTimeline(CASCADE_TIMELINE)).toMatch(/^32 events on 4 devices over 9m 47s\. First: a Link event on R1 at 02:46:11 UTC, part of the root cause\./);
  });

  it("scenario 1: one device, the flaps merged into markers with a count", () => {
    const range = timelineRange(FLAP_TIMELINE)!;
    expect(laneNames(FLAP_TIMELINE)).toEqual(["R1"]);
    const clusters = clusterEvents(FLAP_TIMELINE, range);
    expect(clusters.reduce((sum, c) => sum + c.events.length, 0)).toBe(FLAP_TIMELINE.events.length);
    expect(clusters.every((cluster) => cluster.lane === 0)).toBe(true);
  });

  it("stays readable with 10 devices and 500 events: alike events merge, zooming splits them", () => {
    const timeline = large();
    const range = timelineRange(timeline)!;
    const clusters = clusterEvents(timeline, range);
    expect(laneNames(timeline)).toHaveLength(10);
    expect(clusters.reduce((sum, c) => sum + c.events.length, 0)).toBe(500);
    expect(clusters.length).toBeLessThan(200); // about 18 markers per lane, not 50
    expect(Math.max(...clusters.map((c) => c.events.length))).toBeGreaterThan(1);
    // Zoomed into the first minute: only those events, and fewer per marker.
    const minute = { start: range.start, end: range.start + 60_000 };
    const zoomed = clusterEvents(timeline, minute);
    expect(zoomed.reduce((sum, c) => sum + c.events.length, 0)).toBe(51);
    expect(Math.max(...zoomed.map((c) => c.events.length))).toBe(1);
  });

  it("draws the timeline on the page; clicking a marker finds its line, and zoom can be reset", async () => {
    const { user } = open(CASCADE, cascadeSenior, CASCADE_TIMELINE);

    const chart = await screen.findByTestId("timeline-chart");
    expect(chart).toHaveAttribute("data-lanes", "R1,R4,R2,R3");
    const figure = chart.closest("[role='img']")!;
    expect(figure).toHaveAccessibleName(/^32 events on 4 devices/);
    expect(screen.getByRole("list", { name: "Legend" })).toHaveTextContent(/Link.*OSPF.*BGP/);

    // A BGP marker on R2: its line was not in the evidence panel yet; now it is, and marked.
    await user.click(within(chart).getAllByRole("button", { name: /^Marker: bgp on R2/ })[0]);
    const marked = document.querySelector("[data-selected]")!;
    expect(marked).toHaveTextContent("R2");
    expect(marked).toHaveTextContent("%BGP");

    const reset = screen.getByRole("button", { name: "Reset zoom" });
    expect(reset).toBeDisabled();
    const before = Number(chart.getAttribute("data-markers"));
    await user.click(within(chart).getByRole("button", { name: "Drag to zoom" }));
    await waitFor(() => expect(reset).toBeEnabled());
    expect(Number(screen.getByTestId("timeline-chart").getAttribute("data-markers"))).toBeLessThan(before);
    await user.click(reset);
    expect(Number(screen.getByTestId("timeline-chart").getAttribute("data-markers"))).toBe(before);
  });

  it("renders scenario 1, a single device, on the page", async () => {
    open(FLAP, flapSenior, FLAP_TIMELINE);
    const chart = await screen.findByTestId("timeline-chart");
    expect(chart).toHaveAttribute("data-lanes", "R1");
  });
});

describe("the causal chain", () => {
  it("scenario 2: the root cause on the left, branching into its effects", () => {
    const layout = chainLayout(CASCADE);
    const [root, ...effects] = layout.nodes;
    expect(root.root).toBe(true);
    expect(root.x).toBe(0);
    expect(effects.every((node) => node.x > 0)).toBe(true);
    // The root has several children: the chain branches.
    expect(layout.edges.filter((edge) => edge.from === 0).length).toBeGreaterThan(1);
    // A second level: BGP on R1 follows OSPF on R1.
    const deep = layout.nodes.find((node) => node.column === 2)!;
    expect(deep.step.label).toMatch(/BGP/);
    expect(layout.nodes[deep.parent!].step.label).toMatch(/OSPF adjacency lost on R1/);
    // The root sits level with the middle of its branches.
    const children = layout.nodes.filter((node) => node.parent === 0);
    const middle = (Math.min(...children.map((n) => n.row)) + Math.max(...children.map((n) => n.row))) / 2;
    expect(root.row).toBe(middle);
  });

  it("scenario 1: a single finding is a single node", () => {
    const layout = chainLayout(FLAP);
    expect(layout.nodes).toHaveLength(1);
    expect(layout.edges).toHaveLength(0);
    expect(chainSentences(layout)).toEqual([`Root cause: ${FLAP.story[0].label}.`]);
  });

  it("shows a configuration change as a dashed possible cause leading into the failure", async () => {
    const layout = chainLayout(CONFIG);
    expect(layout.nodes[0].suspect).toBe(true);
    expect(chainSentences(layout)[0]).toMatch(/^Possible cause, not proven: The configuration of R2 was changed/);

    open(CONFIG, configSenior, configTimeline as unknown as IncidentTimeline);
    const diagram = await screen.findByRole("group", { name: /^Causal chain diagram with 2 steps/ });
    const suspect = within(diagram).getByRole("button", { name: /^Possible cause: The configuration of R2/ });
    expect(suspect.querySelector("rect")).toHaveAttribute("stroke-dasharray");
    expect(within(diagram).getByRole("button", { name: /^Effect: BGP session from R2 to 203\.0\.113\.1 went down/ })).toBeInTheDocument();
    expect(screen.getByText(/possible cause: came shortly before, not proven/)).toBeInTheDocument();
  });

  it("highlights a step's evidence when its box is clicked, and works by keyboard", async () => {
    const { user } = open(CASCADE, cascadeSenior, CASCADE_TIMELINE);

    const diagram = await screen.findByRole("group", { name: /^Causal chain diagram with 5 steps/ });
    const step = within(diagram).getByRole("button", { name: /^Effect: OSPF adjacency lost on R2, R3, R4/ });
    await user.click(step);
    expect(step).toHaveAttribute("aria-pressed", "true");
    // Every line of the step's findings: the adjacencies going down, and coming back.
    const marked = [...document.querySelectorAll("[data-selected]")];
    expect(marked.map((row) => row.id)).toEqual(
      expect.arrayContaining(["evidence-line-2284", "evidence-line-2287", "evidence-line-2288"]),
    );
    for (const row of marked) expect(row).toHaveTextContent(/%OSPF-5-ADJCHG.*Nbr 10\.255\.0\.1/);
    expect(marked[0]).toHaveFocus();

    const root = within(diagram).getByRole("button", { name: /^Root cause: Interface GigabitEthernet0\/1 on R1/ });
    root.focus();
    await user.keyboard("{Enter}");
    expect(root).toHaveAttribute("aria-pressed", "true");
    expect(document.getElementById("evidence-line-2260")).toHaveAttribute("data-selected");
  });

  it("is written out as text for screen readers", async () => {
    open(CASCADE, cascadeSenior, CASCADE_TIMELINE);
    const list = await screen.findByRole("list", { name: "The causal chain as text", hidden: true });
    const items = within(list).getAllByRole("listitem", { hidden: true });
    expect(items).toHaveLength(5);
    expect(items[0]).toHaveTextContent("Root cause: Interface GigabitEthernet0/1 on R1 was down for 8m 36s.");
    expect(items[2]).toHaveTextContent(/BGP session down on R1.*caused by "OSPF adjacency lost on R1/);
  });

  it("wraps long labels onto two lines with an ellipsis", () => {
    expect(wrap("short label")).toEqual(["short label"]);
    const lines = wrap("The configuration of R2 was changed by jdoe from 10.10.10.53 shortly before the failure", 34, 2);
    expect(lines).toHaveLength(2);
    expect(lines[1].endsWith("…")).toBe(true);
    expect(lines.every((line) => line.length <= 35)).toBe(true);
  });
});
