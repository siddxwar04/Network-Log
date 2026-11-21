import { act, fireEvent, screen, waitFor, within } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import type { Explanation, IncidentDetail, IncidentTimeline, StoryStep } from "../api/types";
import { evidenceLines } from "../lib/evidence";
import { announce, replaySteps } from "../lib/replay";
import cascadeIncident from "./fixtures/cascade-incident.json";
import cascadeSenior from "./fixtures/cascade-explanation-senior.json";
import cascadeTimeline from "./fixtures/cascade-timeline.json";
import configIncident from "./fixtures/config-incident.json";
import configSenior from "./fixtures/config-explanation-senior.json";
import flapIncident from "./fixtures/flap-incident.json";
import flapSenior from "./fixtures/flap-explanation-senior.json";
import flapTimeline from "./fixtures/flap-timeline.json";
import { HEALTH, mockApi, uploadDetail } from "./mockApi";
import { renderApp } from "./render";

// The real answers of the API for the demo scenarios, saved from a run of the backend with
// no LLM: the explanations are the built-in ones.
const CASCADE = cascadeIncident as unknown as IncidentDetail;
const CASCADE_SENIOR = cascadeSenior as unknown as Explanation;
const CASCADE_TIMELINE = cascadeTimeline as unknown as IncidentTimeline;
const FLAP = flapIncident as unknown as IncidentDetail;
const FLAP_SENIOR = flapSenior as unknown as Explanation;
const FLAP_TIMELINE = flapTimeline as unknown as IncidentTimeline;
const CONFIG = configIncident as unknown as IncidentDetail;
const CONFIG_SENIOR = configSenior as unknown as Explanation;

const STEP_MS = HEALTH.replay.step_seconds * 1000;

function open(incident: IncidentDetail, explanation: Explanation, timeline: IncidentTimeline, health = HEALTH) {
  const base = `/api/uploads/1/incidents/${incident.id}`;
  mockApi({
    "GET /api/health": health,
    "GET /api/uploads/1": uploadDetail(),
    [`GET ${base}`]: incident,
    [`GET ${base}/explanation`]: explanation,
    [`GET ${base}/timeline`]: timeline,
  });
  return renderApp(`/uploads/1/incidents/${incident.id}`);
}

function steps(incident: IncidentDetail, explanation?: Explanation) {
  return replaySteps(incident, explanation, evidenceLines(incident, explanation));
}

async function start(user: ReturnType<typeof renderApp>["user"]) {
  await user.click(await screen.findByRole("button", { name: "Replay step by step" }));
  return screen.getByRole("region", { name: "Replay" });
}

/** Starts the replay with the test's own clock in charge of Play: the timer of the first
 * step was set on the real clock, so Play is pressed again once the clock is the test's. */
async function startOnTestClock(user: ReturnType<typeof renderApp>["user"]) {
  const bar = await start(user);
  expect(within(bar).getByRole("button", { name: "Pause" })).toBeInTheDocument(); // it plays at once
  fireEvent.click(within(bar).getByRole("button", { name: "Pause" }));
  vi.useFakeTimers();
  fireEvent.click(within(bar).getByRole("button", { name: "Play" }));
  return bar;
}

/** Which box of the chain is marked, by its label. */
function markedBox(): string | null {
  const chain = screen.getByRole("group", { name: /Causal chain diagram/ });
  const pressed = within(chain).getAllByRole("button").filter((box) => box.getAttribute("aria-pressed") === "true");
  return pressed.length === 1 ? pressed[0].getAttribute("aria-label") : null;
}

function markedLines(): number {
  return document.querySelectorAll("[data-selected]").length;
}

describe("the steps of a replay", () => {
  it("scenario 1: the built-in explanation tells it in one sentence, so one step", () => {
    const only = steps(FLAP, FLAP_SENIOR);
    expect(only).toHaveLength(1);
    expect(only[0].title).toBe("Root cause");
    expect(only[0].sentence).toBe(FLAP_SENIOR.timeline[0].text);
    expect(only[0].lines).toEqual(FLAP_SENIOR.timeline[0].lines);
  });

  it("an explanation that tells a single finding in three sentences gives three steps", () => {
    const [first] = FLAP_SENIOR.timeline;
    const told = {
      ...FLAP_SENIOR,
      timeline: first.lines.map((line, i) => ({ ...first, text: `Down number ${i + 1}.`, lines: [line] })),
    };
    const all = steps(FLAP, told);
    expect(all.map((step) => step.sentence)).toEqual(["Down number 1.", "Down number 2.", "Down number 3."]);
    expect(all.map((step) => step.lines)).toEqual(first.lines.map((line) => [line]));
    // All three belong to the one box of the chain, the root cause.
    expect(all.every((step) => step.node.index === 0 && step.title === "Root cause")).toBe(true);
  });

  it("scenario 2: one step per sentence of the explanation, in its order, each with its lines", () => {
    const all = steps(CASCADE, CASCADE_SENIOR);
    expect(all.map((step) => step.sentence)).toEqual(CASCADE_SENIOR.timeline.map((statement) => statement.text));
    expect(all.map((step) => step.lines)).toEqual(CASCADE_SENIOR.timeline.map((statement) => statement.lines));
    expect(all.every((step) => step.from === "explanation")).toBe(true);
    // The link first, the root cause; then OSPF on R1; then BGP on R1.
    expect(all[0].title).toBe("Root cause");
    expect(all[0].devices).toEqual(["R1"]);
    expect(all.slice(1).every((step) => step.title === "Effect")).toBe(true);
    const boxes = all.map((step) => step.node.step.label);
    expect(boxes[0]).toMatch(/^Interface GigabitEthernet0\/1 on R1/);
    expect(boxes.slice(1, 4).every((label) => /^OSPF adjacency lost on R1/.test(label))).toBe(true);
    expect(boxes[4]).toMatch(/^BGP session down on R1/);
    expect(all[4].offset).toBe("+20s to +24s");
    // A sentence about another router names that router, from its own log lines.
    expect(all[6].sentence).toMatch(/BGP session from R4/);
    expect(all[6].devices).toEqual(["R4"]);
    expect(all[6].node.step.label).toMatch(/^BGP session down on R2, R3, R4/);
    expect(all.every((step) => step.time)).toBe(true);
  });

  it("works with no explanation at all: the steps are the causal chain's own", () => {
    const all = steps(CASCADE);
    expect(all.map((step) => step.sentence)).toEqual(CASCADE.story.map((step) => step.label));
    expect(all.every((step) => step.from === "chain" && step.lines.length > 0)).toBe(true);
    expect(all[0].time).toBe("2026-03-03T02:46:11.699000Z");
  });

  it("keeps a sentence that cites no known line with the step before it", () => {
    const told = {
      ...CASCADE_SENIOR,
      timeline: [CASCADE_SENIOR.timeline[1], { text: "And then something else.", lines: [999999], evidence: [] }],
    };
    const all = steps(CASCADE, told);
    expect(all[1].node.index).toBe(all[0].node.index);
    expect(all[1].lines).toEqual(steps(CASCADE)[all[0].node.index].lines);
  });

  it("labels a configuration change as a possible cause", () => {
    const all = steps(CONFIG, CONFIG_SENIOR);
    expect(all).toHaveLength(2);
    expect(all[0].title).toBe("Possible cause");
    expect(all[1].title).toBe("Effect");
    expect(announce(all[0], 0, all.length)).toMatch(/^Step 1 of 2\. Possible cause: /);
  });

  it("stays quick for an incident with 10 devices and 500 events", () => {
    const findings = Array.from({ length: 50 }, (_, i) => i + 1);
    const story: StoryStep[] = findings.map((id, i) => ({
      depth: i === 0 ? 0 : 1,
      label: `Finding ${id}`,
      when: i === 0 ? "" : `+${i}s`,
      certainty: i === 0 ? null : "direct",
      explanation: null,
      explained: true,
      findings: [id],
      evidence: [],
    }));
    const big = {
      ...CASCADE,
      story,
      finding_details: findings.map((id) => ({ ...CASCADE.finding_details[0], id, host: `SW${(id % 10) + 1}`, evidence: [] })),
      evidence: Array.from({ length: 500 }, (_, i) => ({
        line: i + 1,
        time: "2026-03-03T02:00:00Z",
        host: `SW${(i % 10) + 1}`,
        event_key: null,
        kind: "link" as const,
        text: `line ${i + 1}`,
        findings: [(i % 50) + 1],
      })),
    } as unknown as IncidentDetail;
    const told = {
      ...CASCADE_SENIOR,
      cited_lines: [],
      timeline: Array.from({ length: 500 }, (_, i) => ({ text: `Sentence ${i + 1}.`, lines: [i + 1], evidence: [] })),
    } as unknown as Explanation;
    const began = performance.now();
    const all = steps(big, told);
    expect(performance.now() - began).toBeLessThan(1000);
    expect(all).toHaveLength(500);
    expect(all[57].node.step.findings).toEqual([8]); // line 58 belongs to finding 8
    expect(steps(big)).toHaveLength(50);
  });
});

describe("the replay on the incident page", () => {
  it("scenario 2: walks the explanation sentence by sentence, marking the box, the markers and the lines", async () => {
    const { user } = open(CASCADE, CASCADE_SENIOR, CASCADE_TIMELINE);
    const bar = await start(user);
    // Paused, so the steps move only when the test moves them.
    await user.click(within(bar).getByRole("button", { name: "Pause" }));
    const told = CASCADE_SENIOR.timeline;

    // Step 1: the link on R1, the root cause.
    expect(within(bar).getByText("Step 1 of 13")).toBeInTheDocument();
    expect(within(bar).getByText("Root cause")).toBeInTheDocument();
    expect(within(bar).getByText(told[0].text)).toBeInTheDocument();
    expect(markedBox()).toMatch(/^Root cause: Interface GigabitEthernet0\/1 on R1/);
    expect(markedLines()).toBe(told[0].lines.length);
    await waitFor(() => expect(document.querySelectorAll("[data-current]").length).toBeGreaterThan(0));
    const rootMarkers = [...document.querySelectorAll("[data-current]")].map((marker) => marker.textContent);
    expect(rootMarkers.every((text) => text?.startsWith("Marker: link on R1"))).toBe(true);
    // A screen reader hears the step.
    expect(within(bar).getByRole("status")).toHaveTextContent(/^Step 1 of 13\. Root cause: .*On R1\./);

    // Step 2: the first OSPF sentence, under the OSPF box, with its own lines only.
    await user.click(within(bar).getByRole("button", { name: "Next" }));
    expect(within(bar).getByText("Step 2 of 13")).toBeInTheDocument();
    expect(within(bar).getByText(told[1].text)).toBeInTheDocument();
    expect(markedBox()).toMatch(/^Effect: OSPF adjacency lost on R1/);
    expect(markedLines()).toBe(told[1].lines.length);

    // Step 5: the first BGP sentence.
    for (let i = 0; i < 3; i += 1) await user.click(within(bar).getByRole("button", { name: "Next" }));
    expect(within(bar).getByText(told[4].text)).toBeInTheDocument();
    expect(markedBox()).toMatch(/^Effect: BGP session down on R1/);
    expect(within(bar).getByText("+20s to +24s")).toBeInTheDocument();
    const bgp = [...document.querySelectorAll("[data-current]")].map((marker) => marker.textContent);
    expect(bgp.length).toBeGreaterThan(0);
    expect(bgp.every((text) => text?.startsWith("Marker: bgp on R1"))).toBe(true);

    // Back goes back; at the first step it is disabled.
    for (let i = 0; i < 4; i += 1) await user.click(within(bar).getByRole("button", { name: "Back" }));
    expect(within(bar).getByText("Step 1 of 13")).toBeInTheDocument();
    expect(within(bar).getByRole("button", { name: "Back" })).toBeDisabled();
  }, 20_000); // many clicks: slow when every test file runs at once

  it("without an explanation's timeline it walks the causal chain instead", async () => {
    const { user } = open(CASCADE, { ...CASCADE_SENIOR, timeline: [] }, CASCADE_TIMELINE);
    const bar = await start(user);
    expect(within(bar).getByText("Step 1 of 5")).toBeInTheDocument();
    await user.click(within(bar).getByRole("button", { name: "Next" }));
    expect(within(bar).getByText(CASCADE.story[1].label)).toBeInTheDocument();
    expect(markedBox()).toMatch(/^Effect: OSPF adjacency lost on R1/);
  });

  it("scenario 1: one step, with nothing to play and nowhere to go", async () => {
    const { user } = open(FLAP, FLAP_SENIOR, FLAP_TIMELINE);
    const bar = await start(user);
    expect(within(bar).getByText("Step 1 of 1")).toBeInTheDocument();
    expect(within(bar).getByRole("button", { name: "Back" })).toBeDisabled();
    expect(within(bar).getByRole("button", { name: "Next" })).toBeDisabled();
    expect(within(bar).getByRole("button", { name: "Play" })).toBeInTheDocument();
  });

  it("draws the steps as a track of numbered circles joined by arrows, and any can be clicked", async () => {
    const { user } = open(CASCADE, CASCADE_SENIOR, CASCADE_TIMELINE);
    const bar = await start(user);
    const track = within(bar).getByRole("list", { name: "Steps" });
    const circles = () => within(track).getAllByRole("button");
    expect(circles()).toHaveLength(13);
    expect(circles().map((circle) => circle.textContent)).toEqual(Array.from({ length: 13 }, (_, i) => String(i + 1)));
    // An arrow after each step but the last.
    expect(track.querySelectorAll("svg")).toHaveLength(12);
    expect(circles()[0]).toHaveAttribute("aria-current", "step");
    expect(circles()[0]).toHaveAccessibleName("Go to step 1: Root cause");

    // Clicking a circle goes straight to that step, and stops Play.
    await user.click(circles()[4]);
    expect(within(bar).getByText("Step 5 of 13")).toBeInTheDocument();
    expect(circles()[4]).toHaveAttribute("aria-current", "step");
    expect(circles()[0]).not.toHaveAttribute("aria-current");
    expect(markedBox()).toMatch(/^Effect: BGP session down on R1/);
    expect(within(bar).getByRole("button", { name: "Play" })).toBeInTheDocument();
  });

  it("a one-step replay draws no track", async () => {
    const { user } = open(FLAP, FLAP_SENIOR, FLAP_TIMELINE);
    const bar = await start(user);
    expect(within(bar).queryByRole("list", { name: "Steps" })).not.toBeInTheDocument();
  });

  it("plays by itself with the delay the API gives, stops on the last step, and can pause", async () => {
    const { user } = open(CASCADE, CASCADE_SENIOR, CASCADE_TIMELINE);
    const bar = await startOnTestClock(user);
    act(() => void vi.advanceTimersByTime(STEP_MS - 100));
    expect(within(bar).getByText("Step 1 of 13")).toBeInTheDocument();
    act(() => void vi.advanceTimersByTime(100));
    expect(within(bar).getByText("Step 2 of 13")).toBeInTheDocument();

    // Pause holds the step.
    fireEvent.click(within(bar).getByRole("button", { name: "Pause" }));
    act(() => void vi.advanceTimersByTime(STEP_MS * 3));
    expect(within(bar).getByText("Step 2 of 13")).toBeInTheDocument();

    // Play goes on to the end and stops there.
    fireEvent.click(within(bar).getByRole("button", { name: "Play" }));
    for (let i = 0; i < 13; i += 1) act(() => void vi.advanceTimersByTime(STEP_MS));
    expect(within(bar).getByText("Step 13 of 13")).toBeInTheDocument();
    expect(within(bar).getByRole("button", { name: "Play" })).toBeInTheDocument();

    // From the end, Play starts over.
    fireEvent.click(within(bar).getByRole("button", { name: "Play" }));
    expect(within(bar).getByText("Step 1 of 13")).toBeInTheDocument();
  });

  it("uses another delay when the settings say so", async () => {
    const { user } = open(CASCADE, CASCADE_SENIOR, CASCADE_TIMELINE, { ...HEALTH, replay: { step_seconds: 1 } });
    const bar = await startOnTestClock(user);
    act(() => void vi.advanceTimersByTime(999));
    expect(within(bar).getByText("Step 1 of 13")).toBeInTheDocument();
    act(() => void vi.advanceTimersByTime(1));
    expect(within(bar).getByText("Step 2 of 13")).toBeInTheDocument();
  });

  it("is driven by the keyboard: arrows step, space plays and pauses, Escape leaves", async () => {
    const { user } = open(CASCADE, CASCADE_SENIOR, CASCADE_TIMELINE);
    const bar = await start(user);
    // Focus is on Play and Pause, so space reaches it at once.
    expect(within(bar).getByRole("button", { name: "Pause" })).toHaveFocus();
    await user.keyboard(" ");
    expect(within(bar).getByRole("button", { name: "Play" })).toBeInTheDocument();

    await user.keyboard("{ArrowRight}{ArrowRight}");
    expect(within(bar).getByText("Step 3 of 13")).toBeInTheDocument();
    await user.keyboard("{ArrowLeft}");
    expect(within(bar).getByText("Step 2 of 13")).toBeInTheDocument();
    expect(markedBox()).toMatch(/^Effect: OSPF adjacency lost on R1/);

    // Away from any button, space still plays and pauses.
    (document.activeElement as HTMLElement).blur();
    await user.keyboard(" ");
    expect(within(bar).getByRole("button", { name: "Pause" })).toBeInTheDocument();

    await user.keyboard("{Escape}");
    expect(screen.queryByRole("region", { name: "Replay" })).not.toBeInTheDocument();
  });

  it("puts the page back as it was when it is left", async () => {
    const { user } = open(CASCADE, CASCADE_SENIOR, CASCADE_TIMELINE);
    // A box of the chain was picked before the replay.
    const chain = await screen.findByRole("group", { name: /Causal chain diagram/ });
    await screen.findByRole("button", { name: "Replay step by step" });
    await user.click(within(chain).getAllByRole("button")[3]);
    const box = markedBox();
    const lines = markedLines();
    expect(box).not.toBeNull();

    const bar = await start(user);
    await user.click(within(bar).getByRole("button", { name: "Next" }));
    expect(markedBox()).not.toBe(box);
    await waitFor(() => expect(document.querySelectorAll("[data-current]").length).toBeGreaterThan(0));

    await user.click(within(bar).getByRole("button", { name: "Exit" }));
    expect(screen.queryByRole("region", { name: "Replay" })).not.toBeInTheDocument();
    expect(markedBox()).toBe(box);
    expect(markedLines()).toBe(lines);
    expect(document.querySelectorAll("[data-current]")).toHaveLength(0);
    const again = screen.getByRole("button", { name: "Replay step by step" });
    expect(again).toBeEnabled();
    await waitFor(() => expect(again).toHaveFocus());
  });

  it("with reduced motion asked for: no animation, and Play still works", async () => {
    vi.stubGlobal("matchMedia", (query: string) => ({
      matches: query.includes("prefers-reduced-motion"),
      media: query,
      addEventListener: () => {},
      removeEventListener: () => {},
      addListener: () => {},
      removeListener: () => {},
    }));
    const { user } = open(CASCADE, CASCADE_SENIOR, CASCADE_TIMELINE);
    const bar = await start(user);
    const sentence = within(bar).getByText(CASCADE_SENIOR.timeline[0].text);
    expect(sentence).toHaveAttribute("data-motion", "off");
    expect(sentence).not.toHaveClass("replay-step");

    fireEvent.click(within(bar).getByRole("button", { name: "Pause" }));
    vi.useFakeTimers();
    fireEvent.click(within(bar).getByRole("button", { name: "Play" }));
    act(() => void vi.advanceTimersByTime(STEP_MS));
    expect(within(bar).getByText("Step 2 of 13")).toBeInTheDocument();
  });

  it("shows log text and sentences as plain text", async () => {
    const hostile = {
      ...CASCADE_SENIOR,
      timeline: [{ ...CASCADE_SENIOR.timeline[0], text: '<img src=x onerror="alert(1)"> the link failed' }],
    };
    const { user } = open(CASCADE, hostile, CASCADE_TIMELINE);
    const bar = await start(user);
    expect(within(bar).getByText('<img src=x onerror="alert(1)"> the link failed')).toBeInTheDocument();
    expect(bar.querySelector("img")).toBeNull();
  });
});
