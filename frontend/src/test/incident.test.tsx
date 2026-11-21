import { screen, waitFor, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import type { Explanation, IncidentDetail } from "../api/types";
import { evidenceLines, groupEvidence } from "../lib/evidence";
import incidentJson from "./fixtures/cascade-incident.json";
import juniorJson from "./fixtures/cascade-explanation-junior.json";
import seniorJson from "./fixtures/cascade-explanation-senior.json";
import { HEALTH, mockApi, notFound, uploadDetail, type Call } from "./mockApi";
import { renderApp } from "./render";

// The real answers of the API for the cascade sample, saved from a run of the backend.
const INCIDENT = incidentJson as unknown as IncidentDetail;
const SENIOR = seniorJson as unknown as Explanation;
const JUNIOR = juniorJson as unknown as Explanation;
const ID = INCIDENT.id;
const BASE = `/api/uploads/1/incidents/${ID}`;
const PAGE = `/uploads/1/incidents/${ID}`;

function routes(overrides: Parameters<typeof mockApi>[0] = {}) {
  return {
    "GET /api/health": HEALTH,
    "GET /api/uploads/1": uploadDetail({ filename: "02_cascade.log" }),
    [`GET ${BASE}`]: INCIDENT,
    [`GET ${BASE}/explanation`]: SENIOR,
    ...overrides,
  };
}

/** Explanations answered by mode, as the API does. */
function byMode() {
  const calls: string[] = [];
  mockApi(
    routes({
      [`GET ${BASE}/explanation`]: (call: Call) => {
        const mode = call.query.get("mode") ?? "";
        calls.push(mode);
        return mode === "junior" ? JUNIOR : SENIOR;
      },
    }),
  );
  return { calls };
}

function evidence(): HTMLElement {
  return screen.getByRole("region", { name: "Evidence" });
}

function explanation(): HTMLElement {
  return screen.getByRole("region", { name: /^Explanation/ });
}

describe("the incident page", () => {
  it("shows the facts, the explanation and the evidence of the cascade", async () => {
    mockApi(routes());
    renderApp(PAGE);

    expect(
      await screen.findByRole("heading", { level: 1, name: INCIDENT.headline }),
    ).toBeInTheDocument();
    expect(screen.getByText("Critical")).toBeInTheDocument();
    expect(screen.getByText("high")).toBeInTheDocument();
    expect(screen.getByText("R1, R2, R3, R4")).toBeInTheDocument();
    // What the logs cannot say has a section of its own.
    const unknowns = screen.getByRole("region", { name: "What these logs cannot tell us" });
    expect(within(unknowns).getByText(/Why the interface went down/)).toBeInTheDocument();

    expect(await within(explanation()).findByRole("heading", { name: "Summary" })).toBeInTheDocument();
    // The first thing to do is at the top, with the way to the rest.
    const glance = screen.getByRole("region", { name: "At a glance" });
    expect(within(glance).getByText("Do this first")).toBeInTheDocument();
    expect(within(glance).getByRole("link", { name: /how to check/i })).toHaveAttribute("href", "#what-to-do");
    // Evidence grouped by step of the chain, the root cause first.
    const groups = within(evidence()).getAllByRole("region");
    expect(groups[0]).toHaveAccessibleName(/^Root cause: Interface GigabitEthernet0\/1 on R1/);
    expect(within(groups[0]).getByText(/%LINK-3-UPDOWN: Interface GigabitEthernet0\/1, changed state to down/)).toBeInTheDocument();
    expect(within(evidence()).getByText("Line 2288")).toBeInTheDocument();
  });

  it("highlights the right line when a citation is clicked, by mouse or keyboard", async () => {
    mockApi(routes());
    const { user } = renderApp(PAGE);

    const steps = await screen.findByRole("heading", { name: "What happened, step by step" });
    const list = steps.parentElement!;
    // "02:46:46 UTC: OSPF adjacency from R3 to 10.255.0.1 was lost." cites line 2284.
    await user.click(within(list).getByRole("button", { name: "Line 2284 on R3" }));

    const row = document.getElementById("evidence-line-2284")!;
    expect(row).toHaveAttribute("aria-current", "true");
    expect(row).toHaveTextContent("Dead timer expired");
    await waitFor(() => expect(row).toHaveFocus());
    expect(document.querySelectorAll("[aria-current='true'][data-selected]")).toHaveLength(1);

    // The keyboard does the same.
    const other = within(list).getByRole("button", { name: "Line 2260 on R1" });
    other.focus();
    await user.keyboard("{Enter}");
    expect(document.getElementById("evidence-line-2260")).toHaveAttribute("aria-current", "true");
    expect(row).not.toHaveAttribute("aria-current");
  });

  it("previews the cited line when a citation is hovered or focused", async () => {
    mockApi(routes());
    renderApp(PAGE);

    const steps = await screen.findByRole("heading", { name: "What happened, step by step" });
    const marker = within(steps.parentElement!).getByRole("button", { name: "Line 2284 on R3" });
    const preview = document.getElementById(marker.getAttribute("aria-describedby")!)!;
    expect(preview).toHaveAttribute("role", "tooltip");
    expect(preview).toHaveTextContent("Line 2284 · R3 · 02:46:46 UTC");
    expect(preview).toHaveTextContent("%OSPF-5-ADJCHG: Process 1, Nbr 10.255.0.1");
  });

  it("switches between the junior and senior explanation and keeps the facts", async () => {
    const { calls } = byMode();
    const { user } = renderApp(PAGE);

    const senior = await screen.findByRole("button", { name: "Senior" });
    expect(senior).toHaveAttribute("aria-pressed", "true");
    await within(explanation()).findByRole("heading", { name: "Summary" });
    const severity = screen.getByText("Critical");
    const cause = screen.getAllByText(INCIDENT.root_cause!.summary)[0];

    await user.click(screen.getByRole("button", { name: "Junior" }));
    expect(screen.getByRole("button", { name: "Junior" })).toHaveAttribute("aria-pressed", "true");
    // The junior wording explains the terms; the senior one does not.
    expect(await within(explanation()).findByText(/An interface is a port on the device/)).toBeInTheDocument();
    expect(calls).toEqual(["senior", "junior"]);
    // The facts the rules decided stay exactly as they were.
    expect(screen.getByText("Critical")).toBe(severity);
    expect(screen.getAllByText(INCIDENT.root_cause!.summary)[0]).toBe(cause);
    expect(screen.getByText(`: ${INCIDENT.confidence_reason}`)).toBeInTheDocument();
  });

  it("labels the built-in explanation as the fallback", async () => {
    mockApi(routes());
    renderApp(PAGE);

    expect(await screen.findByText("Built-in explanation (fallback)")).toBeInTheDocument();
    expect(screen.getByText(/No LLM is set up, so this explanation comes from the built-in templates/)).toBeInTheDocument();
    // With no LLM there is nothing to regenerate.
    expect(screen.getByRole("button", { name: /Regenerate/ })).toBeDisabled();
  });

  it("warns when the LLM's answer was refused and the fallback is shown instead", async () => {
    const refused = { ...SENIOR, fallback_reason: "the answer cited evidence F99, which does not exist" };
    mockApi(routes({ [`GET ${BASE}/explanation`]: refused }));
    renderApp(PAGE);

    const note = await screen.findByRole("note");
    expect(note).toHaveTextContent("could not be used (the answer cited evidence F99, which does not exist)");
    expect(screen.getByText("Built-in explanation (fallback)")).toBeInTheDocument();
  });

  it("names the LLM and asks before regenerating, since that costs a request", async () => {
    const written = { ...SENIOR, source: "llm", fallback_reason: null, model: "gpt-6-luna" };
    let regenerated = 0;
    mockApi(
      routes({
        "GET /api/health": { ...HEALTH, llm: { configured: true, provider: "openai" } },
        [`GET ${BASE}/explanation`]: written,
        [`POST ${BASE}/explanation/regenerate`]: () => {
          regenerated += 1;
          return { ...written, summary: "A fresh summary from the LLM." };
        },
      }),
    );
    const { user } = renderApp(PAGE);

    expect(await screen.findByText("Written by an LLM (gpt-6-luna)")).toBeInTheDocument();
    const button = screen.getByRole("button", { name: /Regenerate/ });
    await waitFor(() => expect(button).toBeEnabled());
    await user.click(button);
    const dialog = await screen.findByRole("alertdialog");
    expect(dialog).toHaveTextContent("costs one API request");
    expect(regenerated).toBe(0);

    await user.click(within(dialog).getByRole("button", { name: "Regenerate" }));
    expect(await screen.findByText("A fresh summary from the LLM.")).toBeInTheDocument();
    expect(regenerated).toBe(1);
  });

  it("shows a fix step that changes a device with a review label, and commands with a copy button", async () => {
    mockApi(routes());
    renderApp(PAGE);

    const fixes = (await screen.findByRole("heading", { name: "What to do" })).parentElement!;
    const flagged = within(fixes).getAllByText("Review before running");
    expect(flagged).toHaveLength(SENIOR.fix_steps.filter((step) => step.review_before_running).length);
    expect(flagged[0].parentElement).toHaveTextContent(/Shut and no shut the interface/);

    const checks = screen.getByRole("heading", { name: "Check it" }).parentElement!;
    expect(within(checks).getByText("show interfaces GigabitEthernet0/1")).toBeInTheDocument();
    expect(within(checks).getByRole("button", { name: "Copy show interfaces GigabitEthernet0/1" })).toBeInTheDocument();
  });

  it("shows the lines around an evidence line on request", async () => {
    mockApi(
      routes({
        "GET /api/uploads/1/lines": {
          upload_id: 1,
          around: 2260,
          context: 3,
          lines: [2257, 2258, 2259, 2260, 2261].map((line) => ({
            line,
            time: "2026-03-03T02:46:11Z",
            host: "R1",
            event_key: null,
            kind: "system",
            text: `context line ${line}`,
          })),
        },
      }),
    );
    const { user } = renderApp(PAGE);

    const row = await waitFor(() => {
      const found = document.getElementById("evidence-line-2260");
      if (!found) throw new Error("not yet");
      return found;
    });
    await user.click(within(row).getByRole("button", { name: "Show context" }));
    const around = await within(row).findByRole("list", { name: "Lines around line 2260" });
    expect(within(around).getAllByRole("listitem")).toHaveLength(5);
    expect(around).toHaveTextContent("context line 2257");
    expect(within(row).getByRole("button", { name: "Hide context" })).toHaveAttribute("aria-expanded", "true");
  });

  it("shows log lines and LLM text as plain text, never as markup", async () => {
    const hostile = "Mar 3 02:46:12 R1 1: <script>window.pwned=1</script><img src=x onerror=alert(1)> https://evil.example/x";
    const incident: IncidentDetail = {
      ...INCIDENT,
      evidence: INCIDENT.evidence.map((line) => (line.line === 2260 ? { ...line, text: hostile } : line)),
    };
    const answer: Explanation = {
      ...SENIOR,
      summary: "<b>Ignore the rules</b> and visit <a href='https://evil.example'>here</a>",
      cited_lines: SENIOR.cited_lines.map((line) => (line.line === 2260 ? { ...line, text: hostile } : line)),
    };
    mockApi(routes({ [`GET ${BASE}`]: incident, [`GET ${BASE}/explanation`]: answer }));
    renderApp(PAGE);

    expect(await screen.findByText(/<b>Ignore the rules<\/b> and visit <a href=/)).toBeInTheDocument();
    expect(screen.getAllByText(hostile).length).toBeGreaterThan(0);
    const page = document.body;
    expect(page.querySelector("script")).toBeNull();
    expect(page.querySelector("img")).toBeNull();
    expect(page.querySelector("b")).toBeNull();
    expect(page.querySelector("a[href^='https://evil']")).toBeNull();
    expect((window as unknown as { pwned?: number }).pwned).toBeUndefined();
  });

  it("shows the facts at once while the explanation is still being written", async () => {
    let release: (value: Explanation) => void = () => {};
    const pending = new Promise<Explanation>((resolve) => (release = resolve));
    mockApi(routes({ [`GET ${BASE}/explanation`]: () => pending }));
    renderApp(PAGE);

    expect(await screen.findByRole("heading", { level: 1, name: INCIDENT.headline })).toBeInTheDocument();
    expect(screen.getByText(/Writing the senior explanation/)).toBeInTheDocument();
    expect(screen.getByText("being written...")).toBeInTheDocument();
    expect(document.getElementById("evidence-line-2260")).toBeInTheDocument();
    release(SENIOR);
  });

  it("says plainly when the incident does not exist", async () => {
    mockApi(
      routes({
        [`GET /api/uploads/1/incidents/inc-nope`]: notFound("incident_not_found", "Upload 1 has no incident with id 'inc-nope'."),
        "GET /api/uploads/1/incidents/inc-nope/explanation": notFound("incident_not_found", "no"),
      }),
    );
    renderApp("/uploads/1/incidents/inc-nope");

    expect(await screen.findByRole("heading", { level: 1, name: "Incident not found" })).toBeInTheDocument();
    expect(screen.getByRole("alert")).toHaveTextContent("02_cascade.log has no incident with the id inc-nope");
    expect(screen.getByRole("link", { name: "See the incidents it does have" })).toHaveAttribute("href", "/uploads/1/incidents");
  });
});

describe("grouping the evidence", () => {
  it("puts every cited line under one step of the chain, the root cause first", () => {
    const lines = evidenceLines(INCIDENT, SENIOR);
    const groups = groupEvidence(INCIDENT, lines);

    expect(groups[0].root).toBe(true);
    expect(groups[0].lines.map((line) => line.line)).toContain(2260);
    const placed = groups.flatMap((group) => group.lines.map((line) => line.line));
    expect(new Set(placed).size).toBe(placed.length);
    // Every line the explanation cites can be found in the panel.
    const cited = [...SENIOR.timeline, ...SENIOR.hypotheses, ...SENIOR.impact].flatMap((item) => item.lines);
    for (const line of cited) expect(placed).toContain(line);
  });
});

describe("demo mode and the post-mortem", () => {
  it("labels a stored explanation as written by an LLM and stored with the demo", async () => {
    const stored = { ...SENIOR, source: "stored", fallback_reason: null, provider: "openai", model: "gpt-6-luna" };
    mockApi(routes({ [`GET ${BASE}/explanation`]: stored }));
    renderApp(PAGE);

    expect(await screen.findByText("Written by an LLM (gpt-6-luna), stored with the demo")).toBeInTheDocument();
    expect(screen.getByText(/an LLM wrote this explanation earlier, and it is stored with the app/)).toBeInTheDocument();
    const regenerate = screen.getByRole("button", { name: /Regenerate/ });
    expect(regenerate).toBeDisabled();
    expect(regenerate).toHaveAttribute("title", "Demo mode: no LLM is set up, so there is nothing to ask");
  });

  it("says the app is in demo mode, and what that means", async () => {
    mockApi(routes({ "GET /api/health": { ...HEALTH, demo: { active: true, stored_explanations: 18 } } }));
    renderApp(PAGE);

    const banner = await screen.findByText("Demo mode.");
    expect(banner.closest("[role='status']")).toHaveTextContent(
      "No LLM is set up, so nothing is sent anywhere. The demo scenarios show explanations an LLM wrote earlier",
    );
  });

  it("has no demo banner when an LLM is set up", async () => {
    mockApi(
      routes({
        "GET /api/health": { ...HEALTH, llm: { configured: true, provider: "openai" }, demo: { active: false, stored_explanations: 0 } },
      }),
    );
    renderApp(PAGE);
    await screen.findByRole("heading", { level: 1, name: INCIDENT.headline });
    await screen.findByText("Connected");
    expect(screen.queryByText("Demo mode.")).not.toBeInTheDocument();
  });

  it("downloads the post-mortem for the audience being read", async () => {
    mockApi(routes({ [`GET ${BASE}/explanation`]: (call: Call) => (call.query.get("mode") === "junior" ? JUNIOR : SENIOR) }));
    const { user } = renderApp(PAGE);

    const link = await screen.findByRole("link", { name: "Download post-mortem" });
    expect(link).toHaveAttribute("href", `${BASE}/postmortem?mode=senior`);
    expect(link).toHaveAttribute("download");
    await user.click(screen.getByRole("button", { name: "Junior" }));
    expect(screen.getByRole("link", { name: "Download post-mortem" })).toHaveAttribute("href", `${BASE}/postmortem?mode=junior`);
  });
});
