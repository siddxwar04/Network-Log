import { render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import type { Stage } from "../api/types";
import { Stepper, stepStates } from "../components/Stepper";
import { apiError, dashboard, HEALTH, mockApi, notFound, status, uploadDetail } from "./mockApi";
import { renderApp } from "./render";

function stepsOf() {
  const list = screen.getByRole("list", { name: "Pipeline stages" });
  return within(list)
    .getAllByRole("listitem")
    // A step not yet started shows its number in the circle; the name follows it.
    .map((item) => [item.textContent?.split(":")[0].replace(/^\d+/, ""), item.getAttribute("data-state")]);
}

describe("the stepper", () => {
  it.each<[Stage, Stage | null, string[]]>([
    ["queued", null, ["pending", "pending", "pending", "pending", "pending"]],
    ["parsing", null, ["active", "pending", "pending", "pending", "pending"]],
    ["detection", null, ["done", "done", "active", "pending", "pending"]],
    ["explanation", null, ["done", "done", "done", "done", "active"]],
    ["done", null, ["done", "done", "done", "done", "done"]],
    ["failed", "correlation", ["done", "done", "done", "failed", "pending"]],
    ["failed", "parsing", ["failed", "pending", "pending", "pending", "pending"]],
    ["failed", "queued", ["failed", "pending", "pending", "pending", "pending"]],
  ])("at %s (failed at %s)", (stage, failedStage, expected) => {
    expect(stepStates(stage, failedStage)).toEqual(expected);
  });

  it("names every step, marks the current one, and says each state in words", () => {
    render(<Stepper stage="detection" />);

    expect(stepsOf()).toEqual([
      ["Parse", "done"],
      ["Templates", "done"],
      ["Detect", "active"],
      ["Correlate", "pending"],
      ["Explain", "pending"],
    ]);
    const current = screen.getByText("Detect").closest("li");
    expect(current).toHaveAttribute("aria-current", "step");
    // Screen readers hear the state, not only see a color.
    expect(current).toHaveTextContent("Detect: in progress");
    expect(screen.getByText("Parse").closest("li")).toHaveTextContent("Parse: done");
  });

  it("shows a failed step", () => {
    render(<Stepper stage="failed" failedStage="templates" />);
    expect(screen.getByText("Templates").closest("li")).toHaveTextContent("Templates: failed");
    expect(screen.queryByRole("listitem", { current: "step" })).not.toBeInTheDocument();
  });
});

describe("the processing screen", () => {
  it("shows the live counts as the stages pass, then opens the dashboard", async () => {
    const sequence = [
      status("parsing", { counts: { lines: 5000, templates: 0, findings: 0, incidents: 0 } }),
      status("templates", { counts: { lines: 48210, templates: 0, findings: 0, incidents: 0 } }),
      status("correlation", { counts: { lines: 48210, templates: 312, findings: 9, incidents: 0 } }),
      status("done", { counts: { lines: 48210, templates: 312, findings: 9, incidents: 3 } }),
    ];
    let asked = 0;
    mockApi({
      ...dashboard(1),
      "GET /api/health": HEALTH,
      "GET /api/uploads/1": () =>
        asked < sequence.length
          ? uploadDetail({ status: "processing" })
          : uploadDetail({ counts: { lines: 48210, templates: 312, findings: 9, incidents: 3 } }),
      "GET /api/uploads/1/status": () => sequence[Math.min(asked++, sequence.length - 1)],
    });
    renderApp("/uploads/1/processing");

    expect(await screen.findByRole("heading", { name: /Analyzing 02_cascade\.log/ })).toBeInTheDocument();
    expect(await screen.findByText("Reading and parsing the lines")).toBeInTheDocument();
    expect(await screen.findByText("312", {}, { timeout: 3000 })).toBeInTheDocument();
    expect(await screen.findByText("Done. Opening the dashboard...", {}, { timeout: 3000 })).toBeInTheDocument();
    expect(screen.getByText("48,210")).toBeInTheDocument();
    expect(stepsOf().every(([, state]) => state === "done")).toBe(true);

    // The dashboard of the finished upload opens by itself.
    expect(await screen.findByRole("link", { name: "All incidents" }, { timeout: 3000 })).toBeInTheDocument();
    expect(screen.getByRole("heading", { level: 1 })).toHaveTextContent("02_cascade.log");
  });

  it("shows which stage failed and why, with a way back", async () => {
    mockApi({
      "GET /api/health": HEALTH,
      "GET /api/uploads/5": uploadDetail({ id: 5, filename: "notes.txt", status: "failed" }),
      "GET /api/uploads/5/status": status("failed", {
        id: 5,
        failed_stage: "parsing",
        error: "No recognizable log lines in the file. Supported: syslog (RFC 3164 and RFC 5424).",
        counts: { lines: 3, templates: 0, findings: 0, incidents: 0 },
      }),
    });
    const { user } = renderApp("/uploads/5/processing");

    expect(await screen.findByText("Failed at the Parse step.")).toBeInTheDocument();
    expect(screen.getByText(/No recognizable log lines in the file/)).toBeInTheDocument();
    expect(stepsOf()[0]).toEqual(["Parse", "failed"]);

    mockApi({
      "GET /api/health": HEALTH,
      "GET /api/demo/scenarios": { items: [], total: 0, limit: 20, offset: 0 },
      "GET /api/uploads": { items: [], total: 0, limit: 20, offset: 0 },
    });
    await user.click(screen.getByRole("link", { name: "Back to uploads" }));
    expect(await screen.findByRole("heading", { name: "Analyze a log file" })).toBeInTheDocument();
  });

  it("says when the upload does not exist", async () => {
    mockApi({
      "GET /api/health": HEALTH,
      "GET /api/uploads/99": notFound("upload_not_found", "There is no upload with id 99."),
      "GET /api/uploads/99/status": notFound("upload_not_found", "There is no upload with id 99."),
    });
    renderApp("/uploads/99/processing");

    expect(await screen.findByText(/There is no upload with id 99\. It may have been deleted\./)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Back to uploads" })).toHaveAttribute("href", "/");
  });

  it("keeps trying when the server goes away, and says so", async () => {
    let up = true;
    let asked = 0;
    mockApi({
      "GET /api/health": HEALTH,
      "GET /api/uploads/1": uploadDetail({ status: "processing" }),
      "GET /api/uploads/1/status": () => {
        asked += 1;
        if (asked === 2) up = false;
        return up ? status("detection") : "unreachable";
      },
    });
    renderApp("/uploads/1/processing");

    expect(await screen.findByText("Lost contact with the netlog server.", {}, { timeout: 3000 })).toBeInTheDocument();
    // The last known progress stays on screen.
    expect(stepsOf()[2]).toEqual(["Detect", "active"]);
  });

  it("shows another error from the server as it is", async () => {
    mockApi({
      "GET /api/health": HEALTH,
      "GET /api/uploads/1": uploadDetail(),
      "GET /api/uploads/1/status": apiError(500, "internal_error", "Something went wrong on the server."),
    });
    renderApp("/uploads/1/processing");
    expect(await screen.findByText("Something went wrong on the server.")).toBeInTheDocument();
  });
});
